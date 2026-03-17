import Redis from "ioredis";
import {
  extractAgentStateFromHeaders,
  encodeAgentStateHeaders,
  ensureRunId,
  mergeAgentVariables,
  type AgentStatePayload,
  type AgentStateVariables,
  type GatewayAnalyticsState,
} from "../../agent-state";
import { redactIfNeeded } from "../core/envelope";
import { attachAuthAttrs, attachBroker, attachQuota, attachAuthZ } from "../core/spans";
import { evaluateLimits } from "../quotas/limiter";
import { getVendorHeaders } from "../broker/vendorBroker";
import { unauthorizedTool } from "../core/errors";
import type { MiddlewareConfig, InvokeContext, InvokeNext } from "./config";
import { normalizePolicyReasonToken, resolveGatewayEscalationPolicy } from "./config";
import { createGatewayDecisionEvaluator, createGatewayTraceIds } from "./runtime";
import { authenticateGatewayRequest, enforceGatewayEntitlements } from "./authz";
import { evaluateGatewaySecurity, isSideEffecting } from "./security";
import { appendGatewayAudit } from "./audit";
import { attemptGatewayEscalation } from "./escalation";

function assertAuditClientConfig(cfg: MiddlewareConfig): void {
  const auditClientNameRaw = cfg.audit?.clientName ?? cfg.audit?.gatewayName;
  const configuredClientNameSource =
    typeof auditClientNameRaw === "string" && auditClientNameRaw.trim().length > 0 ? auditClientNameRaw : undefined;
  if (!configuredClientNameSource) {
    throw new Error("[sec0-gateway] cfg.audit.clientName or cfg.audit.gatewayName must be provided");
  }
}

function createDedupeRedisGetter(cfg: MiddlewareConfig): () => Redis | null {
  let redis: Redis | null = null;
  return () => {
    try {
      if (!cfg.dedupe?.enabled) return null;
      if (!redis) {
        const rawUrl = cfg.dedupe.redisUrl;
        const url = typeof rawUrl === "string" ? rawUrl.trim() : "";
        if (!url) {
          throw new Error("[sec0-gateway] Dedupe is enabled but cfg.dedupe.redisUrl is not configured");
        }
        redis = new Redis(url, { lazyConnect: false, maxRetriesPerRequest: 2 });
      }
      return redis;
    } catch {
      return null;
    }
  };
}

export async function gatewayPipeline(
  cfg: MiddlewareConfig,
  serverName: string,
  toolNameAtVersion: string,
  ctx: InvokeContext,
  span: any,
  next: InvokeNext,
) {
  const redact = !!cfg.privacy?.redact_identities;
  const mode = cfg.enforcement?.mode || "observe";
  const toolRef = `mcp://${serverName}/${toolNameAtVersion}`;
  const { traceId: gwTraceId, spanId: gwSpanId } = createGatewayTraceIds();
  const incomingAgentState: AgentStatePayload = extractAgentStateFromHeaders(ctx.headers as any);
  const nodeId = incomingAgentState.nodeId;
  const agentRunId = ensureRunId(incomingAgentState);
  let agentVariables: AgentStateVariables | undefined = incomingAgentState.variables;
  if (incomingAgentState.metadata) {
    agentVariables = mergeAgentVariables(agentVariables, "AGENT", { metadata: incomingAgentState.metadata });
  }
  let auditAgentVariables = agentVariables;
  assertAuditClientConfig(cfg);

  const telemetryCfg = cfg.agentState;
  const gatewayAnalyticsEnabled = !!telemetryCfg?.enableGatewayAnalytics;
  const includeAp2Analytics = gatewayAnalyticsEnabled && !!telemetryCfg?.includeAp2;
  const includeRiskAnalytics = gatewayAnalyticsEnabled && !!telemetryCfg?.includeRisk;
  let gatewayAnalytics: GatewayAnalyticsState | undefined;
  const ensureGatewayAnalytics = (): GatewayAnalyticsState => {
    if (!gatewayAnalytics) gatewayAnalytics = { version: 1 };
    return gatewayAnalytics;
  };
  const hasAnalyticsPayload = (): boolean => !!gatewayAnalytics && (!!gatewayAnalytics.ap2 || !!gatewayAnalytics.risk);

  const auth = await authenticateGatewayRequest({ cfg, ctx, mode });
  attachAuthAttrs(span, {
    tenant: auth.tenant,
    userHash: redactIfNeeded(auth.authPrincipal, redact),
    plan: undefined,
  });

  const evaluateGatewayDecision = createGatewayDecisionEvaluator({
    cfg,
    effectiveTenant: auth.effectiveTenant,
    serverName,
    toolNameAtVersion,
    nodeId,
    agentRunId,
    mode: mode === "enforce" ? "enforce" : "observe",
  });

  const { plan, rate, daily, matchedAllow } = await enforceGatewayEntitlements({
    cfg,
    effectiveTenant: auth.effectiveTenant,
    toolRef,
    serverName,
    toolNameAtVersion,
    nodeId,
    agentRunId,
    user: auth.user,
    userId: auth.userId,
    roles: auth.roles,
    agentId: auth.agentId,
    args: ctx.args,
    span,
    tenant: auth.tenant,
    evaluateGatewayDecision,
    traceId: gwTraceId,
    spanId: gwSpanId,
  });
  attachAuthAttrs(span, {
    tenant: auth.effectiveTenant,
    userHash: redactIfNeeded(auth.authPrincipal, redact),
    plan,
  });

  const securityOutcome = await evaluateGatewaySecurity({
    cfg,
    ctx,
    span,
    serverName,
    toolNameAtVersion,
    toolRef,
    tenant: auth.tenant,
    effectiveTenant: auth.effectiveTenant,
    nodeId,
    agentRunId,
    matchedAllow,
    traceId: gwTraceId,
    spanId: gwSpanId,
    evaluateGatewayDecision,
    includeAp2Analytics,
    includeRiskAnalytics,
    ensureGatewayAnalytics,
  });
  const reasons = [...securityOutcome.reasons];
  const riskTags = [...securityOutcome.riskTags];
  let gatewayDecision: "allow" | "would_deny" | "deny" = securityOutcome.gatewayDecision;
  let escalationResult = securityOutcome.escalationResult;
  let escalationFailure = securityOutcome.escalationFailure;
  let egressDomain = securityOutcome.egressDomain;
  let fsPath = securityOutcome.fsPath;

  let quotaHdrs: Record<string, string> = {};
  if (cfg.quotas && (rate || daily)) {
    const quota = await evaluateLimits(cfg.quotas.adapter, auth.effectiveTenant, toolRef, { rate, daily });
    attachQuota(span, { rateRemaining: quota.rateRemaining, dailyRemaining: quota.dailyRemaining });
    if (quota.rateRemaining !== undefined) quotaHdrs["x-rate-remaining"] = String(quota.rateRemaining);
    if (quota.dailyRemaining !== undefined) quotaHdrs["x-quota-remaining"] = String(quota.dailyRemaining);
    if (quota.resetAt) quotaHdrs["x-quota-reset-at"] = quota.resetAt;
  }

  const isWrite = isSideEffecting(toolNameAtVersion, ctx.args);
  const idemKey = ctx.idempotencyKey;
  const dedupeEnabled = !!cfg.dedupe?.enabled && !!idemKey && isWrite;
  const dedupeMode = cfg.dedupe?.duplicatePolicy === "reject" ? "reject" : "replay";
  const ttlBase =
    typeof cfg.dedupe?.ttlSec === "number" && Number.isFinite(cfg.dedupe.ttlSec) && cfg.dedupe.ttlSec > 0
      ? cfg.dedupe.ttlSec
      : 1800;
  const ttlSec = Math.max(30, Math.min(24 * 3600, ttlBase));
  const ns = typeof cfg.dedupe?.namespace === "string" && cfg.dedupe.namespace.trim().length > 0 ? cfg.dedupe.namespace.trim() : "idem";
  const dedupeRedis = dedupeEnabled ? createDedupeRedisGetter(cfg)() : null;
  const dedupeKey = dedupeEnabled
    ? `${ns}:${auth.effectiveTenant}:${serverName}:${toolNameAtVersion}:${idemKey}`
    : "";

  if (dedupeEnabled && dedupeRedis) {
    const setRes = await (dedupeRedis as any).set(dedupeKey, `inflight:${Date.now()}`, { NX: true, EX: ttlSec }).catch(() => null);
    if (setRes === null) {
      const existing = await dedupeRedis.get(dedupeKey).catch(() => null);
      if (existing && existing.startsWith("done:")) {
        try {
          const cached = JSON.parse(existing.slice(5));
          return { res: cached, headers: { ...quotaHdrs, "x-dedupe": "replay" } };
        } catch {}
      }
      if (dedupeMode === "replay") {
        const deadline = Date.now() + 2000;
        while (Date.now() < deadline) {
          await new Promise((resolve) => setTimeout(resolve, 100));
          const value = await dedupeRedis.get(dedupeKey).catch(() => null);
          if (value && value.startsWith("done:")) {
            try {
              const cached = JSON.parse(value.slice(5));
              return { res: cached, headers: { ...quotaHdrs, "x-dedupe": "replay" } };
            } catch {}
          }
        }
      }
      const duplicateError: any = new Error("Duplicate idempotent request");
      duplicateError.httpStatus = 409;
      duplicateError.code = "IDEMPOTENT_DUPLICATE";
      quotaHdrs["x-dedupe"] = "reject";
      throw duplicateError;
    }
  }

  let injected: Record<string, string> = {};
  const brokerConfig = cfg.brokers?.[serverName];
  if (brokerConfig) {
    try {
      const broker = await getVendorHeaders(brokerConfig as any);
      injected = broker.headers;
      attachBroker(span, { name: broker.name });
    } catch {}
  }

  const start = Date.now();
  let status: "ok" | "error" = "ok";
  let pipelineError: any | undefined;
  try {
    let forwardedAgentHeaders: Record<string, string> = {};
    if (nodeId) {
      const gatewayId = cfg.audit ? `${cfg.audit.gatewayName}@${cfg.audit.gatewayVersion}` : "gateway@unknown";
      const additions: Record<string, unknown> = { gateway: gatewayId, status };
      if (gatewayAnalyticsEnabled && hasAnalyticsPayload()) {
        additions.analytics = gatewayAnalytics;
      }
      const varsForForward = mergeAgentVariables(agentVariables, "GATEWAY", additions);
      const headerState: AgentStatePayload = {
        nodeId,
        runId: agentRunId,
        variables: varsForForward,
      };
      forwardedAgentHeaders = encodeAgentStateHeaders(headerState);
      agentVariables = varsForForward;
      auditAgentVariables = varsForForward;
    }

    const downstreamHeaders = {
      ...securityOutcome.ap2MandateForwardHeaders,
      ...injected,
      ...securityOutcome.ap2Injected,
      "x-cause-trace": gwTraceId,
      "x-cause-span": gwSpanId,
      ...forwardedAgentHeaders,
    };
    const result = await next(ctx, downstreamHeaders);

    const maxDurationMs = Number(cfg.security?.limits?.max_duration_ms);
    if (Number.isFinite(maxDurationMs) && maxDurationMs > 0) {
      const elapsedMs = Date.now() - start;
      if (elapsedMs > maxDurationMs) {
        const durationReason = "duration_too_long";
        const hadPriorRiskDecision = gatewayDecision !== "allow";
        const normalizedDurationReason = normalizePolicyReasonToken(durationReason);
        reasons.push(normalizedDurationReason);
        riskTags.push(normalizedDurationReason);
        span.setAttribute("decision.reason", reasons.join(","));
        span.setAttribute("risk.tags", riskTags.join(","));
        span.setAttribute("risk.score", Math.min(100, riskTags.length * 25));
        const denyOn = Array.isArray(cfg.enforcement?.deny_on)
          ? cfg.enforcement.deny_on.map((entry) => normalizePolicyReasonToken(String(entry || "").trim())).filter(Boolean)
          : undefined;
        const runtimeDecision = await evaluateGatewayDecision({
          reasons: [durationReason],
          denyOn,
          strategy: "deny_on_match",
          riskTags: [durationReason],
          requestIdSuffix: "duration",
        });
        gatewayDecision = runtimeDecision.shouldDeny ? "deny" : gatewayDecision === "allow" ? "would_deny" : gatewayDecision;
        if (runtimeDecision.shouldDeny) {
          const escalationAttempt = await attemptGatewayEscalation({
            cfg,
            escalationPolicy: resolveGatewayEscalationPolicy(cfg),
            effectiveTenant: auth.effectiveTenant,
            toolRef,
            serverName,
            toolNameAtVersion,
            nodeId,
            agentRunId,
            traceId: gwTraceId,
            spanId: gwSpanId,
            args: ctx.args,
            violationRaw: durationReason,
            reasons,
            riskTags,
          });
          escalationResult = escalationAttempt.result;
          escalationFailure = escalationAttempt.failure;
          attachAuthZ(span, { decision: "deny", reasons, matched: matchedAllow });
          const denyError: any = unauthorizedTool(toolRef, auth.tenant);
          denyError.denial_level = "gateway";
          denyError.denial_reason = durationReason;
          if (escalationResult?.id) {
            denyError.escalation = escalationResult;
            denyError.escalation_id = escalationResult.id;
            denyError.escalation_status = escalationResult.status;
          }
          if (escalationFailure) {
            denyError.escalation_error = escalationFailure;
          }
          throw denyError;
        }
        if (!hadPriorRiskDecision) {
          attachAuthZ(span, { decision: "would_deny", reasons, matched: matchedAllow });
        }
      }
    }

    if (dedupeEnabled && dedupeRedis) {
      try {
        await (dedupeRedis as any).set(dedupeKey, `done:${JSON.stringify(result)}`, { EX: ttlSec });
        quotaHdrs["x-dedupe"] = "first";
      } catch {}
    }

    return { res: result, headers: { ...quotaHdrs, "x-trace-id": gwTraceId, "x-span-id": gwSpanId } };
  } catch (error: any) {
    status = "error";
    pipelineError = error;
    throw error;
  } finally {
    try {
      await appendGatewayAudit({
        cfg,
        ctxHeaders: ctx.headers,
        serverName,
        toolNameAtVersion,
        tenant: auth.effectiveTenant,
        traceId: gwTraceId,
        spanId: gwSpanId,
        status,
        startTimeMs: start,
        gatewayDecision,
        egressDomain,
        fsPath,
        riskTags,
        reasons,
        escalationResult,
        escalationFailure,
        agentRunId,
        nodeId,
        gatewayAnalyticsEnabled,
        hasAnalyticsPayload,
        gatewayAnalytics,
        auditAgentVariables,
        idempotencyKey: ctx.idempotencyKey,
      });
    } catch (auditError) {
      if (!pipelineError) throw auditError;
    }
  }
}
