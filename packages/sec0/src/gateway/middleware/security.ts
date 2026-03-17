import { verifyAp2MandatesFromHeaders } from "../../mandate-ap2";
import { unauthorizedTool } from "../core/errors";
import { attachAuthZ } from "../core/spans";
import { matchesToolPattern } from "./util";
import type { GatewayDecisionEvaluator } from "./runtime";
import {
  normalizePolicyReasonArray,
  normalizePolicyReasonToken,
  resolveGatewayEscalationPolicy,
  type InvokeContext,
  type MiddlewareConfig,
} from "./config";
import { attemptGatewayEscalation } from "./escalation";

function matchAny(value: string, patterns?: string[]): boolean {
  if (!patterns || patterns.length === 0) return true;
  return patterns.some((pattern) => {
    const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*?");
    const re = new RegExp(`^${escaped}$`, "i");
    return re.test(value);
  });
}

function estimateSizeKb(obj: unknown): number {
  try {
    return Math.ceil(Buffer.byteLength(JSON.stringify(obj || {}), "utf8") / 1024);
  } catch {
    return 0;
  }
}

export function isSideEffecting(tool: string, args: any): boolean {
  const name = tool.toLowerCase();
  if (/(write|delete|put|post|patch|create|update)/.test(name)) return true;
  if (name.includes("filesystem") && /write|delete|remove|mkdir|rmdir/.test(name)) return true;
  if (name.includes("fetch") && typeof args?.method === "string" && args.method.toUpperCase() !== "GET") return true;
  return false;
}

function tryUrlHost(urlValue?: string): string | undefined {
  try {
    if (!urlValue) return undefined;
    return new URL(urlValue).hostname;
  } catch {
    return undefined;
  }
}

function readInboundHeader(ctx: InvokeContext, name: string): string | undefined {
  try {
    const headersAny = ctx.headers as Record<string, any> | undefined;
    if (!headersAny) return undefined;
    const raw = headersAny[name] ?? headersAny[name.toLowerCase()];
    if (Array.isArray(raw)) {
      const first = raw[0];
      if (typeof first === "string") {
        const trimmed = first.trim();
        return trimmed || undefined;
      }
      return undefined;
    }
    if (typeof raw === "string") {
      const trimmed = raw.trim();
      return trimmed || undefined;
    }
    return undefined;
  } catch {
    return undefined;
  }
}

export async function evaluateGatewaySecurity(input: {
  cfg: MiddlewareConfig;
  ctx: InvokeContext;
  span: any;
  serverName: string;
  toolNameAtVersion: string;
  toolRef: string;
  tenant: string;
  effectiveTenant: string;
  nodeId: string;
  agentRunId: string;
  matchedAllow?: string;
  traceId: string;
  spanId: string;
  evaluateGatewayDecision: GatewayDecisionEvaluator;
  includeAp2Analytics: boolean;
  includeRiskAnalytics: boolean;
  ensureGatewayAnalytics: () => any;
}): Promise<{
  reasons: string[];
  riskTags: string[];
  egressDomain?: string;
  fsPath?: string;
  ap2Injected: Record<string, string>;
  ap2MandateForwardHeaders: Record<string, string>;
  gatewayDecision: "allow" | "would_deny";
  escalationResult: any;
  escalationFailure: string | null;
}> {
  const riskTags: string[] = [];
  const reasons: string[] = [];
  const sec = input.cfg.security;
  const escalationPolicy = resolveGatewayEscalationPolicy(input.cfg);
  let escalationResult: any = null;
  let escalationFailure: string | null = null;
  const pushReason = (reason: string): void => {
    const normalized = normalizePolicyReasonToken(reason);
    if (!normalized) return;
    reasons.push(normalized);
    riskTags.push(normalized);
  };

  const serverAllowed = sec?.allow_versions?.[input.serverName];
  if (serverAllowed && !serverAllowed.some((version) => input.toolNameAtVersion.endsWith(`@${version}`))) {
    pushReason("version_unpinned");
  }

  const urlStr = typeof input.ctx.args?.url === "string" ? input.ctx.args.url : undefined;
  const egressDomain = tryUrlHost(urlStr);
  if (egressDomain && !matchAny(urlStr!, sec?.egress_allowlist)) {
    pushReason("egress_violation");
  }

  const fsPath = typeof input.ctx.args?.path === "string" ? input.ctx.args.path : undefined;
  if (fsPath && !matchAny(fsPath, sec?.fs_allowlist)) {
    pushReason("fs_violation");
  }

  const maxKb = sec?.limits?.max_payload_kb;
  if (maxKb && estimateSizeKb(input.ctx.args) > maxKb) {
    pushReason("payload_too_large");
  }

  if (sec?.side_effects?.require_idempotency_key && isSideEffecting(input.toolNameAtVersion, input.ctx.args) && !input.ctx.idempotencyKey) {
    pushReason("missing_idempotency_for_side_effect");
  }

  let ap2Injected: Record<string, string> = {};
  const ap2Mode = input.cfg.ap2?.mode ?? "";
  const ap2Enabled =
    input.cfg.ap2?.enabled === true || ap2Mode === "observe" || ap2Mode === "partial" || ap2Mode === "full";
  const ap2Require =
    input.cfg.ap2?.requireForSideEffects === true || ap2Mode === "partial" || ap2Mode === "full";
  const ap2AllowList = Array.isArray(input.cfg.ap2?.tools?.allow) ? (input.cfg.ap2!.tools!.allow as string[]) : [];
  const shouldEnforceAp2 = (() => {
    if (!ap2Enabled) return false;
    if (ap2AllowList.length) {
      return ap2AllowList.some((pattern) => matchesToolPattern(pattern, input.serverName, input.toolNameAtVersion));
    }
    return ap2Require && isSideEffecting(input.toolNameAtVersion, input.ctx.args);
  })();

  const ap2ReasonTags: string[] = [];
  if (shouldEnforceAp2) {
    const ap2Headers = input.ctx.headers ?? {};
    const verification = await verifyAp2MandatesFromHeaders(input.cfg.ap2, ap2Headers, input.ctx.args);
    const reason = verification.reason || "ap2_verification_error";
    if (!verification.ok) {
      reasons.push(reason);
      riskTags.push(reason);
      ap2ReasonTags.push(reason);
    }
    if (input.includeAp2Analytics) {
      const analytics = input.ensureGatewayAnalytics();
      analytics.ap2 = {
        intent_id: verification.intentId,
        cart_id: verification.cartId,
        issuer_did: verification.issuerDid,
        subject_did: verification.subjectDid,
        constraints_sha256: verification.constraintsDigest,
        cart_sha256: verification.cartDigest,
        reason: undefined,
      };
    }
    if (verification.cartDigest) {
      const idem = typeof input.ctx.idempotencyKey === "string" ? input.ctx.idempotencyKey : "";
      if (!idem) {
        reasons.push("ap2_idempotency_missing");
        riskTags.push("ap2_idempotency_missing");
        ap2ReasonTags.push("ap2_idempotency_missing");
      } else if (idem !== verification.cartDigest) {
        reasons.push("ap2_idempotency_mismatch");
        riskTags.push("ap2_idempotency_mismatch");
        ap2ReasonTags.push("ap2_idempotency_mismatch");
      }
    }
    ap2Injected = {
      ...(verification.intentId ? { "x-ap2-intent-id": verification.intentId } : {}),
      ...(verification.cartId ? { "x-ap2-cart-id": verification.cartId } : {}),
      ...(verification.constraintsDigest ? { "x-ap2-constraints-sha256": verification.constraintsDigest } : {}),
      ...(verification.cartDigest ? { "x-ap2-cart-sha256": verification.cartDigest } : {}),
      ...(verification.issuerDid ? { "x-ap2-issuer-did": verification.issuerDid } : {}),
      ...(verification.subjectDid ? { "x-ap2-subject-did": verification.subjectDid } : {}),
    };
  }

  input.span.setAttribute("check.level", "proxy");
  input.span.setAttribute("check.kind", reasons.length ? "static" : "static");

  const denyOn = Array.isArray(input.cfg.enforcement?.deny_on)
    ? new Set(normalizePolicyReasonArray(input.cfg.enforcement.deny_on))
    : null;
  let gatewayDecision: "allow" | "would_deny" = "allow";
  if (reasons.length) {
    const runtimeDecision = await input.evaluateGatewayDecision({
      reasons,
      denyOn: denyOn ? Array.from(denyOn) : undefined,
      strategy: "deny_on_match",
      forceDeny: ap2Mode === "full",
      riskTags,
      requestIdSuffix: "risk",
    });
    gatewayDecision = runtimeDecision.shouldDeny ? "would_deny" : "would_deny";
    input.span.setAttribute("decision.reason", reasons.join(","));
    if (egressDomain) input.span.setAttribute("egress.domain", egressDomain);
    if (fsPath) input.span.setAttribute("fs.path", fsPath);
    input.span.setAttribute("risk.tags", riskTags.join(","));
    input.span.setAttribute("risk.score", Math.min(100, riskTags.length * 25));

    try {
      if (reasons.some((reason) => String(reason).startsWith("ap2_"))) {
        const webhookUrl = input.cfg.ap2?.policyWebhookUrl;
        if (webhookUrl && webhookUrl.trim()) {
          fetch(webhookUrl.trim(), {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              event: "ap2.denied",
              tenant: input.tenant,
              server: input.serverName,
              tool: input.toolNameAtVersion,
              reasons,
              ts: new Date().toISOString(),
            }),
          }).catch(() => {});
        }
      }
    } catch {}

    if (runtimeDecision.shouldDeny) {
      const escalationViolation = reasons.find((entry) => escalationPolicy.escalateOn.has(normalizePolicyReasonToken(entry))) || reasons[0] || "";
      const escalationAttempt = await attemptGatewayEscalation({
        cfg: input.cfg,
        escalationPolicy,
        effectiveTenant: input.effectiveTenant,
        toolRef: input.toolRef,
        serverName: input.serverName,
        toolNameAtVersion: input.toolNameAtVersion,
        nodeId: input.nodeId,
        agentRunId: input.agentRunId,
        traceId: input.traceId,
        spanId: input.spanId,
        args: input.ctx.args,
        violationRaw: escalationViolation,
        reasons,
        riskTags,
      });
      escalationResult = escalationAttempt.result;
      escalationFailure = escalationAttempt.failure;

      attachAuthZ(input.span, { decision: "deny", reasons, matched: input.matchedAllow });
      const denyError: any = unauthorizedTool(input.toolRef, input.tenant);
      const normalizedViolation = normalizePolicyReasonToken(escalationViolation);
      denyError.denial_level = "gateway";
      if (normalizedViolation) {
        denyError.denial_reason = normalizedViolation;
        if (normalizedViolation === "egress_violation" || normalizedViolation === "fs_violation") {
          denyError.denial_type = "rasp";
        }
      }
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

    attachAuthZ(input.span, { decision: "would_deny", reasons, matched: input.matchedAllow });
  }

  if (input.includeAp2Analytics) {
    const analytics = input.ensureGatewayAnalytics();
    if (analytics.ap2) {
      analytics.ap2.reason = ap2ReasonTags.length ? ap2ReasonTags.join(",") : undefined;
    }
  }
  if (input.includeRiskAnalytics) {
    const analytics = input.ensureGatewayAnalytics();
    analytics.risk = {
      decision: gatewayDecision,
      risk_tags: riskTags.length ? [...riskTags] : undefined,
      egress_domain: egressDomain,
      fs_path: fsPath,
    };
  }

  const ap2MandateForwardHeaders: Record<string, string> = {};
  const intentHeader = input.cfg.ap2?.headers?.intent || "x-ap2-intent-mandate";
  const cartHeader = input.cfg.ap2?.headers?.cart || "x-ap2-cart-mandate";
  const bundleHeader = input.cfg.ap2?.headers?.bundle || "x-ap2-bundle";
  [intentHeader, cartHeader, bundleHeader].forEach((header) => {
    const value = readInboundHeader(input.ctx, header);
    if (value) ap2MandateForwardHeaders[header] = value;
  });

  return {
    reasons,
    riskTags,
    egressDomain,
    fsPath,
    ap2Injected,
    ap2MandateForwardHeaders,
    gatewayDecision,
    escalationResult,
    escalationFailure,
  };
}
