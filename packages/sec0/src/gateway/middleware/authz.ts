import { checkEntitlements } from "../entitlements/checker";
import { unauthenticated, unauthorizedTool } from "../core/errors";
import { attachAuthZ } from "../core/spans";
import { verifyOidcJWT } from "../auth/oidc";
import type { GatewayDecisionEvaluator } from "./runtime";
import {
  normalizePolicyReasonToken,
  resolveGatewayEscalationPolicy,
  type InvokeContext,
  type MiddlewareConfig,
} from "./config";
import { attemptGatewayEscalation, type GatewayEscalationAttemptResult } from "./escalation";

export type AuthenticatedGatewayContext = {
  tenant: string;
  effectiveTenant: string;
  user?: string;
  userId?: string;
  agentId?: string;
  roles?: string[];
  authPrincipal?: string;
};

export async function authenticateGatewayRequest(input: {
  cfg: MiddlewareConfig;
  ctx: InvokeContext;
  mode: "observe" | "enforce";
}): Promise<AuthenticatedGatewayContext> {
  let tenantCandidate: string | undefined;
  let user: string | undefined;
  let userId: string | undefined;
  let agentId: string | undefined;
  let roles: string[] | undefined;
  const headerTenant = (() => {
    try {
      const headers = input.ctx.headers as any;
      let raw: any;
      if (headers && typeof headers === "object") {
        if (Object.prototype.hasOwnProperty.call(headers, "x-tenant")) raw = headers["x-tenant"];
        else if (Object.prototype.hasOwnProperty.call(headers, "X-Tenant")) raw = headers["X-Tenant"];
      }
      if (Array.isArray(raw)) {
        const first = raw[0];
        if (typeof first === "string" && first.trim().length > 0) return first.trim();
        return undefined;
      }
      if (typeof raw === "string") {
        const trimmed = raw.trim();
        return trimmed.length > 0 ? trimmed : undefined;
      }
      return undefined;
    } catch {
      return undefined;
    }
  })();
  const cfgTenant = (() => {
    if (typeof input.cfg.tenant !== "string") return undefined;
    const trimmed = input.cfg.tenant.trim();
    return trimmed.length > 0 ? trimmed : undefined;
  })();

  if (input.cfg.authn && !input.cfg.authn.oidc) {
    throw new Error("[sec0-gateway] cfg.authn.oidc must be provided when authn is configured");
  }

  if (input.cfg.authn) {
    if (headerTenant) tenantCandidate = headerTenant;
    else if (cfgTenant) tenantCandidate = cfgTenant;

    const allowUnauthenticated = input.cfg.authn.allowUnauthenticated === true;
    let authHeaderValue: string | undefined;
    if (typeof input.ctx.headers?.authorization === "string") {
      authHeaderValue = input.ctx.headers.authorization;
    } else if (typeof (input.ctx.headers as any)?.Authorization === "string") {
      authHeaderValue = (input.ctx.headers as any).Authorization;
    }
    const auth = typeof authHeaderValue === "string" ? authHeaderValue : "";
    const token = auth.toLowerCase().startsWith("bearer ") ? auth.slice(7) : undefined;
    if (!token) {
      if (!allowUnauthenticated || input.mode === "enforce") throw unauthenticated();
    } else if (input.cfg.authn.oidc) {
      const id = await verifyOidcJWT(token, input.cfg.authn.oidc);
      if (headerTenant && id.tenant && headerTenant !== id.tenant) {
        throw unauthenticated("x-tenant does not match identity token tenant");
      }
      tenantCandidate = id.tenant;
      user = id.user;
      userId = id.userId;
      roles = id.roles;
      agentId = !id.user ? (id.clientId ?? id.userId) : undefined;
    }
  } else {
    if (!cfgTenant) {
      throw new Error("[sec0-gateway] cfg.tenant is required when authn is not configured");
    }
    if (headerTenant && headerTenant !== cfgTenant) {
      throw unauthenticated("x-tenant header is not allowed without authn");
    }
    tenantCandidate = cfgTenant;
  }

  if (!tenantCandidate || tenantCandidate.trim().length === 0) {
    throw new Error("[sec0-gateway] Missing required tenant (cfg.tenant or identity token)");
  }

  const tenant = tenantCandidate.trim();
  return {
    tenant,
    effectiveTenant: tenant,
    user,
    userId,
    agentId,
    roles,
    authPrincipal: user || userId || agentId,
  };
}

export async function enforceGatewayEntitlements(input: {
  cfg: MiddlewareConfig;
  effectiveTenant: string;
  toolRef: string;
  serverName: string;
  toolNameAtVersion: string;
  nodeId: string;
  agentRunId: string;
  user?: string;
  userId?: string;
  roles?: string[];
  agentId?: string;
  args: any;
  span: any;
  tenant: string;
  evaluateGatewayDecision: GatewayDecisionEvaluator;
  traceId: string;
  spanId: string;
}): Promise<{ plan?: string; rate?: number; daily?: number; matchedAllow?: string }> {
  if (!input.cfg.entitlements) {
    return {};
  }

  const entitlementResult = checkEntitlements(input.cfg.entitlements, {
    tenant: input.effectiveTenant,
    user: input.user,
    userId: input.userId,
    roles: input.roles,
    agent: input.agentId,
    agentNode: input.nodeId,
    toolRef: input.toolRef,
  });
  const plan = entitlementResult.plan;
  const rate = entitlementResult.limits.rate;
  const daily = entitlementResult.limits.daily;
  const matchedAllow = entitlementResult.matchedAllow;
  const denyReasons = !entitlementResult.allowed && entitlementResult.reason ? [entitlementResult.reason] : [];
  const runtimeDecision = await input.evaluateGatewayDecision({
    reasons: denyReasons,
    strategy: "deny_on_any",
    requestIdSuffix: "authz",
  });
  const deniedByRuntime = runtimeDecision.shouldDeny;
  const decision = entitlementResult.allowed ? "allow" : deniedByRuntime ? "deny" : "would_deny";
  if (!entitlementResult.allowed && deniedByRuntime) {
    const escalationPolicy = resolveGatewayEscalationPolicy(input.cfg);
    const normalizedDenyReasons = denyReasons.map((reason) => normalizePolicyReasonToken(reason)).filter(Boolean);
    const escalationViolation =
      normalizedDenyReasons.find((reason) => escalationPolicy.escalateOn.has(reason)) || normalizedDenyReasons[0] || "";
    let escalationAttempt: GatewayEscalationAttemptResult = { result: null, failure: null };
    if (escalationViolation) {
      escalationAttempt = await attemptGatewayEscalation({
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
        args: input.args,
        violationRaw: escalationViolation,
        reasons: normalizedDenyReasons,
        stage: "authz",
      });
    }
    const denyError: any = unauthorizedTool(input.toolRef, input.tenant);
    denyError.denial_level = "gateway";
    if (escalationViolation) denyError.denial_reason = escalationViolation;
    if (escalationAttempt.result?.id) {
      denyError.escalation = escalationAttempt.result;
      denyError.escalation_id = escalationAttempt.result.id;
      denyError.escalation_status = escalationAttempt.result.status;
    }
    if (escalationAttempt.failure) {
      denyError.escalation_error = escalationAttempt.failure;
    }
    throw denyError;
  }

  attachAuthZ(input.span, { decision, reasons: denyReasons, matched: matchedAllow });
  return { plan, rate, daily, matchedAllow };
}
