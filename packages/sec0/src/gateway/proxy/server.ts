import http from "node:http";
import { randomBytes } from "node:crypto";
import { gatewayPipeline, type MiddlewareConfig, type InvokeContext } from "../middleware";
import { createControlPlaneEscalationReporter } from "../../middleware/adapters/escalationReporter";
import { createControlPlaneClient } from "../../middleware/adapters/controlPlaneClient";
import YAML from "yaml";

const requireNonEmptyString = (value: unknown, fieldName: string): string => {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`[sec0-gateway] ${fieldName} is required`);
  }
  return value.trim();
};

const optionalNonEmptyString = (value: unknown): string | undefined => {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
};

const optionalBoolean = (value: unknown): boolean | undefined => {
  return typeof value === "boolean" ? value : undefined;
};

const optionalStringArray = (value: unknown): string[] | undefined => {
  if (!Array.isArray(value)) return undefined;
  const out = value
    .map((entry) => (typeof entry === "string" ? entry.trim() : String(entry ?? "").trim()))
    .filter(Boolean);
  return out.length > 0 ? out : undefined;
};

const requireNonEmptyRecord = <T extends Record<string, unknown>>(value: T | undefined, fieldName: string): T => {
  if (!value || Object.keys(value).length === 0) {
    throw new Error(`[sec0-gateway] ${fieldName} is required`);
  }
  return value;
};

const requireHeader = (value: string | string[] | undefined, fieldName: string): string => {
  const resolved = Array.isArray(value) ? value[0] : value;
  if (typeof resolved !== "string" || !resolved.trim()) {
    throw Object.assign(new Error(`[sec0-gateway] ${fieldName} header is required`), { httpStatus: 400 });
  }
  return resolved.trim();
};

const requireRequestString = (value: unknown, fieldName: string): string => {
  if (typeof value !== "string" || !value.trim()) {
    throw Object.assign(new Error(`[sec0-gateway] ${fieldName} is required`), { httpStatus: 400 });
  }
  return value.trim();
};

const copyOptionalHeader = (
  source: Record<string, string | string[] | undefined>,
  headerName: string,
  target: Record<string, string>
) => {
  const raw = source[headerName];
  const value = Array.isArray(raw) ? raw[0] : raw;
  if (typeof value === "string" && value.length > 0) {
    target[headerName] = value;
  }
};

const randomTraceId = () => randomBytes(16).toString("hex");
const randomSpanId = () => randomBytes(8).toString("hex");
const coerceHeaderValue = (value: string | string[] | undefined): string | undefined => {
  if (!value) return undefined;
  if (Array.isArray(value)) {
    const first = value.find((entry) => typeof entry === "string" && entry.trim().length > 0);
    return first?.trim();
  }
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
};

function debugPolicySyncGw(...args: any[]) {
  try {
    const raw = process.env.SEC0_DEBUG_POLICY_SYNC;
    if (!raw) return;
    const normalized = raw.trim().toLowerCase();
    if (normalized && normalized !== "0" && normalized !== "false") {
      // eslint-disable-next-line no-console
      console.log("[sec0-gateway][policySync]", ...args);
    }
  } catch {}
}

export function applyGatewayPolicyOverrides(
  cfg: MiddlewareConfig & { targets?: Record<string, string> },
  policy: any
) {
  if (!policy || typeof policy !== "object" || Array.isArray(policy)) return;

  const authnPolicy = policy?.authn;
  if (authnPolicy && typeof authnPolicy === "object") {
    const modeRaw = optionalNonEmptyString(authnPolicy.mode);
    const mode = modeRaw ? modeRaw.toLowerCase() : undefined;
    if (mode === "service_token") {
      throw new Error("[sec0-gateway] policy authn.mode=service_token is not implemented by gateway middleware. Use authn.mode=oidc.");
    }
    if (mode === "disabled") {
      cfg.authn = undefined;
    } else {
      const oidcPolicy = authnPolicy.oidc;
      if (mode === "oidc" || (oidcPolicy && typeof oidcPolicy === "object")) {
        const merged = {
          issuer: optionalNonEmptyString(oidcPolicy?.issuer) ?? optionalNonEmptyString(cfg.authn?.oidc?.issuer),
          audience: optionalNonEmptyString(oidcPolicy?.audience) ?? optionalNonEmptyString(cfg.authn?.oidc?.audience),
          jwks_uri: optionalNonEmptyString(oidcPolicy?.jwks_uri) ?? optionalNonEmptyString(cfg.authn?.oidc?.jwks_uri),
          tenantClaim: optionalNonEmptyString(oidcPolicy?.tenantClaim) ?? optionalNonEmptyString(cfg.authn?.oidc?.tenantClaim),
          userClaim: optionalNonEmptyString(oidcPolicy?.userClaim) ?? optionalNonEmptyString(cfg.authn?.oidc?.userClaim),
          rolesClaim: optionalNonEmptyString(oidcPolicy?.rolesClaim) ?? optionalNonEmptyString(cfg.authn?.oidc?.rolesClaim),
          subjectClaim: optionalNonEmptyString(oidcPolicy?.subjectClaim) ?? optionalNonEmptyString(cfg.authn?.oidc?.subjectClaim),
          clientIdClaim: optionalNonEmptyString(oidcPolicy?.clientIdClaim) ?? optionalNonEmptyString(cfg.authn?.oidc?.clientIdClaim),
        };
        if (!merged.issuer || !merged.audience || !merged.jwks_uri) {
          throw new Error("[sec0-gateway] authn.oidc requires issuer, audience, and jwks_uri");
        }
        const allowUnauthenticated =
          optionalBoolean(authnPolicy.allowUnauthenticated) ??
          optionalBoolean(authnPolicy.allow_unauthenticated) ??
          cfg.authn?.allowUnauthenticated;
        cfg.authn = {
          oidc: {
            issuer: merged.issuer,
            audience: merged.audience,
            jwks_uri: merged.jwks_uri,
            ...(merged.tenantClaim ? { tenantClaim: merged.tenantClaim } : {}),
            ...(merged.userClaim ? { userClaim: merged.userClaim } : {}),
            ...(merged.rolesClaim ? { rolesClaim: merged.rolesClaim } : {}),
            ...(merged.subjectClaim ? { subjectClaim: merged.subjectClaim } : {}),
            ...(merged.clientIdClaim ? { clientIdClaim: merged.clientIdClaim } : {}),
          },
          ...(typeof allowUnauthenticated === "boolean" ? { allowUnauthenticated } : {}),
        };
      }
    }
  }

  if (policy?.entitlements && typeof policy.entitlements === "object" && !Array.isArray(policy.entitlements)) {
    cfg.entitlements = policy.entitlements;
  }
  if (policy?.brokers && typeof policy.brokers === "object" && !Array.isArray(policy.brokers)) {
    cfg.brokers = policy.brokers;
  }
  if (policy?.targets && typeof policy.targets === "object" && !Array.isArray(policy.targets)) {
    (cfg as any).targets = policy.targets;
  }

  if (policy?.enforcement && typeof policy.enforcement === "object" && !Array.isArray(policy.enforcement)) {
    const mode = optionalNonEmptyString(policy.enforcement.mode);
    const denyOn = optionalStringArray(policy.enforcement.deny_on);
    const escalateOn = optionalStringArray(policy.enforcement.escalate_on);
    cfg.enforcement = {
      ...(cfg.enforcement || { mode: "observe" }),
      ...(mode === "observe" || mode === "enforce" ? { mode } : {}),
      ...(denyOn ? { deny_on: denyOn } : {}),
      ...(escalateOn ? { escalate_on: escalateOn } : {}),
    } as any;
  }

  if (policy?.runtime && typeof policy.runtime === "object" && !Array.isArray(policy.runtime)) {
    const runtimePolicy = policy.runtime as any;
    if (runtimePolicy.enforcement && typeof runtimePolicy.enforcement === "object" && !Array.isArray(runtimePolicy.enforcement)) {
      const enforcementPolicy = runtimePolicy.enforcement as any;
      const mode = optionalNonEmptyString(enforcementPolicy.mode);
      const failureMode = optionalNonEmptyString(enforcementPolicy.failureMode);
      const remote = enforcementPolicy.remote && typeof enforcementPolicy.remote === "object" ? enforcementPolicy.remote : {};
      const remoteEndpoint = optionalNonEmptyString(remote.endpoint);
      const remoteApiKey = optionalNonEmptyString(remote.apiKey);
      const timeoutMs = Number.isFinite(Number(remote.timeoutMs)) ? Number(remote.timeoutMs) : undefined;
      const maxRetries = Number.isFinite(Number(remote.maxRetries)) ? Number(remote.maxRetries) : undefined;
      const retryBackoffMs = Number.isFinite(Number(remote.retryBackoffMs)) ? Number(remote.retryBackoffMs) : undefined;
      const remoteHeaders =
        remote.headers && typeof remote.headers === "object" && !Array.isArray(remote.headers)
          ? Object.fromEntries(
              Object.entries(remote.headers)
                .map(([key, value]) => [String(key).trim(), String(value ?? "").trim()])
                .filter(([key, value]) => key.length > 0 && value.length > 0),
            )
          : undefined;
      cfg.runtime = {
        ...(cfg.runtime || {}),
        enforcement: {
          ...(cfg.runtime?.enforcement || {}),
          ...(mode === "local" || mode === "remote" ? { mode } : {}),
          ...(failureMode === "local" || failureMode === "allow" || failureMode === "deny" ? { failureMode } : {}),
          remote: {
            ...(cfg.runtime?.enforcement?.remote || {}),
            ...(remoteEndpoint ? { endpoint: remoteEndpoint } : {}),
            ...(remoteApiKey ? { apiKey: remoteApiKey } : {}),
            ...(typeof timeoutMs === "number" ? { timeoutMs } : {}),
            ...(typeof maxRetries === "number" ? { maxRetries } : {}),
            ...(typeof retryBackoffMs === "number" ? { retryBackoffMs } : {}),
            ...(remoteHeaders ? { headers: remoteHeaders } : {}),
          },
        },
      };
    }
  }

  if (policy?.security && typeof policy.security === "object" && !Array.isArray(policy.security)) {
    cfg.security = {
      ...(cfg.security || {}),
      ...(policy.security.allow_versions && typeof policy.security.allow_versions === "object" ? { allow_versions: policy.security.allow_versions } : {}),
      ...(optionalStringArray(policy.security.egress_allowlist) ? { egress_allowlist: optionalStringArray(policy.security.egress_allowlist) } : {}),
      ...(optionalStringArray(policy.security.fs_allowlist) ? { fs_allowlist: optionalStringArray(policy.security.fs_allowlist) } : {}),
      ...(policy.security.limits && typeof policy.security.limits === "object" ? { limits: policy.security.limits } : {}),
      ...(policy.security.side_effects && typeof policy.security.side_effects === "object" ? { side_effects: policy.security.side_effects } : {}),
    };
  }

  if (policy?.privacy && typeof policy.privacy === "object" && !Array.isArray(policy.privacy)) {
    cfg.privacy = {
      ...(cfg.privacy || {}),
      ...(typeof policy.privacy.redact_identities !== "undefined" ? { redact_identities: !!policy.privacy.redact_identities } : {}),
    };
  }

  const ap2Policy = policy?.security?.ap2 && typeof policy.security.ap2 === "object"
    ? policy.security.ap2
    : policy?.ap2 && typeof policy.ap2 === "object"
      ? policy.ap2
      : undefined;
  if (ap2Policy) {
    const existingAp2 = (cfg.ap2 || {}) as any;
    const existingHeaders = (existingAp2.headers || {}) as any;
    const existingTrust = (existingAp2.trust || {}) as any;
    const existingTools = (existingAp2.tools || {}) as any;
    const policyHeaders = ap2Policy.headers && typeof ap2Policy.headers === "object" ? ap2Policy.headers : {};
    const policyTrust = ap2Policy.trust && typeof ap2Policy.trust === "object" ? ap2Policy.trust : {};
    const policyTools = ap2Policy.tools && typeof ap2Policy.tools === "object" ? ap2Policy.tools : {};
    const requireForSideEffects =
      optionalBoolean(ap2Policy.require_for_side_effects) ?? optionalBoolean(ap2Policy.requireForSideEffects);
    const mode = optionalNonEmptyString(ap2Policy.mode);
    const policyWebhookUrl =
      optionalNonEmptyString(ap2Policy.policy_webhook_url) ?? optionalNonEmptyString(ap2Policy.policyWebhookUrl);
    const didMethods = optionalStringArray(policyTrust.did_methods) ?? optionalStringArray(policyTrust.didMethods);
    const issuersAllowlist = optionalStringArray(policyTrust.issuers_allowlist) ?? optionalStringArray(policyTrust.issuersAllowlist);
    const clockSkewSec = Number.isFinite(Number(policyTrust.clock_skew_sec))
      ? Number(policyTrust.clock_skew_sec)
      : Number.isFinite(Number(policyTrust.clockSkewSec))
        ? Number(policyTrust.clockSkewSec)
        : undefined;
    const toolsAllow = optionalStringArray(policyTools.allow);

    cfg.ap2 = {
      ...existingAp2,
      ...(typeof ap2Policy.enabled !== "undefined" ? { enabled: !!ap2Policy.enabled } : {}),
      ...(typeof requireForSideEffects === "boolean" ? { requireForSideEffects } : {}),
      ...(mode === "" || mode === "observe" || mode === "partial" || mode === "full" ? { mode: mode as any } : {}),
      ...(policyWebhookUrl ? { policyWebhookUrl } : {}),
      headers: {
        ...existingHeaders,
        ...(optionalNonEmptyString(policyHeaders.intent) ? { intent: optionalNonEmptyString(policyHeaders.intent) } : {}),
        ...(optionalNonEmptyString(policyHeaders.cart) ? { cart: optionalNonEmptyString(policyHeaders.cart) } : {}),
        ...(optionalNonEmptyString(policyHeaders.bundle) ? { bundle: optionalNonEmptyString(policyHeaders.bundle) } : {}),
      },
      trust: {
        ...existingTrust,
        ...(didMethods ? { didMethods } : {}),
        ...(issuersAllowlist ? { issuersAllowlist } : {}),
        ...(typeof clockSkewSec === "number" ? { clockSkewSec } : {}),
      },
      tools: {
        ...existingTools,
        ...(toolsAllow ? { allow: toolsAllow } : {}),
      },
    };
  }

  if (policy?.dedupe && typeof policy.dedupe === "object" && !Array.isArray(policy.dedupe)) {
    const dedupePolicy = policy.dedupe as any;
    const duplicatePolicy = optionalNonEmptyString(dedupePolicy.duplicatePolicy);
    cfg.dedupe = {
      ...(cfg.dedupe || {}),
      ...(typeof dedupePolicy.enabled !== "undefined" ? { enabled: !!dedupePolicy.enabled } : {}),
      ...(duplicatePolicy === "replay" || duplicatePolicy === "reject" ? { duplicatePolicy: duplicatePolicy as "replay" | "reject" } : {}),
      ...(Number.isFinite(Number(dedupePolicy.ttlSec)) ? { ttlSec: Number(dedupePolicy.ttlSec) } : {}),
      ...(optionalNonEmptyString(dedupePolicy.namespace) ? { namespace: optionalNonEmptyString(dedupePolicy.namespace) } : {}),
      ...(optionalNonEmptyString(dedupePolicy.redisUrl) ? { redisUrl: optionalNonEmptyString(dedupePolicy.redisUrl) } : {}),
    };
  }

  if (policy?.agentState && typeof policy.agentState === "object" && !Array.isArray(policy.agentState)) {
    const agentStatePolicy = policy.agentState as any;
    cfg.agentState = {
      ...(cfg.agentState || {}),
      ...(typeof agentStatePolicy.enableGatewayAnalytics !== "undefined" ? { enableGatewayAnalytics: !!agentStatePolicy.enableGatewayAnalytics } : {}),
      ...(typeof agentStatePolicy.includeAp2 !== "undefined" ? { includeAp2: !!agentStatePolicy.includeAp2 } : {}),
      ...(typeof agentStatePolicy.includeRisk !== "undefined" ? { includeRisk: !!agentStatePolicy.includeRisk } : {}),
    };
  }
}

/**
 * Spin up an HTTP listener that funnels MCP-style requests through the
 * middleware pipeline. The server refuses to invent defaults so authors learn
 * about missing configuration immediately.
 */
export function startGatewayServer(cfg: MiddlewareConfig & { port?: number; policyYaml?: string; tenant?: string; policyObject?: any; sec0Dir?: string }) {
  const portValue = cfg.port;
  if (typeof portValue !== "number" || !Number.isFinite(portValue)) {
    throw new Error("[sec0-gateway] cfg.port must be provided as a finite number");
  }
  const tenant = requireNonEmptyString(cfg.tenant, "cfg.tenant");
  cfg.tenant = tenant;
  let resolvedPolicy: any = null;
  if (cfg.policyObject != null) {
    if (typeof cfg.policyObject !== "object" || Array.isArray(cfg.policyObject)) {
      throw new Error("[sec0-gateway] cfg.policyObject must be an object");
    }
    resolvedPolicy = cfg.policyObject;
  } else if (cfg.policyYaml != null) {
    const policyYaml = requireNonEmptyString(cfg.policyYaml, "cfg.policyYaml");
    cfg.policyYaml = policyYaml;
    resolvedPolicy = (YAML.parse(policyYaml) || {}) as any;
  }
  if (resolvedPolicy) {
    applyGatewayPolicyOverrides(cfg as any, resolvedPolicy);
  }
  if (!cfg.escalationReporter) {
    const apiKey = optionalNonEmptyString(process.env.SEC0_API_KEY);
    const bearerToken = optionalNonEmptyString(process.env.SEC0_BEARER_TOKEN);
    if (apiKey || bearerToken) {
      const timeoutMsRaw = Number(process.env.SEC0_ESCALATION_TIMEOUT_MS);
      cfg.escalationReporter = createControlPlaneEscalationReporter({
        auth: {
          ...(apiKey ? { apiKey } : {}),
          ...(bearerToken ? { bearerToken } : {}),
        },
        client: createControlPlaneClient({ baseUrl: optionalNonEmptyString(process.env.SEC0_CONTROL_PLANE_URL) }),
        ...(Number.isFinite(timeoutMsRaw) && timeoutMsRaw > 0 ? { timeoutMs: timeoutMsRaw } : {}),
      });
    }
  }

  if (!cfg.audit) {
    throw new Error("[sec0-gateway] cfg.audit is required");
  }
  if (!cfg.quotas) {
    throw new Error("[sec0-gateway] cfg.quotas is required");
  }
  const targets = requireNonEmptyRecord((cfg as any).targets as Record<string, string> | undefined, "cfg.targets") as Record<string, string>;

  const server = http.createServer(async (req, res) => {
    let currentServerName: string | undefined;
    let currentToolAtVersion: string | undefined;
    try {
      const url = new URL(req.url || "/", `http://${req.headers.host}`);
      const [, root, p2, p3] = url.pathname.split("/");

      if (root === "a2a" && p2 === "invoke") {
        const chunks: Buffer[] = [];
        for await (const c of req) chunks.push(c as Buffer);
        const rawBody = Buffer.concat(chunks).toString("utf8");
        if (!rawBody) {
          throw Object.assign(new Error("[sec0-gateway] request body is required"), { httpStatus: 400 });
        }
        let body: any;
        try {
          body = JSON.parse(rawBody);
        } catch {
          throw Object.assign(new Error("[sec0-gateway] request body must be valid JSON"), { httpStatus: 400 });
        }
        if (!body || typeof body !== "object") {
          throw Object.assign(new Error("[sec0-gateway] request body must be an object"), { httpStatus: 400 });
        }
        const serverName = requireRequestString(body.to, "body.to");
        const toolAtVer = requireRequestString(body.toolAtVersion, "body.toolAtVersion");
        currentServerName = serverName;
        currentToolAtVersion = toolAtVer;
        const args = body.args;
        const idem = requireHeader(req.headers["x-idempotency-key"], "x-idempotency-key");
        const ctx: InvokeContext = { headers: req.headers as any, args, idempotencyKey: idem as any };
        const span = { setAttribute: (_k: string, _v: any) => {} } as any;
        const forward = async (_ctx: InvokeContext, injectedHeaders?: Record<string, string>): Promise<any> => {
          const base = targets[serverName];
          if (!base) {
            const error: any = new Error("TARGET_NOT_FOUND");
            error.httpStatus = 502;
            error.code = "TARGET_NOT_FOUND";
            throw error;
          }
          const upstreamHeaders: Record<string, string> = {
            "Content-Type": "application/json",
            "x-idempotency-key": idem,
          };
          ["x-auth-context", "x-ap2-intent-mandate", "x-ap2-cart-mandate", "x-ap2-bundle", "x-node-id", "x-agent-ref", "x-agent-state", "x-agent-parent-ref"].forEach((header) =>
            copyOptionalHeader(req.headers as any, header, upstreamHeaders)
          );
          copyOptionalHeader(req.headers as any, "traceparent", upstreamHeaders);
          copyOptionalHeader(req.headers as any, "baggage", upstreamHeaders);
          if (injectedHeaders) {
            Object.entries(injectedHeaders).forEach(([key, value]) => {
              upstreamHeaders[key] = value;
            });
          }
          const upstream = await fetch(`${base}/invoke/${encodeURIComponent(toolAtVer)}`, {
            method: "POST",
            headers: upstreamHeaders,
            body: JSON.stringify(args ?? {}),
          });
          const txt = await upstream.text();
          let json: any;
          try {
            json = JSON.parse(txt);
          } catch {
            json = { raw: txt };
          }
          if (!upstream.ok) {
            const error: any = new Error(json?.message || "UPSTREAM");
            error.httpStatus = upstream.status;
            error.code = json?.error || "UPSTREAM";
            error.denial_level = "gateway";
            throw error;
          }
          return json;
        };
        const { res: result, headers } = await gatewayPipeline(cfg, serverName, toolAtVer, ctx, span, forward);
        Object.entries(headers || {}).forEach(([k, v]) => res.setHeader(k, v as any));
        res.setHeader("x-idempotency-key", idem);
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify(result));
        return;
      }

      if (root !== "mcp") {
        res.statusCode = 404;
        res.end("not found");
        return;
      }

      const serverName = requireRequestString(p2, "server");
      const toolAtVer = requireRequestString(p3, "toolAtVersion");
      currentServerName = serverName;
      currentToolAtVersion = toolAtVer;
      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(c as Buffer);
      let body: any;
      if (chunks.length) {
        const raw = Buffer.concat(chunks).toString("utf8");
        try {
          body = JSON.parse(raw);
        } catch {
          throw Object.assign(new Error("[sec0-gateway] request body must be valid JSON"), { httpStatus: 400 });
        }
      }
      const idem = requireHeader(req.headers["x-idempotency-key"], "x-idempotency-key");
      const ctx: InvokeContext = { headers: req.headers as any, args: body, idempotencyKey: idem as any };
      const span = { setAttribute: (_k: string, _v: any) => {} } as any;
      const forward = async (_ctx: InvokeContext, injectedHeaders?: Record<string, string>): Promise<any> => {
        const base = targets[serverName];
        if (!base) {
          const error: any = new Error("TARGET_NOT_FOUND");
          error.httpStatus = 502;
          error.code = "TARGET_NOT_FOUND";
          throw error;
        }
        const upstreamHeaders: Record<string, string> = {
          "Content-Type": "application/json",
          "x-idempotency-key": idem,
        };
        ["x-auth-context", "x-node-id", "x-agent-ref", "x-agent-state", "x-agent-parent-ref"].forEach((header) =>
          copyOptionalHeader(req.headers as any, header, upstreamHeaders)
        );
        copyOptionalHeader(req.headers as any, "traceparent", upstreamHeaders);
        copyOptionalHeader(req.headers as any, "baggage", upstreamHeaders);
        if (injectedHeaders) {
          Object.entries(injectedHeaders).forEach(([key, value]) => {
            upstreamHeaders[key] = value;
          });
        }
        const upstream = await fetch(`${base}/invoke/${encodeURIComponent(toolAtVer)}`, {
          method: "POST",
          headers: upstreamHeaders,
          body: JSON.stringify(body ?? {}),
        });
        const txt = await upstream.text();
        let json: any;
        try {
          json = JSON.parse(txt);
        } catch {
          json = { raw: txt };
        }
        if (!upstream.ok) {
          const error: any = new Error(json?.message || "UPSTREAM");
          error.httpStatus = upstream.status;
          error.code = json?.error || "UPSTREAM";
          error.denial_level = "gateway";
          if (error.code === "egress_violation" || error.code === "fs_violation") {
            error.denial_type = "rasp";
          }
          throw error;
        }
        return json;
      };
      const { res: result, headers } = await gatewayPipeline(cfg, serverName, toolAtVer, ctx, span, forward);
      Object.entries(headers || {}).forEach(([k, v]) => res.setHeader(k, v as any));
      res.setHeader("x-idempotency-key", idem);
      try {
        const incoming = req.headers["traceparent"];
        const tp = Array.isArray(incoming) ? incoming[0] : incoming;
        if (typeof tp === "string" && tp.length > 0) {
          res.setHeader("traceparent", tp);
        }
      } catch {}
      try {
        const traceId = res.getHeader("x-trace-id");
        if (typeof traceId === "string" && traceId.length > 0) {
          res.setHeader("x-trace-id", traceId);
        }
        const spanId = res.getHeader("x-span-id");
        if (typeof spanId === "string" && spanId.length > 0) {
          res.setHeader("x-span-id", spanId);
        }
      } catch {}
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify(result));
    } catch (e: any) {
      const code = e?.httpStatus || 500;
      if (e?.retryAfterSec) res.setHeader("Retry-After", String(e.retryAfterSec));
      if (e?.resetAt) res.setHeader("x-quota-reset-at", e.resetAt);
      res.statusCode = code;
      res.setHeader("Content-Type", "application/json");
      const causeTrace = coerceHeaderValue(req.headers["x-cause-trace"]);
      const causeSpan = coerceHeaderValue(req.headers["x-cause-span"]);
      if (!causeTrace || !causeSpan) {
        console.warn("[sec0-gateway] Missing x-cause-trace/x-cause-span from caller; generating fallback trace IDs", {
          tenant: cfg.tenant,
          server: currentServerName,
          tool: currentToolAtVersion,
          nodeType: "gateway",
          nodeId: cfg.audit?.gatewayName,
        });
      }
      const fallbackTrace = causeTrace || randomTraceId();
      const fallbackSpan = causeSpan || randomSpanId();
      res.setHeader("x-trace-id", fallbackTrace);
      res.setHeader("x-span-id", fallbackSpan);
      res.end(
        JSON.stringify({
          error: e?.code || "ERROR",
          message: e?.message || "error",
          denial_level: e?.denial_level,
          denial_type: e?.denial_type,
          denial_reason: e?.denial_reason,
          escalation_id: e?.escalation_id,
          escalation_status: e?.escalation_status,
          escalation_error: e?.escalation_error,
        }),
      );
    }
  });

  server.listen(portValue, () => console.log(`[gateway] listening on :${portValue}`));
  return server;
}
