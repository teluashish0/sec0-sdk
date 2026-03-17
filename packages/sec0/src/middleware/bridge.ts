// Bridges middleware tool invocations through the sec0 Gateway while forwarding
// tracing, identity, and agent state metadata.
import { createHash, randomUUID } from 'node:crypto';
import { buildIdentityContext, encodeIdentityContextHeader } from './identity';
import {
  encodeAgentStateHeaders,
  ensureRunId,
  normalizeAgentStatePayload,
  type AgentStatePayload,
  type AgentStateVariables,
} from '../agent-state';

// Parameters required to invoke a remote MCP tool via the gateway.
export type BridgeCallOptions = {
  gatewayBaseUrl: string;           // e.g., https://YOUR_GATEWAY_DOMAIN
  server: string;                   // MCP server name
  toolAtVersion: string;            // e.g., fetch@1.0
  args?: any;
  authHeader?: string;              // Bearer ...
  tenant?: string;                  // optional tenant stamp
  traceparent?: string;
  baggage?: string;
  runId?: string;                   // graph run id for multi-agent
  nodeId?: string;                  // graph node id
  idempotencySalt?: string;         // to tweak key generation
  timeoutMs?: number;
  ap2?: { intent?: string; cart?: string; bundle?: string };
  cause?: { traceId: string; spanId: string }; // parent hop identifiers for explicit A2A linking
  identity?: {
    authorization?: string;
    tenant?: string;
    roles?: string[];
    userId?: string;
    userHash?: string;
    assertion?: string;
  };
  agentState?: AgentStatePayload;
};

// Minimal agent metadata captured in outbound requests.
export type AgentContext = {
  nodeId: string;
  runId?: string;
  // @deprecated Use runId instead.
  ref?: string;
  variables?: AgentStateVariables;
  metadata?: Record<string, unknown>;
};

// Convenience options when the caller already has an agent context struct.
export type AgentBridgeCallOptions = Omit<BridgeCallOptions, 'agentState'> & {
  agent: AgentContext;
};

/**
 * Helper to avoid re-importing signer utilities for a simple hash.
 */
function sha256Hex(buf: Buffer): string {
  return createHash('sha256').update(buf).digest('hex');
}

/**
 * Creates a stable idempotency key based on run/node/tool/args.
 */
export function buildIdempotencyKey(opts: { runId?: string; nodeId?: string; toolAtVersion: string; args?: any; salt?: string }): string {
  const payload = JSON.stringify(opts.args || {});
  const h = sha256Hex(Buffer.from(payload)).slice(0, 16);
  const rid = opts.runId || randomUUID();
  const nid = opts.nodeId || 'node';
  const salt = opts.salt ? `:${opts.salt}` : '';
  return `${rid}:${nid}:${opts.toolAtVersion}:${h}${salt}`;
}

/**
 * Core executor that posts tool arguments to the gateway and stitches response
 * tracing metadata back into the result payload.
 */
export async function callToolViaGateway(opts: BridgeCallOptions): Promise<any> {
  if (!opts) throw new Error('[sec0-middleware] callToolViaGateway options are required');
  const gatewayBaseUrl = typeof opts.gatewayBaseUrl === 'string' ? opts.gatewayBaseUrl.trim() : '';
  if (!gatewayBaseUrl) throw new Error('[sec0-middleware] gatewayBaseUrl is required and must be a non-empty string');
  const server = typeof opts.server === 'string' ? opts.server.trim() : '';
  if (!server) throw new Error('[sec0-middleware] server is required and must be a non-empty string');
  const toolAtVersion = typeof opts.toolAtVersion === 'string' ? opts.toolAtVersion.trim() : '';
  if (!toolAtVersion) throw new Error('[sec0-middleware] toolAtVersion is required and must be a non-empty string');

  // Do NOT encode toolAtVersion: gateway expects raw "@" and will encode when forwarding upstream
  const url = `${gatewayBaseUrl.replace(/\/$/, '')}/mcp/${encodeURIComponent(server)}/${toolAtVersion}`;
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (opts.authHeader) headers['Authorization'] = opts.authHeader;
  if (opts.traceparent) headers['traceparent'] = opts.traceparent;
  if (opts.baggage) headers['baggage'] = opts.baggage;
  if (opts.tenant) headers['x-tenant'] = opts.tenant;
  if (opts.runId) headers['x-graph-run-id'] = opts.runId;
  if (opts.nodeId) headers['x-graph-node'] = opts.nodeId;
  if (!opts.cause) {
    throw new Error('[sec0-middleware] opts.cause is required. Ensure upstream decorators populate traceId/spanId.');
  }
  const traceId = typeof opts.cause.traceId === 'string' ? opts.cause.traceId.trim() : '';
  const spanId = typeof opts.cause.spanId === 'string' ? opts.cause.spanId.trim() : '';
  if (!traceId || !spanId) {
    throw new Error('[sec0-middleware] opts.cause must include non-empty traceId and spanId.');
  }
  headers['x-cause-trace'] = traceId;
  headers['x-cause-span'] = spanId;
  headers['x-idempotency-key'] = buildIdempotencyKey({ runId: opts.runId, nodeId: opts.nodeId, toolAtVersion, args: opts.args, salt: opts.idempotencySalt });
  if (opts.ap2?.intent) headers['x-ap2-intent-mandate'] = opts.ap2.intent;
  if (opts.ap2?.cart) headers['x-ap2-cart-mandate'] = opts.ap2.cart;
  if (opts.ap2?.bundle) headers['x-ap2-bundle'] = opts.ap2.bundle;

  if (opts.agentState) {
    const runId = ensureRunId(opts.agentState);
    const normalized = normalizeAgentStatePayload({ ...opts.agentState, runId });
    const agentHeaders = encodeAgentStateHeaders(normalized);
    Object.assign(headers, agentHeaders);
  }

  // Optional privacy-safe identity context header for downstream audit
  try {
    if (opts.identity) {
      const id = buildIdentityContext({
        authorization: opts.identity.authorization,
        tenant: opts.identity.tenant,
        roles: opts.identity.roles,
        userId: opts.identity.userId,
        userHash: opts.identity.userHash,
        assertion: opts.identity.assertion,
      });
      const idHeader = encodeIdentityContextHeader(id);
      headers[idHeader.name] = idHeader.value;
    }
  } catch {}

  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), opts.timeoutMs ?? 60000);
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(opts.args || {}),
      signal: controller.signal
    });
    const body = await res.json().catch(() => ({}));
    const traceId = (res.headers.get('x-trace-id') || '').trim();
    const spanId = (res.headers.get('x-span-id') || '').trim();
    if (!traceId || !spanId) {
      throw new Error('[sec0-middleware] Gateway response missing x-trace-id/x-span-id headers.');
    }
    if (!res.ok) {
      const err: any = new Error(body?.message || `HTTP_${res.status}`);
      err.code = body?.error || 'ERROR';
      err.status = res.status;
      err.traceId = traceId;
      err.spanId = spanId;
      err.denial_level = body?.denial_level;
      err.denial_type = body?.denial_type;
      err.denial_reason = body?.denial_reason;
      err.escalation_id = body?.escalation_id;
      err.escalation_status = body?.escalation_status;
      err.escalation_error = body?.escalation_error;
      throw err;
    }
    if (body && typeof body === 'object' && !Array.isArray(body)) {
      const payload = body as Record<string, any>;
      payload.traceId = traceId;
      payload.spanId = spanId;
      return payload;
    }
    return { result: body, traceId, spanId };
  } finally {
    clearTimeout(t);
  }
}

/**
 * Sugar over callToolViaGateway that ensures agent state headers accompany the
 * tool invocation.
 */
export async function callToolViaGatewayWithAgent(opts: AgentBridgeCallOptions): Promise<any> {
  if (!opts.agent) {
    throw new Error('[sec0-middleware] agent context is required for callToolViaGatewayWithAgent');
  }
  if (typeof opts.agent.nodeId !== 'string' || !opts.agent.nodeId.trim()) {
    throw new Error('[sec0-middleware] agent.nodeId is required and must be a non-empty string');
  }
  const resolvedRunId =
    typeof opts.agent.runId === 'string' && opts.agent.runId.trim()
      ? opts.agent.runId.trim()
      : typeof opts.agent.ref === 'string' && opts.agent.ref.trim()
        ? opts.agent.ref.trim()
        : undefined;
  if (!resolvedRunId) {
    throw new Error('[sec0-middleware] agent.runId is required and must be a non-empty string');
  }
  const agentState: AgentStatePayload = {
    nodeId: opts.agent.nodeId,
    runId: resolvedRunId,
  };
  if (opts.agent.variables) {
    agentState.variables = opts.agent.variables;
  }
  if (opts.agent.metadata) {
    agentState.metadata = opts.agent.metadata;
  }
  return callToolViaGateway({ ...opts, agentState });
}
