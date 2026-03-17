import { mergeAgentVariables, type GatewayAnalyticsState, type AgentStateVariables } from "../../agent-state";
import type { EscalationCreateResult } from "../../core/contracts";
import type { MiddlewareConfig } from "./config";

export async function appendGatewayAudit(input: {
  cfg: MiddlewareConfig;
  ctxHeaders?: Record<string, string>;
  serverName: string;
  toolNameAtVersion: string;
  tenant: string;
  traceId: string;
  spanId: string;
  status: "ok" | "error";
  startTimeMs: number;
  gatewayDecision: "allow" | "would_deny" | "deny";
  egressDomain?: string;
  fsPath?: string;
  riskTags: string[];
  reasons: string[];
  escalationResult: EscalationCreateResult | null;
  escalationFailure: string | null;
  agentRunId: string;
  nodeId: string;
  gatewayAnalyticsEnabled: boolean;
  hasAnalyticsPayload: () => boolean;
  gatewayAnalytics?: GatewayAnalyticsState;
  auditAgentVariables?: AgentStateVariables;
  idempotencyKey?: string | null;
}): Promise<void> {
  const audit = input.cfg.audit;
  if (!audit || typeof audit.append !== "function") {
    throw new Error("[sec0-gateway] Missing or invalid audit configuration; audit.append must be a function");
  }

  const latency = Date.now() - input.startTimeMs;
  const gatewayId = `${audit.gatewayName}@${audit.gatewayVersion}`;
  if (input.gatewayAnalyticsEnabled && input.gatewayAnalytics?.risk) {
    input.gatewayAnalytics.risk.latency_ms = latency;
    if (input.idempotencyKey) {
      input.gatewayAnalytics.risk.idempotency_key = input.idempotencyKey;
    }
  }

  const gatewayVars: Record<string, unknown> = { gateway: gatewayId, status: input.status };
  if (input.gatewayAnalyticsEnabled && input.hasAnalyticsPayload()) {
    gatewayVars.analytics = input.gatewayAnalytics;
  }
  const auditAgentVariables = mergeAgentVariables(input.auditAgentVariables, "GATEWAY", gatewayVars);
  const agentVariablesPayload = auditAgentVariables && Object.keys(auditAgentVariables).length ? auditAgentVariables : undefined;
  const env: any = {
    ts: new Date().toISOString(),
    trace_id: input.traceId,
    span_id: input.spanId,
    ...(input.ctxHeaders?.["x-cause-trace"] ? { cause_trace_id: String(input.ctxHeaders["x-cause-trace"]) } : {}),
    ...(input.ctxHeaders?.["x-cause-span"] ? { cause_span_id: String(input.ctxHeaders["x-cause-span"]) } : {}),
    tenant: input.tenant,
    server: input.serverName,
    tool: input.toolNameAtVersion,
    node_type: "gateway",
    gateway: gatewayId,
    status: input.status,
    latency_ms: latency,
    retries: 0,
    input_sha256: null,
    output_sha256: null,
    policy: { decision: input.gatewayDecision, retention: "standard" },
    ...(input.idempotencyKey ? { idempotency_key: input.idempotencyKey } : {}),
    ...(input.egressDomain ? { egress_domain: input.egressDomain } : {}),
    ...(input.fsPath ? { fs_path: input.fsPath } : {}),
    ...(input.riskTags.length ? { risk_tags: input.riskTags } : {}),
    ...(input.reasons.length ? { decision_reason: input.reasons.join(",") } : {}),
    ...(input.escalationResult?.id ? { escalation_id: input.escalationResult.id } : {}),
    ...(input.escalationResult?.status ? { escalation_status: input.escalationResult.status } : {}),
    ...(input.escalationFailure ? { escalation_error: input.escalationFailure } : {}),
    nodeId: input.nodeId,
    agentRef: input.agentRunId,
    ...(agentVariablesPayload ? { agentVariables: agentVariablesPayload } : {}),
    ...(input.gatewayAnalyticsEnabled && input.hasAnalyticsPayload() ? { analytics: input.gatewayAnalytics } : {}),
  };

  console.log("[Gateway Audit] Appending envelope:", {
    trace_id: input.traceId,
    tool: input.toolNameAtVersion,
    cause: input.ctxHeaders?.["x-cause-trace"],
  });
  await audit.append(env);
  console.log("[Gateway Audit] Appended successfully");
}
