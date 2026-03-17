export const RUNTIME_PROTOCOL_VERSION = "2026-02-01" as const;

export type RuntimeAdapterMode = "local" | "remote";
export type RuntimeDecisionAction = "allow" | "deny";
export type RuntimeExecutionLayer = "middleware" | "gateway" | "decorator";
export type RuntimeEnforcementMode = "observe" | "enforce";
export type RuntimeEvaluationStrategy = "deny_on_match" | "deny_on_any";
export type RuntimeFailureMode = "local" | "allow" | "deny";

export interface RuntimeObligation {
  type: string;
  params?: Record<string, unknown>;
}

export interface RuntimeAuditRef {
  ref: string;
  kind?: string;
  href?: string;
}

export interface RuntimeDecisionInput {
  protocolVersion?: string;
  requestId?: string;
  context: {
    integrationSurface: "sec0";
    executionLayer: RuntimeExecutionLayer;
    tenant?: string;
    server: string;
    tool: string;
    nodeId?: string;
    runId?: string;
    metadata?: Record<string, unknown>;
  };
  enforcement: {
    mode: RuntimeEnforcementMode;
    strategy?: RuntimeEvaluationStrategy;
    denyOn?: string[];
    forceDeny?: boolean;
  };
  input: {
    reasons: string[];
    riskTags?: string[];
    attributes?: Record<string, unknown>;
  };
}

export interface RuntimeDecisionOutput {
  protocolVersion: string;
  adapterMode: RuntimeAdapterMode;
  evaluationSource: "local" | "remote" | "fallback-local" | "fallback-allow" | "fallback-deny";
  decision: RuntimeDecisionAction;
  reason?: string;
  reasons: string[];
  obligations: RuntimeObligation[];
  auditRefs: RuntimeAuditRef[];
}

export interface RuntimeRemoteAdapterConfig {
  endpoint?: string;
  timeoutMs?: number;
  maxRetries?: number;
  retryBackoffMs?: number;
  headers?: Record<string, string>;
  apiKey?: string;
}

export interface RuntimeAdapterConfig {
  mode?: RuntimeAdapterMode;
  protocolVersion?: string;
  failureMode?: RuntimeFailureMode;
  remote?: RuntimeRemoteAdapterConfig;
}

export interface ResolvedRuntimeAdapterConfig {
  mode: RuntimeAdapterMode;
  protocolVersion: string;
  failureMode: RuntimeFailureMode;
  remote: {
    endpoint?: string;
    timeoutMs: number;
    maxRetries: number;
    retryBackoffMs: number;
    headers: Record<string, string>;
    apiKey?: string;
  };
}

export interface RuntimeAdapter {
  evaluate(input: RuntimeDecisionInput): Promise<RuntimeDecisionOutput>;
}

export interface RuntimeProtocolDecisionResponse {
  protocolVersion?: unknown;
  decision?: {
    action?: unknown;
    reason?: unknown;
    reasons?: unknown;
    obligations?: unknown;
    auditRefs?: unknown;
  };
}
