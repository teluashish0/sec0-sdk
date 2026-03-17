export type AgentVariableScope = "AGENT" | "GATEWAY" | "SERVER" | "TOOL" | "ORCHESTRATOR";

export type AgentStateVariables = Partial<Record<AgentVariableScope, Record<string, unknown>>>;

// Gateway-scoped derived state. Every property is optional so emitters can opt-in.
export type GatewayAnalyticsState = {
  version: 1;
  ap2?: {
    intent_id?: string;
    cart_id?: string;
    issuer_did?: string;
    subject_did?: string;
    constraints_sha256?: string;
    cart_sha256?: string;
    reason?: string;
  };
  risk?: {
    decision?: string;
    risk_tags?: string[];
    egress_domain?: string;
    fs_path?: string;
    latency_ms?: number;
    idempotency_key?: string;
  };
};

// Canonical representation of an orchestrator's planned intent chain.
export type OrchestratorPlanStep = {
  id: string;
  type: "tool" | "agent" | "action";
  target_tool?: string;
  target_node_id?: string;
  expected_args_sha256?: string;
  metadata?: Record<string, unknown>;
};

export type OrchestratorPlanState = {
  version: 1;
  steps: OrchestratorPlanStep[];
};

// Reflection of what the executing agent actually did for a given plan step.
export type AgentExecutionRecord = {
  plan_step_id?: string;
  tool_invoked?: string;
  actual_args_sha256?: string;
  status?: "ok" | "error" | string;
  deviation_reason?: string;
  metadata?: Record<string, unknown>;
};

export type AgentExecutionState = {
  version: 1;
  runs: AgentExecutionRecord[];
};

export type AgentStatePayload = {
  nodeId: string;
  runId?: string;
  parentRef?: string;
  variables?: AgentStateVariables;
  metadata?: Record<string, unknown>;
};
