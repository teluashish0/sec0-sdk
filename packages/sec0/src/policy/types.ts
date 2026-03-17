export type RetentionClass = "30d" | "90d" | "180d";

export type SecurityLevel = "gateway" | "middleware";

export type Severity = "low" | "medium" | "high" | "critical";

export type PolicyEnforcementReason =
  | "missing_audit_signature"
  | "tool_not_in_allowlist"
  | "version_unpinned"
  | "missing_idempotency_for_side_effect"
  | "egress_violation"
  | "fs_violation"
  | "payload_too_large"
  | "duration_too_long"
  | "registry_mutation"
  | "handler_swap"
  | "server_code_changed"
  | "tool_code_changed"
  | "skill_version_changed"
  | "skill_code_changed"
  | "skill_scan_pending"
  | "skill_scan_failed"
  | "sast_pending"
  | "sast_failed"
  | "dast_pending"
  | "dast_failed"
  | "agent_guard_failed"
  | "contextual_evaluator_denied"
  | "contextual_evaluator_escalated";

export interface CompliancePackRule {
  id: string;
  // Optional display label preserved for control-plane/UI compatibility.
  name?: string;
  // Rule type. Defaults to "regex" when omitted.
  // "regex": match patterns against scanned text
  // "nl": use a natural-language instruction and a threshold (0-100) scored by an evaluator
  type?: "regex" | "nl";
  location?: "input" | "output" | "both" | "run";
  severity?: Severity;
  message?: string;
  patterns?: string[];
  instruction?: string;
  threshold?: number;
  tags?: string[];
}

export interface CompliancePack {
  id: string;
  name: string;
  description?: string;
  rules?: CompliancePackRule[];
}

export interface CompliancePolicyRef {
  id: string;
  name: string;
  enabled: boolean;
  pack_ids: string[];
}

// Configuration for the LLM Judge used to evaluate natural-language compliance rules.
export interface LlmJudgeConfig {
  // LLM provider: "openai" or "anthropic".
  provider: "openai" | "anthropic";
  // API key for the chosen provider.
  api_key?: string;
  // Model identifier (e.g. "gpt-4.1-mini", "claude-sonnet-4-20250514").
  model?: string;
}

export type EscalationApprovalStrategy =
  | "auto_allow"
  | "single_approver"
  | "human_quorum";

export type EscalationTimeoutAction = "auto_approve" | "auto_reject";

export interface HumanEscalationPolicyConfig {
  approval_strategy?: EscalationApprovalStrategy;
  timeout_action?: EscalationTimeoutAction;
  min_approvals?: number;
  min_rejections?: number;
  required_roles?: string[];
  veto_roles?: string[];
  approval_set_id?: string;
}

export interface PolicyObject {
  tenant: string;
  // Optional marker used by control-plane to distinguish gateway vs middleware policies.
  security_level?: SecurityLevel | string;
  default_retention: RetentionClass | string;
  signing: {
    enabled: boolean;
    key_ref: string;
  };
  observability: {
    otlp_endpoint: string;
    sample: { success: number; error: number };
  };
  tools: {
    allowlist: string[];
    deny_if_unpinned_version: boolean;
  };
  skills?: {
    allowlist?: string[];
    deny_if_unpinned_version?: boolean;
    scan_on_change_only?: boolean;
    block_on_change?: boolean;
    block_on_severity?: Severity;
  };
  privacy: {
    redact_outputs: boolean;
    store_raw_payloads: boolean;
    artifact_retention: { public: string; pii: string; phi: string };
  };
  side_effects: {
    require_idempotency_key: boolean;
    max_retries: number;
  };
  enforcement: {
    deny_on: PolicyEnforcementReason[];
    // Violations that should be escalated for human approval when
    // security.side_effects.approve_high_risk is enabled.
    escalate_on?: PolicyEnforcementReason[];
    circuit_breakers: {
      error_rate_pct: number;
      p95_latency_ms: number;
    };
    agent_guard?: {
      enabled?: boolean;
      block_on_severity?: Severity;
      block_on_count?: number;
    };
  };
  // Primary location for agent guard knobs used by middleware.
  agent_guard?: {
    enabled?: boolean;
    block_on_severity?: Severity;
    block_on_count?: number;
  };
  // Optional compliance configuration: inlined packs and policy-to-pack attachments.
  compliance?: {
    packs?: CompliancePack[];
    policies?: CompliancePolicyRef[];
    // LLM Judge config: which LLM provider/model evaluates NL compliance rules.
    llm_judge?: LlmJudgeConfig;
  };
  // Top-level LLM Judge config (duplicated from compliance for SDK/middleware convenience).
  llm_judge?: LlmJudgeConfig;
  sec0_export: {
    enabled: boolean;
    cadence?: "daily" | "weekly" | "monthly";
    bucket_uri: string;
  };
  security?: {
    allow_versions?: Record<string, string[]>;
    egress_allowlist?: string[];
    fs_allowlist?: string[];
    limits?: { max_payload_kb?: number; max_duration_ms?: number };
    side_effects?: {
      require_idempotency_key?: boolean;
      approve_high_risk?: boolean;
      // Legacy control-plane fields still emitted by some policy editors.
      escalation_ttl_seconds?: number;
      ttl_seconds?: number;
      escalationTtlSeconds?: number;
      escalation_on_timeout?: EscalationTimeoutAction;
      timeout_action?: EscalationTimeoutAction;
      escalationOnTimeout?: EscalationTimeoutAction;
      human_escalation?: HumanEscalationPolicyConfig;
      humanEscalation?: HumanEscalationPolicyConfig;
    };
  };
}

export interface ValidationResult {
  valid: boolean;
  errors?: string[];
}
