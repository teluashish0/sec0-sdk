import type { Entitlements } from "../entitlements/model";
import type { QuotaAdapter } from "../quotas/adapters";
import type { OIDCConfig } from "../auth/oidc";
import type { EscalationReporter } from "../../core/contracts";
import type { HumanEscalationPolicyConfig } from "../../policy/types";
import type { Ap2Config } from "../../mandate-ap2";

export type MiddlewareConfig = {
  tenant?: string;
  authn?: { oidc: OIDCConfig; allowUnauthenticated?: boolean };
  entitlements?: Entitlements;
  quotas?: { adapter: QuotaAdapter };
  privacy?: { redact_identities?: boolean };
  enforcement?: { mode: "observe" | "enforce"; deny_on?: string[]; escalate_on?: string[] };
  ap2?: Ap2Config;
  brokers?: Record<string, { type: string; inject: { header: string; format: "raw" | "bearer" | "template" }; key_refs?: string[] }>;
  security?: {
    allow_versions?: Record<string, string[]>;
    egress_allowlist?: string[];
    fs_allowlist?: string[];
    limits?: { max_payload_kb?: number; max_duration_ms?: number };
    side_effects?: {
      require_idempotency_key?: boolean;
      approve_high_risk?: boolean;
      human_escalation?: HumanEscalationPolicyConfig;
      humanEscalation?: HumanEscalationPolicyConfig;
    };
  };
  escalationReporter?: EscalationReporter;
  dedupe?: {
    enabled?: boolean;
    duplicatePolicy?: "replay" | "reject";
    ttlSec?: number;
    namespace?: string;
    redisUrl?: string;
  };
  audit?: {
    append: (env: any) => Promise<void>;
    gatewayName: string;
    gatewayVersion: string;
    clientName?: string;
  };
  agentState?: {
    enableGatewayAnalytics?: boolean;
    includeAp2?: boolean;
    includeRisk?: boolean;
  };
  runtime?: {
    enforcement?: any;
  };
};

export type InvokeContext = { headers?: Record<string, string>; args: any; idempotencyKey?: string | null };
export type InvokeNext = (ctx: InvokeContext, injectedHeaders?: Record<string, string>) => Promise<any>;

export type ResolvedGatewayHumanEscalationConfig = {
  approvalStrategy?: "auto_allow" | "single_approver" | "human_quorum";
  timeoutAction?: "auto_approve" | "auto_reject";
  minApprovals?: number;
  minRejections?: number;
  requiredRoles?: string[];
  vetoRoles?: string[];
  approvalSetId?: string;
};

export type ResolvedGatewayEscalationPolicy = {
  enabled: boolean;
  escalateOn: Set<string>;
  human: ResolvedGatewayHumanEscalationConfig;
};

export function normalizePolicyReasonToken(value: unknown): string {
  const normalized = String(value || "").trim();
  if (normalized === "idempotency_missing") return "missing_idempotency_for_side_effect";
  if (normalized === "tool_in_denylist") return "tool_not_in_allowlist";
  return normalized;
}

export function normalizePolicyReasonArray(values: unknown): string[] {
  if (!Array.isArray(values)) return [];
  const seen = new Set<string>();
  for (const value of values) {
    const normalized = normalizePolicyReasonToken(value);
    if (!normalized) continue;
    seen.add(normalized);
  }
  return Array.from(seen.values());
}

function asOptionalPositiveInt(value: unknown): number | undefined {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return undefined;
  const floored = Math.floor(parsed);
  return floored > 0 ? floored : undefined;
}

function asOptionalStringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const out: string[] = [];
  for (const entry of value) {
    const normalized = String(entry || "").trim();
    if (!normalized) continue;
    out.push(normalized);
  }
  return out.length ? Array.from(new Set(out)) : undefined;
}

export function resolveGatewayEscalationPolicy(cfg: MiddlewareConfig): ResolvedGatewayEscalationPolicy {
  const sideEffects = cfg.security?.side_effects;
  const approveHighRisk = sideEffects?.approve_high_risk === true;
  const denyOn = normalizePolicyReasonArray(cfg.enforcement?.deny_on);
  const escalateOnRaw = cfg.enforcement?.escalate_on;
  const escalateOn = Array.isArray(escalateOnRaw) ? normalizePolicyReasonArray(escalateOnRaw) : denyOn;
  const humanRaw =
    sideEffects && typeof sideEffects === "object"
      ? ((sideEffects as any).human_escalation && typeof (sideEffects as any).human_escalation === "object"
          ? (sideEffects as any).human_escalation
          : (sideEffects as any).humanEscalation && typeof (sideEffects as any).humanEscalation === "object"
            ? (sideEffects as any).humanEscalation
            : undefined)
      : undefined;
  const strategyRaw = String(humanRaw?.approval_strategy || "").trim().toLowerCase();
  const approvalStrategy =
    strategyRaw === "auto_allow" || strategyRaw === "single_approver" || strategyRaw === "human_quorum"
      ? (strategyRaw as ResolvedGatewayHumanEscalationConfig["approvalStrategy"])
      : undefined;
  const timeoutRaw = String(humanRaw?.timeout_action || "").trim().toLowerCase();
  const timeoutAction =
    timeoutRaw === "auto_approve" || timeoutRaw === "auto_reject"
      ? (timeoutRaw as ResolvedGatewayHumanEscalationConfig["timeoutAction"])
      : undefined;
  const minApprovals = asOptionalPositiveInt(humanRaw?.min_approvals);
  const minRejections = asOptionalPositiveInt(humanRaw?.min_rejections);
  const requiredRoles = asOptionalStringArray(humanRaw?.required_roles);
  const vetoRoles = asOptionalStringArray(humanRaw?.veto_roles);
  const human: ResolvedGatewayHumanEscalationConfig = {
    ...(approvalStrategy ? { approvalStrategy } : {}),
    ...(timeoutAction ? { timeoutAction } : {}),
    ...(typeof minApprovals === "number" ? { minApprovals } : {}),
    ...(typeof minRejections === "number" ? { minRejections } : {}),
    ...(requiredRoles ? { requiredRoles } : {}),
    ...(vetoRoles ? { vetoRoles } : {}),
    ...(typeof humanRaw?.approval_set_id === "string" && humanRaw.approval_set_id.trim()
      ? { approvalSetId: humanRaw.approval_set_id.trim() }
      : {}),
  };
  return {
    enabled: approveHighRisk && escalateOn.length > 0,
    escalateOn: new Set(escalateOn),
    human,
  };
}

export function escalationSeverityForViolation(violation: string): "low" | "medium" | "high" | "critical" {
  const normalized = normalizePolicyReasonToken(violation);
  if (
    normalized === "registry_mutation" ||
    normalized === "handler_swap" ||
    normalized === "server_code_changed" ||
    normalized === "tool_code_changed" ||
    normalized === "subprocess_blocked"
  ) {
    return "critical";
  }
  if (
    normalized === "agent_guard_failed" ||
    normalized === "tool_not_in_allowlist" ||
    normalized === "version_unpinned" ||
    normalized === "skill_scan_failed" ||
    normalized === "skill_code_changed" ||
    normalized === "skill_version_changed"
  ) {
    return "high";
  }
  if (
    normalized === "egress_violation" ||
    normalized === "fs_violation" ||
    normalized === "missing_idempotency_for_side_effect" ||
    normalized === "payload_too_large" ||
    normalized === "missing_audit_signature"
  ) {
    return "medium";
  }
  return "low";
}
