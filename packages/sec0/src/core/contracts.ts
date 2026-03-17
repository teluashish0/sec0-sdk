import type { AuditEnvelopeMinimal, RawPayloadEvent } from "../audit";
import type { PolicyObject } from "../policy";
import type { RuntimeDecisionInput, RuntimeDecisionOutput } from "../runtime-adapter";

export interface PolicyContext {
  nodeId?: string | null;
}

export interface PolicySnapshot {
  policy: PolicyObject;
  hash: string;
  tenant?: string;
  env?: string;
  clientName?: string;
  clientVersion?: string;
}

export interface PolicyProvider {
  getPolicy(context?: PolicyContext): Promise<PolicySnapshot>;
}

export interface ApprovalVerificationInput {
  token: string;
  toolRef: string;
  nodeId?: string;
  agentRef?: string;
}

export interface ApprovalVerificationResult {
  valid: boolean;
  approval?: unknown;
}

export interface ApprovalVerifier {
  verify(input: ApprovalVerificationInput): Promise<ApprovalVerificationResult | null>;
}

export type EscalationSeverity = "low" | "medium" | "high" | "critical";
export type EscalationApprovalStrategy = "auto_allow" | "single_approver" | "human_quorum";
export type EscalationTimeoutAction = "auto_approve" | "auto_reject";

export interface EscalationCreateInput {
  tenant?: string;
  content: string;
  violation: string;
  ruleId?: string | null;
  message?: string | null;
  severity?: EscalationSeverity | null;
  nodeId?: string | null;
  agentRef?: string | null;
  metadata?: Record<string, unknown> | null;
  findingSource?: "rule" | "evaluator" | null;
  evaluatorFingerprint?: string | null;
  evaluatorConfidence?: number | null;
  evaluatorPrinciples?: string[] | null;
  evaluatorSnapshot?: Record<string, unknown> | null;
  ttlSeconds?: number;
  timeoutAction?: EscalationTimeoutAction;
  approvalStrategy?: EscalationApprovalStrategy;
  approvalSetId?: string | null;
  minApprovals?: number | null;
  minRejections?: number | null;
  requiredRoles?: string[] | null;
  vetoRoles?: string[] | null;
}

export interface EscalationCreateResult {
  id: string;
  status: string;
  expiresAt?: string;
  createdAt?: string;
  requesterStatusMessage?: string;
}

export interface EscalationReporter {
  create(input: EscalationCreateInput): Promise<EscalationCreateResult | null>;
}

export type EscalationStatus =
  | "pending"
  | "approved"
  | "rejected"
  | "expired"
  | string;

export interface EscalationStatusResult {
  id: string;
  status: EscalationStatus;
  expiresAt?: string;
  createdAt?: string;
  resolvedAt?: string;
  finalizationReason?: string | null;
  requesterStatusMessage?: string;
  metadata?: Record<string, unknown> | null;
}

export interface EscalationGetInput {
  id: string;
  tenant?: string;
}

export interface EscalationResolveInput {
  id: string;
  action: "approve" | "reject";
  tenant?: string;
  notes?: string | null;
}

export interface EscalationResolver {
  get(input: EscalationGetInput): Promise<EscalationStatusResult | null>;
  resolve?(input: EscalationResolveInput): Promise<EscalationStatusResult | null>;
}

export interface AuditSink {
  append(envelope: AuditEnvelopeMinimal & { sig?: string }): Promise<void>;
  appendRawPayload?(event: RawPayloadEvent): Promise<void>;
  flush?(): Promise<void>;
}

export interface RuntimeInvoker {
  evaluate(input: RuntimeDecisionInput): Promise<RuntimeDecisionOutput>;
}
