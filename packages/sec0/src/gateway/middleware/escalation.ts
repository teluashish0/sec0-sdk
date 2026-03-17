import type { EscalationCreateResult } from "../../core/contracts";
import {
  escalationSeverityForViolation,
  normalizePolicyReasonToken,
  type MiddlewareConfig,
  type ResolvedGatewayEscalationPolicy,
} from "./config";

export type GatewayEscalationAttemptResult = {
  result: EscalationCreateResult | null;
  failure: string | null;
};

function buildHumanEscalationMetadata(policy: ResolvedGatewayEscalationPolicy): Record<string, unknown> {
  return {
    ...(policy.human.approvalStrategy ? { approval_strategy: policy.human.approvalStrategy } : {}),
    ...(policy.human.timeoutAction ? { timeout_action: policy.human.timeoutAction } : {}),
    ...(typeof policy.human.minApprovals === "number" ? { min_approvals: policy.human.minApprovals } : {}),
    ...(typeof policy.human.minRejections === "number" ? { min_rejections: policy.human.minRejections } : {}),
    ...(Array.isArray(policy.human.requiredRoles) ? { required_roles: policy.human.requiredRoles } : {}),
    ...(Array.isArray(policy.human.vetoRoles) ? { veto_roles: policy.human.vetoRoles } : {}),
    ...(typeof policy.human.approvalSetId === "string" ? { approval_set_id: policy.human.approvalSetId } : {}),
  };
}

function isSideEffecting(tool: string, args: any): boolean {
  const name = tool.toLowerCase();
  if (/(write|delete|put|post|patch|create|update)/.test(name)) return true;
  if (name.includes("filesystem") && /write|delete|remove|mkdir|rmdir/.test(name)) return true;
  if (name.includes("fetch") && typeof args?.method === "string" && args.method.toUpperCase() !== "GET") return true;
  return false;
}

export async function attemptGatewayEscalation(input: {
  cfg: MiddlewareConfig;
  escalationPolicy: ResolvedGatewayEscalationPolicy;
  effectiveTenant: string;
  toolRef: string;
  serverName: string;
  toolNameAtVersion: string;
  nodeId: string;
  agentRunId: string;
  traceId: string;
  spanId: string;
  args: any;
  violationRaw: string;
  reasons?: string[];
  riskTags?: string[];
  stage?: string;
}): Promise<GatewayEscalationAttemptResult> {
  const reporter = input.cfg.escalationReporter;
  const violation = normalizePolicyReasonToken(input.violationRaw);
  if (!violation || !input.escalationPolicy.enabled || !input.escalationPolicy.escalateOn.has(violation) || !reporter) {
    return { result: null, failure: null };
  }

  try {
    const humanEscalationMetadata = buildHumanEscalationMetadata(input.escalationPolicy);
    const result = await reporter.create({
      tenant: input.effectiveTenant,
      content: `Policy denied ${input.toolRef} due to ${violation}.`,
      violation,
      message: violation.replace(/_/g, " "),
      severity: escalationSeverityForViolation(violation),
      nodeId: input.nodeId,
      agentRef: input.agentRunId,
      metadata: {
        source: "sec0",
        layer: "gateway",
        ...(input.stage ? { stage: input.stage } : {}),
        tool_ref: input.toolRef,
        server: input.serverName,
        tool: input.toolNameAtVersion,
        op: isSideEffecting(input.toolNameAtVersion, input.args) ? "update" : "read",
        decision_reason: violation,
        trace_id: input.traceId,
        span_id: input.spanId,
        ...(input.riskTags?.length ? { risk_tags: [...input.riskTags] } : {}),
        ...(input.reasons?.length ? { reasons: [...input.reasons] } : {}),
        human_escalation: humanEscalationMetadata,
        security_side_effects_human_escalation: humanEscalationMetadata,
      },
      ...(input.escalationPolicy.human.timeoutAction ? { timeoutAction: input.escalationPolicy.human.timeoutAction } : {}),
      ...(input.escalationPolicy.human.approvalStrategy ? { approvalStrategy: input.escalationPolicy.human.approvalStrategy } : {}),
      ...(typeof input.escalationPolicy.human.minApprovals === "number" ? { minApprovals: input.escalationPolicy.human.minApprovals } : {}),
      ...(typeof input.escalationPolicy.human.minRejections === "number" ? { minRejections: input.escalationPolicy.human.minRejections } : {}),
      ...(Array.isArray(input.escalationPolicy.human.requiredRoles) ? { requiredRoles: input.escalationPolicy.human.requiredRoles } : {}),
      ...(Array.isArray(input.escalationPolicy.human.vetoRoles) ? { vetoRoles: input.escalationPolicy.human.vetoRoles } : {}),
      ...(typeof input.escalationPolicy.human.approvalSetId === "string" ? { approvalSetId: input.escalationPolicy.human.approvalSetId } : {}),
    });
    return { result, failure: null };
  } catch (error: any) {
    return {
      result: null,
      failure: error instanceof Error ? error.message : String(error || "unknown"),
    };
  }
}
