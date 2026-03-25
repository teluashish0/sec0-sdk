import type { EscalationCreateResult, EscalationReporter } from "../core/contracts";
import type { PolicyObject } from "../policy";
import type { MiddlewareInvocationState } from "./invocationState";
import {
  normalizeEscalationFindingSeverity,
  preferredEscalationFindingSource,
  resolveEscalationPolicy,
  selectPrimaryEscalationFinding,
  severityForViolation,
  sortEscalationFindingsForReporting,
} from "./policyUtils";
import { inferOp, normalizePolicyReasonToken, toolUri } from "./tooling";

export type EscalationAssemblyInput = {
  state: MiddlewareInvocationState;
  policy: PolicyObject;
  escalationReporter?: EscalationReporter | null;
  tenant?: string;
  server: { name: string; version: string };
  tool: string;
  ctx: { args: any; headers?: Record<string, string> };
  nodeId?: string;
  agentRef?: string;
  traceId: string;
  spanId: string;
};

function buildHumanEscalationMetadata(human: ReturnType<typeof resolveEscalationPolicy>["human"]) {
  return {
    ...(human.approvalStrategy ? { approval_strategy: human.approvalStrategy } : {}),
    ...(human.timeoutAction ? { timeout_action: human.timeoutAction } : {}),
    ...(typeof human.minApprovals === "number" ? { min_approvals: human.minApprovals } : {}),
    ...(typeof human.minRejections === "number" ? { min_rejections: human.minRejections } : {}),
    ...(Array.isArray(human.requiredRoles) ? { required_roles: human.requiredRoles } : {}),
    ...(Array.isArray(human.vetoRoles) ? { veto_roles: human.vetoRoles } : {}),
    ...(typeof human.approvalSetId === "string" ? { approval_set_id: human.approvalSetId } : {}),
  };
}

export async function createEscalationFromState(input: EscalationAssemblyInput): Promise<{
  escalationResult: EscalationCreateResult | null;
  escalationFailure: string | null;
  escalationViolation: string;
}> {
  const escalationViolation =
    input.state.decision === "deny" && input.state.error && (input.state.error as any).violation
      ? normalizePolicyReasonToken((input.state.error as any).violation)
      : input.state.contextualEvaluatorViolation
        ? normalizePolicyReasonToken(input.state.contextualEvaluatorViolation)
        : "";
  const escalationPolicy = resolveEscalationPolicy(input.policy);
  const isEvaluatorEscalation =
    escalationViolation === "contextual_evaluator_denied" ||
    escalationViolation === "contextual_evaluator_escalated";
  if (
    !escalationViolation ||
    !input.escalationReporter ||
    (!isEvaluatorEscalation && !(escalationPolicy.enabled && escalationPolicy.escalateOn.has(escalationViolation)))
  ) {
    return {
      escalationResult: null,
      escalationFailure: null,
      escalationViolation,
    };
  }

  try {
    const findingsForEscalation = sortEscalationFindingsForReporting(input.state.agentFindings)
      .slice(0, 25)
      .map((finding) => ({
        source: finding.source || "rule",
        code: finding.code,
        severity: finding.severity,
        location: finding.location,
        message: finding.message,
        evidence: typeof finding.evidence === "string" ? finding.evidence.slice(0, 320) : undefined,
        rule_id: finding.rule_id,
        policy_id: finding.policy_id,
        pack_id: finding.pack_id,
        confidence: finding.confidence,
        principles: Array.isArray(finding.principles) ? finding.principles.slice(0, 10) : undefined,
        fingerprint: finding.fingerprint,
        reasoning: typeof finding.reasoning === "string" ? finding.reasoning.slice(0, 1000) : undefined,
      }));
    const primaryFinding = selectPrimaryEscalationFinding(input.state.agentFindings);
    const evaluatorData = input.state.contextualEvaluatorFinding
      ? {
          severity: input.state.contextualEvaluatorFinding.severity,
          fingerprint: input.state.contextualEvaluatorFinding.fingerprint,
          confidence: input.state.contextualEvaluatorFinding.confidence,
          principles: input.state.contextualEvaluatorFinding.principles,
          summary: input.state.contextualEvaluatorFinding.summary,
          reasoning: input.state.contextualEvaluatorFinding.reasoning,
          snapshot: input.state.contextualEvaluatorFinding.snapshot,
        }
      : null;
    const escalationResult = await input.escalationReporter.create({
      tenant: input.tenant,
      content: `Policy denied ${toolUri(input.server.name, input.tool)} due to ${escalationViolation}.`,
      violation: escalationViolation,
      ruleId: typeof primaryFinding?.rule_id === "string" ? primaryFinding.rule_id : null,
      message:
        typeof primaryFinding?.message === "string" && primaryFinding.message.trim()
          ? primaryFinding.message.trim()
          : escalationViolation.replace(/_/g, " "),
      severity:
        normalizeEscalationFindingSeverity(primaryFinding?.severity) ||
        evaluatorData?.severity ||
        severityForViolation(escalationViolation),
      nodeId: input.nodeId || null,
      agentRef: input.agentRef || null,
      findingSource: preferredEscalationFindingSource({
        violation: escalationViolation,
        findings: input.state.agentFindings,
        contextualFinding: input.state.contextualEvaluatorFinding,
      }),
      ...(evaluatorData
        ? {
            evaluatorFingerprint: evaluatorData.fingerprint || null,
            evaluatorConfidence: evaluatorData.confidence ?? null,
            evaluatorPrinciples: evaluatorData.principles || null,
            evaluatorSnapshot: evaluatorData.snapshot || null,
          }
        : {}),
      metadata: {
        source: "sec0-sdk",
        layer: "middleware",
        tool_ref: toolUri(input.server.name, input.tool),
        server: input.server.name,
        tool: input.tool,
        op: inferOp(input.tool, input.ctx.args),
        decision_reason: escalationViolation,
        trace_id: input.traceId,
        span_id: input.spanId,
        risk_tags: [...input.state.riskTags],
        findings: findingsForEscalation,
        ...(evaluatorData
          ? {
              evaluator: {
                fingerprint: evaluatorData.fingerprint,
                confidence: evaluatorData.confidence,
                principles: evaluatorData.principles,
                summary: evaluatorData.summary,
                reasoning: evaluatorData.reasoning,
                snapshot: evaluatorData.snapshot,
              },
            }
          : {}),
        human_escalation: buildHumanEscalationMetadata(escalationPolicy.human),
        security_side_effects_human_escalation: buildHumanEscalationMetadata(escalationPolicy.human),
      },
      ...(escalationPolicy.human.timeoutAction ? { timeoutAction: escalationPolicy.human.timeoutAction } : {}),
      ...(escalationPolicy.human.approvalStrategy ? { approvalStrategy: escalationPolicy.human.approvalStrategy } : {}),
      ...(typeof escalationPolicy.human.minApprovals === "number" ? { minApprovals: escalationPolicy.human.minApprovals } : {}),
      ...(typeof escalationPolicy.human.minRejections === "number" ? { minRejections: escalationPolicy.human.minRejections } : {}),
      ...(Array.isArray(escalationPolicy.human.requiredRoles) ? { requiredRoles: escalationPolicy.human.requiredRoles } : {}),
      ...(Array.isArray(escalationPolicy.human.vetoRoles) ? { vetoRoles: escalationPolicy.human.vetoRoles } : {}),
      ...(typeof escalationPolicy.human.approvalSetId === "string" ? { approvalSetId: escalationPolicy.human.approvalSetId } : {}),
    });
    return {
      escalationResult,
      escalationFailure: null,
      escalationViolation,
    };
  } catch (error: any) {
    return {
      escalationResult: null,
      escalationFailure: error instanceof Error ? error.message : String(error || "unknown"),
      escalationViolation,
    };
  }
}
