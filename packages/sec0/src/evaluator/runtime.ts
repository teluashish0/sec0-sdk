import { type EvaluatorInput, type EvaluatorInputPatch } from "./types";

function cloneArray<T>(value: T[] | undefined): T[] | undefined {
  return Array.isArray(value) ? [...value] : undefined;
}

export function asEvaluatorRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

export function mergeEvaluatorInput(
  base: EvaluatorInput,
  extra?: EvaluatorInputPatch | null,
): EvaluatorInput {
  if (!extra) return base;
  return {
    ...base,
    ...(extra as EvaluatorInput),
    action: {
      ...base.action,
      ...(extra.action || {}),
      ...(extra.action?.tool ? { tool: { ...(base.action.tool || {}), ...extra.action.tool } } : {}),
      ...(extra.action?.target ? { target: { ...(base.action.target || {}), ...extra.action.target } } : {}),
      ...(extra.action?.data ? { data: { ...(base.action.data || {}), ...extra.action.data } } : {}),
    },
    actor: { ...base.actor, ...(extra.actor || {}) },
    purpose: { ...base.purpose, ...(extra.purpose || {}) },
    authority: {
      ...base.authority,
      ...(extra.authority || {}),
      ...(extra.authority?.grantedScopes ? { grantedScopes: [...extra.authority.grantedScopes] } : {}),
      ...(extra.authority?.allowedBoundaries ? { allowedBoundaries: [...extra.authority.allowedBoundaries] } : {}),
      ...(extra.authority?.approvals ? { approvals: [...extra.authority.approvals] } : {}),
      ...(extra.authority?.delegations ? { delegations: [...extra.authority.delegations] } : {}),
    },
    runtimeContext: {
      ...base.runtimeContext,
      ...(extra.runtimeContext || {}),
      ...(extra.runtimeContext?.workflowState ? { workflowState: { ...extra.runtimeContext.workflowState } } : {}),
      ...(extra.runtimeContext?.conversationState
        ? { conversationState: { ...extra.runtimeContext.conversationState } }
        : {}),
      ...(extra.runtimeContext?.unresolvedPrerequisites
        ? { unresolvedPrerequisites: [...extra.runtimeContext.unresolvedPrerequisites] }
        : {}),
    },
    sourceUse: {
      ...base.sourceUse,
      ...(extra.sourceUse || {}),
      ...(extra.sourceUse?.sources ? { sources: [...extra.sourceUse.sources] } : {}),
    },
    constraints: ({
      ...base.constraints,
      ...(extra.constraints || {}),
      ...(extra.constraints?.hard ? { hard: [...extra.constraints.hard] } : {}),
      ...(extra.constraints?.soft ? { soft: [...extra.constraints.soft] } : {}),
      ...(extra.constraints?.requiredPrerequisites
        ? { requiredPrerequisites: [...extra.constraints.requiredPrerequisites] }
        : {}),
      ...(extra.constraints?.requiredApprovals
        ? { requiredApprovals: [...extra.constraints.requiredApprovals] }
        : {}),
      ...(extra.constraints?.forbiddenBoundaries
        ? { forbiddenBoundaries: [...extra.constraints.forbiddenBoundaries] }
        : {}),
      ...(extra.constraints?.disclosureBudget
        ? {
            disclosureBudget: {
              ...(base.constraints.disclosureBudget || {}),
              ...extra.constraints.disclosureBudget,
              maxClassifications: cloneArray(
                extra.constraints.disclosureBudget.maxClassifications ??
                  base.constraints.disclosureBudget?.maxClassifications ??
                  [],
              ) || [],
            } as NonNullable<EvaluatorInput["constraints"]["disclosureBudget"]>,
          }
        : {}),
    }) as EvaluatorInput["constraints"],
    metadata: {
      ...(base.metadata || {}),
      ...(extra.metadata || {}),
    },
  };
}

export function defaultContextualEvaluatorEligible(input: EvaluatorInput): boolean {
  if (input.action.sideEffect || input.action.crossesBoundary || input.action.disclosure) return true;
  if ((input.runtimeContext.unresolvedPrerequisites || []).length > 0) return true;
  if ((input.sourceUse.sources || []).length > 0) return true;
  const dataClasses = input.action.data?.classifications || [];
  return dataClasses.length > 0;
}
