import { contentExcerptFromEvaluatorInput } from "./detectorSignals";
import {
  buildRemediation,
  classificationRank,
  compactText,
  hashFingerprint,
  maxClassificationRank,
  missingScopes,
  normalizeString,
  normalizeStringArray,
  severityFromScore,
} from "./classification";
import { contentHasConcreteSensitiveDisclosure, looksLikePrerequisiteSeekingReply } from "./contentSignals";
import { applyDetectorFindingSignals } from "./scoring";
import {
  EvaluatorInputSchema,
  EvaluatorOutputSchema,
  type EvaluatorEvidence,
  type EvaluatorInput,
  type EvaluatorOutput,
  type EvaluatorPrinciple,
  type EvaluatorSourceUse,
} from "./types";

export type LocalContextualEvaluatorOptions = {
  denyThreshold?: number;
  escalateThreshold?: number;
};

export function evaluateContextualInputLocal(
  rawInput: EvaluatorInput,
  options: LocalContextualEvaluatorOptions = {},
): EvaluatorOutput {
  const input = EvaluatorInputSchema.parse(rawInput);
  const principles = new Set<EvaluatorPrinciple>();
  const evidence: EvaluatorEvidence[] = [];
  const reasoningParts: string[] = [];
  let score = 0;

  const addFinding = (
    principle: EvaluatorPrinciple,
    weight: number,
    label: string,
    detail: string,
    path?: string,
  ) => {
    if (!principles.has(principle)) {
      principles.add(principle);
      score += weight;
    }
    evidence.push({ label, detail: compactText(detail, 1000), ...(path ? { path } : {}) });
    reasoningParts.push(compactText(detail, 320));
  };

  const targetBoundary = normalizeString(input.action.target?.boundary || input.action.data?.destination).toLowerCase();
  const allowedBoundaries = new Set(normalizeStringArray(input.authority.allowedBoundaries));
  const forbiddenBoundaries = new Set(normalizeStringArray(input.constraints.forbiddenBoundaries));
  const unresolvedPrerequisites = normalizeStringArray([
    ...input.runtimeContext.unresolvedPrerequisites,
    ...input.constraints.requiredPrerequisites,
  ]);
  const missingApprovals = normalizeStringArray(input.constraints.requiredApprovals).filter(
    (approval) => !normalizeStringArray(input.authority.approvals).includes(approval),
  );
  const justification = normalizeString(input.purpose.justification);
  const sourceClassifications = (input.sourceUse.sources || []).map(
    (source: EvaluatorSourceUse["sources"][number]) => source.classification,
  );
  const actionClassifications = [input.action.target?.classification, ...(input.action.data?.classifications || [])];
  const maxObservedClassification = maxClassificationRank([...actionClassifications, ...sourceClassifications]);
  const maxDisclosedClassification = maxClassificationRank(actionClassifications);
  const maxAllowedClassification = input.constraints.maxClassification
    ? classificationRank(input.constraints.maxClassification)
    : 99;
  const disclosureBudgetMax = input.constraints.disclosureBudget?.maxRecords;
  const estimatedRecords = input.action.data?.estimatedRecords;
  const contentExcerpt = contentExcerptFromEvaluatorInput(input);
  const prerequisiteSeekingReply = looksLikePrerequisiteSeekingReply(input, contentExcerpt, unresolvedPrerequisites);

  if (targetBoundary && allowedBoundaries.size > 0 && !allowedBoundaries.has(targetBoundary)) {
    addFinding(
      "authority_scope_mismatch",
      0.35,
      "boundary",
      `Action targets boundary "${targetBoundary}" outside the granted authority set.`,
      "action.target.boundary",
    );
  }

  const scopesMissing = missingScopes(input);
  if (scopesMissing.length > 0) {
    addFinding(
      "authority_scope_mismatch",
      0.25,
      "scopes",
      `Action requires scopes ${scopesMissing.join(", ")} that are not present in authority.grantedScopes.`,
      "authority.grantedScopes",
    );
  }

  if (targetBoundary && forbiddenBoundaries.has(targetBoundary)) {
    addFinding(
      "boundary_crossing_without_justification",
      0.25,
      "forbidden_boundary",
      `Target boundary "${targetBoundary}" is explicitly constrained unless separately justified.`,
      "constraints.forbiddenBoundaries",
    );
  }

  if (input.action.crossesBoundary && justification.length < 24) {
    addFinding(
      "boundary_crossing_without_justification",
      0.2,
      "cross_boundary",
      "The action crosses a boundary, but the purpose justification is missing or too weak.",
      "purpose.justification",
    );
  }

  for (const source of input.sourceUse.sources || []) {
    if (source.justified === false) {
      addFinding(
        "source_use_misalignment",
        0.2,
        "source_justification",
        `Source "${source.label || source.id || source.type || "unknown"}" is marked as not justified for this action.`,
        "sourceUse.sources",
      );
      break;
    }
  }

  if (maxObservedClassification > maxAllowedClassification) {
    addFinding(
      "source_use_misalignment",
      0.2,
      "classification",
      "Observed source or target classification exceeds the configured maximum classification constraint.",
      "constraints.maxClassification",
    );
  }

  if (unresolvedPrerequisites.length > 0) {
    addFinding(
      "unmet_preconditions",
      0.25,
      "prerequisites",
      `Unresolved prerequisites remain: ${unresolvedPrerequisites.join(", ")}.`,
      "runtimeContext.unresolvedPrerequisites",
    );
  }

  if (missingApprovals.length > 0) {
    addFinding(
      "unmet_preconditions",
      0.25,
      "approvals",
      `Required approvals are missing: ${missingApprovals.join(", ")}.`,
      "constraints.requiredApprovals",
    );
  }

  if (
    input.action.disclosure &&
    !prerequisiteSeekingReply &&
    ((typeof disclosureBudgetMax === "number" &&
      typeof estimatedRecords === "number" &&
      estimatedRecords > disclosureBudgetMax) ||
      maxDisclosedClassification >= 2 ||
      contentHasConcreteSensitiveDisclosure(contentExcerpt))
  ) {
    addFinding(
      "disproportionate_disclosure",
      0.2,
      "disclosure",
      "The action discloses more data than the current purpose or disclosure budget appears to justify.",
      "action.data",
    );
  }

  if (
    (input.action.sideEffect || input.action.disclosure || input.action.crossesBoundary || maxObservedClassification >= 2) &&
    justification.length < 24
  ) {
    addFinding(
      "insufficient_justification",
      0.15,
      "justification",
      "A risky action was proposed without a concrete purpose justification tied to the stated objective.",
      "purpose.justification",
    );
  }

  const detectorFindings = applyDetectorFindingSignals({
    input,
    contentExcerpt,
    addFinding,
    evidence,
    reasoningParts,
  });

  score = Math.max(0, Math.min(1, score));
  const denyThreshold = Number.isFinite(options.denyThreshold) ? Math.max(0, Math.min(1, Number(options.denyThreshold))) : 0.85;
  const escalateThreshold = Number.isFinite(options.escalateThreshold)
    ? Math.max(0, Math.min(1, Number(options.escalateThreshold)))
    : 0.45;

  let decision: EvaluatorOutput["decision"] = "allow";
  if (score >= denyThreshold || (principles.has("authority_scope_mismatch") && principles.has("unmet_preconditions"))) {
    decision = "deny";
  } else if (score >= escalateThreshold) {
    decision = "escalate";
  }

  const orderedPrinciples = Array.from(principles.values()).sort();
  const reasoning =
    reasoningParts.length > 0
      ? reasoningParts.join(" ")
      : "The structured action context did not surface a contextual mismatch against the evaluator principles.";
  const fingerprint = hashFingerprint({
    principles: orderedPrinciples,
    actionKind: normalizeString(input.action.kind).toLowerCase(),
    operation: normalizeString(input.action.operation).toLowerCase(),
    targetBoundary,
    sourceTypes: (input.sourceUse.sources || [])
      .map((source: EvaluatorSourceUse["sources"][number]) => normalizeString(source.type).toLowerCase())
      .sort(),
    sourceClassifications: normalizeStringArray(sourceClassifications),
    missingScopes: scopesMissing,
    unresolvedPrerequisites,
    detectorFindings: detectorFindings.map((entry) => ({
      code: entry.code,
      subjectType: entry.subjectType,
      ruleId: entry.ruleId || null,
      hardDeny: entry.hardDeny,
      roleMailbox: entry.roleMailbox,
    })),
  });
  const confidence = orderedPrinciples.length === 0 ? 0.82 : Math.max(0.55, Math.min(0.98, 0.55 + score * 0.4));
  const remediation = buildRemediation(orderedPrinciples);
  const summary =
    orderedPrinciples.length === 0
      ? "No contextual concern detected."
      : `Contextual evaluator flagged ${orderedPrinciples.join(", ")}.`;

  return EvaluatorOutputSchema.parse({
    decision,
    confidence,
    principles: orderedPrinciples,
    summary,
    reasoning,
    evidence,
    suggestedSeverity: severityFromScore(score),
    suggestedRemediation: remediation,
    normalizedFingerprint: fingerprint,
  });
}

export function createLocalContextualEvaluator(options: LocalContextualEvaluatorOptions = {}) {
  return {
    async evaluate(input: EvaluatorInput): Promise<EvaluatorOutput> {
      return evaluateContextualInputLocal(input, options);
    },
  };
}
