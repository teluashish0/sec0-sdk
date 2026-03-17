import type { Severity } from "../middleware/agentGuard";
import { readDetectorFindingDescriptors } from "./detectorSignals";
import { compactText, normalizeString } from "./classification";
import { detectorTextHasAny, supportsRoleMailboxDisclosure } from "./contentSignals";
import type { EvaluatorEvidence, EvaluatorInput, EvaluatorPrinciple, EvaluatorSeverity } from "./types";

function detectorSeverityWeight(value: EvaluatorSeverity | Severity): number {
  if (value === "critical") return 0.4;
  if (value === "high") return 0.3;
  if (value === "medium") return 0.2;
  if (value === "low") return 0.12;
  return 0.1;
}

export function applyDetectorFindingSignals(params: {
  input: EvaluatorInput;
  contentExcerpt: string;
  addFinding: (
    principle: EvaluatorPrinciple,
    weight: number,
    label: string,
    detail: string,
    path?: string,
  ) => void;
  evidence: EvaluatorEvidence[];
  reasoningParts: string[];
}) {
  const detectorFindings = readDetectorFindingDescriptors(params.input);
  if (!detectorFindings.length) return detectorFindings;

  for (const detector of detectorFindings) {
    const weight = detectorSeverityWeight(detector.severity as EvaluatorSeverity);
    const detailText = [detector.message, detector.evidence, detector.subjectValue].filter(Boolean).join(" ");
    const evidencePath = detector.path || "metadata.detector_findings";

    if (
      detector.code === "agent_pii" &&
      detector.subjectType === "email" &&
      detector.roleMailbox &&
      supportsRoleMailboxDisclosure(params.input, params.contentExcerpt)
    ) {
      params.evidence.push({
        label: "organizational_contact",
        detail: compactText(
          `Detector matched ${detector.subjectValue || "an email address"}, but the address reads as an organizational mailbox and the surrounding context is routing/coordination oriented.`,
          1000,
        ),
        path: evidencePath,
      });
      params.reasoningParts.push(
        compactText(
          `Role mailbox ${detector.subjectValue || "email"} appears to be organizational contact routing rather than personal PII.`,
          320,
        ),
      );
      continue;
    }

    if (detector.hardDeny) {
      params.addFinding(
        "disproportionate_disclosure",
        Math.max(weight, 0.35),
        "detector_hard_block",
        `Detector matched a non-overridable ${detector.subjectType} pattern (${detector.message}).`,
        evidencePath,
      );
      params.addFinding(
        "insufficient_justification",
        0.2,
        "detector_hard_block_context",
        "The detected pattern is not safe to release based on context alone.",
        evidencePath,
      );
      continue;
    }

    if (detector.code === "agent_pii") {
      params.addFinding(
        "disproportionate_disclosure",
        weight,
        "detector_pii",
        `Detector matched ${detector.subjectType}${detector.subjectValue ? ` "${detector.subjectValue}"` : ""} in the action content.`,
        evidencePath,
      );
      if (detector.subjectType === "email" || detector.subjectType === "phone") {
        params.addFinding(
          "source_use_misalignment",
          Math.max(0.25, weight),
          "detector_contact_context",
          "The matched contact detail looks person-specific rather than a generic organizational routing address.",
          evidencePath,
        );
      }
      if (!normalizeString(params.input.purpose.justification)) {
        params.addFinding(
          "insufficient_justification",
          0.15,
          "detector_pii_justification",
          "Contact detail disclosure was proposed without a concrete business justification in the structured context.",
          "purpose.justification",
        );
      }
      continue;
    }

    if (detector.code === "agent_policy_violation") {
      params.addFinding(
        "source_use_misalignment",
        weight,
        "detector_rule",
        `A concrete policy rule matched this action (${detector.message}).`,
        evidencePath,
      );
      if (detectorTextHasAny(detailText.toLowerCase(), [/\bsla\b/, /\bapproval\b/, /\bprerequisite\b/, /\bpending\b/, /\bwhile\b.*\bfinal/i])) {
        params.addFinding(
          "unmet_preconditions",
          Math.max(0.2, weight - 0.05),
          "detector_rule_prerequisite",
          "The matched rule indicates unresolved prerequisites or approvals remain before the action should proceed.",
          evidencePath,
        );
      }
      if (detectorTextHasAny(detailText.toLowerCase(), [/\bclose\b/, /\bcommit\b/, /\bissue\b/, /\bpo\b/, /\bfinalize\b/, /\bsign\b/])) {
        params.addFinding(
          "boundary_crossing_without_justification",
          Math.max(0.2, weight - 0.05),
          "detector_rule_commitment",
          "The matched rule indicates the action is moving toward commitment or execution without sufficient justification.",
          evidencePath,
        );
      }
      if (detectorTextHasAny(detailText.toLowerCase(), [/\bbudget\b/, /\bbenchmark\b/, /\bpricing\b/, /\bcomparison\b/, /\binternal\b/, /\bapproval ceiling\b/])) {
        params.addFinding(
          "disproportionate_disclosure",
          Math.max(0.2, weight - 0.05),
          "detector_rule_disclosure",
          "The matched rule indicates internal negotiation or pricing context is being exposed beyond what the current purpose justifies.",
          evidencePath,
        );
      }
      continue;
    }

    if (detector.code === "agent_data_exfil") {
      params.addFinding(
        "source_use_misalignment",
        Math.max(weight, 0.3),
        "detector_exfiltration",
        `Detector matched data exfiltration content (${detector.message}).`,
        evidencePath,
      );
      continue;
    }

    if (detector.code === "agent_secret") {
      params.addFinding(
        "disproportionate_disclosure",
        Math.max(weight, 0.35),
        "detector_secret",
        "Detector matched a likely secret or credential in the action content.",
        evidencePath,
      );
      continue;
    }

    if (detector.code === "agent_prompt_injection" || detector.code === "agent_command_unsafe" || detector.code === "agent_malicious_code") {
      params.addFinding(
        "boundary_crossing_without_justification",
        Math.max(weight, 0.25),
        "detector_execution_risk",
        `Detector matched execution-risk content (${detector.message}).`,
        evidencePath,
      );
    }
  }

  return detectorFindings;
}
