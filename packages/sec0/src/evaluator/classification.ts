import crypto from "node:crypto";
import type { EvaluatorInput, EvaluatorOutput, EvaluatorPrinciple, EvaluatorSeverity, EvaluatorSourceUse } from "./types";

export function normalizeString(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

export function normalizeStringArray(values: unknown): string[] {
  if (!Array.isArray(values)) return [];
  const seen = new Set<string>();
  const out: string[] = [];
  for (const value of values) {
    const normalized = normalizeString(value).toLowerCase();
    if (!normalized || seen.has(normalized)) continue;
    seen.add(normalized);
    out.push(normalized);
  }
  return out;
}

function stableSerialize(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((entry) => stableSerialize(entry)).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b));
  return `{${entries.map(([key, entry]) => `${JSON.stringify(key)}:${stableSerialize(entry)}`).join(",")}}`;
}

export function hashFingerprint(value: unknown): string {
  return crypto.createHash("sha256").update(stableSerialize(value)).digest("hex");
}

export function compactText(value: string, maxLength: number): string {
  const normalized = String(value || "").trim().replace(/\s+/g, " ");
  if (normalized.length <= maxLength) return normalized;
  return `${normalized.slice(0, Math.max(0, maxLength - 1))}…`;
}

export function classificationRank(value: unknown): number {
  const normalized = normalizeString(value).toLowerCase();
  if (!normalized) return 0;
  if (["public", "low"].includes(normalized)) return 0;
  if (["internal", "private", "personal", "medium"].includes(normalized)) return 1;
  if (["confidential", "sensitive", "high"].includes(normalized)) return 2;
  if (["restricted", "secret", "critical"].includes(normalized)) return 3;
  return 1;
}

export function maxClassificationRank(values: unknown[]): number {
  return values.reduce<number>((max, value) => Math.max(max, classificationRank(value)), 0);
}

export function severityFromScore(score: number): EvaluatorSeverity {
  if (score >= 0.85) return "critical";
  if (score >= 0.65) return "high";
  if (score >= 0.4) return "medium";
  return "low";
}

function requiredScopes(input: EvaluatorInput): string[] {
  const required = new Set<string>();
  const operation = normalizeString(input.action.operation || input.action.kind).toLowerCase();
  if (input.action.sideEffect || /create|update|delete|write|send|execute|approve/.test(operation)) {
    required.add("write");
  } else {
    required.add("read");
  }
  if (input.action.crossesBoundary) required.add("cross_boundary");
  if (input.action.disclosure) required.add("disclose");
  if (
    maxClassificationRank([
      input.action.target?.classification,
      ...(input.action.data?.classifications || []),
      ...((input.sourceUse.sources || []).map((source: EvaluatorSourceUse["sources"][number]) => source.classification)),
    ]) >= 2
  ) {
    required.add("sensitive_data");
  }
  return Array.from(required.values());
}

export function missingScopes(input: EvaluatorInput): string[] {
  const granted = new Set(normalizeStringArray(input.authority.grantedScopes));
  if (granted.size === 0) return [];
  return requiredScopes(input).filter((scope) => !granted.has(scope));
}

export function buildRemediation(principles: EvaluatorPrinciple[]): EvaluatorOutput["suggestedRemediation"] {
  const steps: string[] = [];
  if (principles.includes("authority_scope_mismatch")) {
    steps.push("Align the action with an explicitly granted scope or reduce the requested action boundary.");
  }
  if (principles.includes("boundary_crossing_without_justification")) {
    steps.push("Document why the boundary crossing is necessary before proceeding.");
  }
  if (principles.includes("source_use_misalignment")) {
    steps.push("Limit source usage to data that matches the stated purpose and constraints.");
  }
  if (principles.includes("unmet_preconditions")) {
    steps.push("Satisfy the missing prerequisite or required approval before execution.");
  }
  if (principles.includes("disproportionate_disclosure")) {
    steps.push("Reduce the disclosure scope to the minimum data needed for the purpose.");
  }
  if (principles.includes("insufficient_justification")) {
    steps.push("Provide a concrete justification that ties the action to the stated objective.");
  }
  return {
    summary: steps.length ? steps[0] : "No remediation required.",
    steps,
  };
}
