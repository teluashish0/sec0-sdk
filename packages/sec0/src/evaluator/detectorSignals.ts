import type { AgentGuardFinding, Severity } from "../middleware/agentGuard";
import { asEvaluatorRecord } from "./runtime";
import type { EvaluatorInput, EvaluatorInputPatch } from "./types";

export type DetectorSubjectType =
  | "email"
  | "phone"
  | "ssn"
  | "card"
  | "secret"
  | "prompt_injection"
  | "command"
  | "malware"
  | "policy"
  | "exfiltration"
  | "unknown";

export type DetectorFindingDescriptor = {
  code: string;
  source: "rule" | "evaluator" | "unknown";
  severity: Severity;
  location: AgentGuardFinding["location"];
  message: string;
  evidence?: string;
  path?: string;
  tags: string[];
  policyId?: string;
  policyName?: string;
  packId?: string;
  packName?: string;
  ruleId?: string;
  subjectType: DetectorSubjectType;
  subjectValue?: string;
  roleMailbox: boolean;
  ruleBacked: boolean;
  hardDeny: boolean;
};

const EMAIL_RE = /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i;
const PHONE_RE = /\b\+?\d{1,3}[ -]?\(?\d{2,4}\)?[ -]?\d{3,4}[ -]?\d{3,4}\b/;
const SSN_RE = /\b\d{3}-\d{2}-\d{4}\b/;
const CARD_RE = /\b(?:\d[ -]*?){13,16}\b/;
const ROLE_MAILBOX_TOKENS = new Set([
  "accounts",
  "admin",
  "billing",
  "business",
  "compliance",
  "contact",
  "contracts",
  "coordination",
  "finance",
  "help",
  "hello",
  "info",
  "invoices",
  "legal",
  "ops",
  "operations",
  "payments",
  "pricing",
  "privacy",
  "procurement",
  "purchasing",
  "sales",
  "security",
  "support",
  "team",
]);

function truncate(value: string, maxLength: number): string {
  const normalized = String(value || "").trim().replace(/\s+/g, " ");
  if (normalized.length <= maxLength) return normalized;
  return `${normalized.slice(0, Math.max(0, maxLength - 1))}…`;
}

function stringValue(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function collectStringValues(
  value: unknown,
  out: string[],
  seen = new Set<unknown>(),
): void {
  if (value == null) return;
  if (seen.has(value)) return;
  if (typeof value === "string") {
    const normalized = value.trim();
    if (normalized) out.push(normalized);
    return;
  }
  if (typeof value !== "object") return;
  seen.add(value);
  if (Array.isArray(value)) {
    for (const entry of value) collectStringValues(entry, out, seen);
    return;
  }
  for (const entry of Object.values(value as Record<string, unknown>)) {
    collectStringValues(entry, out, seen);
  }
}

function normalizeSource(value: unknown): DetectorFindingDescriptor["source"] {
  const normalized = String(value || "").trim().toLowerCase();
  if (normalized === "rule" || normalized === "evaluator") return normalized;
  return "unknown";
}

function normalizeSeverity(value: unknown): Severity {
  const normalized = String(value || "").trim().toLowerCase();
  if (
    normalized === "unknown" ||
    normalized === "low" ||
    normalized === "medium" ||
    normalized === "high" ||
    normalized === "critical"
  ) {
    return normalized;
  }
  return "unknown";
}

function normalizeLocation(value: unknown): AgentGuardFinding["location"] {
  const normalized = String(value || "").trim().toLowerCase();
  if (normalized === "input" || normalized === "output" || normalized === "run") return normalized;
  return "run";
}

function normalizeTags(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const seen = new Set<string>();
  const out: string[] = [];
  for (const entry of value) {
    const normalized = String(entry || "").trim();
    if (!normalized || seen.has(normalized)) continue;
    seen.add(normalized);
    out.push(normalized.slice(0, 180));
  }
  return out;
}

function readFindingText(finding: Partial<AgentGuardFinding>): string {
  return [stringValue(finding.evidence), stringValue(finding.message), stringValue(finding.path)]
    .filter(Boolean)
    .join(" ");
}

function subjectFromText(code: string, text: string): {
  type: DetectorSubjectType;
  value?: string;
} {
  if (!text) return { type: fallbackSubjectType(code) };
  const email = text.match(EMAIL_RE)?.[0];
  if (email) return { type: "email", value: email };
  const ssn = text.match(SSN_RE)?.[0];
  if (ssn) return { type: "ssn", value: ssn };
  const card = text.match(CARD_RE)?.[0];
  if (card) return { type: "card", value: card };
  const phone = text.match(PHONE_RE)?.[0];
  if (phone) return { type: "phone", value: phone };
  return { type: fallbackSubjectType(code) };
}

function fallbackSubjectType(code: string): DetectorSubjectType {
  switch (code) {
    case "agent_secret":
      return "secret";
    case "agent_prompt_injection":
      return "prompt_injection";
    case "agent_command_unsafe":
      return "command";
    case "agent_malicious_code":
      return "malware";
    case "agent_data_exfil":
      return "exfiltration";
    case "agent_policy_violation":
      return "policy";
    default:
      return "unknown";
  }
}

function isRoleMailboxAddress(email: string | undefined): boolean {
  if (!email) return false;
  const at = email.indexOf("@");
  const localPart = (at >= 0 ? email.slice(0, at) : email).toLowerCase();
  if (!localPart) return false;
  const tokens = localPart.split(/[._+-]+/).filter(Boolean);
  if (!tokens.length) return false;
  if (tokens.some((token) => /\d/.test(token))) return false;
  return tokens.every((token) => ROLE_MAILBOX_TOKENS.has(token));
}

function isRuleBackedFinding(finding: Partial<AgentGuardFinding>): boolean {
  return Boolean(
    stringValue((finding as any).rule_id) ||
      stringValue((finding as any).policy_id) ||
      stringValue((finding as any).pack_id),
  );
}

function isHardDenyDescriptor(descriptor: DetectorFindingDescriptor): boolean {
  if (descriptor.severity === "critical") return true;
  if (
    descriptor.code === "agent_secret" ||
    descriptor.code === "agent_prompt_injection" ||
    descriptor.code === "agent_command_unsafe" ||
    descriptor.code === "agent_malicious_code" ||
    descriptor.code === "agent_data_exfil"
  ) {
    return true;
  }
  return descriptor.code === "agent_pii" && (descriptor.subjectType === "ssn" || descriptor.subjectType === "card");
}

export function describeDetectorFinding(
  finding: Partial<AgentGuardFinding> | null | undefined,
): DetectorFindingDescriptor | null {
  if (!finding || typeof finding !== "object") return null;
  const code = stringValue(finding.code);
  if (!code) return null;
  const text = readFindingText(finding);
  const subject = subjectFromText(code, text);
  const descriptor: DetectorFindingDescriptor = {
    code,
    source: normalizeSource(finding.source),
    severity: normalizeSeverity(finding.severity),
    location: normalizeLocation(finding.location),
    message: truncate(stringValue(finding.message) || code, 240),
    ...(stringValue(finding.evidence) ? { evidence: truncate(stringValue(finding.evidence), 360) } : {}),
    ...(stringValue(finding.path) ? { path: truncate(stringValue(finding.path), 220) } : {}),
    tags: normalizeTags(finding.tags),
    ...(stringValue((finding as any).policy_id) ? { policyId: stringValue((finding as any).policy_id) } : {}),
    ...(stringValue((finding as any).policy_name) ? { policyName: truncate(stringValue((finding as any).policy_name), 180) } : {}),
    ...(stringValue((finding as any).pack_id) ? { packId: stringValue((finding as any).pack_id) } : {}),
    ...(stringValue((finding as any).pack_name) ? { packName: truncate(stringValue((finding as any).pack_name), 180) } : {}),
    ...(stringValue((finding as any).rule_id) ? { ruleId: stringValue((finding as any).rule_id) } : {}),
    subjectType: subject.type,
    ...(subject.value ? { subjectValue: truncate(subject.value, 180) } : {}),
    roleMailbox: subject.type === "email" && isRoleMailboxAddress(subject.value),
    ruleBacked: isRuleBackedFinding(finding),
    hardDeny: false,
  };
  descriptor.hardDeny = isHardDenyDescriptor(descriptor);
  return descriptor;
}

export function describeDetectorFindings(
  findings: AgentGuardFinding[] | undefined,
  maxFindings = 25,
): DetectorFindingDescriptor[] {
  if (!Array.isArray(findings) || findings.length === 0) return [];
  const out: DetectorFindingDescriptor[] = [];
  for (const finding of findings) {
    const descriptor = describeDetectorFinding(finding);
    if (!descriptor) continue;
    out.push(descriptor);
    if (out.length >= maxFindings) break;
  }
  return out;
}

export function extractContentExcerpt(value: unknown, maxLength = 900): string | undefined {
  if (typeof value === "string") {
    const normalized = truncate(value, maxLength);
    return normalized || undefined;
  }
  const parts: string[] = [];
  collectStringValues(value, parts);
  if (!parts.length) return undefined;
  return truncate(parts.join(" | "), maxLength);
}

export function buildDetectorContextEvaluatorPatch(params: {
  findings?: AgentGuardFinding[];
  violation?: string | null;
  content?: unknown;
}): EvaluatorInputPatch | null {
  const descriptors = describeDetectorFindings(params.findings);
  const contentExcerpt = extractContentExcerpt(params.content);
  if (!descriptors.length && !contentExcerpt && !stringValue(params.violation)) return null;
  const hardCount = descriptors.filter((entry) => entry.hardDeny).length;
  const ruleCount = descriptors.filter((entry) => entry.ruleBacked).length;
  return {
    metadata: {
      ...(stringValue(params.violation) ? { raw_violation: stringValue(params.violation) } : {}),
      ...(contentExcerpt ? { content_excerpt: contentExcerpt } : {}),
      detector_findings: descriptors,
      detector_summary: {
        total: descriptors.length,
        hard_count: hardCount,
        contextual_count: Math.max(0, descriptors.length - hardCount),
        rule_count: ruleCount,
      },
    },
  };
}

export function annotateFindingsWithContextualAdjudication(params: {
  findings: AgentGuardFinding[] | undefined;
  decision: "allow" | "escalate" | "deny" | null;
  fingerprint?: string | null;
}): AgentGuardFinding[] {
  if (!Array.isArray(params.findings) || params.findings.length === 0 || !params.decision) {
    return Array.isArray(params.findings) ? [...params.findings] : [];
  }
  return params.findings.map((finding) => {
    const tags = normalizeTags(finding?.tags);
    tags.push(`contextual_adjudication:${params.decision}`);
    if (params.fingerprint) {
      tags.push(`contextual_fingerprint:${String(params.fingerprint).slice(0, 64)}`);
    }
    return {
      ...finding,
      tags: Array.from(new Set(tags)).slice(0, 40),
    };
  });
}

export function resolveDetectorContextualViolation(params: {
  violation: string | null;
  findings: AgentGuardFinding[] | undefined;
  contextualDecision: "allow" | "escalate" | "deny" | null;
  contextualFingerprint?: string | null;
}): {
  violation: string | null;
  findings: AgentGuardFinding[];
  suppressed: boolean;
} {
  const findings = annotateFindingsWithContextualAdjudication({
    findings: params.findings,
    decision: params.contextualDecision,
    fingerprint: params.contextualFingerprint,
  });
  const filteredFindings = findings.filter((finding) => {
    const descriptor = describeDetectorFinding(finding);
    if (!descriptor || descriptor.hardDeny || !params.contextualDecision) return true;
    if (
      descriptor.code === "agent_pii" &&
      descriptor.subjectType === "email" &&
      descriptor.roleMailbox &&
      params.contextualDecision !== "deny"
    ) {
      return false;
    }
    return true;
  });
  const suppressed = filteredFindings.length !== findings.length;
  if (!params.contextualDecision) {
    return { violation: params.violation, findings, suppressed: false };
  }
  const descriptors = describeDetectorFindings(filteredFindings);
  const hasHardFinding = descriptors.some((descriptor) => descriptor.hardDeny);
  if (params.contextualDecision === "allow" && filteredFindings.length > 0 && !hasHardFinding) {
    return { violation: null, findings: filteredFindings, suppressed: Boolean(params.violation) || suppressed };
  }
  const normalizedViolation = stringValue(params.violation).toLowerCase();
  if (params.violation) {
    if (normalizedViolation === "agent_guard_failed" && filteredFindings.length === 0 && suppressed) {
      if (params.contextualDecision === "deny") {
        return { violation: "contextual_evaluator_denied", findings: filteredFindings, suppressed: true };
      }
      if (params.contextualDecision === "escalate") {
        return { violation: "contextual_evaluator_escalated", findings: filteredFindings, suppressed: true };
      }
      return { violation: null, findings: filteredFindings, suppressed: true };
    }
    return { violation: params.violation, findings: filteredFindings, suppressed };
  }
  if (params.contextualDecision === "deny") {
    return { violation: "contextual_evaluator_denied", findings: filteredFindings, suppressed };
  }
  if (params.contextualDecision === "escalate") {
    return { violation: "contextual_evaluator_escalated", findings: filteredFindings, suppressed };
  }
  return { violation: null, findings: filteredFindings, suppressed };
}

export function readDetectorFindingDescriptors(input: EvaluatorInput): DetectorFindingDescriptor[] {
  const metadata = asEvaluatorRecord(input.metadata);
  const raw = Array.isArray(metadata?.detector_findings) ? metadata?.detector_findings : [];
  const out: DetectorFindingDescriptor[] = [];
  for (const entry of raw) {
    const descriptor = describeDetectorFinding(entry as Partial<AgentGuardFinding>);
    if (!descriptor) continue;
    out.push(descriptor);
  }
  return out;
}

export function contentExcerptFromEvaluatorInput(input: EvaluatorInput): string {
  const metadata = asEvaluatorRecord(input.metadata);
  return stringValue(metadata?.content_excerpt);
}
