import { createHash } from "node:crypto";
import { matchesAllowlist, type PolicyObject } from "../policy";
import { AgentGuard, type AgentGuardFinding } from "../middleware/agentGuard";
import type {
  GuardDecision,
  GuardInput,
  GuardInputContext,
  GuardInputKind,
  GuardMode,
  GuardOutcome,
  GuardPolicy,
  GuardPolicyInput,
  GuardProviderSnapshot,
} from "./types";

const BASIC_REDACTION_PATTERNS: RegExp[] = [
  /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi,
  /\b\d{3}-\d{2}-\d{4}\b/g,
  /\b(?:\d[ -]*?){13,16}\b/g,
  /\b\+?\d{1,3}[ -]?\(?\d{2,4}\)?[ -]?\d{3,4}[ -]?\d{3,4}\b/g,
];

const AGENT_GUARD_CACHE = new Map<string, AgentGuard>();

type ParsedTarget = {
  serverName?: string;
  toolNameAtVersion?: string;
  raw: string;
};

function stableHash(value: unknown): string {
  const encoded = JSON.stringify(value ?? null);
  return createHash("sha256").update(encoded).digest("hex");
}

function normalizePolicyReasonToken(value: unknown): string {
  const normalized = String(value || "").trim();
  if (normalized === "idempotency_missing") return "missing_idempotency_for_side_effect";
  if (normalized === "tool_in_denylist") return "tool_not_in_allowlist";
  return normalized;
}

function normalizePolicyReasonArray(values: unknown): string[] {
  if (!Array.isArray(values)) return [];
  const seen = new Set<string>();
  for (const value of values) {
    const normalized = normalizePolicyReasonToken(value);
    if (!normalized) continue;
    seen.add(normalized);
  }
  return Array.from(seen.values());
}

function isLegacyPolicyObject(policy: GuardPolicyInput): policy is PolicyObject {
  const value = policy as any;
  return Boolean(value && typeof value === "object" && value.enforcement && value.tools);
}

function asString(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function readTarget(input: GuardInput): string {
  return asString(input.target) || asString(input.context?.target);
}

function parseMcpTarget(target: string): ParsedTarget {
  const raw = String(target || "").trim();
  if (!raw) return { raw: "" };
  if (raw.startsWith("mcp://")) {
    const body = raw.slice("mcp://".length);
    const slash = body.indexOf("/");
    if (slash >= 0) {
      return {
        raw,
        serverName: body.slice(0, slash) || undefined,
        toolNameAtVersion: body.slice(slash + 1) || undefined,
      };
    }
  }
  if (raw.includes(":")) {
    const [serverName, rest] = raw.split(":", 2);
    if (rest) return { raw, serverName: serverName || undefined, toolNameAtVersion: rest || undefined };
  }
  return { raw, toolNameAtVersion: raw };
}

function wildcardMatch(value: string, patterns: string[]): boolean {
  if (!patterns.length) return true;
  return patterns.some((pattern) => {
    const p = String(pattern || "").trim();
    if (!p) return false;
    if (p === "*") return true;
    const escaped = p.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*?");
    return new RegExp(`^${escaped}$`, "i").test(value);
  });
}

function tagsMatch(input: GuardInputContext | undefined, expected: string[] | undefined): boolean {
  if (!expected || expected.length === 0) return true;
  const tags = Array.isArray(input?.tags) ? input!.tags.map((tag) => String(tag || "").trim()).filter(Boolean) : [];
  if (!tags.length) return false;
  const set = new Set(tags.map((tag) => tag.toLowerCase()));
  return expected.some((tag) => set.has(String(tag || "").trim().toLowerCase()));
}

function normalizeRuleKinds(raw: unknown): GuardInputKind[] | null {
  if (!raw || raw === "*") return null;
  const source = Array.isArray(raw) ? raw : [raw];
  const values = source.map((entry) => String(entry || "").trim()).filter(Boolean);
  return values.length ? (values as GuardInputKind[]) : null;
}

function stringifyContent(content: unknown): string {
  if (typeof content === "string") return content;
  try {
    return JSON.stringify(content ?? null);
  } catch {
    return String(content ?? "");
  }
}

function redactContent(content: unknown, patterns?: string[], replacement = "[REDACTED]"): string {
  let text = stringifyContent(content);
  for (const re of BASIC_REDACTION_PATTERNS) {
    text = text.replace(re, replacement);
  }
  if (Array.isArray(patterns)) {
    for (const raw of patterns) {
      const source = String(raw || "").trim();
      if (!source) continue;
      try {
        text = text.replace(new RegExp(source, "gi"), replacement);
      } catch {
        continue;
      }
    }
  }
  return text;
}

function buildAgentGuard(policy: PolicyObject, hash: string): AgentGuard {
  const cached = AGENT_GUARD_CACHE.get(hash);
  if (cached) return cached;
  const guardPolicy =
    (policy as any)?.agent_guard && typeof (policy as any).agent_guard === "object"
      ? (policy as any).agent_guard
      : (policy as any)?.enforcement?.agent_guard && typeof (policy as any).enforcement.agent_guard === "object"
        ? (policy as any).enforcement.agent_guard
        : {};
  const guard = new AgentGuard({
    enabled: guardPolicy.enabled !== false,
    block_on_severity: guardPolicy.block_on_severity,
    block_on_count: guardPolicy.block_on_count,
  });
  AGENT_GUARD_CACHE.set(hash, guard);
  return guard;
}

function evaluateGuardPolicyRule(policy: GuardPolicy, input: GuardInput): {
  outcome: GuardOutcome;
  reason: string | null;
  reasons: string[];
  violation?: string;
  redactedContent?: string;
} {
  const rules = Array.isArray(policy.rules) ? policy.rules : [];
  if (!rules.length) {
    const defaultOutcome = policy.defaultOutcome === "block" ? "block" : "allow";
    return {
      outcome: defaultOutcome,
      reason: defaultOutcome === "block" ? "policy_default_block" : null,
      reasons: defaultOutcome === "block" ? ["policy_default_block"] : [],
    };
  }

  const target = readTarget(input);
  for (const rule of rules) {
    const allowedKinds = normalizeRuleKinds(rule.kind);
    if (allowedKinds && !allowedKinds.includes(input.kind)) continue;
    if (rule.target) {
      const targets = Array.isArray(rule.target) ? rule.target : [rule.target];
      if (!wildcardMatch(target, targets.map((entry) => String(entry || "")))) continue;
    }
    if (!tagsMatch(input.context, rule.tagsAny)) continue;
    const outcome: GuardOutcome = rule.outcome;
    const reason = asString(rule.reason) || asString(rule.violation) || `rule_${asString(rule.id) || "matched"}`;
    return {
      outcome,
      reason: reason || null,
      reasons: reason ? [reason] : [],
      ...(asString(rule.violation) ? { violation: asString(rule.violation) } : {}),
      ...(outcome === "redact"
        ? {
            redactedContent: redactContent(
              input.content,
              rule.redact?.patterns,
              rule.redact?.replacement || "[REDACTED]",
            ),
          }
        : {}),
    };
  }

  const defaultOutcome = policy.defaultOutcome === "block" ? "block" : "allow";
  return {
    outcome: defaultOutcome,
    reason: defaultOutcome === "block" ? "policy_default_block" : null,
    reasons: defaultOutcome === "block" ? ["policy_default_block"] : [],
  };
}

export async function evaluateGuardDecision(opts: {
  snapshot: GuardProviderSnapshot;
  mode: GuardMode;
  input: GuardInput;
}): Promise<GuardDecision> {
  const source = opts.snapshot.source;
  const policyHash = opts.snapshot.hash || stableHash(opts.snapshot.policy);
  if (isLegacyPolicyObject(opts.snapshot.policy)) {
    const policy = opts.snapshot.policy as PolicyObject;
    const kind = opts.input.kind;
    const target = readTarget(opts.input);
    let reasons: string[] = [];
    let violation: string | undefined;
    let findings: AgentGuardFinding[] = [];
    let redactedContent: string | undefined;

    if (kind === "tool_call" || kind === "mcp_call") {
      const parsedTarget = parseMcpTarget(target);
      const allowlist = Array.isArray((policy as any)?.tools?.allowlist)
        ? ((policy as any).tools.allowlist as string[])
        : ["*"];
      const toolRef = parsedTarget.toolNameAtVersion || target;
      const allowed = toolRef ? matchesAllowlist(allowlist, toolRef, { serverName: parsedTarget.serverName }) : true;
      if (!allowed) {
        violation = "tool_not_in_allowlist";
        reasons = [violation];
      }
    }

    if (kind === "api_call" && target) {
      const egressAllowlist = Array.isArray((policy as any)?.security?.egress_allowlist)
        ? ((policy as any).security.egress_allowlist as string[])
        : [];
      if (egressAllowlist.length && !wildcardMatch(target, egressAllowlist)) {
        try {
          const hostname = new URL(target).hostname;
          if (!wildcardMatch(hostname, egressAllowlist)) {
            violation = "egress_violation";
            reasons = [violation];
          }
        } catch {
          violation = "egress_violation";
          reasons = [violation];
        }
      }
    }

    if (kind === "message_outbound") {
      const agentGuard = buildAgentGuard(policy, policyHash);
      findings = await agentGuard.scanOutput({
        content: opts.input.content,
        context: opts.input.context,
      });
      const block = agentGuard.shouldBlock(findings);
      if (block.block) {
        violation = "agent_guard_failed";
        reasons = [violation];
      }
      if ((policy as any)?.privacy?.redact_outputs === true && findings.length) {
        redactedContent = redactContent(opts.input.content, undefined, "[REDACTED]");
      }
    }

    const denyOn = normalizePolicyReasonArray((policy as any)?.enforcement?.deny_on);
    const escalateOnRaw = (policy as any)?.enforcement?.escalate_on;
    const escalateOn = Array.isArray(escalateOnRaw)
      ? normalizePolicyReasonArray(escalateOnRaw)
      : [...denyOn];
    const approveHighRisk = (policy as any)?.security?.side_effects?.approve_high_risk === true;

    let outcome: GuardOutcome = "allow";
    if (violation && approveHighRisk && escalateOn.includes(violation)) {
      outcome = "escalate";
    } else if (violation && denyOn.includes(violation)) {
      outcome = "block";
    } else if (redactedContent) {
      outcome = "redact";
    }

    return {
      outcome,
      shouldProceed: outcome === "allow" || outcome === "redact",
      kind,
      reason: reasons[0] || null,
      reasons,
      ...(violation ? { violation } : {}),
      ...(findings.length ? { findings } : {}),
      ...(redactedContent ? { redactedContent } : {}),
      provider: {
        mode: opts.mode,
        source,
        policyHash,
        ...(opts.snapshot.fallbackReason ? { fallbackReason: opts.snapshot.fallbackReason } : {}),
      },
      ...(outcome === "escalate"
        ? {
            escalation: {
              shouldEscalate: true,
              waitForResolution: true,
            },
          }
        : {}),
    };
  }

  const policy = opts.snapshot.policy as GuardPolicy;
  const decision = evaluateGuardPolicyRule(policy, opts.input);
  return {
    outcome: decision.outcome,
    shouldProceed: decision.outcome === "allow" || decision.outcome === "redact",
    kind: opts.input.kind,
    reason: decision.reason,
    reasons: decision.reasons,
    ...(decision.violation ? { violation: decision.violation } : {}),
    ...(decision.redactedContent ? { redactedContent: decision.redactedContent } : {}),
    provider: {
      mode: opts.mode,
      source,
      policyHash,
      ...(opts.snapshot.fallbackReason ? { fallbackReason: opts.snapshot.fallbackReason } : {}),
    },
    ...(decision.outcome === "escalate"
      ? {
          escalation: {
            shouldEscalate: true,
            waitForResolution: true,
          },
        }
      : {}),
  };
}
