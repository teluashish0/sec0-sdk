// Lightweight adapters that let AgentGuard delegate scanning to hosted services.
import type { AgentGuardFinding } from "../agentGuard";

// Supported upstream providers the adapter can call.
type Provider = "nemo" | "guardrails" | "llmguard";

const KNOWN_AGENT_CODES: AgentGuardFinding["code"][] = [
  "agent_prompt_injection",
  "agent_pii",
  "agent_secret",
  "agent_command_unsafe",
  "agent_toxic_content",
  "agent_malicious_code",
  "agent_policy_violation",
  "agent_data_exfil",
  "agent_unknown"
];

const KNOWN_AGENT_CODE_SET = new Set(KNOWN_AGENT_CODES);

/**
 * Maps provider-specific codes into the standard AgentGuard taxonomy.
 */
function normalizeAgentCode(raw: unknown, kind: "prompt" | "output"): AgentGuardFinding["code"] {
  if (typeof raw === "string") {
    const trimmed = raw.trim();
    if (trimmed) {
      if (KNOWN_AGENT_CODE_SET.has(trimmed as AgentGuardFinding["code"])) {
        return trimmed as AgentGuardFinding["code"];
      }
      const lowered = trimmed.toLowerCase();
      for (const code of KNOWN_AGENT_CODE_SET) {
        if (code.toLowerCase() === lowered) return code;
      }
    }
  }
  return kind === "prompt" ? "agent_prompt_injection" : "agent_pii";
}

/**
 * Normalizes arbitrary severity strings to the enum AgentGuard understands.
 */
function normSeverity(s: string | undefined): AgentGuardFinding["severity"] {
  const v = String(s || "").trim().toLowerCase();
  if (v.startsWith("crit")) return "critical";
  if (v.startsWith("high") || v.startsWith("sev")) return "high";
  if (v.startsWith("med")) return "medium";
  if (v.startsWith("low")) return "low";
  return "unknown";
}

/**
 * Generic HTTP helper shared by all adapters to invoke the hosted service.
 */
async function callService(serviceUrl: string, provider: Provider, kind: "prompt" | "output", text: string): Promise<AgentGuardFinding[]> {
  try {
    const url = serviceUrl.replace(/\/$/, "") + "/scan";
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ provider, kind, text })
    });
    const data = await res.json().catch(() => ({}));
    const arr = Array.isArray(data?.findings) ? data.findings : [];
    const out: AgentGuardFinding[] = [];
    for (const f of arr) {
      out.push({
        code: normalizeAgentCode(f.code, kind),
        severity: normSeverity(f.severity),
        location: kind,
        message: String(f.message || f.title || "finding"),
        evidence: f.evidence || f.sample || undefined
      } as AgentGuardFinding);
    }
    return out;
  } catch {
    return [];
  }
}

/**
 * Binds the AgentGuard hooks to NVIDIA NeMo Guardrails.
 */
export function createNeMoGuardrailsAdapter(opts: { serviceUrl: string }) {
  return {
    onScanPrompt: (text: string) => callService(opts.serviceUrl, "nemo", "prompt", text),
    onScanOutput: (text: string) => callService(opts.serviceUrl, "nemo", "output", text)
  };
}

/**
 * Binds the AgentGuard hooks to the Guardrails AI SaaS.
 */
export function createGuardrailsAIAdapter(opts: { serviceUrl: string }) {
  return {
    onScanPrompt: (text: string) => callService(opts.serviceUrl, "guardrails", "prompt", text),
    onScanOutput: (text: string) => callService(opts.serviceUrl, "guardrails", "output", text)
  };
}

/**
 * Binds the AgentGuard hooks to LLM Guard.
 */
export function createLLMGuardAdapter(opts: { serviceUrl: string }) {
  return {
    onScanPrompt: (text: string) => callService(opts.serviceUrl, "llmguard", "prompt", text),
    onScanOutput: (text: string) => callService(opts.serviceUrl, "llmguard", "output", text)
  };
}


