import type { RuntimeAdapter, RuntimeDecisionInput, RuntimeDecisionOutput } from "./types";
import { RUNTIME_PROTOCOL_VERSION } from "./types";
import { normalizeRuntimeDecisionInput } from "./shared";

function pickDenyReason(input: ReturnType<typeof normalizeRuntimeDecisionInput>): string | undefined {
  const reasons = input.input.reasons;
  if (!reasons.length) return undefined;
  if (input.enforcement.strategy === "deny_on_any") {
    return reasons[0];
  }
  if (!input.enforcement.denyOn.length) {
    return reasons[0];
  }
  const denyOn = new Set(input.enforcement.denyOn);
  const matched = reasons.find((reason) => denyOn.has(reason));
  return matched ?? reasons[0];
}

export class LocalRuntimeAdapter implements RuntimeAdapter {
  async evaluate(input: RuntimeDecisionInput): Promise<RuntimeDecisionOutput> {
    const normalized = normalizeRuntimeDecisionInput(input, RUNTIME_PROTOCOL_VERSION);
    const reasons = normalized.input.reasons;
    const hasReasons = reasons.length > 0;

    let deny = false;
    if (normalized.enforcement.forceDeny && hasReasons) {
      deny = true;
    } else if (normalized.enforcement.mode === "enforce") {
      if (normalized.enforcement.strategy === "deny_on_any") {
        deny = hasReasons;
      } else if (!normalized.enforcement.denyOn.length) {
        deny = hasReasons;
      } else {
        const denyOn = new Set(normalized.enforcement.denyOn);
        deny = reasons.some((reason) => denyOn.has(reason));
      }
    }

    const reason = deny ? pickDenyReason(normalized) : undefined;
    return {
      protocolVersion: normalized.protocolVersion,
      adapterMode: "local",
      evaluationSource: "local",
      decision: deny ? "deny" : "allow",
      ...(reason ? { reason } : {}),
      reasons,
      obligations: [],
      auditRefs: [],
    };
  }
}
