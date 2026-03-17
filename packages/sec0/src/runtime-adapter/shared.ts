import {
  RUNTIME_PROTOCOL_VERSION,
  type RuntimeDecisionAction,
  type RuntimeDecisionInput,
  type RuntimeDecisionOutput,
  type RuntimeObligation,
  type RuntimeAuditRef,
  type RuntimeProtocolDecisionResponse,
} from "./types";

export interface NormalizedRuntimeDecisionInput extends RuntimeDecisionInput {
  protocolVersion: string;
  enforcement: {
    mode: "observe" | "enforce";
    strategy: "deny_on_match" | "deny_on_any";
    denyOn: string[];
    forceDeny: boolean;
  };
  input: {
    reasons: string[];
    riskTags: string[];
    attributes: Record<string, unknown>;
  };
}

export function normalizeStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const seen = new Set<string>();
  const out: string[] = [];
  for (const entry of value) {
    const v = String(entry ?? "").trim();
    if (!v || seen.has(v)) continue;
    seen.add(v);
    out.push(v);
  }
  return out;
}

export function normalizeDecisionAction(value: unknown): RuntimeDecisionAction | null {
  return value === "allow" || value === "deny" ? value : null;
}

export function normalizeRuntimeDecisionInput(
  input: RuntimeDecisionInput,
  fallbackProtocolVersion: string = RUNTIME_PROTOCOL_VERSION,
): NormalizedRuntimeDecisionInput {
  const protocolVersion =
    typeof input?.protocolVersion === "string" && input.protocolVersion.trim()
      ? input.protocolVersion.trim()
      : fallbackProtocolVersion;
  const mode = input?.enforcement?.mode === "enforce" ? "enforce" : "observe";
  const strategy = input?.enforcement?.strategy === "deny_on_any" ? "deny_on_any" : "deny_on_match";
  const denyOn = normalizeStringArray(input?.enforcement?.denyOn);
  const forceDeny = input?.enforcement?.forceDeny === true;
  const reasons = normalizeStringArray(input?.input?.reasons);
  const riskTags = normalizeStringArray(input?.input?.riskTags);
  const attributes =
    input?.input?.attributes && typeof input.input.attributes === "object" && !Array.isArray(input.input.attributes)
      ? (input.input.attributes as Record<string, unknown>)
      : {};

  return {
    ...input,
    protocolVersion,
    requestId: typeof input?.requestId === "string" && input.requestId.trim() ? input.requestId.trim() : undefined,
    context: {
      integrationSurface: "sec0",
      executionLayer: input?.context?.executionLayer ?? "middleware",
      server: String(input?.context?.server ?? "unknown"),
      tool: String(input?.context?.tool ?? "unknown"),
      ...(typeof input?.context?.tenant === "string" && input.context.tenant.trim() ? { tenant: input.context.tenant.trim() } : {}),
      ...(typeof input?.context?.nodeId === "string" && input.context.nodeId.trim() ? { nodeId: input.context.nodeId.trim() } : {}),
      ...(typeof input?.context?.runId === "string" && input.context.runId.trim() ? { runId: input.context.runId.trim() } : {}),
      ...(input?.context?.metadata && typeof input.context.metadata === "object" && !Array.isArray(input.context.metadata)
        ? { metadata: input.context.metadata }
        : {}),
    },
    enforcement: {
      mode,
      strategy,
      denyOn,
      forceDeny,
    },
    input: {
      reasons,
      riskTags,
      attributes,
    },
  };
}

function normalizeObligations(value: unknown): RuntimeObligation[] {
  if (!Array.isArray(value)) return [];
  const out: RuntimeObligation[] = [];
  for (const entry of value) {
    if (!entry || typeof entry !== "object") continue;
    const type = String((entry as any).type ?? "").trim();
    if (!type) continue;
    const paramsRaw = (entry as any).params;
    const params = paramsRaw && typeof paramsRaw === "object" && !Array.isArray(paramsRaw) ? paramsRaw : undefined;
    out.push({ type, ...(params ? { params } : {}) });
  }
  return out;
}

function normalizeAuditRefs(value: unknown): RuntimeAuditRef[] {
  if (!Array.isArray(value)) return [];
  const out: RuntimeAuditRef[] = [];
  for (const entry of value) {
    if (!entry || typeof entry !== "object") continue;
    const ref = String((entry as any).ref ?? "").trim();
    if (!ref) continue;
    const kind = String((entry as any).kind ?? "").trim();
    const href = String((entry as any).href ?? "").trim();
    out.push({ ref, ...(kind ? { kind } : {}), ...(href ? { href } : {}) });
  }
  return out;
}

export function parseRuntimeProtocolResponse(
  payload: RuntimeProtocolDecisionResponse,
  adapterMode: RuntimeDecisionOutput["adapterMode"],
): RuntimeDecisionOutput {
  const protocolVersion =
    typeof payload?.protocolVersion === "string" && payload.protocolVersion.trim()
      ? payload.protocolVersion.trim()
      : RUNTIME_PROTOCOL_VERSION;
  const action = normalizeDecisionAction(payload?.decision?.action);
  if (!action) {
    throw new Error("runtime_response_invalid_decision");
  }
  const reasons = normalizeStringArray(payload?.decision?.reasons);
  const primaryReasonRaw = typeof payload?.decision?.reason === "string" ? payload.decision.reason.trim() : "";
  const reason = primaryReasonRaw || (action === "deny" ? reasons[0] : undefined);
  return {
    protocolVersion,
    adapterMode,
    evaluationSource: "remote",
    decision: action,
    reasons,
    ...(reason ? { reason } : {}),
    obligations: normalizeObligations(payload?.decision?.obligations),
    auditRefs: normalizeAuditRefs(payload?.decision?.auditRefs),
  };
}

export function withEvaluationSource(
  output: RuntimeDecisionOutput,
  evaluationSource: RuntimeDecisionOutput["evaluationSource"],
): RuntimeDecisionOutput {
  return {
    ...output,
    evaluationSource,
  };
}
