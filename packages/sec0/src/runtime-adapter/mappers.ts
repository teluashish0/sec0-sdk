import type {
  RuntimeDecisionInput,
  RuntimeDecisionOutput,
  RuntimeEnforcementMode,
  RuntimeEvaluationStrategy,
  RuntimeExecutionLayer,
} from "./types";
import { RUNTIME_PROTOCOL_VERSION } from "./types";
import { normalizeStringArray } from "./shared";

export interface RuntimeMapperInput {
  executionLayer: RuntimeExecutionLayer;
  tenant?: string;
  server: string;
  tool: string;
  nodeId?: string;
  runId?: string;
  mode?: RuntimeEnforcementMode;
  strategy?: RuntimeEvaluationStrategy;
  denyOn?: string[];
  forceDeny?: boolean;
  reasons?: string[];
  riskTags?: string[];
  attributes?: Record<string, unknown>;
  requestId?: string;
  protocolVersion?: string;
}

export function mapRuntimeDecisionRequest(input: RuntimeMapperInput): RuntimeDecisionInput {
  return {
    protocolVersion:
      typeof input.protocolVersion === "string" && input.protocolVersion.trim()
        ? input.protocolVersion.trim()
        : RUNTIME_PROTOCOL_VERSION,
    ...(typeof input.requestId === "string" && input.requestId.trim() ? { requestId: input.requestId.trim() } : {}),
    context: {
      integrationSurface: "sec0",
      executionLayer: input.executionLayer,
      tenant: typeof input.tenant === "string" && input.tenant.trim() ? input.tenant.trim() : undefined,
      server: String(input.server),
      tool: String(input.tool),
      ...(typeof input.nodeId === "string" && input.nodeId.trim() ? { nodeId: input.nodeId.trim() } : {}),
      ...(typeof input.runId === "string" && input.runId.trim() ? { runId: input.runId.trim() } : {}),
    },
    enforcement: {
      mode: input.mode === "enforce" ? "enforce" : "observe",
      strategy: input.strategy === "deny_on_any" ? "deny_on_any" : "deny_on_match",
      denyOn: normalizeStringArray(input.denyOn),
      forceDeny: input.forceDeny === true,
    },
    input: {
      reasons: normalizeStringArray(input.reasons),
      riskTags: normalizeStringArray(input.riskTags),
      attributes: input.attributes && typeof input.attributes === "object" ? input.attributes : {},
    },
  };
}

export interface LegacyRuntimeDecision {
  shouldDeny: boolean;
  decision: "allow" | "deny";
  reason?: string;
  reasons: string[];
  obligations: RuntimeDecisionOutput["obligations"];
  auditRefs: RuntimeDecisionOutput["auditRefs"];
  evaluationSource: RuntimeDecisionOutput["evaluationSource"];
  adapterMode: RuntimeDecisionOutput["adapterMode"];
}

export function mapRuntimeDecisionToLegacy(output: RuntimeDecisionOutput): LegacyRuntimeDecision {
  return {
    shouldDeny: output.decision === "deny",
    decision: output.decision,
    ...(output.reason ? { reason: output.reason } : {}),
    reasons: normalizeStringArray(output.reasons),
    obligations: Array.isArray(output.obligations) ? output.obligations : [],
    auditRefs: Array.isArray(output.auditRefs) ? output.auditRefs : [],
    evaluationSource: output.evaluationSource,
    adapterMode: output.adapterMode,
  };
}
