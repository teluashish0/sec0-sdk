import type { RuntimeAdapter, RuntimeAdapterConfig } from "./types";
import { LocalRuntimeAdapter } from "./localAdapter";
import { RemoteRuntimeAdapter } from "./remoteAdapter";
import { resolveRuntimeAdapterConfig } from "./resolver";

export function createRuntimeAdapter(config?: RuntimeAdapterConfig): RuntimeAdapter {
  const resolved = resolveRuntimeAdapterConfig(config);
  const local = new LocalRuntimeAdapter();
  if (resolved.mode !== "remote") {
    return local;
  }
  return new RemoteRuntimeAdapter(resolved, local);
}

export { LocalRuntimeAdapter } from "./localAdapter";
export { RemoteRuntimeAdapter } from "./remoteAdapter";
export { resolveRuntimeAdapterConfig } from "./resolver";
export { mapRuntimeDecisionRequest, mapRuntimeDecisionToLegacy, type RuntimeMapperInput, type LegacyRuntimeDecision } from "./mappers";
export type {
  RuntimeAdapter,
  RuntimeAdapterConfig,
  RuntimeAdapterMode,
  RuntimeDecisionAction,
  RuntimeDecisionInput,
  RuntimeDecisionOutput,
  RuntimeFailureMode,
  RuntimeRemoteAdapterConfig,
  RuntimeExecutionLayer,
  RuntimeEnforcementMode,
  RuntimeEvaluationStrategy,
  RuntimeObligation,
  RuntimeAuditRef,
} from "./types";
export { RUNTIME_PROTOCOL_VERSION } from "./types";
