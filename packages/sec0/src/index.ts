// Sec0 root entrypoint: intentionally small and stable.
export { validatePolicy, parsePolicyYaml, normalizeAllowlist, matchesAllowlist } from "./policy";
export type { PolicyObject, LlmJudgeConfig } from "./policy";
export { createRuntimeAdapter, LocalRuntimeAdapter, RemoteRuntimeAdapter, RUNTIME_PROTOCOL_VERSION } from "./runtime-adapter";
export type {
  RuntimeAdapter,
  RuntimeAdapterConfig,
  RuntimeDecisionInput,
  RuntimeDecisionOutput,
  RuntimeExecutionLayer,
} from "./runtime-adapter";
export {
  createEscalationManager,
  Sec0EscalationError,
  Sec0EscalationCreateError,
  Sec0EscalationGetError,
  Sec0EscalationResolveError,
  Sec0EscalationWaitError,
  Sec0EscalationAbortError,
} from "./escalation";
export type {
  EscalationManager,
  EscalationManagerConfig,
  EscalationResolution,
  EscalationWaitOptions,
} from "./escalation";
export { createSec0Guard, createNoopApprovalTransport, createApprovalsBridgeTransport } from "./guard";
export type {
  Sec0Guard,
  Sec0GuardConfig,
  GuardDecision,
  GuardInput,
  GuardPolicy,
  GuardRule,
} from "./guard";
export { Sec0Appender } from "./audit";
export type { Sec0Config, AuditEnvelopeMinimal, RawPayloadEvent } from "./audit";
export type {
  EvaluatorInput,
  EvaluatorOutput,
  EvaluatorDecision,
  EvaluatorMode,
  EvaluatorPrinciple,
  EvaluatorSource,
} from "./evaluator";
