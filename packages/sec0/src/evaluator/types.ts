import { z } from "zod";

export const EvaluatorDecisionSchema = z.enum(["allow", "escalate", "deny"]);
export type EvaluatorDecision = z.infer<typeof EvaluatorDecisionSchema>;

export const EvaluatorModeSchema = z.enum(["sync", "async", "hybrid"]);
export type EvaluatorMode = z.infer<typeof EvaluatorModeSchema>;

export const EvaluatorSourceSchema = z.enum(["disabled", "local", "control-plane"]);
export type EvaluatorSource = z.infer<typeof EvaluatorSourceSchema>;

export const EvaluatorSeveritySchema = z.enum(["low", "medium", "high", "critical"]);
export type EvaluatorSeverity = z.infer<typeof EvaluatorSeveritySchema>;

export const EvaluatorPrincipleSchema = z.enum([
  "authority_scope_mismatch",
  "boundary_crossing_without_justification",
  "source_use_misalignment",
  "unmet_preconditions",
  "disproportionate_disclosure",
  "insufficient_justification",
]);
export type EvaluatorPrinciple = z.infer<typeof EvaluatorPrincipleSchema>;

const IdentifierSchema = z.object({
  id: z.string().min(1).max(200).optional(),
  type: z.string().min(1).max(120).optional(),
  label: z.string().min(1).max(200).optional(),
}).passthrough();

export const EvaluatorActionSchema = z.object({
  kind: z.string().min(1).max(120),
  summary: z.string().min(1).max(1000),
  operation: z.string().min(1).max(120).optional(),
  sideEffect: z.boolean().optional(),
  disclosure: z.boolean().optional(),
  crossesBoundary: z.boolean().optional(),
  tool: z.object({
    name: z.string().min(1).max(200).optional(),
    version: z.string().min(1).max(120).optional(),
    server: z.string().min(1).max(200).optional(),
  }).passthrough().optional(),
  target: z.object({
    id: z.string().min(1).max(200).optional(),
    type: z.string().min(1).max(120).optional(),
    boundary: z.string().min(1).max(200).optional(),
    owner: z.string().min(1).max(200).optional(),
    classification: z.string().min(1).max(120).optional(),
    destination: z.string().min(1).max(500).optional(),
  }).passthrough().optional(),
  data: z.object({
    classifications: z.array(z.string().min(1).max(120)).max(50).optional(),
    estimatedRecords: z.number().int().nonnegative().optional(),
    destination: z.string().min(1).max(500).optional(),
  }).passthrough().optional(),
}).passthrough();
export type EvaluatorAction = z.infer<typeof EvaluatorActionSchema>;

export const EvaluatorActorSchema = IdentifierSchema.extend({
  role: z.string().min(1).max(120).optional(),
  boundary: z.string().min(1).max(200).optional(),
  labels: z.array(z.string().min(1).max(120)).max(50).optional(),
}).passthrough();
export type EvaluatorActor = z.infer<typeof EvaluatorActorSchema>;

export const EvaluatorPurposeSchema = z.object({
  summary: z.string().min(1).max(1000),
  objective: z.string().min(1).max(2000).optional(),
  justification: z.string().min(1).max(4000).optional(),
  expectedOutcome: z.string().min(1).max(2000).optional(),
}).passthrough();
export type EvaluatorPurpose = z.infer<typeof EvaluatorPurposeSchema>;

export const EvaluatorAuthoritySchema = z.object({
  scope: z.string().min(1).max(120).optional(),
  grantedScopes: z.array(z.string().min(1).max(120)).max(100).default([]),
  allowedBoundaries: z.array(z.string().min(1).max(200)).max(100).default([]),
  approvals: z.array(z.string().min(1).max(120)).max(100).default([]),
  delegations: z.array(z.string().min(1).max(200)).max(50).default([]),
}).passthrough();
export type EvaluatorAuthority = z.infer<typeof EvaluatorAuthoritySchema>;

const SourceDescriptorSchema = IdentifierSchema.extend({
  boundary: z.string().min(1).max(200).optional(),
  classification: z.string().min(1).max(120).optional(),
  provenance: z.string().min(1).max(200).optional(),
  justified: z.boolean().optional(),
  intendedUse: z.string().min(1).max(500).optional(),
}).passthrough();

export const EvaluatorRuntimeContextSchema = z.object({
  integrationSurface: z.string().min(1).max(120).optional(),
  executionLayer: z.string().min(1).max(120).optional(),
  runId: z.string().min(1).max(200).optional(),
  traceId: z.string().min(1).max(200).optional(),
  spanId: z.string().min(1).max(200).optional(),
  sessionId: z.string().min(1).max(200).optional(),
  workflowState: z.record(z.unknown()).optional(),
  conversationState: z.record(z.unknown()).optional(),
  unresolvedPrerequisites: z.array(z.string().min(1).max(500)).max(100).default([]),
}).passthrough();
export type EvaluatorRuntimeContext = z.infer<typeof EvaluatorRuntimeContextSchema>;

export const EvaluatorSourceUseSchema = z.object({
  sources: z.array(SourceDescriptorSchema).max(100).default([]),
  provenanceSummary: z.string().min(1).max(2000).optional(),
}).passthrough();
export type EvaluatorSourceUse = z.infer<typeof EvaluatorSourceUseSchema>;

export const EvaluatorConstraintsSchema = z.object({
  hard: z.array(z.string().min(1).max(500)).max(100).default([]),
  soft: z.array(z.string().min(1).max(500)).max(100).default([]),
  requiredPrerequisites: z.array(z.string().min(1).max(500)).max(100).default([]),
  requiredApprovals: z.array(z.string().min(1).max(120)).max(100).default([]),
  forbiddenBoundaries: z.array(z.string().min(1).max(200)).max(100).default([]),
  maxClassification: z.string().min(1).max(120).optional(),
  disclosureBudget: z.object({
    maxRecords: z.number().int().nonnegative().optional(),
    maxClassifications: z.array(z.string().min(1).max(120)).max(50).default([]),
  }).passthrough().optional(),
}).passthrough();
export type EvaluatorConstraints = z.infer<typeof EvaluatorConstraintsSchema>;

export const EvaluatorInputSchema = z.object({
  action: EvaluatorActionSchema,
  actor: EvaluatorActorSchema,
  purpose: EvaluatorPurposeSchema,
  authority: EvaluatorAuthoritySchema,
  runtimeContext: EvaluatorRuntimeContextSchema,
  sourceUse: EvaluatorSourceUseSchema,
  constraints: EvaluatorConstraintsSchema,
  metadata: z.record(z.unknown()).default({}),
}).passthrough();
export type EvaluatorInput = z.infer<typeof EvaluatorInputSchema>;
export type DeepPartial<T> =
  T extends Array<infer U>
    ? Array<DeepPartial<U>>
    : T extends Record<string, unknown>
      ? { [K in keyof T]?: DeepPartial<T[K]> }
      : T;
export type EvaluatorInputPatch = DeepPartial<EvaluatorInput>;

export const EvaluatorEvidenceSchema = z.object({
  label: z.string().min(1).max(120),
  detail: z.string().min(1).max(1000),
  path: z.string().min(1).max(300).optional(),
}).passthrough();
export type EvaluatorEvidence = z.infer<typeof EvaluatorEvidenceSchema>;

export const EvaluatorRemediationSchema = z.object({
  summary: z.string().min(1).max(2000),
  steps: z.array(z.string().min(1).max(1000)).max(20).default([]),
}).passthrough();
export type EvaluatorRemediation = z.infer<typeof EvaluatorRemediationSchema>;

export const EvaluatorOutputSchema = z.object({
  decision: EvaluatorDecisionSchema,
  confidence: z.number().min(0).max(1),
  principles: z.array(EvaluatorPrincipleSchema).max(20),
  summary: z.string().min(1).max(2000),
  reasoning: z.string().min(1).max(4000),
  evidence: z.array(EvaluatorEvidenceSchema).max(50),
  suggestedSeverity: EvaluatorSeveritySchema,
  suggestedRemediation: EvaluatorRemediationSchema,
  normalizedFingerprint: z.string().min(8).max(128),
}).passthrough();
export type EvaluatorOutput = z.infer<typeof EvaluatorOutputSchema>;
