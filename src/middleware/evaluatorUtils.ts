import {
  asEvaluatorRecord,
  type ContextualEvaluatorFinding,
  type EvaluatorInput,
  type EvaluatorInputPatch,
} from "../evaluator";
import type { AgentGuardFinding } from "./agentGuard";
import type { IdentityContext } from "./identity";
import { parseToolDescriptor, readHeaderCaseInsensitive } from "./tooling";

export function dedupeFindings(findings: AgentGuardFinding[]): AgentGuardFinding[] {
  if (!Array.isArray(findings) || findings.length <= 1) return findings || [];
  const seen = new Set<string>();
  const out: AgentGuardFinding[] = [];
  for (const f of findings) {
    if (!f) continue;
    const key = [
      f.code || "",
      f.location || "",
      (f as any).policy_id || "",
      (f as any).pack_id || "",
      (f as any).rule_id || "",
      f.message || "",
      f.evidence || "",
    ]
      .join("|")
      .slice(0, 512);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(f);
  }
  return out;
}

export function extractInlineEvaluatorContext(
  ctx: { args: any; headers?: Record<string, string> } | undefined,
): EvaluatorInputPatch | null {
  if (!ctx) return null;
  const rawFromArgs = asEvaluatorRecord((ctx.args as any)?.__sec0_contextual || (ctx.args as any)?.sec0_contextual);
  if (rawFromArgs) return rawFromArgs as EvaluatorInputPatch;
  const headerValue =
    readHeaderCaseInsensitive(ctx.headers as any, "x-sec0-evaluator-context") ||
    readHeaderCaseInsensitive(ctx.headers as any, "x-sec0-contextual-evaluator");
  if (!headerValue) return null;
  try {
    const parsed = JSON.parse(headerValue);
    return asEvaluatorRecord(parsed) as EvaluatorInputPatch | null;
  } catch {
    return null;
  }
}

export function mapContextualEvaluatorFindingToAgentFinding(
  finding: ContextualEvaluatorFinding,
  location: AgentGuardFinding["location"] = "run",
): AgentGuardFinding {
  return {
    source: "evaluator",
    code: "contextual_evaluator",
    severity: finding.severity as any,
    location,
    message: finding.message,
    evidence: finding.evidence,
    tags: [
      `evaluator:fingerprint:${finding.fingerprint}`,
      ...finding.principles.map((principle) => `evaluator:principle:${principle}`),
    ],
    confidence: finding.confidence,
    principles: [...finding.principles],
    fingerprint: finding.fingerprint,
    summary: finding.summary,
    reasoning: finding.reasoning,
    snapshot: finding.snapshot as unknown as Record<string, unknown>,
  };
}

export function buildDefaultMiddlewareEvaluatorInput(params: {
  tenant?: string;
  server: { name: string; version: string };
  tool: string;
  toolRef: string;
  op: "read" | "create" | "update" | "delete";
  ctx: { args: any; idempotencyKey?: string | null; headers?: Record<string, string> };
  nodeId?: string;
  agentRunId?: string;
  objective?: string | null;
  identity?: IdentityContext;
}): EvaluatorInput {
  const url = typeof params.ctx.args?.url === "string" ? params.ctx.args.url.trim() : "";
  const pathArg = typeof params.ctx.args?.path === "string" ? params.ctx.args.path.trim() : "";
  const destination = url || pathArg || undefined;
  const actorBoundary =
    (typeof params.identity?.tenant === "string" && params.identity.tenant.trim()) ||
    (typeof params.tenant === "string" && params.tenant.trim()) ||
    undefined;
  return {
    action: {
      kind: params.tool,
      summary: params.objective
        ? `Execute ${params.toolRef} in support of ${params.objective}`
        : `Execute ${params.toolRef}`,
      operation: params.op,
      sideEffect: params.op !== "read",
      disclosure: false,
      crossesBoundary: Boolean(destination),
      tool: {
        name: params.tool,
        version: parseToolDescriptor(params.tool).version,
        server: params.server.name,
      },
      target: {
        type: destination ? (url ? "egress" : "filesystem") : "tool",
        boundary: actorBoundary,
        destination,
      },
      data: {},
    },
    actor: {
      id: params.identity?.user_hash || params.nodeId || params.agentRunId,
      type: params.identity ? "identity" : "agent",
      role: params.identity?.roles?.[0],
      boundary: actorBoundary,
      labels: params.identity?.roles || [],
    },
    purpose: {
      summary: params.objective || `Process ${params.op} action through ${params.toolRef}`,
      ...(params.objective ? { objective: params.objective } : {}),
    },
    authority: {
      scope: params.identity?.roles?.[0],
      grantedScopes: [],
      allowedBoundaries: actorBoundary ? [actorBoundary] : [],
      approvals: [],
      delegations: [],
    },
    runtimeContext: {
      integrationSurface: "@coreax/sdk",
      executionLayer: "middleware",
      runId: params.agentRunId,
      traceId: readHeaderCaseInsensitive(params.ctx.headers as any, "x-trace-id"),
      spanId: readHeaderCaseInsensitive(params.ctx.headers as any, "x-span-id"),
      unresolvedPrerequisites: [],
    },
    sourceUse: {
      sources: [],
    },
    constraints: {
      hard: [],
      soft: [],
      requiredPrerequisites: [],
      requiredApprovals: [],
      forbiddenBoundaries: [],
    },
    workflowSlice: {
      nodeId: params.nodeId,
      parentSubmissionIds: [],
      boundaryCrossings: destination ? [destination] : [],
    },
    decisionHistory: {
      priorDecisions: [],
      priorDenies: [],
      priorEscalations: [],
      priorClarifications: [],
      priorHumanResolutions: [],
    },
    executionHistory: {
      recentExecutions: [],
      recentOutcomes: [],
      failureCount: 0,
      recoveryCount: 0,
    },
    reflectionHistory: {
      enabled: false,
      recentReflections: [],
      repeatedDeviationCount: 0,
      repeatedUncertaintyCount: 0,
      persistentMissingFacts: [],
      reflectionOutcomeDisagreementCount: 0,
      reflectionConfirmedRetryCount: 0,
    },
    stateDeltas: [],
    auditEvidence: [],
    derivedFacts: {
      missingApprovals: [],
      missingFacts: [],
      suggestedQuestions: [],
      suggestedSources: [],
      resumeConditions: [],
      retryCount: 0,
      retryReasons: [],
      priorHumanEditCount: 0,
      unresolvedClarificationCount: 0,
      priorDenyCount: 0,
      priorEscalationCount: 0,
      failureCount: 0,
      recoveryCount: 0,
      repeatedReflectionDeviationCount: 0,
      repeatedReflectionUncertaintyCount: 0,
      persistentReflectionMissingFacts: [],
      reflectionOutcomeDisagreementCount: 0,
      reflectionConfirmedRetryCount: 0,
      reflectionEnabled: false,
      contradictoryState: [],
      exactMatchReusable: false,
      managedRuleEligible: true,
      lowRiskReadOnly: params.op === "read" && !destination,
      requiresSemanticReview: params.op !== "read" || Boolean(destination),
      sideEffectful: params.op !== "read",
      crossBoundary: Boolean(destination),
      disclosureRelevant: false,
      approvalSensitive: false,
    },
    metadata: {
      server_name: params.server.name,
      server_version: params.server.version,
      tool_ref: params.toolRef,
      node_id: params.nodeId || null,
      agent_run_id: params.agentRunId || null,
      destination: destination || null,
    },
  };
}
