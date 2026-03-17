// Main middleware entry point that wires sec0 policy enforcement, tracing,
// SAST/DAST orchestration, and agent guardrails into MCP servers.
import { initTracing, startInvokeSpan, endSpanOk, endSpanErr, setSpanAttributes, extractContextFromHeaders } from "../otel";
import { context, propagation, trace } from "@opentelemetry/api";
import type { PolicyObject } from "../policy";
import {
  createContextualEvaluatorManager,
  asEvaluatorRecord,
  buildDetectorContextEvaluatorPatch,
  defaultContextualEvaluatorEligible,
  mergeEvaluatorInput,
  resolveDetectorContextualViolation,
  type ContextualEvaluatorAdapter,
  type ContextualEvaluatorFinding,
  type EvaluatorInput,
  type EvaluatorInputPatch,
  type EvaluatorMode,
  type EvaluatorSource,
} from "../evaluator";
import { canonicalize, sha256Hex, Signer } from "../signer";
import type { Sec0Config } from "../audit";
import {
  extractAgentStateFromHeaders,
  mergeAgentVariables,
  ensureRunId,
  type AgentStatePayload,
  type AgentStateVariables,
} from "../agent-state";
import {
  verifyAp2MandatesFromHeaders,
  AP2_CART_DIGEST_HEADER,
  AP2_CONSTRAINTS_DIGEST_HEADER,
  compareArgsToDigest,
  type Ap2Config,
} from "../mandate-ap2";
import { SastManager, type SastOptions, maxSeverityOf, type SastFinding } from "./sast";
import { DastManager, type DastOptions, type DastFinding } from "./dast";
import { nucleiOnScan } from "./nuclei";
import { AgentGuard, type AgentGuardFinding, type AgentGuardOptions } from "./agentGuard";
import { createNeMoGuardrailsAdapter, createGuardrailsAIAdapter, createLLMGuardAdapter } from "./adapters/agentGuardAdapters";
import { getSec0Meta, type Sec0Meta } from "./meta";
import { parseIdentityContextHeader, type IdentityContext } from "./identity";
import { semgrepOnScan } from "./semgrep";
import * as fs from "node:fs";
import * as path from "node:path";
import * as YAML from "yaml";
import { randomBytes } from "node:crypto";
import { resolveHierarchy, extractApiKey } from "./apiKeyResolver";
import {
  isControlPlanePolicySource,
  type ControlPlanePolicySource,
} from "./controlPlanePolicy";
import { resolveControlPlaneUrl } from "./controlPlane";
import {
  mapRuntimeDecisionRequest,
  mapRuntimeDecisionToLegacy,
  type RuntimeAdapterConfig,
} from "../runtime-adapter";
import type {
  ApprovalVerifier,
  AuditSink,
  EscalationCreateResult,
  EscalationReporter,
  PolicyProvider,
  RuntimeInvoker,
} from "../core/contracts";
import { createSec0AuditSink } from "./adapters/auditSink";
import { createControlPlaneApprovalVerifier, createNoopApprovalVerifier } from "./adapters/approvalVerifier";
import { createControlPlaneNlEvaluator } from "./adapters/complianceEvaluator";
import { createControlPlaneContextualEvaluator } from "./adapters/contextualEvaluator";
import { createControlPlaneClient, type ControlPlaneClient } from "./adapters/controlPlaneClient";
import { createControlPlaneEscalationReporter, createNoopEscalationReporter } from "./adapters/escalationReporter";
import { createControlPlanePolicyProvider, createStaticPolicyProvider } from "./adapters/policyProvider";
import { publishPolicyToControlPlaneIfChanged as publishPolicyToControlPlaneAdapter } from "./adapters/policyPublisher";
import { createRuntimeInvoker } from "./adapters/runtimeInvoker";
import { uploadScanEvidence } from "./adapters/scanEvidenceUploader";
import { fireAndForgetPolicyWebhookEvent } from "./adapters/webhookNotifier";
import {
  createHostedSec0Preset,
  createLocalSec0Preset,
  type HostedSec0PresetOptions,
  type LocalSec0PresetOptions,
  type MiddlewarePresetDependencies,
} from "./presets";

/**
 * Best-effort SDK version stamp for middleware hop identity.
 * Avoid throwing if package.json cannot be resolved in a bundled environment.
 */
const SDK_VERSION = (() => {
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const pkg = require("../../package.json");
    const v = typeof pkg?.version === "string" ? pkg.version.trim() : "";
    return v || "0.1.0";
  } catch {
    return "0.1.0";
  }
})();

// Common shape for AgentGuard adapter callbacks.
type AgentGuardScanFn = (text: string) => Promise<AgentGuardFinding[]> | AgentGuardFinding[];

// Declares the supported adapter flavors that can extend AgentGuard.
type AgentGuardAdapterConfig =
  | { type: "nemo" | "guardrails" | "llmguard"; serviceUrl: string }
  | { type: "custom"; onScanPrompt?: AgentGuardScanFn; onScanOutput?: AgentGuardScanFn; onScanRun?: AgentGuardScanFn };

// AgentGuard options surfaced through the middleware configuration.
type MiddlewareAgentGuardOptions = AgentGuardOptions & {
  adapters?: AgentGuardAdapterConfig[];
  run_context?: {
    enabled?: boolean;
    max_chars?: number;
    max_events?: number;
    max_event_chars?: number;
    max_runs?: number;
    ttl_ms?: number;
    include_objective?: boolean;
    include_metadata?: boolean;
  };
};

type MiddlewareContextualEvaluatorOptions = {
  evaluatorSource: EvaluatorSource;
  evaluatorMode: EvaluatorMode;
  debug?: boolean;
  local?: {
    adapter?: ContextualEvaluatorAdapter;
    denyThreshold?: number;
    escalateThreshold?: number;
  };
  controlPlane?: {
    adapter?: ContextualEvaluatorAdapter;
    timeoutMs?: number;
  };
  eligible?: (info: {
    server: { name: string; version: string };
    tool: string;
    toolRef: string;
    op: "read" | "create" | "update" | "delete";
    ctx: { args: any; idempotencyKey?: string | null; headers?: Record<string, string> };
    nodeId?: string;
    agentRunId?: string;
    policy: PolicyObject;
    explicitReasons: string[];
    input: EvaluatorInput;
  }) => boolean;
  buildContext?: (info: {
    tenant?: string;
    server: { name: string; version: string };
    tool: string;
    toolRef: string;
    op: "read" | "create" | "update" | "delete";
    ctx: { args: any; idempotencyKey?: string | null; headers?: Record<string, string> };
    nodeId?: string;
    agentRunId?: string;
    policy: PolicyObject;
    objective?: string | null;
    identity?: IdentityContext;
    explicitReasons: string[];
    defaultInput: EvaluatorInput;
  }) => Promise<EvaluatorInputPatch | null | undefined> | EvaluatorInputPatch | null | undefined;
};

type UploadApiConfig = { baseUrl: string; apiKey: string };
type RuntimeDebugConfig = { policySync?: boolean; sast?: boolean; dast?: boolean };
type PresignFlushConfig = { enabled: boolean; intervalMs: number };
type RuntimeWebhookConfig = { policyUrl?: string };
type RuntimeConfig = {
  uploadApi?: UploadApiConfig;
  debug?: RuntimeDebugConfig;
  presignFlush?: PresignFlushConfig;
  webhook?: RuntimeWebhookConfig;
  forceDastRawUpload?: boolean;
  rawPayloads?: RawPayloadCaptureConfig;
  enforcement?: RuntimeAdapterConfig;
};

export interface MiddlewareAdapters {
  policyProvider?: PolicyProvider;
  approvalVerifier?: ApprovalVerifier;
  escalationReporter?: EscalationReporter;
  auditSink?: AuditSink;
  runtimeInvoker?: RuntimeInvoker;
}

type RawPayloadCaptureConfig = {
  enabled: boolean;
  captureInputs?: boolean;
  captureOutputs?: boolean;
  includeAgentState?: boolean;
  maxBytes?: number;
  redact?: RawPayloadRedactor;
};

type RawPayloadRecorder = (input: RawPayloadRecordInput) => Promise<void>;

type RawPayloadRecordInput = {
  direction: "input" | "output";
  payload: any;
  runId: string;
  traceId: string;
  spanId: string;
  nodeId?: string;
  tool: string;
  decision: string;
  riskTags: string[];
  idempotencyKey?: string | null;
  agentVariables?: Record<string, unknown>;
};

type RawPayloadRedactor = (payload: any, ctx: RawPayloadRecordInput) => any | Promise<any>;

// Merges multiple adapter callbacks into a single best-effort function.
const combineAgentGuardFns = (fns: AgentGuardScanFn[]): AgentGuardScanFn | undefined => {
  if (!fns.length) return undefined;
  return async (text: string) => {
    const settled = await Promise.allSettled(fns.map((fn) => Promise.resolve(fn(text))));
    const findings: AgentGuardFinding[] = [];
    for (const result of settled) {
      if (result.status !== "fulfilled") continue;
      const value = result.value;
      if (Array.isArray(value)) {
        findings.push(...value);
      }
    }
    return findings;
  };
};

type RunContextConfig = {
  enabled: boolean;
  maxChars: number;
  maxEvents: number;
  maxEventChars: number;
  maxRuns: number;
  ttlMs: number;
  includeObjective: boolean;
  includeMetadata: boolean;
};

type RunContextState = {
  key: string;
  tenant?: string;
  nodeId?: string;
  runId?: string;
  createdAt: number;
  lastSeenAt: number;
  objective?: string;
  metadata?: Record<string, unknown>;
  events: string[];
  eventChars: number;
};

const RUN_CONTEXT_CACHE: Map<string, RunContextState> = new Map();
const DEFAULT_RUN_CONTEXT: RunContextConfig = {
  enabled: true,
  maxChars: 6000,
  maxEvents: 50,
  maxEventChars: 1200,
  maxRuns: 500,
  ttlMs: 30 * 60 * 1000,
  includeObjective: true,
  includeMetadata: false,
};

function clampPositiveInt(value: unknown, fallback: number): number {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  const v = Math.floor(n);
  return v > 0 ? v : fallback;
}

function resolveRunContextConfig(opts: MiddlewareAgentGuardOptions | undefined, hasRunScanner: boolean): RunContextConfig | null {
  if (!hasRunScanner) return null;
  const raw = (opts as any)?.run_context || {};
  if (raw && raw.enabled === false) return null;
  const cfg: RunContextConfig = {
    ...DEFAULT_RUN_CONTEXT,
    maxChars: clampPositiveInt(raw?.max_chars, DEFAULT_RUN_CONTEXT.maxChars),
    maxEvents: clampPositiveInt(raw?.max_events, DEFAULT_RUN_CONTEXT.maxEvents),
    maxEventChars: clampPositiveInt(raw?.max_event_chars, DEFAULT_RUN_CONTEXT.maxEventChars),
    maxRuns: clampPositiveInt(raw?.max_runs, DEFAULT_RUN_CONTEXT.maxRuns),
    ttlMs: clampPositiveInt(raw?.ttl_ms, DEFAULT_RUN_CONTEXT.ttlMs),
    includeObjective: raw?.include_objective !== false,
    includeMetadata: raw?.include_metadata === true,
  };
  return cfg;
}

function runContextKey(tenant?: string, nodeId?: string, runId?: string): string | null {
  const t = typeof tenant === "string" ? tenant.trim() : "";
  const n = typeof nodeId === "string" ? nodeId.trim() : "";
  const r = typeof runId === "string" ? runId.trim() : "";
  if (!n || !r) return null;
  return [t || "unknown", n, r].join("|");
}

function evictRunContexts(now: number, cfg: RunContextConfig) {
  if (!RUN_CONTEXT_CACHE.size) return;
  for (const [key, ctx] of RUN_CONTEXT_CACHE.entries()) {
    if (now - ctx.lastSeenAt > cfg.ttlMs) {
      RUN_CONTEXT_CACHE.delete(key);
    }
  }
  if (RUN_CONTEXT_CACHE.size <= cfg.maxRuns) return;
  const entries = Array.from(RUN_CONTEXT_CACHE.entries()).sort((a, b) => a[1].lastSeenAt - b[1].lastSeenAt);
  const overflow = entries.length - cfg.maxRuns;
  for (let i = 0; i < overflow; i += 1) {
    RUN_CONTEXT_CACHE.delete(entries[i][0]);
  }
}

function ensureRunContextState(
  cfg: RunContextConfig,
  opts: { tenant?: string; nodeId?: string; runId?: string; now: number }
): RunContextState | null {
  const key = runContextKey(opts.tenant, opts.nodeId, opts.runId);
  if (!key) return null;
  evictRunContexts(opts.now, cfg);
  const existing = RUN_CONTEXT_CACHE.get(key);
  if (existing) {
    existing.lastSeenAt = opts.now;
    return existing;
  }
  const created: RunContextState = {
    key,
    tenant: opts.tenant,
    nodeId: opts.nodeId,
    runId: opts.runId,
    createdAt: opts.now,
    lastSeenAt: opts.now,
    events: [],
    eventChars: 0,
  };
  RUN_CONTEXT_CACHE.set(key, created);
  return created;
}

function stringifyForRunContext(value: unknown, maxChars: number): string {
  let raw = "";
  try {
    raw = JSON.stringify(value ?? null);
  } catch {
    raw = String(value ?? "");
  }
  const trimmed = raw.trim();
  if (!trimmed) return "";
  if (trimmed.length <= maxChars) return trimmed;
  return `${trimmed.slice(0, Math.max(0, maxChars - 1))}…`;
}

function extractObjective(variables?: AgentStateVariables, incoming?: AgentStatePayload): string | null {
  const candidates = [
    (variables as any)?.AGENT?.objective,
    (variables as any)?.AGENT?.goal,
    (variables as any)?.AGENT?.task,
    (variables as any)?.ORCHESTRATOR?.objective,
    (incoming as any)?.metadata?.objective,
  ];
  for (const c of candidates) {
    const s = typeof c === "string" ? c.trim() : "";
    if (s) return s.slice(0, 480);
  }
  return null;
}

function extractMetadata(incoming?: AgentStatePayload): Record<string, unknown> | null {
  const meta = incoming?.metadata;
  if (!meta || typeof meta !== "object") return null;
  try {
    return JSON.parse(JSON.stringify(meta));
  } catch {
    return null;
  }
}

function appendRunEvent(state: RunContextState, entry: string, cfg: RunContextConfig) {
  const trimmed = entry.trim();
  if (!trimmed) return;
  const safe = trimmed.length > cfg.maxEventChars ? `${trimmed.slice(0, cfg.maxEventChars - 1)}…` : trimmed;
  state.events.push(safe);
  state.eventChars += safe.length + 1;
  while (state.events.length > cfg.maxEvents) {
    const removed = state.events.shift();
    if (removed) state.eventChars -= removed.length + 1;
  }
  const headerLen = buildRunContextHeader(state, cfg).length + 1;
  const maxBody = Math.max(0, cfg.maxChars - headerLen);
  while (state.eventChars > maxBody && state.events.length > 1) {
    const removed = state.events.shift();
    if (removed) state.eventChars -= removed.length + 1;
  }
}

function buildRunContextHeader(state: RunContextState, cfg: RunContextConfig): string {
  const parts: string[] = [];
  parts.push("# run_context");
  if (state.nodeId) parts.push(`node_id=${state.nodeId}`);
  if (state.runId) parts.push(`run_id=${state.runId}`);
  if (cfg.includeObjective && state.objective) parts.push(`objective=${state.objective}`);
  if (cfg.includeMetadata && state.metadata && Object.keys(state.metadata).length) {
    try {
      parts.push(`metadata=${JSON.stringify(state.metadata).slice(0, 480)}`);
    } catch {}
  }
  return parts.join("\n");
}

function buildRunContextText(state: RunContextState, cfg: RunContextConfig): string {
  const header = buildRunContextHeader(state, cfg);
  const body = state.events.join("\n");
  if (!body) return header;
  const combined = `${header}\n${body}`;
  if (combined.length <= cfg.maxChars) return combined;
  return combined.slice(combined.length - cfg.maxChars);
}

function buildRunEvent(
  direction: "input" | "output",
  tool: string,
  payload: unknown,
  cfg: RunContextConfig
): string | null {
  const body = stringifyForRunContext(payload, cfg.maxEventChars);
  if (!body) return null;
  const ts = new Date().toISOString();
  return `[${ts}] ${direction.toUpperCase()} tool=${tool}\n${body}`;
}

function dedupeFindings(findings: AgentGuardFinding[]): AgentGuardFinding[] {
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

function extractInlineEvaluatorContext(
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

function mapContextualEvaluatorFindingToAgentFinding(
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

function buildDefaultMiddlewareEvaluatorInput(params: {
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
      integrationSurface: "sec0-sdk",
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

type ComplianceRuleLocation = "input" | "output" | "both" | "run";
type ComplianceRuleSeverity = "low" | "medium" | "high" | "critical";

type CompiledComplianceRuleApp = {
  policyId: string;
  policyName: string;
  packId: string;
  packName: string;
  ruleId: string;
  location: ComplianceRuleLocation;
  severity: ComplianceRuleSeverity;
  message: string;
  tags: string[];
  type: "regex" | "nl";
  patterns?: RegExp[];
  instruction?: string;
  threshold?: number;
};

function normalizeCompliancePattern(raw: string): { source: string; flags: string } {
  const trimmed = String(raw || "").trim();
  // Accept a simple inline case-insensitive prefix "(?i)" for ergonomics
  if (trimmed.startsWith("(?i)")) return { source: trimmed.slice(4), flags: "i" };
  return { source: trimmed, flags: "i" };
}

function snippetAround(text: string, re: RegExp): string {
  try {
    const m = text.match(re);
    if (!m) return "";
    const i = (m as any).index ?? 0;
    const start = Math.max(0, i - 40);
    const end = Math.min(text.length, i + (m[0]?.length || 0) + 40);
    return text.slice(start, end);
  } catch {
    return "";
  }
}

function buildCompliancePackScanners(opts: {
  policyObj: any;
  tenant?: string;
  nlEvaluator?: (input: {
    instruction: string;
    text: string;
    threshold: number;
    llmJudge?: { provider: "openai" | "anthropic"; apiKey?: string; model?: string };
  }) => Promise<{ score: number; matched: boolean; evidence: string } | null>;
}): {
  enabled: boolean;
  onScanPrompt?: AgentGuardScanFn;
  onScanOutput?: AgentGuardScanFn;
  onScanRun?: AgentGuardScanFn;
  ruleAppsCount: number;
} {
  try {
    const policyObj = opts.policyObj;
    const tenantKey = String(opts.tenant || "").trim();

    /**
     * Read LLM Judge config from the policy YAML (set via the Configure UI)
     */
    const llmJudgeCfg = (() => {
      const j = policyObj?.llm_judge || policyObj?.compliance?.llm_judge;
      if (!j || typeof j !== "object") return undefined;
      const prov = String(j.provider || "").toLowerCase();
      if (prov !== "openai" && prov !== "anthropic") return undefined;
      return {
        provider: prov as "openai" | "anthropic",
        apiKey: String(j.api_key || "").trim() || undefined,
        model: String(j.model || "").trim() || undefined,
      };
    })();

    type NlEvalCached = { score: number; matched: boolean; evidence: string; expiresAt: number };
    const nlCache: Map<string, NlEvalCached> = new Map();
    const nlEval = async (input: { instruction: string; text: string; threshold: number }): Promise<NlEvalCached | null> => {
      if (!opts.nlEvaluator) return null;
      const instruction = String(input.instruction || "").trim();
      const threshold = Number.isFinite(input.threshold) ? Math.max(0, Math.min(100, Math.round(input.threshold))) : 50;
      const textRaw = String(input.text || "");
      const text = textRaw.length > 8000 ? textRaw.slice(0, 8000) : textRaw;
      if (!instruction || !text.trim()) return null;

      const cacheKey = sha256Hex(Buffer.from(JSON.stringify({ tenant: tenantKey, provider: llmJudgeCfg?.provider, instruction, threshold, text })));
      const hit = nlCache.get(cacheKey);
      const now = Date.now();
      if (hit && hit.expiresAt > now) return hit;

      try {
        const evaluated = await opts.nlEvaluator({
          instruction,
          text,
          threshold,
          ...(llmJudgeCfg ? { llmJudge: llmJudgeCfg } : {}),
        });
        if (!evaluated) return null;
        const out: NlEvalCached = {
          score: evaluated.score,
          matched: evaluated.matched,
          evidence: evaluated.evidence,
          expiresAt: now + 5 * 60 * 1000,
        };
        nlCache.set(cacheKey, out);
        return out;
      } catch {
        return null;
      }
    };

    const compliance = policyObj?.compliance;
    const packs: any[] = Array.isArray(compliance?.packs) ? compliance.packs : [];
    const policies: any[] = Array.isArray(compliance?.policies) ? compliance.policies : [];
    if (!packs.length || !policies.length) return { enabled: false, ruleAppsCount: 0 };

    const packById = new Map<string, any>();
    for (const p of packs) {
      const id = typeof p?.id === "string" ? p.id.trim() : "";
      const name = typeof p?.name === "string" ? p.name.trim() : "";
      if (!id || !name) continue;
      packById.set(id, p);
    }

    const apps: CompiledComplianceRuleApp[] = [];
    for (const pol of policies) {
      if (!pol || pol.enabled !== true) continue;
      const policyId = typeof pol.id === "string" ? pol.id.trim() : "";
      if (!policyId) continue;
      const policyName = (typeof pol.name === "string" ? pol.name.trim() : "") || policyId;
      const packIds: string[] = Array.isArray(pol.pack_ids) ? pol.pack_ids.map((x: any) => String(x)) : [];
      for (const packIdRaw of packIds) {
        const packId = String(packIdRaw || "").trim();
        if (!packId) continue;
        const pack = packById.get(packId);
        if (!pack) continue;
        const packName = (typeof pack.name === "string" ? pack.name.trim() : "") || packId;
        const rules: any[] = Array.isArray(pack.rules) ? pack.rules : [];
        for (const r of rules) {
          const ruleId = typeof r?.id === "string" ? r.id.trim() : "";
          if (!ruleId) continue;
          const location: ComplianceRuleLocation = (r.location === "input" || r.location === "output" || r.location === "both" || r.location === "run")
            ? r.location
            : "both";
          const severity: ComplianceRuleSeverity = (r.severity === "low" || r.severity === "medium" || r.severity === "high" || r.severity === "critical")
            ? r.severity
            : "medium";
          const message = (typeof r.message === "string" && r.message.trim())
            ? r.message.trim()
            : `Compliance rule matched (${packName}:${ruleId})`;
          const typeRaw = (typeof r?.type === "string" ? r.type.trim().toLowerCase() : "") as any;
          const ruleType: "regex" | "nl" | null =
            typeRaw === "nl" ? "nl" : (typeRaw === "regex" || !typeRaw) ? "regex" : null;
          if (!ruleType) continue;

          let patterns: RegExp[] | undefined = undefined;
          let instruction: string | undefined = undefined;
          let threshold: number | undefined = undefined;

          if (ruleType === "nl") {
            instruction = typeof r?.instruction === "string" ? r.instruction.trim() : "";
            const thr = Number(r?.threshold);
            threshold = Number.isFinite(thr) ? Math.max(0, Math.min(100, Math.round(thr))) : undefined;
            if (!instruction || threshold === undefined) continue;
          } else {
            const patternsRaw: string[] = Array.isArray(r.patterns) ? r.patterns.map((x: any) => String(x)) : [];
            const compiled: RegExp[] = [];
            for (const p of patternsRaw) {
              try {
                const { source, flags } = normalizeCompliancePattern(p);
                if (!source) continue;
                compiled.push(new RegExp(source, flags));
              } catch {
                // Skip invalid patterns at runtime; pack API should validate on write.
                continue;
              }
            }
            if (compiled.length === 0) continue;
            patterns = compiled;
          }
          const tagSet = new Set<string>();
          tagSet.add(`pack:${packId}`);
          tagSet.add(`policy:${policyId}`);
          tagSet.add(`rule:${ruleId}`);
          tagSet.add(`rule_type:${ruleType}`);
          const extraTags: string[] = Array.isArray(r.tags) ? r.tags.map((x: any) => String(x)) : [];
          for (const t of extraTags) if (t) tagSet.add(t);

          apps.push({
            policyId,
            policyName,
            packId,
            packName,
            ruleId,
            location,
            severity,
            message,
            tags: Array.from(tagSet),
            type: ruleType,
            ...(patterns ? { patterns } : {}),
            ...(instruction ? { instruction } : {}),
            ...(threshold !== undefined ? { threshold } : {}),
          });
        }
      }
    }

    const enabled = apps.length > 0;
    if (!enabled) return { enabled: false, ruleAppsCount: 0 };
    const hasRunRules = apps.some((app) => app.location === "run");

    const scan = async (text: string, loc: "input" | "output" | "run"): Promise<AgentGuardFinding[]> => {
      if (!text || !text.trim()) return [];
      const out: AgentGuardFinding[] = [];
      const maxFindings = 50;
      for (const app of apps) {
        if (loc === "run") {
          if (app.location !== "run") continue;
        } else {
          if (app.location !== "both" && app.location !== loc) continue;
        }

        if (app.type === "regex") {
          const patterns = Array.isArray(app.patterns) ? app.patterns : [];
          for (const re of patterns) {
            if (!re.test(text)) continue;
            out.push({
              code: "agent_policy_violation",
              severity: app.severity as any,
              location: loc,
              message: app.message,
              evidence: snippetAround(text, re),
              tags: app.tags,
              policy_id: app.policyId,
              pack_id: app.packId,
              rule_id: app.ruleId,
              policy_name: app.policyName,
              pack_name: app.packName,
            } as any);
            break;
          }
          if (out.length >= maxFindings) break;
          continue;
        }

        if (app.type === "nl") {
          const instruction = String(app.instruction || "").trim();
          const threshold = typeof app.threshold === "number" ? app.threshold : 50;
          if (!instruction) continue;
          const scored = await nlEval({ instruction, text, threshold });
          if (!scored || !scored.matched) continue;
          const scoreText = `score=${scored.score} threshold=${threshold}`;
          const evidence = scored.evidence ? `${scoreText}; ${scored.evidence}` : scoreText;
          out.push({
            code: "agent_policy_violation",
            severity: app.severity as any,
            location: loc,
            message: app.message,
            evidence,
            tags: app.tags,
            policy_id: app.policyId,
            pack_id: app.packId,
            rule_id: app.ruleId,
            policy_name: app.policyName,
            pack_name: app.packName,
          } as any);
          if (out.length >= maxFindings) break;
        }
      }
      return out;
    };

    return {
      enabled: true,
      ruleAppsCount: apps.length,
      onScanPrompt: (text: string) => scan(text, "input"),
      onScanOutput: (text: string) => scan(text, "output"),
      ...(hasRunRules ? { onScanRun: (text: string) => scan(text, "run") } : {}),
    };
  } catch {
    return { enabled: false, ruleAppsCount: 0 };
  }
}

/**
 * Conditional logger for verbose policy synchronization debugging.
 */
function debugPolicySyncMw(enabled: boolean, ...args: any[]) {
  if (!enabled) return;
  try {
    // eslint-disable-next-line no-console
    console.log("[sec0-middleware][policySync]", ...args);
  } catch {}
}

// Reads a header regardless of the casing used by the server/client.
const readHeaderCaseInsensitive = (headers: Record<string, any> | undefined, name: string): string | undefined => {
  if (!headers) return undefined;
  const direct = headers[name];
  const lowered = headers[name.toLowerCase()];
  const raw = direct ?? lowered;
  if (Array.isArray(raw)) {
    const first = raw[0];
    return typeof first === "string" ? first.trim() || undefined : undefined;
  }
  if (typeof raw === "string") {
    const trimmed = raw.trim();
    return trimmed || undefined;
  }
  return undefined;
};

/**
 * Validates and normalizes a 32-char hex trace id from inbound requests.
 */
function normalizeTraceId(value?: string | null): string | undefined {
  if (!value) return undefined;
  const hex = value.trim().toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(hex)) return undefined;
  if (/^0+$/.test(hex)) return undefined;
  return hex;
}

/**
 * Validates and normalizes a 16-char hex span id from inbound requests.
 */
function normalizeSpanId(value?: string | null): string | undefined {
  if (!value) return undefined;
  const hex = value.trim().toLowerCase();
  if (!/^[0-9a-f]{16}$/.test(hex)) return undefined;
  if (/^0+$/.test(hex)) return undefined;
  return hex;
}

/**
 * Generates a new trace id when callers do not propagate one.
 */
function generateTraceId(): string {
  return randomBytes(16).toString("hex");
}

/**
 * Generates a new span id when a parent span was not provided.
 */
function generateSpanId(): string {
  return randomBytes(8).toString("hex");
}

/**
 * Uploads raw scan payloads to presigned object storage when strict mode requires
 * persisting evidence for audit.
 */
async function persistScanRawIfConfigured(opts: {
  tenant?: string;
  level: "gateway" | "middleware";
  kind: "sast" | "dast" | "agent_guard_findings";
  scanId: string;
  raw: any;
  uploadConfig?: UploadApiConfig;
}): Promise<string | null> {
  const tenant = (opts.tenant || "").trim();
  if (!tenant) return null;
  return uploadScanEvidence({
    kind: opts.kind,
    scanId: opts.scanId,
    raw: opts.raw,
    uploadConfig: opts.uploadConfig,
    controlPlaneClientFactory: (baseUrl) => createControlPlaneClient({ baseUrl }),
  });
}

function createRawPayloadRecorder(params: {
  auditSink: AuditSink;
  tenant?: string;
  environment?: string;
  client?: string;
  clientVersion?: string;
  config: RawPayloadCaptureConfig;
}): RawPayloadRecorder {
  const tenant = ensureRuntimeString(params.tenant, "opts.otel.tenant");
  const environment = ensureRuntimeString(params.environment, "opts.otel.environment or sec0.presign.environment");
  const client = ensureRuntimeString(params.client, "sec0.presign.clientName");
  const clientVersion = ensureRuntimeString(params.clientVersion, "sec0.presign.clientVersion");
  const rawMaxBytes = params.config.maxBytes ?? 64 * 1024;
  if (!Number.isFinite(rawMaxBytes) || rawMaxBytes <= 0) {
    throw new Error("[sec0-middleware] runtime.rawPayloads.maxBytes must be a positive number");
  }
  const maxBytes = Math.floor(rawMaxBytes);
  const includeAgentState = params.config.includeAgentState === true;
  return async (input) => {
    const runId = ensureRuntimeString(input.runId, "agent runId");
    const traceId = ensureRuntimeString(input.traceId, "trace id");
    const spanId = ensureRuntimeString(input.spanId, "span id");
    const tool = ensureRuntimeString(input.tool, "tool name");
    const payloadValue = params.config.redact ? await Promise.resolve(params.config.redact(input.payload, input)) : input.payload;
    const snapshot = preparePayloadSnapshot(payloadValue, maxBytes);
    const metadata: Record<string, unknown> = {
      decision: input.decision,
    };
    if (input.riskTags.length) metadata.risk_tags = [...input.riskTags];
    if (input.idempotencyKey) metadata.idempotency_key = input.idempotencyKey;
    const agentState = includeAgentState ? sanitizeAgentStateForRaw(input.agentVariables) : undefined;
    if (!params.auditSink.appendRawPayload) {
      throw new Error("[sec0-middleware] configured audit sink does not support raw payload capture");
    }
    await params.auditSink.appendRawPayload({
      ts: new Date().toISOString(),
      trace_id: traceId,
      span_id: spanId,
      runId,
      tenant,
      environment,
      client,
      clientVersion,
      nodeId: input.nodeId,
      tool,
      direction: input.direction,
      ...(snapshot.payload !== undefined ? { payload: snapshot.payload } : {}),
      ...(snapshot.preview ? { payload_preview: snapshot.preview } : {}),
      ...(snapshot.truncated ? { payload_truncated: true } : {}),
      payload_bytes: snapshot.bytes,
      ...(Object.keys(metadata).length ? { metadata } : {}),
      ...(agentState ? { agent_state: agentState } : {}),
    });
  };
}

function ensureRuntimeString(value: string | undefined, label: string): string {
  if (typeof value !== "string") {
    throw new Error(`[sec0-middleware] ${label} is required for raw payload capture`);
  }
  const trimmed = value.trim();
  if (!trimmed) {
    throw new Error(`[sec0-middleware] ${label} cannot be empty for raw payload capture`);
  }
  return trimmed;
}

type PayloadSnapshot = {
  payload?: any;
  preview?: string;
  truncated: boolean;
  bytes: number;
};

function preparePayloadSnapshot(value: any, maxBytes: number): PayloadSnapshot {
  let json: string;
  try {
    json = JSON.stringify(value ?? null);
  } catch (err: any) {
    throw new Error(`[sec0-middleware] Failed to serialize raw payload: ${err?.message || err}`);
  }
  const bytes = Buffer.byteLength(json, "utf8");
  if (bytes <= maxBytes) {
    return { payload: JSON.parse(json), truncated: false, bytes };
  }
  return { preview: json.slice(0, maxBytes), truncated: true, bytes };
}

function sanitizeAgentStateForRaw(value?: Record<string, unknown>): Record<string, unknown> | undefined {
  if (!value) return undefined;
  try {
    return JSON.parse(JSON.stringify(value));
  } catch (err: any) {
    throw new Error(`[sec0-middleware] Agent state is not JSON serializable (${err?.message || err})`);
  }
}

/**
 * Publishes the effective policy to the control plane so it can render what the runtime is enforcing.
 * This is best-effort: failures are logged but do not block tool execution.
 */
async function publishPolicyToControlPlaneIfChanged(opts: {
  tenant?: string;
  level: "gateway" | "middleware";
  policy: PolicyObject;
  controlPlaneUrl?: string;
  auth?: { apiKey?: string; bearerToken?: string };
  urlOverride?: string;
  debug?: boolean;
}) {
  const authToken = String(opts.auth?.apiKey || opts.auth?.bearerToken || "").trim();
  if (!authToken) {
    debugPolicySyncMw(!!opts.debug, "skip: no auth configured");
    return;
  }
  const client = createControlPlaneClient({ baseUrl: resolveControlPlaneUrl(opts.controlPlaneUrl) });
  await publishPolicyToControlPlaneAdapter({
    tenant: opts.tenant,
    level: opts.level,
    policy: opts.policy,
    authToken,
    urlOverride: opts.urlOverride,
    debug: opts.debug,
    client,
  });
}

export interface McpServerLike {
  name: string;
  version: string;
  // Register a tool handler by key like "echo@1.0"
  tool(nameAtVersion: string, handler: (ctx: { args: any; idempotencyKey?: string | null; headers?: Record<string, string> }) => Promise<any> | any): void;
  // For middleware to wrap existing handlers
  __getTools?(): Map<string, (ctx: { args: any; idempotencyKey?: string | null; headers?: Record<string, string> }) => Promise<any> | any>;
  __setTool?(nameAtVersion: string, handler: (ctx: { args: any; idempotencyKey?: string | null; headers?: Record<string, string> }) => Promise<any> | any): void;
}

export interface OTelConfig { endpoint: string; serviceName: string; serviceVersion?: string; environment?: string; tenant?: string }

export interface MiddlewareOptions {
  policy: PolicyObject | string | ControlPlanePolicySource;
  signer: Signer;
  otel: OTelConfig;
  sec0: Sec0Config;
  adapters?: MiddlewareAdapters;
  // Optional override. Defaults to the Sec0 control plane.
  controlPlaneUrl?: string;
  // API key for automatic audit upload to the Sec0 control plane.
  // When provided, this enables automatic audit uploads without requiring
  // manual configuration of `sec0.presign`. The control plane URL and
  // hierarchy (tenant, env, clientName, clientVersion) are auto-discovered
  // from the API key via the /api/discover endpoint.
  // This is a convenience option - if you need more control, configure
  // `sec0.presign` directly instead.
  apiKey?: string;
  auth?: { apiKey?: string; bearerToken?: string };
  runtime?: RuntimeConfig;
  // Middleware hop identity configuration.
  // By default, middleware emits `node_type = "middleware"` and uses a stable,
  // versioned SDK identity for `server/tool` so posture can distinguish enforcement hops
  // from actual tool execution hops.
  middlewareHop?: {
    // Hop identity for the middleware layer. Recommended format: "sec0-middleware@<sdkVersion>"
    server?: string;
    // Operation name for middleware enforcement. Recommended format: "mcp.enforce@<schemaVersion>"
    tool?: string;
  };
  telemetry?: { enabled?: boolean };
  // Opt-in controls for reflecting derived state back into sec0-agent-state.
  agentStateTelemetry?: {
    includeServerSignals?: boolean; // add SERVER-scope analytics (decision/latency/risk)
    includeToolSignals?: boolean;   // add TOOL-scope analytics (tool decision/results)
  };
  ap2?: {
    enabled?: boolean;
    requireForSideEffects?: boolean;
    headers?: { intent?: string; cart?: string; bundle?: string };
    trust?: { issuersAllowlist?: string[]; didMethods?: string[]; clockSkewSec?: number };
    tools?: { allow?: string[] };
  };
  sast?: SastOptions;
  dast?: DastOptions;
  agentGuard?: MiddlewareAgentGuardOptions;
  contextualEvaluator?: MiddlewareContextualEvaluatorOptions;
  augment?: (info: {
    tenant: string;
    server: { name: string; version: string };
    tool: string;
    ctx: { args: any; idempotencyKey?: string | null; headers?: Record<string,string> };
  }) => Promise<{ envelope?: Record<string, any>; span?: Record<string, any> }> | { envelope?: Record<string, any>; span?: Record<string, any> };
}

export type PolicyViolation =
  | "policy_fetch_failed"
  | "tool_not_in_allowlist"
  | "version_unpinned"
  | "missing_idempotency_for_side_effect"
  | "missing_audit_signature"
  | "agent_guard_failed"
  | "egress_violation"
  | "fs_violation"
  | "payload_too_large"
  | "subprocess_blocked"
  | "registry_mutation"
  | "handler_swap"
  | "server_code_changed"
  | "tool_code_changed"
  | "skill_version_changed"
  | "skill_code_changed"
  | "skill_scan_pending"
  | "skill_scan_failed"
  | "contextual_evaluator_denied"
  | "contextual_evaluator_escalated";

export class PolicyDeniedError extends Error {
  code = "POLICY_DENIED" as const;
  violation: PolicyViolation;
  constructor(violation: PolicyViolation, message?: string) {
    super(message ?? violation);
    this.violation = violation;
  }
}

export class SigningFailedError extends Error { code = "SIGNING_FAILED" as const; }
export class UnpinnedVersionError extends Error { code = "UNPINNED_VERSION" as const; }
export class IdempotencyRequiredError extends Error { code = "IDEMPOTENCY_REQUIRED" as const; }

function isPinned(nameAtVersion: string): boolean {
  return /@\d+/.test(nameAtVersion);
}

function isSideEffecting(toolNameAtVersion: string, args: any): boolean {
  try {
    const name = toolNameAtVersion.toLowerCase();
    if (/(write|delete|put|post|patch|create|update)/.test(name)) return true;
    if (name.includes('filesystem') && /write|delete|remove|mkdir|rmdir/.test(name)) return true;
    if (name.includes('fetch') && typeof args?.method === 'string' && args.method.toUpperCase() !== 'GET') return true;
    return false;
  } catch { return false; }
}

function inferOp(toolNameAtVersion: string, args: any): "read" | "create" | "update" | "delete" {
  const name = String(toolNameAtVersion || "").toLowerCase();
  const method = typeof args?.method === "string" ? args.method.trim().toUpperCase() : "";
  if (method === "DELETE" || name.includes("delete") || name.includes("remove")) return "delete";
  if (method === "POST" || name.includes("create")) return "create";
  if (method === "PUT" || method === "PATCH" || name.includes("update") || name.includes("write")) return "update";
  if (method === "GET" || name.includes("read") || name.includes(".get") || name.includes("get@")) return "read";
  return isSideEffecting(toolNameAtVersion, args) ? "update" : "read";
}

function normalizePolicyReasonToken(value: unknown): string {
  const normalized = String(value || "").trim();
  if (normalized === "idempotency_missing") return "missing_idempotency_for_side_effect";
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

type ResolvedHumanEscalationConfig = {
  approvalStrategy?: "auto_allow" | "single_approver" | "human_quorum";
  timeoutAction?: "auto_approve" | "auto_reject";
  minApprovals?: number;
  minRejections?: number;
  requiredRoles?: string[];
  vetoRoles?: string[];
  approvalSetId?: string;
};

type ResolvedEscalationPolicy = {
  enabled: boolean;
  escalateOn: Set<string>;
  human: ResolvedHumanEscalationConfig;
};

function asOptionalPositiveInt(value: unknown): number | undefined {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return undefined;
  const floored = Math.floor(parsed);
  return floored > 0 ? floored : undefined;
}

function asOptionalStringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const out: string[] = [];
  for (const entry of value) {
    const normalized = String(entry || "").trim();
    if (!normalized) continue;
    out.push(normalized);
  }
  return out.length ? Array.from(new Set(out)) : undefined;
}

function resolveEscalationPolicy(policyObj: PolicyObject): ResolvedEscalationPolicy {
  const security = (policyObj as any)?.security;
  const sideEffects = security && typeof security === "object" ? (security as any).side_effects : undefined;
  const approveHighRisk = sideEffects?.approve_high_risk === true;
  const denyOn = normalizePolicyReasonArray((policyObj as any)?.enforcement?.deny_on);
  const escalateOnRaw = (policyObj as any)?.enforcement?.escalate_on;
  const escalateOn = Array.isArray(escalateOnRaw)
    ? normalizePolicyReasonArray(escalateOnRaw)
    : denyOn;
  const humanRaw =
    sideEffects && typeof sideEffects === "object"
      ? ((sideEffects as any).human_escalation && typeof (sideEffects as any).human_escalation === "object"
          ? (sideEffects as any).human_escalation
          : (sideEffects as any).humanEscalation && typeof (sideEffects as any).humanEscalation === "object"
            ? (sideEffects as any).humanEscalation
            : undefined)
      : undefined;
  const strategyRaw = String(humanRaw?.approval_strategy || "").trim().toLowerCase();
  const approvalStrategy =
    strategyRaw === "auto_allow" || strategyRaw === "single_approver" || strategyRaw === "human_quorum"
      ? (strategyRaw as ResolvedHumanEscalationConfig["approvalStrategy"])
      : undefined;
  const timeoutRaw = String(humanRaw?.timeout_action || "").trim().toLowerCase();
  const timeoutAction =
    timeoutRaw === "auto_approve" || timeoutRaw === "auto_reject"
      ? (timeoutRaw as ResolvedHumanEscalationConfig["timeoutAction"])
      : undefined;
  const human: ResolvedHumanEscalationConfig = {
    ...(approvalStrategy ? { approvalStrategy } : {}),
    ...(timeoutAction ? { timeoutAction } : {}),
    ...(asOptionalPositiveInt(humanRaw?.min_approvals) ? { minApprovals: asOptionalPositiveInt(humanRaw?.min_approvals)! } : {}),
    ...(asOptionalPositiveInt(humanRaw?.min_rejections) ? { minRejections: asOptionalPositiveInt(humanRaw?.min_rejections)! } : {}),
    ...(asOptionalStringArray(humanRaw?.required_roles) ? { requiredRoles: asOptionalStringArray(humanRaw?.required_roles)! } : {}),
    ...(asOptionalStringArray(humanRaw?.veto_roles) ? { vetoRoles: asOptionalStringArray(humanRaw?.veto_roles)! } : {}),
    ...(typeof humanRaw?.approval_set_id === "string" && humanRaw.approval_set_id.trim()
      ? { approvalSetId: humanRaw.approval_set_id.trim() }
      : {}),
  };
  return {
    enabled: approveHighRisk && escalateOn.length > 0,
    escalateOn: new Set(escalateOn),
    human,
  };
}

function severityForViolation(violation: string): "low" | "medium" | "high" | "critical" {
  const normalized = normalizePolicyReasonToken(violation);
  if (
    normalized === "registry_mutation" ||
    normalized === "handler_swap" ||
    normalized === "server_code_changed" ||
    normalized === "tool_code_changed" ||
    normalized === "subprocess_blocked"
  ) {
    return "critical";
  }
  if (
    normalized === "agent_guard_failed" ||
    normalized === "tool_not_in_allowlist" ||
    normalized === "version_unpinned" ||
    normalized === "contextual_evaluator_denied" ||
    normalized === "contextual_evaluator_escalated" ||
    normalized === "skill_scan_failed" ||
    normalized === "skill_code_changed" ||
    normalized === "skill_version_changed"
  ) {
    return "high";
  }
  if (
    normalized === "egress_violation" ||
    normalized === "fs_violation" ||
    normalized === "missing_idempotency_for_side_effect" ||
    normalized === "payload_too_large" ||
    normalized === "missing_audit_signature"
  ) {
    return "medium";
  }
  return "low";
}

function normalizeEscalationFindingSeverity(raw: unknown): "low" | "medium" | "high" | "critical" | null {
  const normalized = String(raw || "").trim().toLowerCase();
  if (normalized === "low" || normalized === "medium" || normalized === "high" || normalized === "critical") {
    return normalized;
  }
  return null;
}

function escalationFindingSeverityWeight(raw: unknown): number {
  const severity = normalizeEscalationFindingSeverity(raw);
  if (severity === "critical") return 4;
  if (severity === "high") return 3;
  if (severity === "medium") return 2;
  if (severity === "low") return 1;
  return 0;
}

function isRuleBackedAgentFinding(finding: AgentGuardFinding | null | undefined): boolean {
  if (!finding || typeof finding !== "object") return false;
  const source = String(finding.source || "").trim().toLowerCase();
  if (source === "evaluator") return false;
  return Boolean(
    (typeof finding.rule_id === "string" && finding.rule_id.trim()) ||
      (typeof finding.policy_id === "string" && finding.policy_id.trim()) ||
      (typeof finding.pack_id === "string" && finding.pack_id.trim()),
  );
}

function hasConcreteRuleFinding(findings: AgentGuardFinding[] | undefined): boolean {
  if (!Array.isArray(findings) || findings.length === 0) return false;
  return findings.some((finding) => isRuleBackedAgentFinding(finding));
}

function sortEscalationFindingsForReporting(findings: AgentGuardFinding[] | undefined): AgentGuardFinding[] {
  if (!Array.isArray(findings) || findings.length === 0) return [];
  return [...findings].sort((left, right) => {
    const leftRule = isRuleBackedAgentFinding(left);
    const rightRule = isRuleBackedAgentFinding(right);
    if (leftRule !== rightRule) return leftRule ? -1 : 1;
    const leftSeverity = escalationFindingSeverityWeight(left?.severity);
    const rightSeverity = escalationFindingSeverityWeight(right?.severity);
    if (leftSeverity !== rightSeverity) return rightSeverity - leftSeverity;
    const leftMessage = String(left?.message || "").trim().toLowerCase();
    const rightMessage = String(right?.message || "").trim().toLowerCase();
    return leftMessage.localeCompare(rightMessage);
  });
}

function selectPrimaryEscalationFinding(findings: AgentGuardFinding[] | undefined): AgentGuardFinding | null {
  const ordered = sortEscalationFindingsForReporting(findings);
  return ordered[0] ?? null;
}

function isContextualEscalationViolation(reason: string | null | undefined): boolean {
  const normalized = normalizePolicyReasonToken(reason || "");
  return normalized === "contextual_evaluator_denied" || normalized === "contextual_evaluator_escalated";
}

function preferredEscalationFindingSource(params: {
  violation: string | null;
  findings: AgentGuardFinding[] | undefined;
  contextualFinding: ContextualEvaluatorFinding | null;
}): "rule" | "evaluator" {
  if (hasConcreteRuleFinding(params.findings)) return "rule";
  if (params.contextualFinding && isContextualEscalationViolation(params.violation)) return "evaluator";
  if (params.violation && !isContextualEscalationViolation(params.violation)) return "rule";
  if (params.contextualFinding) return "evaluator";
  return "rule";
}

function matchesToolPattern(pattern: string, serverName: string, toolNameAtVersion: string): boolean {
  const pat = String(pattern || '').trim().toLowerCase();
  if (!pat) return false;
  const descriptor = parseToolDescriptor(toolNameAtVersion);
  const normalizedWithVersion = `${descriptor.name}@${descriptor.version}`;
  const toolRefFull = `${serverName}:${normalizedWithVersion}`.toLowerCase();
  const toolRefNoVersion = `${serverName}:${descriptor.name}`.toLowerCase();
  const toolWithVersion = normalizedWithVersion.toLowerCase();
  const toolOnly = descriptor.name.toLowerCase();
  const serverOnly = serverName.toLowerCase();
  if (pat.includes('*')) {
    const esc = pat.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*?');
    const re = new RegExp(`^${esc}$`, 'i');
    return re.test(toolRefFull) || re.test(toolRefNoVersion) || re.test(toolWithVersion) || re.test(toolOnly) || re.test(serverOnly);
  }
  return pat === toolRefFull || pat === toolRefNoVersion || pat === toolWithVersion || pat === toolOnly || pat === serverOnly;
}

type ToolDescriptor = { name: string; version: string };

function parseToolDescriptor(toolNameAtVersion: string): ToolDescriptor {
  const [rawName, rawVersion] = String(toolNameAtVersion ?? "").split("@");
  const name = rawName?.trim();
  const version = rawVersion?.trim();
  if (!name) {
    throw new Error(`[sec0-middleware] tool name is required (${toolNameAtVersion || "unknown"})`);
  }
  if (!version) {
    throw new Error(`[sec0-middleware] tool version is required (${toolNameAtVersion || "unknown"})`);
  }
  return { name, version };
}

function toolUri(serverName: string, toolNameAtVersion: string): string {
  const { name, version } = parseToolDescriptor(toolNameAtVersion);
  return `mcp://${serverName}/${name}@${version}`;
}

function toolUriNoVersion(serverName: string, toolNameAtVersion: string): string {
  const { name } = parseToolDescriptor(toolNameAtVersion);
  return `mcp://${serverName}/${name}`;
}

type AllowMatchKind = "exact" | "versionless" | "wildcard" | null;
function matchAllowlist(allowlist: string[], serverName: string, toolNameAtVersion: string): { allowed: boolean; kind: AllowMatchKind } {
  const descriptor = parseToolDescriptor(toolNameAtVersion);
  // Exact match with version
  const withVer = toolUri(serverName, toolNameAtVersion);
  if (allowlist.includes(withVer)) return { allowed: true, kind: "exact" };
  // Match when policy omits version: treat as wildcard any version
  const noVer = toolUriNoVersion(serverName, toolNameAtVersion);
  if (allowlist.includes(noVer)) return { allowed: true, kind: "versionless" };
  // Allow simple wildcard entries like mcp://server/tool@*
  const wildcard = `mcp://${serverName}/${descriptor.name}@*`;
  if (allowlist.includes(wildcard)) return { allowed: true, kind: "wildcard" };
  // Global wildcard support to allow all tools for SAST/DAST testing or permissive modes
  // Accept entries like "*", "mcp://*", or "mcp://*/*@*"
  if (allowlist.includes("*") || allowlist.includes("mcp://*") || allowlist.includes("mcp://*/*@*")) {
    return { allowed: true, kind: "wildcard" };
  }
  return { allowed: false, kind: null };
}

// --- Security guard helpers (modular) ---
type SecurityConfigLike = {
  egress_allowlist?: string[];
  fs_allowlist?: string[];
  limits?: { max_payload_kb?: number };
  deny_subprocess?: boolean;
};

function matchesAny(value: string, patterns?: string[]): boolean {
  if (!patterns || patterns.length === 0) return true;
  return patterns.some((p) => {
    const esc = p.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*?");
    try { return new RegExp(`^${esc}$`, "i").test(value); } catch { return true; }
  });
}

function estimateSizeKb(obj: unknown): number {
  try { return Math.ceil(Buffer.byteLength(JSON.stringify(obj || {}), "utf8") / 1024); } catch { return 0; }
}

function buildUrlFromHttpArgs(args: any[]): string | undefined {
  try {
    const a0 = args[0];
    if (typeof a0 === "string") return a0;
    if (a0 && typeof a0 === "object" && a0.href && typeof a0.href === "string") return a0.href;
    const opts = a0 && typeof a0 === "object" ? a0 : (args[1] && typeof args[1] === "object" ? args[1] : undefined);
    if (!opts) return undefined;
    const protocol = opts.protocol || (opts.agent && opts.agent.protocol) || "http:";
    const host = opts.hostname || opts.host || (opts.servername);
    if (!host) return undefined;
    const port = opts.port ? `:${opts.port}` : "";
    const path = typeof opts.path === "string" ? opts.path : "/";
    return `${protocol}//${host}${port}${path}`;
  } catch { return undefined; }
}

async function withGuardedIO<T>(sec: SecurityConfigLike, fn: () => Promise<T>): Promise<T> {
  // Lazy-require to avoid unused imports when not enabled
  const http = require("node:http");
  const https = require("node:https");
  const fs = require("node:fs");
  const cp = require("node:child_process");

  const originals = {
    fetch: globalThis.fetch,
    httpRequest: http.request,
    httpGet: http.get,
    httpsRequest: https.request,
    httpsGet: https.get,
    fsWriteFile: fs.writeFile,
    fsReadFile: fs.readFile,
    fsUnlink: fs.unlink,
    fsMkdir: fs.mkdir,
    fsRename: fs.rename,
    fsRmdir: fs.rmdir,
    pWriteFile: fs.promises?.writeFile,
    pReadFile: fs.promises?.readFile,
    pUnlink: fs.promises?.unlink,
    pMkdir: fs.promises?.mkdir,
    pRename: fs.promises?.rename,
    pRmdir: fs.promises?.rmdir,
    spawn: cp.spawn,
    exec: cp.exec,
    execFile: cp.execFile,
  } as any;

  const throwViolation = (code: PolicyViolation, info?: Record<string, any>) => {
    const err: any = new Error(code);
    err.code = code;
    if (info) Object.assign(err, info);
    throw err;
  };

  const installHttpGuards = () => {
    if (!sec.egress_allowlist) return;
    const guardUrl = (urlStr?: string) => {
      if (!urlStr) return;
      if (!matchesAny(urlStr, sec.egress_allowlist)) throwViolation("egress_violation", { url: urlStr });
    };
    http.request = (...a: any[]) => { guardUrl(buildUrlFromHttpArgs(a)); return originals.httpRequest(...a); };
    http.get = (...a: any[]) => { guardUrl(buildUrlFromHttpArgs(a)); return originals.httpGet(...a); };
    https.request = (...a: any[]) => { guardUrl(buildUrlFromHttpArgs(a)); return originals.httpsRequest(...a); };
    https.get = (...a: any[]) => { guardUrl(buildUrlFromHttpArgs(a)); return originals.httpsGet(...a); };
    if (typeof globalThis.fetch === "function") {
      (globalThis as any).fetch = ((input: any, init?: any) => {
        try {
          const urlStr = typeof input === "string" ? input : (input && typeof input.url === "string" ? input.url : undefined);
          guardUrl(urlStr);
        } catch (e) { /* rethrow to caller */ throw e; }
        return originals.fetch(input, init);
      }) as any;
    }
  };

  const installFsGuards = () => {
    if (!sec.fs_allowlist) return;
    const guardPath = (p?: any) => {
      const pathStr = typeof p === "string" ? p : undefined;
      if (!pathStr) return;
      if (!matchesAny(pathStr, sec.fs_allowlist)) throwViolation("fs_violation", { path: pathStr });
    };
    fs.writeFile = (...a: any[]) => { guardPath(a[0]); return originals.fsWriteFile(...a); };
    fs.readFile = (...a: any[]) => { guardPath(a[0]); return originals.fsReadFile(...a); };
    fs.unlink = (...a: any[]) => { guardPath(a[0]); return originals.fsUnlink(...a); };
    fs.mkdir = (...a: any[]) => { guardPath(a[0]); return originals.fsMkdir(...a); };
    fs.rename = (...a: any[]) => { guardPath(a[0]); guardPath(a[1]); return originals.fsRename(...a); };
    if (fs.rmdir) fs.rmdir = (...a: any[]) => { guardPath(a[0]); return originals.fsRmdir(...a); };
    if (fs.promises) {
      if (fs.promises.writeFile) fs.promises.writeFile = (...a: any[]) => { guardPath(a[0]); return originals.pWriteFile(...a); };
      if (fs.promises.readFile) fs.promises.readFile = (...a: any[]) => { guardPath(a[0]); return originals.pReadFile(...a); };
      if (fs.promises.unlink) fs.promises.unlink = (...a: any[]) => { guardPath(a[0]); return originals.pUnlink(...a); };
      if (fs.promises.mkdir) fs.promises.mkdir = (...a: any[]) => { guardPath(a[0]); return originals.pMkdir(...a); };
      if (fs.promises.rename) fs.promises.rename = (...a: any[]) => { guardPath(a[0]); guardPath(a[1]); return originals.pRename(...a); };
      if (fs.promises.rmdir) fs.promises.rmdir = (...a: any[]) => { guardPath(a[0]); return originals.pRmdir(...a); };
    }
  };

  const installSubprocessGuards = () => {
    if (sec.deny_subprocess === false) return;
    cp.spawn = () => { throwViolation("subprocess_blocked"); };
    cp.exec = () => { throwViolation("subprocess_blocked"); };
    cp.execFile = () => { throwViolation("subprocess_blocked"); };
  };

  try {
    installHttpGuards();
    installFsGuards();
    installSubprocessGuards();
    return await fn();
  } finally {
    // Restore originals
    http.request = originals.httpRequest;
    http.get = originals.httpGet;
    https.request = originals.httpsRequest;
    https.get = originals.httpsGet;
    if (typeof originals.fetch === "function") (globalThis as any).fetch = originals.fetch;
    const fs = require("node:fs");
    const cp = require("node:child_process");
    fs.writeFile = originals.fsWriteFile;
    fs.readFile = originals.fsReadFile;
    fs.unlink = originals.fsUnlink;
    fs.mkdir = originals.fsMkdir;
    fs.rename = originals.fsRename;
    if (originals.fsRmdir) fs.rmdir = originals.fsRmdir;
    if (fs.promises) {
      if (originals.pWriteFile) fs.promises.writeFile = originals.pWriteFile;
      if (originals.pReadFile) fs.promises.readFile = originals.pReadFile;
      if (originals.pUnlink) fs.promises.unlink = originals.pUnlink;
      if (originals.pMkdir) fs.promises.mkdir = originals.pMkdir;
      if (originals.pRename) fs.promises.rename = originals.pRename;
      if (originals.pRmdir) fs.promises.rmdir = originals.pRmdir;
    }
    cp.spawn = originals.spawn;
    cp.exec = originals.exec;
    cp.execFile = originals.execFile;
  }
}

/**
 * Async initialization helper to resolve hierarchy from API key
 */
export async function initializeSec0Middleware(opts: MiddlewareOptions): Promise<{ tenant: string; env: string; clientName: string; clientVersion: string }> {
  const controlPlaneUrl = resolveControlPlaneUrl(opts.controlPlaneUrl);
  const apiKey = extractApiKey({
    'x-api-key': opts.auth?.apiKey,
    'authorization': opts.auth?.bearerToken ? `Bearer ${opts.auth?.bearerToken}` : undefined,
  } as any);
  if (!apiKey) {
    throw new Error('[sec0-middleware] auth.apiKey or auth.bearerToken is required to resolve hierarchy');
  }
  
  const hierarchy = await resolveHierarchy(apiKey, { controlPlaneUrl });
  
  return {
    tenant: hierarchy.tenant,
    env: hierarchy.env,
    clientName: hierarchy.clientName,
    clientVersion: hierarchy.clientVersion,
  };
}

function normalizePolicyObject(input: any): any {
  const obj: any = input && typeof input === "object" ? input : {};
  const enforcement: any = obj.enforcement && typeof obj.enforcement === "object" ? obj.enforcement : {};
  if (!Array.isArray(enforcement.deny_on)) enforcement.deny_on = [];
  if (enforcement.escalate_on !== undefined && !Array.isArray(enforcement.escalate_on)) {
    enforcement.escalate_on = [];
  }
  obj.enforcement = enforcement;
  return obj;
}

/**
 * Factory that decorates an MCP server with sec0 security instrumentation.
 */
export const sec0SecurityMiddleware = (opts: MiddlewareOptions) => (server: McpServerLike) => {
  // Allow policy to be passed as YAML string as well; parse to object if needed
  try {
    if (typeof (opts as any).policy === 'string') {
      const parsed = YAML.parse((opts as any).policy as unknown as string) as any;
      (opts as any).policy = parsed || (opts as any).policy;
    }
  } catch {}
  const policySource = isControlPlanePolicySource(opts.policy) ? (opts.policy as ControlPlanePolicySource) : null;
  let policyObj = normalizePolicyObject(policySource ? ({} as any) : (opts.policy as PolicyObject));
  const telemetryEnabled = opts.telemetry?.enabled !== false;
  // Derived agent-state telemetry is off by default to give server authors full control.
  const agentStateTelemetry = opts.agentStateTelemetry ?? {};
  const includeServerAgentState = !!agentStateTelemetry.includeServerSignals;
  const includeToolAgentState = !!agentStateTelemetry.includeToolSignals;
  const runtimeConfig = opts.runtime;
  const runtimeInvoker = opts.adapters?.runtimeInvoker ?? createRuntimeInvoker(runtimeConfig?.enforcement);
  const runtimeDebug = runtimeConfig?.debug;
  const uploadApiConfig = runtimeConfig?.uploadApi;
  const presignFlushConfig = runtimeConfig?.presignFlush;
  const policyWebhookUrl = runtimeConfig?.webhook?.policyUrl;
  const forceDastRawUpload = runtimeConfig?.forceDastRawUpload === true;
  const rawPayloadConfig = runtimeConfig?.rawPayloads;
  const debugSastEnabled = runtimeDebug?.sast === true;
  const debugDastEnabled = runtimeDebug?.dast === true;
  const debugPolicySyncEnabled = runtimeDebug?.policySync === true;
  const controlPlaneUrl = resolveControlPlaneUrl(opts.controlPlaneUrl);
  const controlPlaneClient = createControlPlaneClient({ baseUrl: controlPlaneUrl });
  const policyProvider: PolicyProvider =
    opts.adapters?.policyProvider ??
    (policySource
      ? createControlPlanePolicyProvider({
          source: policySource,
          controlPlaneUrl,
          auth: opts.auth,
          debug: debugPolicySyncEnabled,
          client: controlPlaneClient,
        })
      : createStaticPolicyProvider(policyObj));
  const approvalVerifier: ApprovalVerifier =
    opts.adapters?.approvalVerifier ??
    (opts.auth
      ? createControlPlaneApprovalVerifier({
          auth: opts.auth,
          client: controlPlaneClient,
        })
      : createNoopApprovalVerifier());
  const escalationReporter: EscalationReporter =
    opts.adapters?.escalationReporter ??
    (opts.auth
      ? createControlPlaneEscalationReporter({
          auth: opts.auth,
          client: controlPlaneClient,
        })
      : createNoopEscalationReporter());
  const controlPlaneApiKey = (() => {
    try {
      return extractApiKey({
        "x-api-key": opts.auth?.apiKey,
        authorization: opts.auth?.bearerToken ? `Bearer ${opts.auth?.bearerToken}` : undefined,
      } as any);
    } catch {
      return undefined;
    }
  })();
  const nlEvaluator = createControlPlaneNlEvaluator({
    authToken: controlPlaneApiKey,
    client: controlPlaneClient,
  });
  const controlPlaneContextualEvaluator =
    opts.contextualEvaluator?.evaluatorSource === "control-plane"
      ? createControlPlaneContextualEvaluator({
          auth: opts.auth,
          client: controlPlaneClient,
          timeoutMs: opts.contextualEvaluator.controlPlane?.timeoutMs,
        })
      : null;
  const contextualEvaluatorManager = opts.contextualEvaluator
    ? createContextualEvaluatorManager({
        evaluatorSource: opts.contextualEvaluator.evaluatorSource,
        evaluatorMode: opts.contextualEvaluator.evaluatorMode,
        debug: opts.contextualEvaluator.debug === true,
        logger: ({ level, message, data }) => {
          if (level === "warn") {
            console.warn("[sec0-evaluator]", message, data ?? "");
            return;
          }
          if (opts.contextualEvaluator?.debug) {
            console.log("[sec0-evaluator]", message, data ?? "");
          }
        },
        local: {
          adapter: opts.contextualEvaluator.local?.adapter,
          denyThreshold: opts.contextualEvaluator.local?.denyThreshold,
          escalateThreshold: opts.contextualEvaluator.local?.escalateThreshold,
        },
        controlPlane: {
          adapter: opts.contextualEvaluator.controlPlane?.adapter ?? controlPlaneContextualEvaluator ?? undefined,
        },
      })
    : null;
  let currentPolicyHash: string | null = (() => {
    try {
      if (policySource) return null;
      return sha256Hex(Buffer.from(canonicalize(policyObj as any)));
    } catch {
      return policySource ? null : "static";
    }
  })();

  let cachedAgentGuard: { policyHash: string | null; agentGuard: AgentGuard } | null = null;
  let cachedRunContext: { policyHash: string | null; config: RunContextConfig | null } | null = null;
  const getAgentGuardForCurrentPolicy = (): AgentGuard => {
    if (cachedAgentGuard && cachedAgentGuard.policyHash === currentPolicyHash) return cachedAgentGuard.agentGuard;

    const policyAgentGuard: any = (policyObj as any)?.agent_guard || (policyObj as any)?.enforcement?.agent_guard || {};
    const complianceScanners = buildCompliancePackScanners({
      policyObj: policyObj as any,
      tenant: opts.otel?.tenant,
      nlEvaluator: nlEvaluator || undefined,
    });
    const {
      adapters: agentGuardAdapterConfigs = [],
      onScanPrompt: customAgentGuardPrompt,
      onScanOutput: customAgentGuardOutput,
      onScanRun: customAgentGuardRun,
      enabled: agentGuardEnabledOverride,
      block_on_severity: agentGuardBlockSeverityOverride,
      block_on_count: agentGuardBlockCountOverride,
      ...agentGuardOptionRest
    } = (opts.agentGuard ?? {}) as MiddlewareAgentGuardOptions;

    const adapterPromptFns: AgentGuardScanFn[] = [];
    const adapterOutputFns: AgentGuardScanFn[] = [];
    const adapterRunFns: AgentGuardScanFn[] = [];
    if (complianceScanners.onScanPrompt) adapterPromptFns.push(complianceScanners.onScanPrompt);
    if (complianceScanners.onScanOutput) adapterOutputFns.push(complianceScanners.onScanOutput);
    if (complianceScanners.onScanRun) adapterRunFns.push(complianceScanners.onScanRun);
    for (const adapter of agentGuardAdapterConfigs) {
      if (!adapter) continue;
      if (adapter.type === "custom") {
        if (adapter.onScanPrompt) adapterPromptFns.push(adapter.onScanPrompt);
        if (adapter.onScanOutput) adapterOutputFns.push(adapter.onScanOutput);
        if (adapter.onScanRun) adapterRunFns.push(adapter.onScanRun);
        continue;
      }
      const serviceUrl = String((adapter as any).serviceUrl || "").trim();
      if (!serviceUrl) continue;
      try {
        let built:
          | ReturnType<typeof createNeMoGuardrailsAdapter>
          | ReturnType<typeof createGuardrailsAIAdapter>
          | ReturnType<typeof createLLMGuardAdapter>
          | null = null;
        if (adapter.type === "nemo") built = createNeMoGuardrailsAdapter({ serviceUrl });
        if (adapter.type === "guardrails") built = createGuardrailsAIAdapter({ serviceUrl });
        if (adapter.type === "llmguard") built = createLLMGuardAdapter({ serviceUrl });
        if (built) {
          adapterPromptFns.push(built.onScanPrompt);
          adapterOutputFns.push(built.onScanOutput);
        }
      } catch {}
    }
    if (customAgentGuardPrompt) adapterPromptFns.push(customAgentGuardPrompt);
    if (customAgentGuardOutput) adapterOutputFns.push(customAgentGuardOutput);
    if (customAgentGuardRun) adapterRunFns.push(customAgentGuardRun);
    const finalAgentGuardOnPrompt = combineAgentGuardFns(adapterPromptFns);
    const finalAgentGuardOnOutput = combineAgentGuardFns(adapterOutputFns);
    const finalAgentGuardOnRun = combineAgentGuardFns(adapterRunFns);
    const denyOnAgentGuardFailed = !!(policyObj as any)?.enforcement?.deny_on?.includes("agent_guard_failed");
    const effectiveAgentGuardSeverity = (agentGuardBlockSeverityOverride ?? policyAgentGuard?.block_on_severity) as any;
    const effectiveAgentGuardCount = (agentGuardBlockCountOverride ?? policyAgentGuard?.block_on_count) as any;
    const agentGuard = new AgentGuard({
      ...agentGuardOptionRest,
      enabled: !!(agentGuardEnabledOverride ?? policyAgentGuard?.enabled ?? complianceScanners.enabled ?? false),
      block_on_severity: effectiveAgentGuardSeverity,
      block_on_count: effectiveAgentGuardCount ?? (denyOnAgentGuardFailed && !effectiveAgentGuardSeverity ? 1 : undefined),
      onScanPrompt: finalAgentGuardOnPrompt,
      onScanOutput: finalAgentGuardOnOutput,
      onScanRun: finalAgentGuardOnRun
    });

    cachedRunContext = {
      policyHash: currentPolicyHash,
      config: resolveRunContextConfig(opts.agentGuard, !!finalAgentGuardOnRun),
    };
    cachedAgentGuard = { policyHash: currentPolicyHash, agentGuard };
    return agentGuard;
  };
  const requireUploadConfig = (): UploadApiConfig => {
    if (!uploadApiConfig) {
      throw new Error("[sec0-middleware] runtime.uploadApi configuration is required for uploading scan artifacts");
    }
    return uploadApiConfig;
  };
  if (telemetryEnabled) {
    initTracing({ ...opts.otel, serviceName: opts.otel.serviceName ?? server.name, serviceVersion: server.version, sample: (policyObj as any)?.observability?.sample });
  }

  // Best-effort: on initialization, publish the policy to the control plane if it differs.
  if (!policySource) {
    void (async () => {
      try {
        await publishPolicyToControlPlaneIfChanged({
          level: "middleware",
          tenant: opts.otel?.tenant,
          policy: policyObj,
          controlPlaneUrl,
          auth: opts.auth,
          urlOverride: policyWebhookUrl,
          debug: debugPolicySyncEnabled,
        });
      } catch (err: any) {
        console.error("[sec0-middleware] Policy sync failed:", err?.message || err);
      }
    })();
  }
  // Build the effective sec0 config, auto-wiring presign when apiKey convenience option is provided.
  // This allows users to just pass apiKey and have presign automatically configured with discovery.
  let effectiveSec0Config: Sec0Config = opts.sec0;
  if (opts.apiKey && !opts.sec0?.presign) {
    const apiKeyStr = String(opts.apiKey).trim();
    if (apiKeyStr) {
      effectiveSec0Config = {
        ...opts.sec0,
        presign: {
          // apiBaseUrl omitted - will be auto-discovered from API key
          apiBaseUrl: opts.controlPlaneUrl || undefined,
          auditKey: apiKeyStr.startsWith("Bearer ") ? apiKeyStr : `Bearer ${apiKeyStr}`,
        },
      };
    }
  }
  
  const auditSink = opts.adapters?.auditSink ?? createSec0AuditSink({ config: effectiveSec0Config, signer: opts.signer });
  // Raw payload capture is optional and should not require callers to know hierarchy.
  // We instantiate the recorder per invocation once we have effective tenant/env/client metadata.
  
  // Background uploader: periodically flush without blocking tool execution
  if (effectiveSec0Config?.presign && presignFlushConfig?.enabled) {
    const uploadIntervalMs = presignFlushConfig.intervalMs;
    if (!Number.isFinite(uploadIntervalMs) || uploadIntervalMs <= 0) {
      throw new Error("[sec0-middleware] runtime.presignFlush.intervalMs must be a positive number when enabled");
    }
    // Avoid noisy logs (especially in interactive CLIs). Only surface failures.
    setInterval(() => {
      if (!auditSink.flush) return;
      auditSink.flush().catch((err) => {
        console.error(`[sec0-middleware] Background upload failed:`, err.message);
      });
    }, uploadIntervalMs);
  }
  const policySast: any = (policyObj as any)?.sast || {};
  // Sanitize DAST policy for middleware: ignore sandbox_url from policy (set centrally via config/runtime)
  const policyDastRaw: any = (policyObj as any)?.dast || {};
  const policyDast: any = (() => { try { const c = { ...policyDastRaw }; if (c && typeof c === 'object') { delete (c as any).sandbox_url; } return c; } catch { return policyDastRaw; } })();
  const sastCacheTtlMs = (() => {
    const fromOpts = Number((opts.sast as any)?.cache_ttl_ms);
    if (Number.isFinite(fromOpts) && fromOpts > 0) return Math.floor(fromOpts);
    const fromPolicy = Number((policySast as any)?.cache_ttl_ms);
    if (Number.isFinite(fromPolicy) && fromPolicy > 0) return Math.floor(fromPolicy);
    return 60_000;
  })();
  const sast = new SastManager({
    ...policySast,
    ...(opts.sast || {}),
    // Ensure required fields remain valid after spreads.
    cache_ttl_ms: sastCacheTtlMs,
    onScan: opts.sast?.onScan ?? semgrepOnScan,
  });
  const defaultDastOnScan = async (info: { server: { name: string; version: string }; tool: string; handlerHash: string; sandboxUrl?: string }) => {
    // Do not read templates path from policy; use centralized adapter defaults/config
    return nucleiOnScan({ ...info, tags: (opts.dast as any)?.tags || (policyDast as any)?.tags, excludeTags: (opts.dast as any)?.exclude_tags || (policyDast as any)?.exclude_tags, severity: (opts.dast as any)?.severity || (policyDast as any)?.severity });
  };
  const dastEnabled = Boolean(opts.dast?.enabled ?? policyDast?.enabled ?? false);
  let computedSandboxUrl: string | undefined;
  if (dastEnabled) {
    const fromOpts = (opts.dast as any)?.sandbox_url;
    if (typeof fromOpts === "string" && fromOpts.trim()) {
      computedSandboxUrl = fromOpts.trim();
    } else {
      throw new Error("[sec0-middleware] opts.dast.sandbox_url is required when DAST is enabled");
    }
  }
  const dast = dastEnabled
    ? new DastManager({ onScan: opts.dast?.onScan ?? defaultDastOnScan, ...policyDast, ...(opts.dast || {}), sandbox_url: computedSandboxUrl! })
    : null;
  const sastEnabled = Boolean(opts.sast?.enabled ?? policySast?.enabled ?? false);
  const tools = server.__getTools?.() ?? new Map();
  // Capture original file paths from tool metadata before wrapping so we can feed real files to SAST
  const toolFilePathByKey: Map<string, string> = new Map();
  const debugSastLog = (...args: any[]) => {
    if (!debugSastEnabled) return;
    try {
      console.log('[sec0-middleware][sast]', ...args);
    } catch {}
  };

  // Span indexer + attribution: compute handler spans per file and cache file-level scans
  type ToolSpan = { tool: string; startLine: number; endLine: number };
  const spansByFilePath: Map<string, ToolSpan[]> = new Map();
  const handlerFirstScanDone: Set<string> = new Set();
  function computeToolSpans(filePath: string): ToolSpan[] {
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      const spans: ToolSpan[] = [];
      // Match: tool('name@ver', withSec0Meta(async (...) => { ... }) )
      const re = /tool\(\s*'([^']+)'\s*,\s*withSec0Meta\(\s*async\s*\([^)]*\)\s*=>\s*\{/g;
      let m: RegExpExecArray | null;
      while ((m = re.exec(content)) !== null) {
        const tool = m[1];
        let idx = re.lastIndex - 1; // opening '{'
        let depth = 0;
        let startIdx = idx;
        let endIdx = idx;
        for (let i = idx; i < content.length; i++) {
          const ch = content.charAt(i);
          if (ch === '{') { depth++; if (depth === 1) startIdx = i; }
          else if (ch === '}') { depth--; if (depth === 0) { endIdx = i; re.lastIndex = i; break; } }
        }
        const pre = content.slice(0, startIdx);
        const startLine = (pre.match(/\n/g)?.length || 0) + 1;
        const block = content.slice(startIdx, endIdx + 1);
        const endLine = startLine + (block.match(/\n/g)?.length || 0);
        spans.push({ tool, startLine, endLine });
      }
      debugSastLog('computed spans', { filePath, count: spans.length });
      return spans;
    } catch { return []; }
  }

  type FileScan = { status: "pass" | "fail" | "pending"; findings: any[]; scanId?: string; raw?: any; raw_key?: string; updatedAt: number };
  const fileScanCache: Map<string, FileScan> = new Map();
  async function scanFileIfNeeded(filePath: string, serverInfo: { name: string; version: string }): Promise<FileScan> {
    const cached = fileScanCache.get(filePath);
    if (cached && cached.status !== 'pending') return cached;
    const handlerHash = sha256Hex(Buffer.from(filePath));
    const res = await semgrepOnScan({ server: serverInfo, tool: 'FILE', handlerHash, filePath });
    const fsr: FileScan = { status: res.status as any, findings: (res.findings || []) as any[], scanId: res.scanId, raw: res.raw, updatedAt: Date.now() };
    fileScanCache.set(filePath, fsr);
    return fsr;
  }

  // --- Registry snapshot and freeze controls ---
  const functionCodeHash = (fn: any): string => {
    try {
      const src = typeof fn === "function" ? Function.prototype.toString.call(fn) : String(fn);
      return sha256Hex(Buffer.from(src));
    } catch {
      return sha256Hex(Buffer.from("unknown"));
    }
  };

  const initialOriginalHandlerHashByTool: Map<string, string> = new Map();
  const registryParts: string[] = [];
  for (const [k, v] of tools) {
    const h = functionCodeHash(v);
    initialOriginalHandlerHashByTool.set(k, h);
    registryParts.push(`${k}:${h}`);
  }
  const initialServerSnapshotHash = sha256Hex(Buffer.from(registryParts.sort().join("|")));

  let registryFrozen = false;
  let installingWrapper = false;
  let registryMutationAttempted: { tool?: string; when: number; kind: "tool" | "setTool" | "map" } | null = null;

  // Override registration APIs to freeze after wrapping
  const originalToolRegister = server.tool?.bind(server);
  const originalSetTool = server.__setTool?.bind(server);
  // Always override .tool since it is part of the interface
  (server as any).tool = (nameAtVersion: string, handler: any) => {
    if (registryFrozen && !installingWrapper) {
      registryMutationAttempted = { tool: nameAtVersion, when: Date.now(), kind: "tool" };
      const err: any = new Error("REGISTRY_FROZEN");
      err.code = "REGISTRY_FROZEN";
      throw err;
    }
    return originalToolRegister!(nameAtVersion, handler);
  };
  if (server.__setTool) {
    (server as any).__setTool = (nameAtVersion: string, handler: any) => {
      if (registryFrozen && !installingWrapper) {
        registryMutationAttempted = { tool: nameAtVersion, when: Date.now(), kind: "setTool" };
        const err: any = new Error("REGISTRY_FROZEN");
        err.code = "REGISTRY_FROZEN";
        throw err;
      }
      return originalSetTool!(nameAtVersion, handler);
    };
  }

  // If we can, harden the Map against direct mutation
  try {
    const throwFrozen = () => { const e: any = new Error("REGISTRY_FROZEN"); (e as any).code = "REGISTRY_FROZEN"; throw e; };
    if (tools && typeof (tools as any).set === "function") {
      const origSet = tools.set.bind(tools);
      (tools as any).set = (...args: any[]) => { if (registryFrozen && !installingWrapper) { registryMutationAttempted = { tool: String(args[0]), when: Date.now(), kind: "map" }; throwFrozen(); } return (origSet as any).apply(null, args); };
    }
    if (tools && typeof (tools as any).delete === "function") {
      const origDel = tools.delete.bind(tools);
      (tools as any).delete = (...args: any[]) => { if (registryFrozen && !installingWrapper) { registryMutationAttempted = { tool: String(args[0]), when: Date.now(), kind: "map" }; throwFrozen(); } return (origDel as any).apply(null, args); };
    }
    if (tools && typeof (tools as any).clear === "function") {
      const origClr = tools.clear.bind(tools);
      (tools as any).clear = (...args: any[]) => { if (registryFrozen && !installingWrapper) { registryMutationAttempted = { tool: undefined, when: Date.now(), kind: "map" }; throwFrozen(); } return (origClr as any).apply(null, args); };
    }
  } catch {}

  // Minimal in-memory circuit breaker per tool key (name@ver)
  const recentByTool: Map<string, Array<{ ok: boolean; latency: number; ts: number }>> = new Map();
  // Track last seen version per tool (policy-approved visibility)
  const lastVersionByToolBase: Map<string, string> = new Map();
  const WINDOW = 100; // sliding window size
  function pushStat(toolKey: string, ok: boolean, latency: number) {
    const arr = recentByTool.get(toolKey) ?? [];
    arr.push({ ok, latency, ts: Date.now() });
    if (arr.length > WINDOW) arr.shift();
    recentByTool.set(toolKey, arr);
  }
  function calcErrorRate(toolKey: string): number {
    const arr = recentByTool.get(toolKey) ?? [];
    if (arr.length === 0) return 0;
    const errs = arr.filter(r => !r.ok).length;
    return (errs / arr.length) * 100.0;
  }
  function calcP95(toolKey: string): number {
    const arr = recentByTool.get(toolKey) ?? [];
    if (arr.length === 0) return 0;
    const lat = arr.map(r => r.latency).slice().sort((a,b) => a-b);
    const idx = Math.max(0, Math.min(lat.length - 1, Math.floor(lat.length * 0.95) - 1));
    return lat[idx] ?? 0;
  }

  for (const [nameAtVersion, handler] of tools) {
    try {
      const m = getSec0Meta(handler);
      if (m?.filePath) toolFilePathByKey.set(nameAtVersion, m.filePath);
      debugSastLog('tool meta', { tool: nameAtVersion, filePath: m?.filePath || null });
    } catch {}
    const wrapped = async (ctx: { args: any; idempotencyKey?: string | null; headers?: Record<string, string> }) => {
      // Freeze registry on first actual invocation to allow initial registration phase
      registryFrozen = true;
      const start = Date.now();
      const { name: toolBaseName, version: toolVersion } = parseToolDescriptor(nameAtVersion);

      // Idempotency propagation: accept header-only transports.
      // Many application/tool authors only forward headers; normalize that into ctx.idempotencyKey.
      if (ctx && (ctx.idempotencyKey === undefined || ctx.idempotencyKey === null || ctx.idempotencyKey === "")) {
        const h =
          readHeaderCaseInsensitive(ctx.headers as any, "x-idempotency-key") ||
          readHeaderCaseInsensitive(ctx.headers as any, "x-idempotency");
        if (h) {
          ctx.idempotencyKey = h;
        }
      }

      let span: any;
      let activeCtx = context.active();
      if (telemetryEnabled) {
        const parentCtx = extractContextFromHeaders(ctx.headers);
        const serviceName = (opts.otel.serviceName || "").trim();
        if (!serviceName) {
          throw new Error("[sec0-middleware] opts.otel.serviceName is required when telemetry is enabled");
        }
        const environment = (opts.otel.environment || "").trim();
        if (!environment) {
          throw new Error("[sec0-middleware] opts.otel.environment is required when telemetry is enabled");
        }
        const invokeSpanName = `${serviceName}.invoke`;
        span = startInvokeSpan(invokeSpanName, {
          "mcp.server": server.name,
          "mcp.tool": toolBaseName,
          "mcp.tool.name": nameAtVersion,
          "mcp.version": toolVersion,
          "deployment.env": environment,
        }, parentCtx);
        // Mark context to avoid duplicate parent spans in SDKs
        const activeWithSpan = trace.setSpan(context.active(), span);
        const carrier: Record<string,string> = {};
        // stamp baggage via propagation API (best-effort)
        carrier['baggage'] = 'mcp.audit.parent=1';
        activeCtx = propagation.extract(activeWithSpan, carrier);
      } else {
        span = { spanContext: () => ({ traceId: "0".repeat(32), spanId: "0".repeat(16) }) };
      }
      const addAttrs = (attrs: Record<string, any>) => { if (telemetryEnabled) setSpanAttributes(span, attrs); };
      const spanCtx = typeof span?.spanContext === 'function' ? span.spanContext() : undefined;
      const incomingAgentState: AgentStatePayload = extractAgentStateFromHeaders(ctx.headers as any);
      const nodeId = incomingAgentState.nodeId;
      const agentRunId = ensureRunId(incomingAgentState);
      let agentVariables: AgentStateVariables | undefined = incomingAgentState.variables;
      const identityContext = parseIdentityContextHeader(
        readHeaderCaseInsensitive(ctx.headers as any, "x-auth-context"),
      );

      // Effective hierarchy metadata. In strict mode, callers omit these and Sec0 resolves internally.
      let effectiveTenant: string | undefined = opts.otel?.tenant;
      let effectiveEnv: string | undefined = opts.otel?.environment || (opts.sec0 as any)?.presign?.environment;
      let effectiveClientName: string | undefined = (opts.sec0 as any)?.presign?.clientName;
      let effectiveClientVersion: string | undefined = (opts.sec0 as any)?.presign?.clientVersion;
      /**
       * Optional: short-lived approval token used to bypass agent_guard_failed in enforce mode.
       * Prefer headers to avoid polluting args hashes / raw payload captures.
       */
      const approvalTokenRaw = (() => {
        const h =
          readHeaderCaseInsensitive(ctx.headers as any, "x-sec0-approval-token") ||
          readHeaderCaseInsensitive(ctx.headers as any, "x-sec0-approval");
        const a: any = (ctx as any)?.args;
        const fromArgs =
          (a && typeof a === "object")
            ? (typeof a.__sec0_approval_token === "string" ? a.__sec0_approval_token
              : typeof a.approval_token === "string" ? a.approval_token
              : typeof a.approvalToken === "string" ? a.approvalToken
              : undefined)
            : undefined;
        const v = typeof h === "string" && h.trim() ? h.trim() : (typeof fromArgs === "string" ? fromArgs.trim() : "");
        return v || undefined;
      })();
      // Scrub token from ctx so it doesn't leak into audit hashes/payloads or downstream calls.
      if (approvalTokenRaw) {
        try {
          if (ctx.headers) {
            delete (ctx.headers as any)["x-sec0-approval-token"];
            delete (ctx.headers as any)["X-Sec0-Approval-Token"];
            delete (ctx.headers as any)["x-sec0-approval"];
            delete (ctx.headers as any)["X-Sec0-Approval"];
          }
        } catch {}
        try {
          const a: any = (ctx as any)?.args;
          if (a && typeof a === "object") {
            delete a.__sec0_approval_token;
            delete a.approval_token;
            delete a.approvalToken;
          }
        } catch {}
      }
      let approvalChecked: { valid: boolean; approval?: any } | null = null;
      const verifyApprovalIfAny = async (): Promise<{ valid: boolean; approval?: any } | null> => {
        if (!approvalTokenRaw) return null;
        if (approvalChecked) return approvalChecked;
        try {
          const out = await approvalVerifier.verify({
            token: approvalTokenRaw,
            toolRef: toolUri(server.name, nameAtVersion),
            nodeId: nodeId || undefined,
            agentRef: agentRunId || undefined,
          });
          approvalChecked = out ? { valid: out.valid, approval: out.approval } : null;
          return approvalChecked;
        } catch {
          return null;
        }
      };

      let decision: "allow" | "deny" = "allow";
      let violation: PolicyViolation | null = null;
      let result: any = null;
      let error: Error | null = null;
      let escalationResult: EscalationCreateResult | null = null;
      let escalationFailure: string | null = null;
      let inputHash: string | null = null;
      let outputHash: string | null = null;
      let handler_swap_detected = false;
      let server_code_changed = false;
      let registry_mutation = false;
      let tool_code_changed = false;
      let sast_status: "pass" | "fail" | "pending" | undefined = undefined;
      let sast_findings: SastFinding[] | undefined = undefined;
      let sast_scan_id: string | undefined = undefined;
      let dast_status: "pass" | "fail" | "pending" | undefined = undefined;
      let dast_findings: DastFinding[] | undefined = undefined;
      let dast_scan_id: string | undefined = undefined;
      let sast_raw_key: string | undefined = undefined;
      let dast_raw_key: string | undefined = undefined;
      let agent_findings: AgentGuardFinding[] | undefined = undefined;
      let agent_guard_raw_key: string | undefined = undefined;
      let contextualEvaluatorFinding: any = null;
      let contextualEvaluatorViolation: PolicyViolation | null = null;
      let contextualAgentFindings: AgentGuardFinding[] = [];
      // Track which security tests executed for this invocation
      let didSast = false;
      let didDast = false;
      // Version change tracking
      const toolBaseUri = toolUriNoVersion(server.name, nameAtVersion);
      const currentVersion = toolVersion;
      let version_changed = false;
      let previous_version: string | undefined = undefined;
      const runtimeDecisionCache: Map<string, boolean> = new Map();
      const getPolicyDenyOn = (): string[] => {
        const raw = (policyObj as any)?.enforcement?.deny_on;
        if (!Array.isArray(raw)) return [];
        return raw.map((entry: unknown) => String(entry ?? "").trim()).filter(Boolean);
      };
      const policyDeniesReason = (reason: string): boolean => {
        if (!reason) return false;
        return getPolicyDenyOn().includes(normalizePolicyReasonToken(reason));
      };
      const shouldRuntimeDeny = async (
        reasons: string[],
        opts?: { requestIdSuffix?: string; strategy?: "deny_on_match" | "deny_on_any"; forceDeny?: boolean },
      ): Promise<boolean> => {
        const normalizedReasons = reasons.map((entry) => String(entry ?? "").trim()).filter(Boolean);
        if (!normalizedReasons.length) return false;
        const denyOn = getPolicyDenyOn();
        const strategy = opts?.strategy ?? "deny_on_match";
        const forceDeny = opts?.forceDeny === true;
        const cacheKey = `${strategy}|${forceDeny ? "1" : "0"}|${denyOn.join(",")}|${normalizedReasons.join(",")}`;
        const cached = runtimeDecisionCache.get(cacheKey);
        if (typeof cached === "boolean") return cached;
        const runtimeDecision = await runtimeInvoker.evaluate(
          mapRuntimeDecisionRequest({
            executionLayer: "middleware",
            tenant: effectiveTenant,
            server: server.name,
            tool: nameAtVersion,
            nodeId,
            runId: agentRunId,
            mode: "enforce",
            strategy,
            denyOn,
            forceDeny,
            reasons: normalizedReasons,
            requestId: `${toolUri(server.name, nameAtVersion)}:${opts?.requestIdSuffix || "runtime"}`,
          }),
        );
        const shouldDeny = mapRuntimeDecisionToLegacy(runtimeDecision).shouldDeny;
        runtimeDecisionCache.set(cacheKey, shouldDeny);
        return shouldDeny;
      };

      // Detect handler swaps by checking registry view if available
      try {
        if (server.__getTools) {
          const currentFn = server.__getTools()?.get(nameAtVersion);
          // Tag the wrapped function with identity and original handler hash
          (wrapped as any).__sec0_wrapper__ = true;
          (wrapped as any).__sec0_handler_hash = functionCodeHash(handler);
          if (!currentFn || currentFn !== wrapped) {
            handler_swap_detected = true;
          }
          // Compare current tool handler original hash with initial snapshot
          try {
            const currentHash = (currentFn as any)?.__sec0_handler_hash || functionCodeHash(currentFn);
            const initialHash = initialOriginalHandlerHashByTool.get(nameAtVersion);
            if (initialHash && currentHash && currentHash !== initialHash) {
              tool_code_changed = true;
            }
          } catch {}
        }
      } catch {}

      // Resolve effective policy through the configured provider.
      if (!error) {
        try {
          const resolved = await policyProvider.getPolicy({ nodeId });
          const nextHash = resolved.hash;
          if (currentPolicyHash !== nextHash) {
            policyObj = normalizePolicyObject(resolved.policy as any);
            currentPolicyHash = nextHash;
            cachedAgentGuard = null;
            cachedRunContext = null;
          }
          if (!effectiveTenant) effectiveTenant = resolved.tenant;
          if (!effectiveEnv) effectiveEnv = resolved.env;
          if (!effectiveClientName) effectiveClientName = resolved.clientName;
          if (!effectiveClientVersion) effectiveClientVersion = resolved.clientVersion;
        } catch (e: any) {
          decision = "deny";
          violation = "policy_fetch_failed";
          error = new PolicyDeniedError("policy_fetch_failed", e?.message || "policy_fetch_failed");
        }
      }

      let allowMatch: { allowed: boolean; kind: AllowMatchKind } = { allowed: false, kind: null };
      if (!error && !violation) {
        const toolsCfgRaw: any = (policyObj as any)?.tools;
        // No tools section means "no enforcement" (demo-friendly): allow all tools.
        // If tools exists but allowlist is empty, treat it as an intentional "deny all".
        const toolsCfg: any = toolsCfgRaw && typeof toolsCfgRaw === "object" ? toolsCfgRaw : {};
        const allowlist: string[] =
          toolsCfgRaw == null
            ? ["*"]
            : (Array.isArray(toolsCfg.allowlist) ? toolsCfg.allowlist.map(String).filter(Boolean) : []);
        allowMatch = matchAllowlist(allowlist, server.name, nameAtVersion);
        const denyIfUnpinned = !!toolsCfg.deny_if_unpinned_version;
        if (denyIfUnpinned && !isPinned(nameAtVersion)) {
          // Relax unpinned violation if policy allowlist grants versionless or wildcard access
          const relax = allowMatch.allowed && (allowMatch.kind === "versionless" || allowMatch.kind === "wildcard");
          if (!relax) violation = "version_unpinned";
        }
        if (!allowMatch.allowed) {
          violation = "tool_not_in_allowlist";
        }
      }
      // If policy allows, compute version change against previous seen version for this tool base
      if (allowMatch.allowed) {
        const prev = lastVersionByToolBase.get(toolBaseUri);
        if (prev && prev !== currentVersion) {
          version_changed = true;
          previous_version = prev;
        }
      }

      // Build (or reuse) an AgentGuard instance for the current effective policy snapshot.
      const agentGuard = getAgentGuardForCurrentPolicy();
      const runContextConfig =
        cachedRunContext && cachedRunContext.policyHash === currentPolicyHash
          ? cachedRunContext.config
          : null;
      const runContextState =
        runContextConfig
          ? ensureRunContextState(runContextConfig, {
              tenant: effectiveTenant,
              nodeId,
              runId: agentRunId,
              now: Date.now(),
            })
          : null;
      if (runContextState && runContextConfig) {
        const objective = extractObjective(agentVariables, incomingAgentState);
        if (objective) runContextState.objective = objective;
        if (runContextConfig.includeMetadata && !runContextState.metadata) {
          const meta = extractMetadata(incomingAgentState);
          if (meta) runContextState.metadata = meta;
        }
      }

      // Enforce idempotency for side-effecting operations when configured
      if (policyObj.side_effects?.require_idempotency_key && isSideEffecting(nameAtVersion, ctx.args) && !ctx.idempotencyKey) {
        violation = "missing_idempotency_for_side_effect";
      }
      // AP2 embedded enforcement (when running without gateway)
      let ap2IntentId: string | undefined;
      let ap2CartId: string | undefined;
      let ap2ConstraintsSha256: string | undefined;
      let ap2CartSha256: string | undefined;
      let ap2IssuerDid: string | undefined;
      let ap2SubjectDid: string | undefined;
      try {
        const ap2 = (opts as any)?.ap2 || {};
        const isWrite = isSideEffecting(nameAtVersion, ctx.args);
        if (ap2.enabled && ap2.requireForSideEffects && isWrite) {
          const getH = (n: string) => (ctx.headers?.[n] as string) || (ctx.headers?.[n.toLowerCase()] as string) || '';
          const intentRaw = getH(ap2.headers?.intent || 'x-ap2-intent-mandate');
          const cartRaw = getH(ap2.headers?.cart || 'x-ap2-cart-mandate');
          const bundleRaw = getH(ap2.headers?.bundle || 'x-ap2-bundle');
          const rawIntent = intentRaw || ((): string => { try { const b = JSON.parse(bundleRaw||'{}'); return String(b.intent || b.intentMandate || ''); } catch { return ''; } })();
          const rawCart = cartRaw || ((): string => { try { const b = JSON.parse(bundleRaw||'{}'); return String(b.cart || b.cartMandate || ''); } catch { return ''; } })();
          const decodePayload = (s?: string): any | undefined => {
            try { if (!s) return undefined; const j = JSON.parse(s); return j; } catch {}
            try {
              if (!s || s.split('.').length < 2) return undefined;
              const b64 = s.split('.')[1].replace(/-/g,'+').replace(/_/g,'/');
              const pad = b64.length % 4 === 2 ? '==' : (b64.length % 4 === 3 ? '=' : '');
              const json = Buffer.from(b64 + pad, 'base64').toString('utf8');
              return JSON.parse(json);
            } catch { return undefined; }
          };
          const canon = (o: any): string => {
            const seen = new WeakSet();
            const sort = (v: any): any => { if (v===null || typeof v!=='object') return v; if (seen.has(v)) return null; seen.add(v); if (Array.isArray(v)) return v.map(sort); const out: any = {}; Object.keys(v).sort().forEach(k=>out[k]=sort(v[k])); return out; };
            return JSON.stringify(sort(o));
          };
          const sha256HexLocal = (buf: Buffer) => { try { return require('node:crypto').createHash('sha256').update(buf).digest('hex'); } catch { return ''; } };
          const intent = decodePayload(rawIntent);
          const cart = decodePayload(rawCart);
          if (!cart) {
            violation = (violation as any) || 'ap2_mandate_missing';
          } else {
            ap2IntentId = (intent?.jti || intent?.id) ? String(intent.jti || intent.id) : undefined;
            ap2CartId = (cart?.jti || cart?.id) ? String(cart.jti || cart.id) : undefined;
            ap2IssuerDid = (cart?.iss || cart?.issuer) ? String(cart.iss || cart.issuer) : undefined;
            ap2SubjectDid = (cart?.sub || cart?.subject) ? String(cart.sub || cart.subject) : undefined;
            ap2ConstraintsSha256 = intent?.constraints ? sha256HexLocal(Buffer.from(canon(intent.constraints))) : undefined;
            ap2CartSha256 = sha256HexLocal(Buffer.from(canon(cart)));
            // Idempotency binding check if available
            const idem = String(ctx.idempotencyKey || '');
            if (!idem) {
              violation = (violation as any) || 'ap2_idempotency_missing';
            } else if (ap2CartSha256 && idem !== ap2CartSha256) {
              violation = (violation as any) || 'ap2_idempotency_mismatch';
            }
          }
        }
      } catch {}

      // Security: enforce payload cap before execution if configured
      const sec: SecurityConfigLike = (policyObj as any).security || {};
      if (sec?.limits?.max_payload_kb && estimateSizeKb((ctx as any)?.args) > sec.limits.max_payload_kb) {
        violation = "payload_too_large";
      }

      // Minimal circuit breaker: deny if thresholds exceeded in last WINDOW invocations
      try {
        const errPct = calcErrorRate(nameAtVersion);
        const p95 = calcP95(nameAtVersion);
        const br = policyObj.enforcement?.circuit_breakers;
        const samples = (recentByTool.get(nameAtVersion) ?? []).length;
        const minSamplesRaw = (br as any)?.min_samples ?? (br as any)?.minSamples;
        const minSamples =
          (typeof minSamplesRaw === "number" && Number.isFinite(minSamplesRaw) && minSamplesRaw > 0)
            ? Math.floor(minSamplesRaw)
            : 20;
        const brErr = (br as any)?.error_rate_pct;
        const brP95 = (br as any)?.p95_latency_ms;
        const openByErr = brErr !== undefined && errPct >= brErr;
        const openByP95 = brP95 !== undefined && p95 >= brP95;
        const shouldEvaluate = Boolean(br && samples >= minSamples);
        const shouldOpen = Boolean(shouldEvaluate && (openByErr || openByP95));
        if (shouldOpen) {
          addAttrs({ "circuit.open": true, "circuit.err_pct": errPct, "circuit.p95_ms": p95 });
          const e = new Error("CIRCUIT_OPEN");
          (e as any).code = "CIRCUIT_OPEN";
          throw e;
        }
      } catch (preErr: any) {
        if (!error) {
          error = preErr instanceof Error ? preErr : new Error(String(preErr));
        }
      }

      await context.with(activeCtx, async () => {
        try {
          inputHash = ctx?.args ? sha256Hex(Buffer.from(JSON.stringify(ctx.args))) : null;
          // Determine registry mutation and server snapshot drift
          registry_mutation = !!registryMutationAttempted;
          try {
            const nowParts: string[] = [];
            for (const [k, v] of server.__getTools ? server.__getTools() : tools) {
              // Note: after wrapping, v will be the wrapped function; we still detect swaps via tag
              const id = (v as any).__sec0_wrapper__ && (v as any).__sec0_handler_hash ? `${k}:${(v as any).__sec0_handler_hash}` : `${k}:${functionCodeHash(v)}`;
              nowParts.push(id);
            }
            const nowHash = sha256Hex(Buffer.from(nowParts.sort().join("|")));
            if (nowHash !== initialServerSnapshotHash) server_code_changed = true;
          } catch {}
          if (violation) {
            decision = "deny";
            if (await shouldRuntimeDeny([violation], { requestIdSuffix: "pre-handler-violation" })) {
              // Fire webhook alert if configured
              if (policyWebhookUrl) {
                try {
                  fireAndForgetPolicyWebhookEvent(policyWebhookUrl, {
                    event: "policy.denied",
                    tenant: opts.otel.tenant,
                    server: server.name,
                    tool: nameAtVersion,
                    violation,
                    timestamp: new Date().toISOString(),
                  });
                } catch {}
              }
              throw new PolicyDeniedError(violation);
            }
          }

          if (
            !error &&
            contextualEvaluatorManager?.enabled &&
            (!violation || violation === "agent_guard_failed")
          ) {
            const op = inferOp(nameAtVersion, (ctx as any)?.args);
            const defaultEvaluatorInput = buildDefaultMiddlewareEvaluatorInput({
              tenant: effectiveTenant,
              server: { name: server.name, version: server.version },
              tool: nameAtVersion,
              toolRef: toolUri(server.name, nameAtVersion),
              op,
              ctx,
              nodeId: nodeId || undefined,
              agentRunId: agentRunId || undefined,
              objective: extractObjective(agentVariables, incomingAgentState),
              identity: identityContext,
            });
            const detectorPatch = buildDetectorContextEvaluatorPatch({
              findings: agent_findings,
              violation,
              content: (ctx as any)?.args,
            });
            const inlineOverride = extractInlineEvaluatorContext(ctx);
            let callbackOverride: EvaluatorInputPatch | null | undefined = null;
            if (opts.contextualEvaluator?.buildContext) {
              try {
                callbackOverride = await Promise.resolve(
                  opts.contextualEvaluator.buildContext({
                    tenant: effectiveTenant,
                    server: { name: server.name, version: server.version },
                    tool: nameAtVersion,
                    toolRef: toolUri(server.name, nameAtVersion),
                    op,
                    ctx,
                    nodeId: nodeId || undefined,
                    agentRunId: agentRunId || undefined,
                    policy: policyObj as PolicyObject,
                    objective: extractObjective(agentVariables, incomingAgentState),
                    identity: identityContext,
                    explicitReasons: violation ? [violation] : [],
                    defaultInput: defaultEvaluatorInput,
                  }),
                );
              } catch (builderError: any) {
                console.warn(
                  "[sec0-evaluator] middleware buildContext failed",
                  builderError instanceof Error ? builderError.message : String(builderError || "unknown"),
                );
              }
            }
            const evaluatorInput = mergeEvaluatorInput(
              mergeEvaluatorInput(
                mergeEvaluatorInput(defaultEvaluatorInput, detectorPatch),
                inlineOverride,
              ),
              callbackOverride,
            );
            const eligible = opts.contextualEvaluator?.eligible
              ? opts.contextualEvaluator.eligible({
                  server: { name: server.name, version: server.version },
                  tool: nameAtVersion,
                  toolRef: toolUri(server.name, nameAtVersion),
                  op,
                  ctx,
                  nodeId: nodeId || undefined,
                  agentRunId: agentRunId || undefined,
                  policy: policyObj as PolicyObject,
                  explicitReasons: violation ? [violation] : [],
                  input: evaluatorInput,
                })
              : defaultContextualEvaluatorEligible(evaluatorInput);
            addAttrs({
              "evaluator.source": contextualEvaluatorManager.source,
              "evaluator.mode": contextualEvaluatorManager.mode,
              "evaluator.eligible": eligible,
            });
            if (eligible) {
              if (contextualEvaluatorManager.mode === "async") {
                contextualEvaluatorManager.schedule(evaluatorInput);
              } else {
                const evaluation = await contextualEvaluatorManager.evaluate(evaluatorInput);
                if (evaluation) {
                  contextualEvaluatorFinding = evaluation.finding;
                  addAttrs({
                    "evaluator.decision": evaluation.output.decision,
                    "evaluator.confidence": evaluation.output.confidence,
                    "evaluator.principles": evaluation.output.principles.join(","),
                  });
                  const contextualDecisionViolation =
                    evaluation.output.decision === "deny"
                      ? "contextual_evaluator_denied"
                      : evaluation.output.decision === "escalate"
                        ? "contextual_evaluator_escalated"
                        : null;
                  const adjudicated = resolveDetectorContextualViolation({
                    violation,
                    findings: agent_findings,
                    contextualDecision: evaluation.output.decision,
                    contextualFingerprint: evaluation.finding.fingerprint,
                  });
                  if (adjudicated.findings.length) {
                    agent_findings = adjudicated.findings;
                  }
                  violation = adjudicated.violation as PolicyViolation | null;
                  contextualEvaluatorViolation = contextualDecisionViolation;
                  if (evaluation.output.decision !== "allow") {
                    contextualAgentFindings = [
                      mapContextualEvaluatorFindingToAgentFinding(evaluation.finding, "run"),
                    ];
                    if (
                      await shouldRuntimeDeny(
                        [
                          violation &&
                          (violation !== contextualDecisionViolation || policyDeniesReason(violation))
                            ? violation
                            : null,
                          contextualDecisionViolation && policyDeniesReason(contextualDecisionViolation)
                            && contextualDecisionViolation !== violation
                            ? contextualDecisionViolation
                            : null,
                        ].filter(Boolean) as string[],
                        {
                        requestIdSuffix: "contextual-evaluator",
                        },
                      )
                    ) {
                      violation = violation || contextualDecisionViolation;
                      decision = "deny";
                      error = new PolicyDeniedError(
                        (violation || contextualDecisionViolation) as PolicyViolation,
                      );
                    }
                  }
                  if (
                    contextualEvaluatorManager.mode === "hybrid" &&
                    contextualEvaluatorManager.source === "control-plane"
                  ) {
                    contextualEvaluatorManager.schedule(evaluatorInput);
                  }
                }
              }
            }
          }

          if (
            !error &&
            violation === "agent_guard_failed" &&
            (await shouldRuntimeDeny(["agent_guard_failed"], { requestIdSuffix: "agent-guard-input" }))
          ) {
            const approval = await verifyApprovalIfAny();
            if (approval && approval.valid) {
              try { addAttrs({ "agent_guard.approved": true, "agent_guard.approval_id": approval?.approval?.id || "" }); } catch {}
            } else {
              decision = "deny";
              error = new PolicyDeniedError("agent_guard_failed");
            }
          }

          if (!error) {
            // Run the tool handler with in-process I/O guards (egress/fs/subprocess)
            result = await withGuardedIO(sec, async () => Promise.resolve(handler(ctx)));
            outputHash = result != null ? sha256Hex(Buffer.from(JSON.stringify(result))) : null;
            // On successful call and when allowed by policy, update last seen version
            if (allowMatch.allowed) {
              lastVersionByToolBase.set(toolBaseUri, currentVersion);
            }
          }
        } catch (e: any) {
          // Map guard errors to policy violations for enforcement
          const code = (e && typeof e === "object") ? (e as any).code : undefined;
          if (code === "egress_violation" || code === "fs_violation" || code === "subprocess_blocked") {
            violation = code as PolicyViolation;
            decision = "deny";
            if (await shouldRuntimeDeny([violation], { requestIdSuffix: "guard-violation" })) {
              error = new PolicyDeniedError(violation);
            } else {
              error = e;
            }
          } else {
            error = e;
          }
        } finally {
          // end handled below
        }
      });

      {
        const latency = Date.now() - start;
        // Compute risk tags and contextual info (non-enforcing here; enforcement happens upstream when configured)
        const risk_tags: string[] = [];
        let decision_reason: string | undefined = undefined;
        let egress_domain: string | undefined = undefined;
        let fs_path: string | undefined = undefined;

        // Map policy violation to decision_reason
        if (violation) {
          decision_reason = violation;
          risk_tags.push(violation);
        } else if (contextualEvaluatorViolation) {
          risk_tags.push(contextualEvaluatorViolation);
        }
        // Optional security checks from policy
        const sec = (policyObj as any).security || {};
        const ap2CtrlPolicyTop = (policyObj as any).security?.ap2;
        const matchAny = (value: string, patterns?: string[]): boolean => {
          if (!patterns || patterns.length === 0) return true;
          return patterns.some((p) => {
            const esc = p.replace(/[.+^${}()|\[\]\\]/g, "\\$&").replace(/\*/g, ".*?");
            try { return new RegExp(`^${esc}$`, 'i').test(value); } catch { return true; }
          });
        };
        const estimateKb = (obj: unknown): number => { try { return Math.ceil(Buffer.byteLength(JSON.stringify(obj||{}),'utf8')/1024); } catch { return 0; } };
        const lowerTool = nameAtVersion.toLowerCase();
        // egress
        const urlStr = typeof (ctx as any)?.args?.url === 'string' ? (ctx as any).args.url : undefined;
        try { if (urlStr) { const u = new URL(urlStr); egress_domain = u.hostname; } } catch {}
        if (urlStr && sec.egress_allowlist && !matchAny(urlStr, sec.egress_allowlist)) {
          risk_tags.push('egress_violation');
        }
        // fs
        fs_path = typeof (ctx as any)?.args?.path === 'string' ? (ctx as any).args.path : undefined;
        if (fs_path && sec.fs_allowlist && !matchAny(fs_path, sec.fs_allowlist)) {
          risk_tags.push('fs_violation');
        }
        // payload size
        if (sec?.limits?.max_payload_kb && estimateKb((ctx as any)?.args) > sec.limits.max_payload_kb) {
          risk_tags.push('payload_too_large');
        }

        const ap2CtrlPolicyLocal: Ap2Config | undefined = ap2CtrlPolicyTop;
        const ap2Allow = Array.isArray(ap2CtrlPolicyLocal?.tools?.allow) ? ap2CtrlPolicyLocal.tools.allow : [];
        const legacyRequireFlag = (ap2CtrlPolicyLocal as any)?.require_for_side_effects;
        const requireForSideEffects = ap2CtrlPolicyLocal?.requireForSideEffects ?? legacyRequireFlag;
        const shouldEnforcePolicyAp2 = (() => {
          if (!ap2CtrlPolicyLocal || ap2CtrlPolicyLocal.enabled === false) return false;
          if (ap2Allow.length) return ap2Allow.some((pattern: string) => matchesToolPattern(pattern, server.name, nameAtVersion));
          return requireForSideEffects !== false && isSideEffecting(nameAtVersion, ctx.args);
        })();

        const forwardedCartDigest = readHeaderCaseInsensitive(ctx.headers as any, AP2_CART_DIGEST_HEADER);
        const forwardedIntentMandate = readHeaderCaseInsensitive(ctx.headers as any, (ap2CtrlPolicyLocal?.headers?.intent) || 'x-ap2-intent-mandate');
        const forwardedCartMandate = readHeaderCaseInsensitive(ctx.headers as any, (ap2CtrlPolicyLocal?.headers?.cart) || 'x-ap2-cart-mandate');
        const forwardedBundle = readHeaderCaseInsensitive(ctx.headers as any, (ap2CtrlPolicyLocal?.headers?.bundle) || 'x-ap2-bundle');
        const shouldVerifyAp2Hop = Boolean(
          forwardedCartDigest ||
          forwardedIntentMandate ||
          forwardedCartMandate ||
          forwardedBundle ||
          shouldEnforcePolicyAp2
        );

        if (shouldVerifyAp2Hop) {
          let ap2HopViolation: string | undefined;
          if (forwardedCartDigest) {
            const digestCheck = compareArgsToDigest(forwardedCartDigest, (ctx as any)?.args);
            if (!digestCheck.ok) {
              ap2HopViolation = digestCheck.reason || 'ap2_cart_mismatch';
            }
          }
          if (!ap2HopViolation) {
            const verification = await verifyAp2MandatesFromHeaders(ap2CtrlPolicyLocal, ctx.headers as any, ctx.args);
            if (!verification.ok) {
              ap2HopViolation = verification.reason || 'ap2_verification_error';
            } else {
              if (verification.constraintsDigest) {
                if (!ctx.headers) ctx.headers = {};
                ctx.headers[AP2_CONSTRAINTS_DIGEST_HEADER] = verification.constraintsDigest;
              }
              if (verification.cartDigest) {
                if (!ctx.headers) ctx.headers = {};
                ctx.headers[AP2_CART_DIGEST_HEADER] = verification.cartDigest;
              }
            }
          }
          if (ap2HopViolation) {
            risk_tags.push(ap2HopViolation);
            violation = (violation as any) || ap2HopViolation;
          }
        }
        // Version/change and registry signals
        if (version_changed) {
          risk_tags.push('tool_version_changed');
          addAttrs({ "tool.version.prev": previous_version ?? "", "tool.version.new": currentVersion });
          // Fire optional webhook alert
          if (policyWebhookUrl) {
            try {
              fireAndForgetPolicyWebhookEvent(policyWebhookUrl, {
                event: "tool.version_changed",
                tenant: opts.otel.tenant,
                server: server.name,
                tool_base: toolBaseUri,
                previous_version: previous_version,
                new_version: currentVersion,
                timestamp: new Date().toISOString(),
              });
            } catch {}
          }
        }
        if (server_code_changed) {
          risk_tags.push('server_code_changed');
          if (await shouldRuntimeDeny(['server_code_changed'], { requestIdSuffix: 'server-code-changed' })) {
            decision = 'deny';
            error = new PolicyDeniedError('server_code_changed');
          }
        }
        if (tool_code_changed) {
          risk_tags.push('tool_code_changed');
          if (await shouldRuntimeDeny(['tool_code_changed'], { requestIdSuffix: 'tool-code-changed' })) {
            decision = 'deny';
            error = new PolicyDeniedError('tool_code_changed');
          }
        }
        if (registry_mutation) {
          risk_tags.push('registry_mutation');
          if (await shouldRuntimeDeny(['registry_mutation'], { requestIdSuffix: 'registry-mutation' })) {
            decision = 'deny';
            error = new PolicyDeniedError('registry_mutation');
          }
        }
        if (handler_swap_detected) {
          risk_tags.push('handler_swap');
          if (await shouldRuntimeDeny(['handler_swap'], { requestIdSuffix: 'handler-swap' })) {
            decision = 'deny';
            error = new PolicyDeniedError('handler_swap');
          }
        }

        // Agent Guard: scan inputs for prompt/PII/secrets/commands (pre)
        try {
          agent_findings = await agentGuard.scanInput((ctx as any)?.args);
          if (contextualAgentFindings.length) {
            agent_findings = [...contextualAgentFindings, ...(agent_findings || [])];
          }
          if (runContextState && runContextConfig) {
            const entry = buildRunEvent("input", nameAtVersion, (ctx as any)?.args, runContextConfig);
            if (entry) appendRunEvent(runContextState, entry, runContextConfig);
            const runText = buildRunContextText(runContextState, runContextConfig);
            const runFindings = await agentGuard.scanRun(runText);
            if (runFindings && runFindings.length) {
              agent_findings = [...(agent_findings || []), ...runFindings];
            }
          }
          if (agent_findings && agent_findings.length) {
            agent_findings = dedupeFindings(agent_findings);
          }
          const agBlock = agentGuard.shouldBlock(agent_findings || []);
          const deferInputAgentGuardDecision = agBlock.block && contextualEvaluatorManager?.enabled;
          if (!violation && agBlock.block) {
            violation = 'agent_guard_failed';
          }
          if (
            agBlock.block &&
            !deferInputAgentGuardDecision &&
            (await shouldRuntimeDeny(['agent_guard_failed'], { requestIdSuffix: 'agent-guard-input' }))
          ) {
            const approval = await verifyApprovalIfAny();
            if (approval && approval.valid) {
              try { addAttrs({ "agent_guard.approved": true, "agent_guard.approval_id": approval?.approval?.id || "" }); } catch {}
              risk_tags.push('agent_guard_approved');
              // Annotate policy-violation findings so the UI can show justification in Run D.
              try {
                const approvalId = typeof approval?.approval?.id === "string" ? approval.approval.id : "";
                const approvalReason = typeof approval?.approval?.reason === "string" ? approval.approval.reason : "";
                const suffix = approvalId ? `approved=true approval_id=${approvalId}` : "approved=true";
                agent_findings = (agent_findings || []).map((f: any) => {
                  if (!f || f.code !== "agent_policy_violation") return f;
                  const msg = typeof f.message === "string" && f.message.includes("approved") ? f.message : `${f.message} (approved)`;
                  const evBase = typeof f.evidence === "string" && f.evidence.trim() ? f.evidence.trim() : "";
                  const ev = [evBase, suffix, (approvalReason ? `reason=${String(approvalReason).slice(0, 160)}` : "")].filter(Boolean).join("; ").slice(0, 480);
                  const tags = Array.isArray(f.tags) ? [...f.tags] : [];
                  if (approvalId) tags.push(`approval_id:${approvalId}`);
                  return { ...f, message: msg, evidence: ev, tags };
                });
              } catch {}
            } else {
              decision = 'deny';
              error = new PolicyDeniedError('agent_guard_failed');
              risk_tags.push('agent_guard_failed');
              // Ensure denials surface with a stable reason in audit + posture UI.
              violation = 'agent_guard_failed';
              if (!decision_reason) decision_reason = 'agent_guard_failed';
            }
          }
        } catch {}

        // SAST: trigger on code change or (optionally) first invocation
        if (sastEnabled) {
          try {
            const currentFn = server.__getTools?.().get(nameAtVersion) || handler;
            const handlerHash = (currentFn as any)?.__sec0_handler_hash || functionCodeHash(currentFn);
            const meta: Sec0Meta | undefined = getSec0Meta(currentFn);
            // Allow policy to require scans only when code changes (skip first-invocation scan)
            const runOnChangeOnly = !!(policySast as any)?.scan_on_change_only;
            const shouldRunNow = (tool_code_changed || server_code_changed) || (!runOnChangeOnly && !sast.getCached(handlerHash));
            if (!shouldRunNow) {
              // Skip scan this invocation; no change and not first-invocation mode
            } else {
              // Prefer metadata from the actual tool handler; fallback to wrapped function
              const metaEff = meta || getSec0Meta(handler);
              const filePath = toolFilePathByKey.get(nameAtVersion) || metaEff?.filePath;
              const debugUsingPath = (p?: string) => {
                if (!debugSastEnabled) return;
                try {
                  console.log('[sec0-middleware][sast] using filePath', { tool: nameAtVersion, filePath: p || null });
                } catch {}
              };
              debugUsingPath(filePath);
              let blockEval: { block: boolean; reason?: string } = { block: false };
              if (filePath) {
                // Scan the whole file once and attribute findings to the tool span
                if (!spansByFilePath.has(filePath)) spansByFilePath.set(filePath, computeToolSpans(filePath));
                const fileRes = await scanFileIfNeeded(filePath, { name: server.name, version: server.version });
                sast_status = fileRes.status;
                didSast = true;
                const spans = spansByFilePath.get(filePath) || [];
                const span = spans.find(s => s.tool === nameAtVersion);
                let attributed: any[] = [];
                if (span) {
                  attributed = (fileRes.findings || []).filter((f: any) => {
                    const ln = Number((f && (f.startLine ?? f.start?.line)) || 0);
                    const fileOk = !f.file || String(f.file).endsWith(filePath);
                    return fileOk && ln >= span.startLine && ln <= span.endLine;
                  });
                }
                if (attributed.length) {
                  const max = maxSeverityOf(attributed as any);
                  if (max) addAttrs({ "sast.max_severity": max });
                  sast_findings = attributed as any;
                }
                sast_scan_id = fileRes.scanId;
                if ((fileRes as any).raw && !(fileRes as any).raw_key) {
                  const key = await persistScanRawIfConfigured({
                    tenant: opts.otel?.tenant,
                    level: 'middleware',
                    kind: 'sast',
                    scanId: fileRes.scanId || handlerHash.slice(0,12),
                    raw: (fileRes as any).raw,
                    uploadConfig: requireUploadConfig()
                  });
                  if (key) { (fileRes as any).raw_key = key; sast_raw_key = key; }
                }
                // Use SastManager's block logic against the attributed findings by constructing a pseudo cache entry
                const pseudo = { status: fileRes.status, findings: attributed } as any;
                blockEval = sast.shouldBlock(pseudo, opts.sast?.block_on_change, opts.sast?.block_on_severity);
              } else {
                // Fallback: scan handler source (temp file path inside semgrep.ts)
                const cached = sast.ensureScan(handlerHash, {
                  server: { name: server.name, version: server.version },
                  tool: nameAtVersion,
                  handlerHash,
                  source: Function.prototype.toString.call(handler)
                });
                if (cached.status === 'pending') {
                  const res = await semgrepOnScan({ server: { name: server.name, version: server.version }, tool: nameAtVersion, handlerHash, source: Function.prototype.toString.call(handler) });
                  (cached as any).status = res.status; (cached as any).findings = res.findings; (cached as any).scanId = res.scanId; (cached as any).raw = res.raw; (cached as any).updatedAt = Date.now();
                }
                sast_status = cached.status;
                didSast = true;
                if (cached.findings && cached.findings.length) {
                  const max = maxSeverityOf(cached.findings as any);
                  if (max) addAttrs({ "sast.max_severity": max });
                  sast_findings = cached.findings as any;
                }
                sast_scan_id = cached.scanId;
                if ((cached as any).raw && !cached.raw_key) {
                  const key = await persistScanRawIfConfigured({
                    tenant: opts.otel?.tenant,
                    level: 'middleware',
                    kind: 'sast',
                    scanId: cached.scanId || handlerHash.slice(0,12),
                    raw: (cached as any).raw,
                    uploadConfig: requireUploadConfig()
                  });
                  if (key) { (cached as any).raw_key = key; sast_raw_key = key; }
                }
                blockEval = sast.shouldBlock(cached, opts.sast?.block_on_change, opts.sast?.block_on_severity);
              }
              if (blockEval.block) {
                decision = 'deny';
                error = new PolicyDeniedError('tool_code_changed');
                risk_tags.push(blockEval.reason || 'sast_block');
              }
            }
          } catch {}
        }

        // DAST: trigger on code change or (optionally) first invocation, and apply dynamic blocking
        if (dastEnabled) {
          try {
            const activeDast = dast;
            if (!activeDast) throw new Error("[sec0-middleware] DAST manager not initialized");
            const currentFn = server.__getTools?.().get(nameAtVersion) || handler;
            const handlerHash = (currentFn as any)?.__sec0_handler_hash || functionCodeHash(currentFn);
            const effectiveScope = ((opts.dast as any)?.scope) || ((policyDast as any)?.scope) || 'tool';
            let scopeKey = handlerHash;
            if (effectiveScope === 'server') {
              // Use server snapshot hash as scope key to run once per server version
              scopeKey = initialServerSnapshotHash;
            }
            // Allow policy to require scans only when code changes (skip first-invocation scan)
            const runOnChangeOnlyDast = !!(policyDast as any)?.scan_on_change_only;
            const shouldRunDast = (tool_code_changed || server_code_changed) || (!runOnChangeOnlyDast && !activeDast.getCached(scopeKey));
            const runMeta = { server: { name: server.name, version: server.version }, tool: nameAtVersion, handlerHash: scopeKey, sandboxUrl: computedSandboxUrl } as const;
            const effectiveDastMode = ((opts.dast as any)?.mode) || ((policyDast as any)?.mode);
            const cachedD = shouldRunDast
              ? (effectiveDastMode === 'sync' ? await activeDast.ensureScanSync(scopeKey, runMeta) : activeDast.ensureScan(scopeKey, runMeta))
              : (activeDast.getCached(scopeKey) as any);
            if (debugDastEnabled) {
              try {
                console.log('[sec0-middleware][dast] result', { tool: nameAtVersion, mode: effectiveDastMode || 'async', status: cachedD?.status, findings: (cachedD?.findings || []).length });
              } catch {}
            }
            // Always reflect latest cached status/findings (even if we didn't trigger a new scan)
            if (cachedD) {
              dast_status = cachedD.status;
              didDast = true;
              if (cachedD.findings && cachedD.findings.length) {
                dast_findings = cachedD.findings;
              }
              dast_scan_id = cachedD.scanId;
              if ((cachedD as any).raw && (!cachedD.raw_key || forceDastRawUpload)) {
                const key = await persistScanRawIfConfigured({
                  tenant: opts.otel?.tenant,
                  level: 'middleware',
                  kind: 'dast',
                  scanId: cachedD.scanId || handlerHash.slice(0,12),
                  raw: (cachedD as any).raw,
                  uploadConfig: requireUploadConfig()
                });
                if (key) { (cachedD as any).raw_key = key; dast_raw_key = key; }
              }
              const blockD = activeDast.shouldBlock(cachedD, opts.dast?.block_on_change, opts.dast?.block_on_severity, opts.dast?.block_on_count);
              if (blockD.block) {
                decision = 'deny';
                error = new PolicyDeniedError('tool_code_changed');
                risk_tags.push(blockD.reason || 'dast_block');
                if (opts.dast?.rule_ttl_ms && blockD.reason === 'dast_failed') {
                  activeDast.setDynamicBlock(nameAtVersion);
                }
              }
            }
          } catch {}
        }

        // Apply dynamic runtime block if active
        if (dastEnabled && dast?.isDynamicallyBlocked(nameAtVersion)) {
          decision = 'deny';
          error = new PolicyDeniedError('tool_code_changed');
          risk_tags.push('dast_dynamic_rule');
        }

        // Agent Guard: scan outputs (post)
        try {
          const postFindings = await agentGuard.scanOutput(result);
          agent_findings = [...(agent_findings || []), ...(postFindings || [])];
          if (runContextState && runContextConfig) {
            const entry = buildRunEvent("output", nameAtVersion, result, runContextConfig);
            if (entry) appendRunEvent(runContextState, entry, runContextConfig);
            const runText = buildRunContextText(runContextState, runContextConfig);
            const runFindings = await agentGuard.scanRun(runText);
            if (runFindings && runFindings.length) {
              agent_findings = [...(agent_findings || []), ...runFindings];
            }
          }
          if (agent_findings && agent_findings.length) {
            agent_findings = dedupeFindings(agent_findings);
          }
          const agBlock = agentGuard.shouldBlock(agent_findings || []);
          let outputViolation: PolicyViolation | null = agBlock.block ? "agent_guard_failed" : null;
          if (
            contextualEvaluatorManager?.enabled &&
            agent_findings &&
            agent_findings.length > 0 &&
            (!violation || violation === "agent_guard_failed")
          ) {
            const op = inferOp(nameAtVersion, (ctx as any)?.args);
            const defaultEvaluatorInput = buildDefaultMiddlewareEvaluatorInput({
              tenant: effectiveTenant,
              server: { name: server.name, version: server.version },
              tool: nameAtVersion,
              toolRef: toolUri(server.name, nameAtVersion),
              op,
              ctx,
              nodeId: nodeId || undefined,
              agentRunId: agentRunId || undefined,
              objective: extractObjective(agentVariables, incomingAgentState),
              identity: identityContext,
            });
            const detectorPatch = buildDetectorContextEvaluatorPatch({
              findings: agent_findings,
              violation: outputViolation,
              content: result,
            });
            const inlineOverride = extractInlineEvaluatorContext(ctx);
            let callbackOverride: EvaluatorInputPatch | null | undefined = null;
            if (opts.contextualEvaluator?.buildContext) {
              try {
                callbackOverride = await Promise.resolve(
                  opts.contextualEvaluator.buildContext({
                    tenant: effectiveTenant,
                    server: { name: server.name, version: server.version },
                    tool: nameAtVersion,
                    toolRef: toolUri(server.name, nameAtVersion),
                    op,
                    ctx,
                    nodeId: nodeId || undefined,
                    agentRunId: agentRunId || undefined,
                    policy: policyObj as PolicyObject,
                    objective: extractObjective(agentVariables, incomingAgentState),
                    identity: identityContext,
                    explicitReasons: outputViolation ? [outputViolation] : [],
                    defaultInput: defaultEvaluatorInput,
                  }),
                );
              } catch (builderError: any) {
                console.warn(
                  "[sec0-evaluator] middleware buildContext failed",
                  builderError instanceof Error ? builderError.message : String(builderError || "unknown"),
                );
              }
            }
            const evaluatorInput = mergeEvaluatorInput(
              mergeEvaluatorInput(
                mergeEvaluatorInput(defaultEvaluatorInput, detectorPatch),
                inlineOverride,
              ),
              callbackOverride,
            );
            const eligible = opts.contextualEvaluator?.eligible
              ? opts.contextualEvaluator.eligible({
                  server: { name: server.name, version: server.version },
                  tool: nameAtVersion,
                  toolRef: toolUri(server.name, nameAtVersion),
                  op,
                  ctx,
                  nodeId: nodeId || undefined,
                  agentRunId: agentRunId || undefined,
                  policy: policyObj as PolicyObject,
                  explicitReasons: outputViolation ? [outputViolation] : [],
                  input: evaluatorInput,
                })
              : defaultContextualEvaluatorEligible(evaluatorInput);
            if (eligible) {
              let evaluation = null as Awaited<ReturnType<typeof contextualEvaluatorManager.evaluate>>;
              if (contextualEvaluatorManager.mode === "async") {
                contextualEvaluatorManager.schedule(evaluatorInput);
              } else {
                evaluation = await contextualEvaluatorManager.evaluate(evaluatorInput);
              }
              if (evaluation) {
                contextualEvaluatorFinding = evaluation.finding;
                addAttrs({
                  "evaluator.decision": evaluation.output.decision,
                  "evaluator.confidence": evaluation.output.confidence,
                  "evaluator.principles": evaluation.output.principles.join(","),
                });
                const contextualDecisionViolation =
                  evaluation.output.decision === "deny"
                    ? "contextual_evaluator_denied"
                    : evaluation.output.decision === "escalate"
                      ? "contextual_evaluator_escalated"
                      : null;
                const adjudicated = resolveDetectorContextualViolation({
                  violation: outputViolation,
                  findings: agent_findings,
                  contextualDecision: evaluation.output.decision,
                  contextualFingerprint: evaluation.finding.fingerprint,
                });
                agent_findings = adjudicated.findings.length ? adjudicated.findings : agent_findings;
                outputViolation = adjudicated.violation as PolicyViolation | null;
                contextualEvaluatorViolation = contextualDecisionViolation || contextualEvaluatorViolation;
                if (evaluation.output.decision !== "allow") {
                  contextualAgentFindings = [
                    mapContextualEvaluatorFindingToAgentFinding(evaluation.finding, "run"),
                  ];
                  if (contextualAgentFindings.length) {
                    agent_findings = [...(agent_findings || []), ...contextualAgentFindings];
                  }
                }
                if (
                  contextualEvaluatorManager.mode === "hybrid" &&
                  contextualEvaluatorManager.source === "control-plane"
                ) {
                  contextualEvaluatorManager.schedule(evaluatorInput);
                }
              }
            }
          }
          if (!violation && outputViolation) {
            violation = outputViolation;
          }
          const outputEnforcementReasons = [
            outputViolation &&
            (outputViolation !== contextualEvaluatorViolation || policyDeniesReason(outputViolation))
              ? outputViolation
              : null,
            contextualEvaluatorViolation && policyDeniesReason(contextualEvaluatorViolation)
              && contextualEvaluatorViolation !== outputViolation
              ? contextualEvaluatorViolation
              : null,
          ].filter(Boolean) as string[];
          if (
            outputEnforcementReasons.length > 0 &&
            (await shouldRuntimeDeny(outputEnforcementReasons, { requestIdSuffix: "agent-guard-output" }))
          ) {
            const approval = await verifyApprovalIfAny();
            if (approval && approval.valid) {
              try { addAttrs({ "agent_guard.approved": true, "agent_guard.approval_id": approval?.approval?.id || "" }); } catch {}
              risk_tags.push('agent_guard_approved');
              try {
                const approvalId = typeof approval?.approval?.id === "string" ? approval.approval.id : "";
                const approvalReason = typeof approval?.approval?.reason === "string" ? approval.approval.reason : "";
                const suffix = approvalId ? `approved=true approval_id=${approvalId}` : "approved=true";
                agent_findings = (agent_findings || []).map((f: any) => {
                  if (!f || f.code !== "agent_policy_violation") return f;
                  const msg = typeof f.message === "string" && f.message.includes("approved") ? f.message : `${f.message} (approved)`;
                  const evBase = typeof f.evidence === "string" && f.evidence.trim() ? f.evidence.trim() : "";
                  const ev = [evBase, suffix, (approvalReason ? `reason=${String(approvalReason).slice(0, 160)}` : "")].filter(Boolean).join("; ").slice(0, 480);
                  const tags = Array.isArray(f.tags) ? [...f.tags] : [];
                  if (approvalId) tags.push(`approval_id:${approvalId}`);
                  return { ...f, message: msg, evidence: ev, tags };
                });
              } catch {}
            } else {
              const finalViolation = (outputViolation || contextualEvaluatorViolation || "agent_guard_failed") as PolicyViolation;
              decision = 'deny';
              error = new PolicyDeniedError(finalViolation);
              risk_tags.push(finalViolation);
              // Ensure denials surface with a stable reason in audit + posture UI.
              violation = finalViolation;
              if (!decision_reason) decision_reason = finalViolation;
            }
          }
        } finally {
          if (!agent_findings && contextualAgentFindings.length) {
            agent_findings = [...contextualAgentFindings];
          }
        }

        // Agent Guard: persist raw findings for full custody
        if (agent_findings && agent_findings.length) {
          const agScanId = (() => {
            try {
              // IMPORTANT: When OTEL is disabled, some span implementations return an all-zero traceId.
              // Using that would cause scan uploads to overwrite the same object key (e.g. 000000000000.json),
              // which fails under WORM/retention buckets. Prefer the normalized traceId, and if unavailable
              // generate a fresh one so every scan artifact key is unique.
              const t = normalizeTraceId(spanCtx?.traceId) || generateTraceId();
              return t;
            } catch {
              return generateTraceId();
            }
          })();
          const key = await persistScanRawIfConfigured({
            tenant: opts.otel?.tenant,
            level: 'middleware',
            kind: 'agent_guard_findings',
            scanId: agScanId,
            raw: {
              tenant: opts.otel?.tenant,
              server: { name: server.name, version: server.version },
              tool: nameAtVersion,
              input_sha256: inputHash,
              output_sha256: outputHash,
              findings: agent_findings
            },
            uploadConfig: requireUploadConfig()
          });
          if (key) agent_guard_raw_key = key;
        }

        // Hierarchy and check kind classification
        const check_level = 'middleware';
        const check_kind = (version_changed || server_code_changed || handler_swap_detected || registry_mutation) ? 'dynamic' : 'static';

        // Extract minimal auth object for chain-of-custody (hash token; do not store secrets)
        let authObj: any = undefined;
        try {
          // Prefer enterprise-provided x-auth-context (privacy-safe)
          const ctxHeader = (ctx.headers?.["x-auth-context"] as string) || undefined;
          const parsed: IdentityContext | undefined = parseIdentityContextHeader(ctxHeader);
          if (parsed) {
            authObj = { ...parsed };
          } else {
            // Fallback to Authorization hash if forwarded
            const hdr = (ctx.headers?.authorization as string) || (ctx.headers?.Authorization as string);
            if (typeof hdr === 'string' && hdr.length) {
              const parts = hdr.split(/\s+/);
              const scheme = parts[0] || '';
              const token = parts.slice(1).join(' ');
              const token_sha256 = token ? sha256Hex(Buffer.from(token)) : undefined;
              let jwt: any = undefined;
              if (token && token.split('.').length >= 2) {
                try {
                  const b64 = token.split('.')[1].replace(/-/g,'+').replace(/_/g,'/');
                  const payload = JSON.parse(Buffer.from(b64, 'base64').toString('utf8'));
                  const { sub, iss, aud, exp, iat, email, tenant } = payload || {};
                  jwt = { sub, iss, aud, exp, iat, email, tenant };
                } catch {}
              }
              authObj = { scheme: scheme.toLowerCase(), token_sha256, ...(jwt ? { jwt } : {}) };
            }
          }
        } catch {}

        // Derive compliance tags (e.g., NIST, OWASP, CWE) from built-in checks and scanner findings
        const nistTagsSet = new Set<string>();
        const owaspTagsSet = new Set<string>();
        const cweTagsSet = new Set<string>();
        const cveTagsSet = new Set<string>();
        const addNist = (...codes: (string|undefined)[]) => codes.filter(Boolean).forEach(c => nistTagsSet.add(String(c)));
        const addOwasp = (...codes: (string|undefined)[]) => codes.filter(Boolean).forEach(c => owaspTagsSet.add(String(c)));
        const addCwe = (...codes: (string|undefined)[]) => codes.filter(Boolean).forEach(c => cweTagsSet.add(String(c)));
        try {
          // Only ingest tags from SAST/DAST findings; no manual mappings
          const scanFindings: any[] = [];
          if (Array.isArray(sast_findings)) scanFindings.push(...sast_findings);
          if (Array.isArray(dast_findings)) scanFindings.push(...dast_findings);
          for (const f of scanFindings) {
            const tags: any[] = Array.isArray((f as any)?.tags) ? (f as any).tags : [];
            for (const t of tags) {
              const s = String(t);
              if (/^nist\b/i.test(s) || /SP\s*800-53/i.test(s)) addNist(s);
              if (/OWASP/i.test(s)) addOwasp(s);
              if (/^CWE[-_ ]?\d+/i.test(s)) addCwe(s.toUpperCase());
              if (/^CVE-\d{4}-\d{4,}$/i.test(s)) cveTagsSet.add(s.toUpperCase());
            }
            const cwe = (f as any)?.cwe; const owasp = (f as any)?.owasp; const nist = (f as any)?.nist;
            if (cwe) (Array.isArray(cwe) ? cwe : [cwe]).forEach((x: any) => addCwe(String(x)));
            if (owasp) (Array.isArray(owasp) ? owasp : [owasp]).forEach((x: any) => addOwasp(String(x)));
            if (nist) (Array.isArray(nist) ? nist : [nist]).forEach((x: any) => addNist(String(x)));
            const code = (f as any)?.code;
            if (typeof code === 'string' && /^CVE-\d{4}-\d{4,}$/i.test(code)) cveTagsSet.add(code.toUpperCase());
          }
        } catch {}

        const compliance = {
          nist: Array.from(nistTagsSet),
          owasp: Array.from(owaspTagsSet),
          cwe: Array.from(cweTagsSet)
        };
        const vuln_refs = {
          cve: Array.from(cveTagsSet),
          cwe: Array.from(cweTagsSet),
          owasp: Array.from(owaspTagsSet),
          nist: Array.from(nistTagsSet)
        };

        const tests_performed = [didSast ? "sast" : undefined, didDast ? "dast" : undefined].filter(Boolean) as string[];
        const test_summary: any = {
          ...(didSast ? { sast: { performed: true, status: sast_status } } : {}),
          ...(didDast ? { dast: { performed: true, status: dast_status } } : {})
        };

        if (nodeId) {
          if (incomingAgentState.metadata) {
            agentVariables = mergeAgentVariables(agentVariables, 'AGENT', { metadata: incomingAgentState.metadata });
          }
          if (includeServerAgentState) {
            // SERVER scope: policy/decision metadata contributed by the MCP server itself.
            agentVariables = mergeAgentVariables(agentVariables, 'SERVER', {
              server: server.name,
              server_version: server.version,
              check_level,
              decision,
              status: error ? 'error' : 'ok',
              latency_ms: latency,
              risk_tags,
              ...(ap2IntentId ? { ap2_intent_id: ap2IntentId } : {}),
              ...(ap2CartId ? { ap2_cart_id: ap2CartId } : {}),
              ...(ctx.headers?.['x-ap2-intent-id'] ? { header_ap2_intent: ctx.headers['x-ap2-intent-id'] } : {}),
              ...(ctx.headers?.['x-ap2-cart-id'] ? { header_ap2_cart: ctx.headers['x-ap2-cart-id'] } : {}),
            });
          }
          if (includeToolAgentState) {
            // TOOL scope: per-tool execution telemetry for downstream analytics.
            const toolVars: Record<string, unknown> = {
              tool: nameAtVersion,
              tool_name: toolBaseName,
              tool_version: currentVersion,
              decision,
              status: error ? 'error' : 'ok',
              latency_ms: latency,
              risk_tags,
              ...(authObj?.scheme ? { auth_scheme: authObj.scheme } : {}),
              ...(authObj?.token_sha256 ? { auth_token_sha256: authObj.token_sha256 } : {}),
              ...(agent_findings && agent_findings.length ? { agent_guard_findings: agent_findings.length } : {}),
              ...(sast_status ? { sast_status } : {}),
              ...(dast_status ? { dast_status } : {}),
            };
            agentVariables = mergeAgentVariables(agentVariables, 'TOOL', toolVars);
          }
        }
        const agentVariablesPayload = nodeId && agentVariables && Object.keys(agentVariables).length ? agentVariables : undefined;
        const agentRefValue = agentRunId;

        /**
         * Fallback: infer cause from W3C traceparent when explicit headers are missing
         */
        const inferredParent = (() => {
          try {
            const tpRaw = String((ctx.headers as any)?.['traceparent'] || '').trim()
            if (!tpRaw) return null
            const m = tpRaw.match(/^\s*([\da-fA-F]{2})-([\da-fA-F]{32})-([\da-fA-F]{16})-([\da-fA-F]{2})/)
            if (!m) return null
            const traceId = m[2].toLowerCase()
            const spanId = m[3].toLowerCase()
            if (!/^0+$/.test(traceId) && traceId !== span.spanContext().traceId) {
              return { traceId, spanId }
            }
          } catch {}
          return null
        })()

        const causeTraceId = normalizeTraceId(ctx.headers?.['x-cause-trace']) ?? normalizeTraceId(inferredParent?.traceId);
        const causeSpanId = normalizeSpanId(ctx.headers?.['x-cause-span']) ?? normalizeSpanId(inferredParent?.spanId);
        let traceId = normalizeTraceId(spanCtx?.traceId);
        if (!traceId) traceId = generateTraceId();
        let spanId = normalizeSpanId(spanCtx?.spanId);
        if (!spanId) spanId = generateSpanId();
        const escalationViolation =
          decision === "deny" && error instanceof PolicyDeniedError
            ? normalizePolicyReasonToken(error.violation)
            : contextualEvaluatorViolation
              ? normalizePolicyReasonToken(contextualEvaluatorViolation)
              : "";
        const escalationPolicy = resolveEscalationPolicy(policyObj as PolicyObject);
        const isEvaluatorEscalation =
          escalationViolation === "contextual_evaluator_denied" ||
          escalationViolation === "contextual_evaluator_escalated";
        const evaluatorEscalationData = contextualEvaluatorFinding
          ? {
              severity: contextualEvaluatorFinding.severity,
              fingerprint: contextualEvaluatorFinding.fingerprint,
              confidence: contextualEvaluatorFinding.confidence,
              principles: contextualEvaluatorFinding.principles,
              summary: contextualEvaluatorFinding.summary,
              reasoning: contextualEvaluatorFinding.reasoning,
              snapshot: contextualEvaluatorFinding.snapshot,
            }
          : null;
        if (
          escalationViolation &&
          escalationReporter &&
          (isEvaluatorEscalation || (escalationPolicy.enabled && escalationPolicy.escalateOn.has(escalationViolation)))
        ) {
          try {
            const findingsForEscalation = sortEscalationFindingsForReporting(agent_findings)
              .slice(0, 25)
              .map((finding) => ({
                  source: finding.source || "rule",
                  code: finding.code,
                  severity: finding.severity,
                  location: finding.location,
                  message: finding.message,
                  evidence: typeof finding.evidence === "string" ? finding.evidence.slice(0, 320) : undefined,
                  rule_id: finding.rule_id,
                  policy_id: finding.policy_id,
                  pack_id: finding.pack_id,
                  confidence: finding.confidence,
                  principles: Array.isArray(finding.principles) ? finding.principles.slice(0, 10) : undefined,
                  fingerprint: finding.fingerprint,
                  reasoning: typeof finding.reasoning === "string" ? finding.reasoning.slice(0, 1000) : undefined,
                }));
            const primaryFinding = selectPrimaryEscalationFinding(agent_findings);
            const primarySeverity = normalizeEscalationFindingSeverity(primaryFinding?.severity);
            const escalationFindingSource = preferredEscalationFindingSource({
              violation: escalationViolation,
              findings: agent_findings,
              contextualFinding: contextualEvaluatorFinding,
            });
            escalationResult = await escalationReporter.create({
              tenant: effectiveTenant,
              content: `Policy denied ${toolUri(server.name, nameAtVersion)} due to ${escalationViolation}.`,
              violation: escalationViolation,
              ruleId: typeof primaryFinding?.rule_id === "string" ? primaryFinding.rule_id : null,
              message:
                typeof primaryFinding?.message === "string" && primaryFinding.message.trim()
                  ? primaryFinding.message.trim()
                  : escalationViolation.replace(/_/g, " "),
              severity: primarySeverity || evaluatorEscalationData?.severity || severityForViolation(escalationViolation),
              nodeId: nodeId || null,
              agentRef: agentRefValue || null,
              ...(escalationFindingSource === "evaluator"
                ? {
                    findingSource: "evaluator" as const,
                  }
                : {
                    findingSource: "rule" as const,
                  }),
              ...(evaluatorEscalationData
                ? {
                    evaluatorFingerprint: evaluatorEscalationData.fingerprint || null,
                    evaluatorConfidence: evaluatorEscalationData.confidence ?? null,
                    evaluatorPrinciples: evaluatorEscalationData.principles || null,
                    evaluatorSnapshot: evaluatorEscalationData.snapshot || null,
                  }
                : {}),
              metadata: {
                source: "sec0-sdk",
                layer: "middleware",
                tool_ref: toolUri(server.name, nameAtVersion),
                server: server.name,
                tool: nameAtVersion,
                op: inferOp(nameAtVersion, (ctx as any)?.args),
                decision_reason: escalationViolation,
                trace_id: traceId,
                span_id: spanId,
                risk_tags: [...risk_tags],
                findings: findingsForEscalation,
                ...(evaluatorEscalationData
                  ? {
                      evaluator: {
                        fingerprint: evaluatorEscalationData.fingerprint,
                        confidence: evaluatorEscalationData.confidence,
                        principles: evaluatorEscalationData.principles,
                        summary: evaluatorEscalationData.summary,
                        reasoning: evaluatorEscalationData.reasoning,
                        snapshot: evaluatorEscalationData.snapshot,
                      },
                    }
                  : {}),
                human_escalation: {
                  ...(escalationPolicy.human.approvalStrategy
                    ? { approval_strategy: escalationPolicy.human.approvalStrategy }
                    : {}),
                  ...(escalationPolicy.human.timeoutAction
                    ? { timeout_action: escalationPolicy.human.timeoutAction }
                    : {}),
                  ...(typeof escalationPolicy.human.minApprovals === "number"
                    ? { min_approvals: escalationPolicy.human.minApprovals }
                    : {}),
                  ...(typeof escalationPolicy.human.minRejections === "number"
                    ? { min_rejections: escalationPolicy.human.minRejections }
                    : {}),
                  ...(Array.isArray(escalationPolicy.human.requiredRoles)
                    ? { required_roles: escalationPolicy.human.requiredRoles }
                    : {}),
                  ...(Array.isArray(escalationPolicy.human.vetoRoles)
                    ? { veto_roles: escalationPolicy.human.vetoRoles }
                    : {}),
                  ...(typeof escalationPolicy.human.approvalSetId === "string"
                    ? { approval_set_id: escalationPolicy.human.approvalSetId }
                    : {}),
                },
                security_side_effects_human_escalation: {
                  ...(escalationPolicy.human.approvalStrategy
                    ? { approval_strategy: escalationPolicy.human.approvalStrategy }
                    : {}),
                  ...(escalationPolicy.human.timeoutAction
                    ? { timeout_action: escalationPolicy.human.timeoutAction }
                    : {}),
                  ...(typeof escalationPolicy.human.minApprovals === "number"
                    ? { min_approvals: escalationPolicy.human.minApprovals }
                    : {}),
                  ...(typeof escalationPolicy.human.minRejections === "number"
                    ? { min_rejections: escalationPolicy.human.minRejections }
                    : {}),
                  ...(Array.isArray(escalationPolicy.human.requiredRoles)
                    ? { required_roles: escalationPolicy.human.requiredRoles }
                    : {}),
                  ...(Array.isArray(escalationPolicy.human.vetoRoles)
                    ? { veto_roles: escalationPolicy.human.vetoRoles }
                    : {}),
                  ...(typeof escalationPolicy.human.approvalSetId === "string"
                    ? { approval_set_id: escalationPolicy.human.approvalSetId }
                    : {}),
                },
              },
              ...(escalationPolicy.human.timeoutAction
                ? { timeoutAction: escalationPolicy.human.timeoutAction }
                : {}),
              ...(escalationPolicy.human.approvalStrategy
                ? { approvalStrategy: escalationPolicy.human.approvalStrategy }
                : {}),
              ...(typeof escalationPolicy.human.minApprovals === "number"
                ? { minApprovals: escalationPolicy.human.minApprovals }
                : {}),
              ...(typeof escalationPolicy.human.minRejections === "number"
                ? { minRejections: escalationPolicy.human.minRejections }
                : {}),
              ...(Array.isArray(escalationPolicy.human.requiredRoles)
                ? { requiredRoles: escalationPolicy.human.requiredRoles }
                : {}),
              ...(Array.isArray(escalationPolicy.human.vetoRoles)
                ? { vetoRoles: escalationPolicy.human.vetoRoles }
                : {}),
              ...(typeof escalationPolicy.human.approvalSetId === "string"
                ? { approvalSetId: escalationPolicy.human.approvalSetId }
                : {}),
            });
          } catch (escalationErr: any) {
            escalationFailure = escalationErr instanceof Error ? escalationErr.message : String(escalationErr || "unknown");
          }
        }

        if (result && typeof result === "object") {
          const payload = result as Record<string, any>;
          if (payload.trace === undefined) payload.trace = traceId;
          if (payload.traceId === undefined) payload.traceId = traceId;
          if (payload.trace_id === undefined) payload.trace_id = traceId;
          if (payload.span === undefined) payload.span = spanId;
          if (payload.spanId === undefined) payload.spanId = spanId;
          if (payload.span_id === undefined) payload.span_id = spanId;
        }

        const rawPayloadRecorder =
          rawPayloadConfig?.enabled === true
            ? createRawPayloadRecorder({
                auditSink,
                tenant: effectiveTenant,
                environment: effectiveEnv,
                client: effectiveClientName,
                clientVersion: effectiveClientVersion,
                config: rawPayloadConfig,
              })
            : null;

        if (rawPayloadRecorder) {
          const rawRunId = agentRefValue || (() => { throw new Error("[sec0-middleware] agent runId is required when raw payload capture is enabled"); })();
          const baseRaw: Omit<RawPayloadRecordInput, "payload" | "direction"> = {
            runId: rawRunId,
            traceId,
            spanId,
            nodeId,
            tool: nameAtVersion,
            decision,
            riskTags: [...risk_tags],
            idempotencyKey: ctx.idempotencyKey ?? null,
            agentVariables: agentVariablesPayload,
          };
          if (runtimeConfig?.rawPayloads?.captureInputs !== false) {
            await rawPayloadRecorder({ ...baseRaw, direction: "input", payload: (ctx as any)?.args });
          }
          if (runtimeConfig?.rawPayloads?.captureOutputs !== false) {
            await rawPayloadRecorder({ ...baseRaw, direction: "output", payload: result });
          }
        }

        const targetServer = `${server.name}@${server.version}`;
        const targetTool = nameAtVersion;
        // Production-grade: do not rely on hard-coded identities. Allow overrides via opts.middlewareHop,
        // and include stable versioned defaults so operators can attribute enforcement hops.
        const middlewareServer = String(opts.middlewareHop?.server || `sec0-middleware@${SDK_VERSION}`);
        const middlewareTool = String(opts.middlewareHop?.tool || 'mcp.enforce@1.0');
        const envelope: any = {
          ts: new Date(start).toISOString(),
          trace_id: traceId,
          span_id: spanId,
          // explicit parent linkage for A2A hops if forwarded via gateway/bridge
          ...(causeTraceId ? { cause_trace_id: causeTraceId } : {}),
          ...(causeSpanId ? { cause_span_id: causeSpanId } : {}),
          tenant: effectiveTenant || "unknown",
          env: effectiveEnv,
          client: effectiveClientName,
          clientVersion: effectiveClientVersion,
          // Middleware hop identity (distinct from the target tool execution hop).
          server: middlewareServer,
          tool: middlewareTool,
          // Operation classification for Monitor UI ("read" for GET-like tools by default)
          op: inferOp(nameAtVersion, (ctx as any)?.args),
          // Hop attribution for middleware-level audits
          tool_ref: `${middlewareServer} ${middlewareTool}`,
          node_type: 'middleware',
          // Target attribution (the actual MCP tool being enforced/invoked)
          target_server: targetServer,
          target_tool: targetTool,
          target_tool_ref: `${targetServer} ${targetTool}`,
          status: error ? "error" : "ok",
          latency_ms: latency,
          retries: 0,
          input_sha256: inputHash,
          output_sha256: outputHash,
          policy: { decision, retention: policyObj.default_retention, ...(decision_reason ? { reason: decision_reason } : {}), ...(ctx?.headers && (ctx.headers as any)['x-dedupe'] ? { duplicate_policy: (ctx.headers as any)['x-dedupe'] } : {}) },
          idempotency_key: ctx.idempotencyKey ?? null,
          ...(effectiveTenant ? { actor: effectiveTenant } : {}),
          registry_frozen: registryFrozen,
          server_snapshot: initialServerSnapshotHash,
          ...(tool_code_changed ? { tool_hash_changed: true } : {}),
          check_level,
          check_kind,
          ...(authObj ? { auth: authObj } : {}),
          ...(sast_status ? { sast_status } : {}),
          ...(sast_findings ? { sast_findings } : {}),
          ...(sast_scan_id ? { sast_scan_id } : {}),
          ...(sast_raw_key ? { sast_raw_key } : {}),
          ...(agent_guard_raw_key ? { agent_guard_raw_key } : {}),
          ...(agent_findings && agent_findings.length ? { agent_guard_findings: agent_findings } : {}),
          ...(dast_status ? { dast_status } : {}),
          ...(dast_findings ? { dast_findings } : {}),
          ...(dast_scan_id ? { dast_scan_id } : {}),
          ...(dast_raw_key ? { dast_raw_key } : {}),
          ...(escalationResult?.id ? { escalation_id: escalationResult.id } : {}),
          ...(escalationResult?.status ? { escalation_status: escalationResult.status } : {}),
          ...(risk_tags.length ? { risk_tags } : {}),
          ...(nodeId ? { nodeId, agentRef: agentRefValue, ...(agentVariablesPayload ? { agentVariables: agentVariablesPayload } : {}) } : {}),
          // New: classify denial source and type for UI
          ...(decision === 'deny' ? { denial_level: 'middleware' as const } : {}),
          ...(decision === 'deny' ? { denial_type: (() => {
            if (decision_reason === 'subprocess_blocked') return 'rasp';
            if (decision_reason === 'fs_violation' || decision_reason === 'egress_violation') return 'rasp';
            if (decision_reason?.includes('sast')) return 'sast';
            if (decision_reason?.includes('dast')) return 'dast';
            return undefined;
          })() } : {}),
          ...(tests_performed.length ? { tests_performed } : {}),
          ...(Object.keys(test_summary).length ? { test_summary } : {}),
          ...(compliance.nist.length || compliance.owasp.length || compliance.cwe.length ? { compliance } : {}),
          ...(vuln_refs.cve.length || vuln_refs.cwe.length || vuln_refs.owasp.length ? { vuln_refs } : {}),
          ...(egress_domain ? { egress_domain } : {}),
          ...(fs_path ? { fs_path } : {}),
          ...(decision_reason ? { decision_reason } : {}),
          ...(ap2IntentId ? { ap2_intent_id: ap2IntentId } : {}),
          ...(ap2CartId ? { ap2_cart_id: ap2CartId } : {}),
          ...(ap2ConstraintsSha256 ? { ap2_constraints_sha256: ap2ConstraintsSha256 } : {}),
          ...(ap2CartSha256 ? { ap2_cart_sha256: ap2CartSha256 } : {}),
          ...(ap2IssuerDid ? { ap2_issuer_did: ap2IssuerDid } : {}),
          ...(ap2SubjectDid ? { ap2_subject_did: ap2SubjectDid } : {}),
          // AP2 placeholders: attach passthrough hashes/ids if forwarded by gateway via headers
          ...(ctx.headers?.['x-ap2-intent-id'] ? { ap2_intent_id: ctx.headers?.['x-ap2-intent-id'] } : {}),
          ...(ctx.headers?.['x-ap2-cart-id'] ? { ap2_cart_id: ctx.headers?.['x-ap2-cart-id'] } : {}),
          ...(ctx.headers?.['x-ap2-constraints-sha256'] ? { ap2_constraints_sha256: ctx.headers?.['x-ap2-constraints-sha256'] } : {}),
          ...(ctx.headers?.['x-ap2-cart-sha256'] ? { ap2_cart_sha256: ctx.headers?.['x-ap2-cart-sha256'] } : {}),
          ...(version_changed ? { previous_tool_version: previous_version, new_tool_version: currentVersion } : {}),
          ...(escalationFailure ? { escalation_error: escalationFailure } : {}),
          risk_score: risk_tags.length ? Math.min(100, risk_tags.length * 25) : undefined
        };
        try {
          if (opts.augment) {
            const extra = await Promise.resolve(opts.augment({ tenant: opts.otel.tenant ?? "unknown", server: { name: server.name, version: server.version }, tool: nameAtVersion, ctx }));
            if (extra?.envelope) Object.assign(envelope, extra.envelope);
            if (extra?.span) addAttrs(extra.span);
          }
        } catch {}
        try {
          await auditSink.append(envelope as any);
          // Upload happens via background interval timer - no per-event flush needed
        } catch (signErr: any) {
          if (await shouldRuntimeDeny(["missing_audit_signature"], { requestIdSuffix: "audit-signature" })) {
            error = new SigningFailedError(signErr?.message);
          }
        }

        addAttrs({
          "policy.decision": decision,
          "audit.input_sha256": inputHash ?? "",
          "audit.output_sha256": outputHash ?? "",
          "retention.class": policyObj.default_retention,
          "idempotency.key": ctx.idempotencyKey ?? "",
          ...(escalationResult?.id ? { "escalation.id": escalationResult.id } : {}),
          ...(escalationResult?.status ? { "escalation.status": escalationResult.status } : {}),
          ...(escalationFailure ? { "escalation.error": escalationFailure } : {}),
          "status.code": error ? 2 : 1,
          "latency_ms": latency
        });
        // Update circuit breaker stats
        pushStat(nameAtVersion, !error, latency);
        if (telemetryEnabled) {
          if (error) endSpanErr(span, error, latency); else endSpanOk(span, latency);
        }
      }

      if (error) {
        if (escalationResult?.id) {
          try {
            (error as any).escalation = escalationResult;
            (error as any).escalation_id = escalationResult.id;
            (error as any).escalation_status = escalationResult.status;
          } catch {}
        }
        throw error;
      }
      return result;
    };
    installingWrapper = true;
    try {
      // Tag wrapper identity once
      (wrapped as any).__sec0_wrapper__ = true;
      (wrapped as any).__sec0_handler_hash = functionCodeHash(handler);
      server.__setTool?.(nameAtVersion, wrapped);
    } finally {
      installingWrapper = false;
    }
  }
  // Freeze registry after we have wrapped all current tools
  registryFrozen = true;
};

export const sec0LocalMiddleware = (opts: LocalSec0PresetOptions) => sec0SecurityMiddleware(createLocalSec0Preset(opts));
export const sec0HostedMiddleware = (
  opts: HostedSec0PresetOptions,
  deps?: MiddlewarePresetDependencies,
) => sec0SecurityMiddleware(createHostedSec0Preset(opts, deps));

// Backwards-compat export name
export const mcpAuditMiddleware = sec0SecurityMiddleware;

export { withSec0Meta, getSec0Meta } from './meta';
export {
  callToolViaGateway,
  callToolViaGatewayWithAgent,
  buildIdempotencyKey,
  type AgentContext,
  type AgentBridgeCallOptions,
} from './bridge';
export { createControlPlanePolicyManager, isControlPlanePolicySource, type ControlPlanePolicySource } from './controlPlanePolicy';
export { buildIdentityContext, encodeIdentityContextHeader, parseIdentityContextHeader } from './identity';
export { matchesToolPattern };
export {
  SkillScanManager,
  maxSkillSeverityOf,
  type SkillDescriptor,
  type SkillFinding,
  type SkillScanHook,
  type SkillScanOptions,
  type SkillSeverity,
} from './skill';
export {
  semgrepOnScan,
} from './semgrep';
export {
  nucleiOnScan,
} from './nuclei';

export type { PolicyObject };
export type {
  PolicyContext,
  PolicySnapshot,
  PolicyProvider,
  ApprovalVerificationInput,
  ApprovalVerificationResult,
  ApprovalVerifier,
  EscalationSeverity,
  EscalationApprovalStrategy,
  EscalationTimeoutAction,
  EscalationCreateInput,
  EscalationCreateResult,
  EscalationReporter,
  EscalationStatus,
  EscalationStatusResult,
  EscalationGetInput,
  EscalationResolveInput,
  EscalationResolver,
  AuditSink,
  RuntimeInvoker,
} from "../core/contracts";

export {
  createNoopEscalationResolver,
  createControlPlaneEscalationResolver,
} from "./adapters/escalationResolver";

export {
  createControlPlaneClient,
  type ControlPlaneClient,
  type ControlPlaneClientOptions,
  type ControlPlaneClientDiscoveryResult,
  type ControlPlaneClientValidationResult,
  type ControlPlaneContextualEvaluatorResult,
  type ControlPlaneCreateEscalationPayload,
  type ControlPlaneCreateEscalationResult,
  type ControlPlaneEscalationResolveResult,
  type ControlPlaneEscalationStatusResult,
  type ControlPlanePolicyFetchResult,
  type ControlPlaneUploadUrlResponse,
} from "./adapters/controlPlaneClient";

export {
  createControlPlaneApprovalVerifier,
  createNoopApprovalVerifier,
} from "./adapters/approvalVerifier";

export {
  createControlPlaneContextualEvaluator,
} from "./adapters/contextualEvaluator";

export {
  createControlPlaneNlEvaluator,
} from "./adapters/complianceEvaluator";

export {
  createControlPlaneEscalationReporter,
  createNoopEscalationReporter,
} from "./adapters/escalationReporter";

export {
  createControlPlanePolicyProvider,
  createStaticPolicyProvider,
} from "./adapters/policyProvider";

export {
  publishPolicyToControlPlaneIfChanged,
} from "./adapters/policyPublisher";

export {
  createRuntimeInvoker,
} from "./adapters/runtimeInvoker";

export {
  createSec0AuditSink,
} from "./adapters/auditSink";

export {
  createLocalSec0Preset,
  createHostedSec0Preset,
};
export type {
  HostedSec0PresetOptions,
  LocalSec0PresetOptions,
  MiddlewarePresetDependencies,
} from "./presets";

export {
  uploadScanEvidence,
} from "./adapters/scanEvidenceUploader";

export {
  encodeAgentStateHeaders,
  extractAgentStateFromHeaders,
  mergeAgentVariables,
  ensureRunId,
  NODE_ID_HEADER,
  AGENT_REF_HEADER,
  AGENT_STATE_HEADER,
  AGENT_PARENT_REF_HEADER,
  type AgentStatePayload,
  type AgentStateVariables,
} from '../agent-state';
