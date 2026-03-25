// Main middleware entry point that wires sec0 policy enforcement, tracing,
// SAST/DAST orchestration, and agent guardrails into MCP servers.
import { initTracing } from "../otel";
import type { PolicyObject } from "../policy";
import {
  createContextualEvaluatorManager,
} from "../evaluator";
import { canonicalize, sha256Hex, Signer } from "../signer";
import type { Sec0Config } from "../audit";
import { SastManager } from "./sast";
import { DastManager } from "./dast";
import { nucleiOnScan } from "./nuclei";
import { AgentGuard, type AgentGuardFinding } from "./agentGuard";
import { createNeMoGuardrailsAdapter, createGuardrailsAIAdapter, createLLMGuardAdapter } from "./adapters/agentGuardAdapters";
import { buildCompliancePackScanners, type AgentGuardScanFn } from "./compliance";
import { getSec0Meta } from "./meta";
import {
  normalizePolicyObject,
} from "./policyUtils";
import {
  resolveRunContextConfig,
  type RunContextConfig,
} from "./runContext";
import {
  type UploadApiConfig,
} from "./rawPayloads";
import {
  createInvocationStats,
  createRegistryState,
  functionCodeHash,
} from "./registryState";
import { createScanPipeline } from "./scanPipeline";
import { semgrepOnScan } from "./semgrep";
import { createWrappedToolHandler } from "./toolInvocationPipeline";
import type {
  McpServerLike,
  MiddlewareAgentGuardOptions,
  MiddlewareOptions,
} from "./middlewareTypes";
import * as YAML from "yaml";
import { resolveHierarchy, extractApiKey } from "./apiKeyResolver";
import {
  isControlPlanePolicySource,
  type ControlPlanePolicySource,
} from "./controlPlanePolicy";
import { resolveControlPlaneUrl } from "./controlPlane";
import type {
  ApprovalVerifier,
  AuditSink,
  EscalationReporter,
  PolicyProvider,
  RuntimeInvoker,
} from "../core/contracts";
import { createSec0AuditSink } from "./adapters/auditSink";
import { createControlPlaneApprovalVerifier, createNoopApprovalVerifier } from "./adapters/approvalVerifier";
import { createControlPlaneNlEvaluator } from "./adapters/complianceEvaluator";
import { createControlPlaneContextualEvaluator } from "./adapters/contextualEvaluator";
import { createControlPlaneClient } from "./adapters/controlPlaneClient";
import { createControlPlaneEscalationReporter, createNoopEscalationReporter } from "./adapters/escalationReporter";
import { createControlPlanePolicyProvider, createStaticPolicyProvider } from "./adapters/policyProvider";
import { publishPolicyToControlPlaneIfChanged as publishPolicyToControlPlaneAdapter } from "./adapters/policyPublisher";
import { createRuntimeInvoker } from "./adapters/runtimeInvoker";
import {
  createHostedSec0Preset,
  createLocalSec0Preset,
  type HostedSec0PresetOptions,
  type LocalSec0PresetOptions,
  type MiddlewarePresetDependencies,
} from "./presets";

export type {
  McpServerLike,
  MiddlewareAdapters,
  MiddlewareOptions,
  OTelConfig,
  PolicyViolation,
} from "./middlewareTypes";
export {
  IdempotencyRequiredError,
  PolicyDeniedError,
  SigningFailedError,
  UnpinnedVersionError,
} from "./middlewareTypes";

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
    // AgentGuard construction is policy-derived and relatively heavy, so we rebuild
    // only when the resolved policy hash changes.
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
  const requireUploadConfig = (): UploadApiConfig | undefined => uploadApiConfig;
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
        console.error("[sec0-middleware] Profile sync failed:", err?.message || err);
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

  const registryState = createRegistryState({ server, tools, codeHash: functionCodeHash });
  const invocationStats = createInvocationStats();
  const scanPipeline = createScanPipeline({
    server: { name: server.name, version: server.version },
    tenant: opts.otel?.tenant,
    registrySnapshotHash: registryState.initialServerSnapshotHash,
    requireUploadConfig,
    debugSastEnabled,
    debugDastEnabled,
    semgrepFallbackScan: semgrepOnScan,
  });
  // Track last seen version per tool (policy-approved visibility)
  const lastVersionByToolBase: Map<string, string> = new Map();

  for (const [nameAtVersion, handler] of tools) {
    try {
      const m = getSec0Meta(handler);
      if (m?.filePath) toolFilePathByKey.set(nameAtVersion, m.filePath);
      debugSastLog('tool meta', { tool: nameAtVersion, filePath: m?.filePath || null });
    } catch {}
    const wrapped = createWrappedToolHandler({
      sdkVersion: SDK_VERSION,
      opts,
      server,
      nameAtVersion,
      handler,
      telemetryEnabled,
      includeServerAgentState,
      includeToolAgentState,
      policyProvider,
      approvalVerifier,
      escalationReporter,
      auditSink,
      runtimeInvoker,
      contextualEvaluatorManager,
      rawPayloadConfig,
      policyWebhookUrl,
      forceDastRawUpload,
      computedSandboxUrl,
      sastEnabled,
      sast,
      policySast,
      dastEnabled,
      dast,
      policyDast,
      toolFilePathByKey,
      lastVersionByToolBase,
      registryState,
      invocationStats,
      scanPipeline,
      getAgentGuardForCurrentPolicy,
      getRunContextConfigForCurrentPolicy: () =>
        cachedRunContext && cachedRunContext.policyHash === currentPolicyHash
          ? cachedRunContext.config
          : null,
      getPolicy: () => policyObj,
      onPolicyResolved: (resolved) => {
        const nextHash = resolved.hash;
        if (currentPolicyHash !== nextHash) {
          policyObj = normalizePolicyObject(resolved.policy as any);
          currentPolicyHash = nextHash;
          cachedAgentGuard = null;
          cachedRunContext = null;
        }
      },
      requireUploadConfig,
    });
    registryState.installWrappedTool(nameAtVersion, wrapped, handler);
  }
  // Freeze registry after we have wrapped all current tools
  registryState.freeze();
};

export const sec0LocalMiddleware = (opts: LocalSec0PresetOptions) => sec0SecurityMiddleware(createLocalSec0Preset(opts));
export const sec0HostedMiddleware = (
  opts: HostedSec0PresetOptions,
  deps?: MiddlewarePresetDependencies,
) => sec0SecurityMiddleware(createHostedSec0Preset(opts, deps));

// Backwards-compat export name
export const mcpAuditMiddleware = sec0SecurityMiddleware;
