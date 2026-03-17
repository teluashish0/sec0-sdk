import type {
  EscalationCreateInput,
  EscalationReporter,
  EscalationResolver,
} from "../core/contracts";
import {
  Sec0EscalationAbortError,
  Sec0EscalationError,
  createEscalationManager,
  isEscalationTerminal as isTerminalEscalationStatus,
  type EscalationManager,
} from "../escalation";
import { GuardAbortError, GuardEscalationError } from "./errors";
import type {
  GuardDecision,
  GuardEscalationLifecycleConfig,
  GuardEscalationResolution,
  GuardExecuteHandlers,
  GuardHooks,
  GuardInput,
  GuardRuntimeContext,
  GuardTransportResolvedEvent,
  GuardWaitForResolutionOptions,
} from "./types";

type ResolvedEscalationLifecycleConfig = {
  enabled: boolean;
  tenant?: string;
  waitForResolutionByDefault: boolean;
  timeoutMs: number;
  pollIntervalMs: number;
  maxRetries: number;
  retryBackoffMs: number;
  ttlSeconds: number;
  reporter?: EscalationReporter;
  resolver?: EscalationResolver;
};

function mapViolationSeverity(violation?: string): "low" | "medium" | "high" | "critical" {
  const reason = String(violation || "").trim();
  if (
    reason === "registry_mutation" ||
    reason === "handler_swap" ||
    reason === "server_code_changed" ||
    reason === "tool_code_changed"
  ) {
    return "critical";
  }
  if (
    reason === "agent_guard_failed" ||
    reason === "tool_not_in_allowlist" ||
    reason === "version_unpinned"
  ) {
    return "high";
  }
  if (
    reason === "egress_violation" ||
    reason === "fs_violation" ||
    reason === "missing_idempotency_for_side_effect"
  ) {
    return "medium";
  }
  return "low";
}

function normalizeLifecycleConfig(config?: GuardEscalationLifecycleConfig): ResolvedEscalationLifecycleConfig {
  const timeoutMs = Number(config?.timeoutMs);
  const pollIntervalMs = Number(config?.pollIntervalMs);
  const maxRetries = Number(config?.maxRetries);
  const retryBackoffMs = Number(config?.retryBackoffMs);
  const ttlSeconds = Number(config?.ttlSeconds);
  return {
    enabled: config?.enabled !== false,
    tenant: typeof config?.tenant === "string" && config.tenant.trim() ? config.tenant.trim() : undefined,
    waitForResolutionByDefault: config?.waitForResolutionByDefault !== false,
    timeoutMs: Number.isFinite(timeoutMs) && timeoutMs > 0 ? Math.floor(timeoutMs) : 10 * 60 * 1000,
    pollIntervalMs: Number.isFinite(pollIntervalMs) && pollIntervalMs > 0 ? Math.floor(pollIntervalMs) : 2_000,
    maxRetries: Number.isFinite(maxRetries) && maxRetries >= 0 ? Math.floor(maxRetries) : 3,
    retryBackoffMs: Number.isFinite(retryBackoffMs) && retryBackoffMs > 0 ? Math.floor(retryBackoffMs) : 250,
    ttlSeconds: Number.isFinite(ttlSeconds) && ttlSeconds > 0 ? Math.floor(ttlSeconds) : 3600,
    reporter: config?.reporter,
    resolver: config?.resolver,
  };
}

function toEscalationPayload(input: GuardInput, decision: GuardDecision, cfg: ResolvedEscalationLifecycleConfig): EscalationCreateInput {
  const violation = String(decision.violation || decision.reason || "policy_violation");
  const contentText = (() => {
    if (typeof input.content === "string") return input.content;
    try {
      return JSON.stringify(input.content ?? null);
    } catch {
      return String(input.content ?? "");
    }
  })();
  return {
    ...(cfg.tenant ? { tenant: cfg.tenant } : {}),
    content: contentText.slice(0, 4000),
    violation,
    message: violation.replace(/_/g, " "),
    severity: mapViolationSeverity(violation),
    nodeId: input.context?.nodeId,
    agentRef: input.context?.runId,
    metadata: {
      kind: input.kind,
      target: input.target || input.context?.target || null,
      tags: input.context?.tags || [],
      reason: decision.reason,
      reasons: decision.reasons,
    },
    ttlSeconds: cfg.ttlSeconds,
  };
}

export class GuardEscalationLifecycle {
  private readonly config: ResolvedEscalationLifecycleConfig;
  private readonly manager: EscalationManager;

  constructor(
    config: GuardEscalationLifecycleConfig | undefined,
    private readonly runtime: GuardRuntimeContext,
    private readonly hooks: Partial<GuardHooks>,
    private readonly transport?: {
      sendResolved(event: GuardTransportResolvedEvent): Promise<void>;
    },
  ) {
    this.config = normalizeLifecycleConfig(config);
    this.manager = createEscalationManager({
      tenant: this.config.tenant,
      reporter: this.config.reporter,
      resolver: this.config.resolver,
      timeoutMs: this.config.timeoutMs,
      pollIntervalMs: this.config.pollIntervalMs,
      maxRetries: this.config.maxRetries,
      retryBackoffMs: this.config.retryBackoffMs,
      defaults: {
        ttlSeconds: this.config.ttlSeconds,
      },
      now: this.runtime.now,
      sleep: this.runtime.sleep,
    });
  }

  get enabled(): boolean {
    return this.config.enabled;
  }

  withFallbackReporter(reporter?: EscalationReporter): GuardEscalationLifecycle {
    if (!reporter || this.config.reporter) return this;
    return new GuardEscalationLifecycle(
      {
        ...this.config,
        reporter,
      },
      this.runtime,
      this.hooks,
      this.transport,
    );
  }

  withFallbackResolver(resolver?: EscalationResolver): GuardEscalationLifecycle {
    if (!resolver || this.config.resolver) return this;
    return new GuardEscalationLifecycle(
      {
        ...this.config,
        resolver,
      },
      this.runtime,
      this.hooks,
      this.transport,
    );
  }

  buildEscalationPayload(input: GuardInput, decision: GuardDecision): EscalationCreateInput {
    return toEscalationPayload(input, decision, this.config);
  }

  async requestEscalation(input: GuardInput, decision: GuardDecision): Promise<{
    payload: EscalationCreateInput;
    created: { id: string; status: string };
  }> {
    const payload = this.buildEscalationPayload(input, decision);
    try {
      const created = await this.manager.create(payload);
      return {
        payload,
        created: { id: created.id, status: created.status },
      };
    } catch (error: any) {
      throw new GuardEscalationError(error?.message || "Escalation flow failed", {
        cause: error?.message || String(error),
      });
    }
  }

  async waitForResolution(escalationId: string, options?: GuardWaitForResolutionOptions): Promise<GuardEscalationResolution> {
    try {
      return await this.manager.waitForResolution(escalationId, options);
    } catch (error: any) {
      if (error instanceof Sec0EscalationAbortError) {
        throw new GuardAbortError(error.message, error.details);
      }
      if (error instanceof Sec0EscalationError) {
        throw new GuardEscalationError(error.message, error.details);
      }
      throw new GuardEscalationError(error?.message || "Escalation flow failed", {
        cause: error?.message || String(error),
      });
    }
  }

  async maybeWaitForResolution(opts: {
    input: GuardInput;
    decision: GuardDecision;
    escalationId: string;
    handlers?: GuardExecuteHandlers<any>;
  }): Promise<GuardEscalationResolution | null> {
    const waitForEscalation = typeof opts.handlers?.waitForEscalation === "boolean"
      ? opts.handlers.waitForEscalation
      : this.config.waitForResolutionByDefault;
    if (!waitForEscalation) return null;
    const resolution = await this.waitForResolution(opts.escalationId);
    try {
      await Promise.resolve(this.hooks.onEscalationResolved?.({
        input: opts.input,
        decision: opts.decision,
        resolution,
      }));
    } catch {}
    try {
      await Promise.resolve(opts.handlers?.onEscalationResolved?.({
        input: opts.input,
        decision: opts.decision,
        resolution,
      } as any));
    } catch {}
    if (this.transport) {
      try {
        await this.transport.sendResolved({
          escalationId: opts.escalationId,
          input: opts.input,
          decision: opts.decision,
          resolution,
        });
      } catch {}
    }
    return resolution;
  }

  async emitEscalationError(input: GuardInput, decision: GuardDecision, error: Error, handlers?: GuardExecuteHandlers<any>): Promise<void> {
    try {
      await Promise.resolve(this.hooks.onEscalationError?.({ input, decision, error }));
    } catch {}
    try {
      await Promise.resolve(handlers?.onEscalationError?.({ input, decision, error } as any));
    } catch {}
  }
}

export function isEscalationTerminal(status: string): boolean {
  return isTerminalEscalationStatus(status);
}
