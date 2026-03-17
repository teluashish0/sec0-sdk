import { GuardBlockedError, GuardConfigError, GuardEscalationError, GuardEscalationTimeoutError } from "./errors";
import { evaluateGuardDecision } from "./policy";
import {
  createGuardPolicyProvider,
  resolveGuardMode,
} from "./providers";
import { GuardEscalationLifecycle } from "./escalation";
import { createNoopApprovalTransport } from "./transport";
import type {
  GuardDecision,
  GuardExecuteHandlers,
  GuardExecutionResult,
  GuardHooks,
  GuardInput,
  GuardLogEvent,
  GuardRuntimeContext,
  GuardWaitForResolutionOptions,
  Sec0Guard,
  Sec0GuardConfig,
} from "./types";

function toRuntimeContext(config: Sec0GuardConfig): GuardRuntimeContext {
  const log = (event: GuardLogEvent) => {
    if (!config.logger) return;
    try {
      config.logger(event);
    } catch {}
  };
  return {
    now: config.now || (() => Date.now()),
    sleep: config.sleep || ((ms: number) => new Promise((resolve) => setTimeout(resolve, ms))),
    log,
  };
}

function mergeHooks(globalHooks?: Partial<GuardHooks>, localHooks?: Partial<GuardHooks>): Partial<GuardHooks> {
  return {
    onEscalationRequested: async (event) => {
      await Promise.resolve(globalHooks?.onEscalationRequested?.(event));
      await Promise.resolve(localHooks?.onEscalationRequested?.(event));
    },
    onEscalationResolved: async (event) => {
      await Promise.resolve(globalHooks?.onEscalationResolved?.(event));
      await Promise.resolve(localHooks?.onEscalationResolved?.(event));
    },
    onEscalationError: async (event) => {
      await Promise.resolve(globalHooks?.onEscalationError?.(event));
      await Promise.resolve(localHooks?.onEscalationError?.(event));
    },
  };
}

function applyRedaction(input: GuardInput, decision: GuardDecision): GuardInput {
  if (!decision.redactedContent) return input;
  return {
    ...input,
    content: decision.redactedContent,
  };
}

export function createSec0Guard(config: Sec0GuardConfig = {}): Sec0Guard {
  const mode = resolveGuardMode(config);
  const runtime = toRuntimeContext(config);
  const policyProvider = createGuardPolicyProvider({
    mode,
    provider: config.provider,
    runtime,
  });
  const transport = config.transport ?? createNoopApprovalTransport();

  const lifecycle = new GuardEscalationLifecycle(
    {
      ...config.escalation,
    },
    runtime,
    config.hooks || {},
    transport,
  );

  async function check(input: GuardInput): Promise<GuardDecision> {
    if (!input || typeof input !== "object") {
      throw new GuardConfigError("guard.check input is required");
    }
    if (
      input.kind !== "message_outbound" &&
      input.kind !== "tool_call" &&
      input.kind !== "mcp_call" &&
      input.kind !== "api_call"
    ) {
      throw new GuardConfigError("guard.check input.kind must be one of message_outbound|tool_call|mcp_call|api_call");
    }
    const snapshot = await policyProvider.getPolicy(input);
    const decision = await evaluateGuardDecision({
      snapshot,
      mode,
      input,
    });
    return decision;
  }

  async function execute<T>(
    input: GuardInput,
    actionFn: (input: GuardInput, decision: GuardDecision) => Promise<T> | T,
    handlers?: GuardExecuteHandlers<T>,
  ): Promise<GuardExecutionResult<T>> {
    if (typeof actionFn !== "function") {
      throw new GuardConfigError("guard.execute requires an actionFn function");
    }
    const decision = await check(input);
    const mergedHooks = mergeHooks(config.hooks, handlers);

    if (decision.outcome === "allow") {
      const value = await Promise.resolve(actionFn(input, decision));
      return { decision, value };
    }

    if (decision.outcome === "redact") {
      const redactedInput = handlers?.onRedactInput
        ? await Promise.resolve(handlers.onRedactInput(input, decision))
        : applyRedaction(input, decision);
      const value = await Promise.resolve(actionFn(redactedInput, decision));
      return { decision, value };
    }

    if (decision.outcome === "block") {
      if (handlers?.onBlock) {
        const value = await Promise.resolve(handlers.onBlock(decision));
        return { decision, value };
      }
      throw new GuardBlockedError(`Guard blocked execution (${decision.reason || "policy_denied"})`, {
        reason: decision.reason,
        reasons: decision.reasons,
        provider: decision.provider,
      });
    }

    // escalate
    if (!lifecycle.enabled) {
      throw new GuardBlockedError("Guard escalation is disabled and cannot proceed", {
        reason: decision.reason,
        reasons: decision.reasons,
        provider: decision.provider,
      });
    }

    try {
      const requested = await lifecycle.requestEscalation(input, decision);
      const escalationId = requested.created.id;
      const escalateDecision: GuardDecision = {
        ...decision,
        escalation: {
          shouldEscalate: true,
          waitForResolution: handlers?.waitForEscalation ?? config.escalation?.waitForResolutionByDefault ?? true,
          escalationId,
          status: requested.created.status,
        },
      };

      await Promise.resolve(mergedHooks.onEscalationRequested?.({
        input,
        decision: escalateDecision,
        payload: requested.payload,
        created: {
          id: requested.created.id,
          status: requested.created.status,
        } as any,
      }));

      try {
        await transport.sendPending({
          escalationId,
          input,
          decision: escalateDecision,
          payload: requested.payload,
          createResult: {
            id: requested.created.id,
            status: requested.created.status,
          } as any,
        });
      } catch (transportError: any) {
        runtime.log({
          level: "warn",
          message: "guard transport pending notification failed",
          data: { cause: transportError?.message || String(transportError) },
        });
      }

      const resolution = await lifecycle.maybeWaitForResolution({
        input,
        decision: escalateDecision,
        escalationId,
        handlers: handlers as any,
      });

      if (!resolution) {
        return {
          decision: escalateDecision,
        };
      }

      const finalizedDecision: GuardDecision = {
        ...escalateDecision,
        escalation: {
          shouldEscalate: true,
          waitForResolution:
            handlers?.waitForEscalation ??
            config.escalation?.waitForResolutionByDefault ??
            true,
          escalationId,
          status: requested.created.status,
          resolution,
        },
      };

      if (resolution.status === "approved") {
        const value = await Promise.resolve(actionFn(input, finalizedDecision));
        return {
          decision: finalizedDecision,
          escalation: resolution,
          value,
        };
      }

      if (handlers?.onBlock) {
        const value = await Promise.resolve(handlers.onBlock(finalizedDecision));
        return {
          decision: finalizedDecision,
          escalation: resolution,
          value,
        };
      }

      if (resolution.status === "timeout") {
        throw new GuardEscalationTimeoutError("Escalation resolution timed out", {
          escalationId,
          resolution,
        });
      }

      throw new GuardBlockedError(`Escalation resolved as ${resolution.status}`, {
        escalationId,
        resolution,
      });
    } catch (error: any) {
      await lifecycle.emitEscalationError(
        input,
        decision,
        error instanceof Error ? error : new Error(String(error)),
        handlers as any,
      );
      if (error instanceof GuardBlockedError || error instanceof GuardEscalationTimeoutError) {
        throw error;
      }
      throw new GuardEscalationError(error?.message || "Escalation flow failed", {
        cause: error?.message || String(error),
      });
    }
  }

  async function waitForResolution(escalationId: string, opts?: GuardWaitForResolutionOptions) {
    return lifecycle.waitForResolution(escalationId, opts);
  }

  return {
    check,
    execute,
    waitForResolution,
  };
}

export * from "./types";
export * from "./errors";
export { createNoopApprovalTransport, createApprovalsBridgeTransport } from "./transport";
