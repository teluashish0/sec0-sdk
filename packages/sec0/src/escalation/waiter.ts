import type { EscalationStatusResult } from "../core";
import type {
  EscalationErrorEvent,
  EscalationResolvedEvent,
  EscalationResolution,
  EscalationWaitOptions,
  ResolvedEscalationManagerConfig,
} from "./config";
import {
  abortIfNeeded,
  invokeHook,
  normalizeNonNegativeInt,
  normalizePositiveInt,
  normalizeTenant,
} from "./config";
import { mapResolutionStatus, Sec0EscalationWaitError } from "./errors";

export async function waitForEscalationResolution(params: {
  escalationId: string;
  config: ResolvedEscalationManagerConfig;
  get: (input: { id: string; tenant?: string }) => Promise<EscalationStatusResult | null>;
  options?: EscalationWaitOptions;
}): Promise<EscalationResolution> {
  const { config, escalationId, get, options = {} } = params;
  const startedAtMs = config.now();
  const startedAtIso = new Date(startedAtMs).toISOString();
  const timeoutMs = normalizePositiveInt(options.timeoutMs, config.timeoutMs);
  const pollIntervalMs = normalizePositiveInt(options.pollIntervalMs, config.pollIntervalMs);
  const maxRetries = normalizeNonNegativeInt(options.maxRetries, config.maxRetries);
  const retryBackoffMs = normalizePositiveInt(options.retryBackoffMs, config.retryBackoffMs);
  let attempts = 0;
  let retryCount = 0;
  let lastKnownStatus: string | undefined;
  let lastDetails: EscalationStatusResult | null = null;

  while (true) {
    abortIfNeeded(options.signal);
    attempts += 1;
    try {
      const details = await get({
        id: escalationId,
        ...(normalizeTenant(options.tenant) || config.tenant
          ? { tenant: normalizeTenant(options.tenant) || config.tenant }
          : {}),
      });
      lastDetails = details;
      lastKnownStatus = details?.status ? String(details.status) : undefined;
      const mapped = lastKnownStatus ? mapResolutionStatus(lastKnownStatus) : null;
      if (mapped) {
        const resolvedAtMs = config.now();
        const resolution: EscalationResolution = {
          escalationId,
          status: mapped,
          details,
          metadata: {
            attempts,
            retryCount,
            startedAt: startedAtIso,
            resolvedAt: new Date(resolvedAtMs).toISOString(),
            elapsedMs: resolvedAtMs - startedAtMs,
            ...(lastKnownStatus ? { lastKnownStatus } : {}),
            ...(details?.finalizationReason !== undefined ? { finalizationReason: details.finalizationReason } : {}),
          },
        };
        await invokeHook<EscalationResolvedEvent>(config.hooks.onResolved, { escalationId, resolution });
        return resolution;
      }
      retryCount = 0;
    } catch (error: any) {
      retryCount += 1;
      if (retryCount > maxRetries) {
        const err = new Sec0EscalationWaitError(error?.message || "Escalation wait failed", {
          escalationId,
          attempts,
          retryCount,
        });
        await invokeHook<EscalationErrorEvent>(config.hooks.onError, {
          operation: "wait",
          error: err,
          escalationId,
        });
        throw err;
      }
      await config.sleep(retryBackoffMs * retryCount);
      continue;
    }

    const elapsedMs = config.now() - startedAtMs;
    if (elapsedMs >= timeoutMs) {
      const resolvedAtMs = config.now();
      return {
        escalationId,
        status: "timeout",
        details: lastDetails,
        metadata: {
          attempts,
          retryCount,
          startedAt: startedAtIso,
          resolvedAt: new Date(resolvedAtMs).toISOString(),
          elapsedMs: resolvedAtMs - startedAtMs,
          ...(lastKnownStatus ? { lastKnownStatus } : {}),
        },
      };
    }

    await config.sleep(pollIntervalMs);
  }
}
