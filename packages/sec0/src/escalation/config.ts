import type {
  EscalationCreateInput,
  EscalationCreateResult,
  EscalationGetInput,
  EscalationResolveInput,
  EscalationReporter,
  EscalationResolver,
  EscalationStatusResult,
} from "../core";
import type { ControlPlaneClient } from "../middleware/adapters/controlPlaneClient";
import { createControlPlaneClient } from "../middleware/adapters/controlPlaneClient";
import { createControlPlaneEscalationReporter } from "../middleware/adapters/escalationReporter";
import { createControlPlaneEscalationResolver } from "../middleware/adapters/escalationResolver";
import { Sec0EscalationAbortError, Sec0EscalationCreateError } from "./errors";

export interface EscalationWaitOptions {
  signal?: AbortSignal;
  timeoutMs?: number;
  pollIntervalMs?: number;
  maxRetries?: number;
  retryBackoffMs?: number;
  tenant?: string;
}

export interface EscalationResolutionStatusMetadata {
  attempts: number;
  retryCount: number;
  startedAt: string;
  resolvedAt: string;
  elapsedMs: number;
  lastKnownStatus?: string;
  finalizationReason?: string | null;
}

export interface EscalationResolution {
  escalationId: string;
  status: "approved" | "rejected" | "expired" | "timeout";
  details?: EscalationStatusResult | null;
  metadata: EscalationResolutionStatusMetadata;
}

export interface EscalationCreatedEvent {
  payload: EscalationCreateInput;
  created: EscalationCreateResult;
}

export interface EscalationResolvedEvent {
  escalationId: string;
  resolution: EscalationResolution;
}

export interface EscalationErrorEvent {
  operation: "create" | "get" | "resolve" | "wait";
  error: Error;
  escalationId?: string;
  payload?: EscalationCreateInput;
}

export interface EscalationManagerHooks {
  onCreated(event: EscalationCreatedEvent): Promise<void> | void;
  onResolved(event: EscalationResolvedEvent): Promise<void> | void;
  onError(event: EscalationErrorEvent): Promise<void> | void;
}

export interface EscalationManagerConfig {
  tenant?: string;
  timeoutMs?: number;
  pollIntervalMs?: number;
  maxRetries?: number;
  retryBackoffMs?: number;
  controlPlaneTimeoutMs?: number;
  apiKey?: string;
  bearerToken?: string;
  controlPlaneUrl?: string;
  client?: ControlPlaneClient;
  reporter?: EscalationReporter;
  resolver?: EscalationResolver;
  defaults?: Partial<EscalationCreateInput>;
  hooks?: Partial<EscalationManagerHooks>;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
}

export interface EscalationManager {
  create(input: EscalationCreateInput): Promise<EscalationCreateResult>;
  get(input: EscalationGetInput): Promise<EscalationStatusResult | null>;
  resolve(input: EscalationResolveInput): Promise<EscalationStatusResult | null>;
  waitForResolution(escalationId: string, options?: EscalationWaitOptions): Promise<EscalationResolution>;
  createAndWait(
    input: EscalationCreateInput,
    options?: EscalationWaitOptions,
  ): Promise<{ created: EscalationCreateResult; resolution: EscalationResolution }>;
}

export type ResolvedEscalationManagerConfig = {
  tenant?: string;
  timeoutMs: number;
  pollIntervalMs: number;
  maxRetries: number;
  retryBackoffMs: number;
  reporter?: EscalationReporter;
  resolver?: EscalationResolver;
  defaults?: Partial<EscalationCreateInput>;
  hooks: Partial<EscalationManagerHooks>;
  now: () => number;
  sleep: (ms: number) => Promise<void>;
};

export function normalizeTenant(raw: unknown): string | undefined {
  const tenant = typeof raw === "string" ? raw.trim() : "";
  return tenant || undefined;
}

export function normalizePositiveInt(raw: unknown, fallback: number, minimum = 1): number {
  const value = Number(raw);
  if (!Number.isFinite(value)) return fallback;
  return Math.max(minimum, Math.floor(value));
}

export function normalizeNonNegativeInt(raw: unknown, fallback: number): number {
  const value = Number(raw);
  if (!Number.isFinite(value)) return fallback;
  return Math.max(0, Math.floor(value));
}

export function abortIfNeeded(signal?: AbortSignal): void {
  if (signal?.aborted) {
    throw new Sec0EscalationAbortError("Escalation wait was aborted by AbortSignal");
  }
}

export async function invokeHook<T>(
  hook: ((event: T) => Promise<void> | void) | undefined,
  event: T,
): Promise<void> {
  if (!hook) return;
  try {
    await Promise.resolve(hook(event));
  } catch {}
}

export function sanitizeCreateInput(
  input: EscalationCreateInput,
  defaults?: Partial<EscalationCreateInput>,
  tenant?: string,
): EscalationCreateInput {
  const merged: EscalationCreateInput = {
    ...(defaults || {}),
    ...input,
  };
  const content = typeof merged.content === "string" ? merged.content : String(merged.content ?? "");
  const violation = String(merged.violation || "").trim();
  if (!violation) {
    throw new Sec0EscalationCreateError("Escalation violation is required");
  }
  return {
    ...merged,
    content,
    violation,
    ...(normalizeTenant(merged.tenant) || tenant ? { tenant: normalizeTenant(merged.tenant) || tenant } : {}),
  };
}

export function createResolvedConfig(config: EscalationManagerConfig = {}): ResolvedEscalationManagerConfig {
  const apiKey = String(config.apiKey || "").trim();
  const bearerToken = String(config.bearerToken || "").trim();
  const shouldAutowire = (!config.reporter || !config.resolver) && (apiKey || bearerToken);
  const client = shouldAutowire
    ? config.client || createControlPlaneClient({ ...(config.controlPlaneUrl ? { baseUrl: config.controlPlaneUrl } : {}) })
    : config.client;
  const controlPlaneTimeoutMs = normalizePositiveInt(config.controlPlaneTimeoutMs, 8_000, 1_000);

  const reporter =
    config.reporter ||
    (shouldAutowire && client
      ? createControlPlaneEscalationReporter({
          auth: {
            ...(apiKey ? { apiKey } : {}),
            ...(bearerToken ? { bearerToken } : {}),
          },
          client,
          timeoutMs: controlPlaneTimeoutMs,
        })
      : undefined);

  const resolver =
    config.resolver ||
    (shouldAutowire && client
      ? createControlPlaneEscalationResolver({
          auth: {
            ...(apiKey ? { apiKey } : {}),
            ...(bearerToken ? { bearerToken } : {}),
          },
          client,
          timeoutMs: controlPlaneTimeoutMs,
        })
      : undefined);

  return {
    tenant: normalizeTenant(config.tenant),
    timeoutMs: normalizePositiveInt(config.timeoutMs, 10 * 60 * 1000),
    pollIntervalMs: normalizePositiveInt(config.pollIntervalMs, 2_000),
    maxRetries: normalizeNonNegativeInt(config.maxRetries, 3),
    retryBackoffMs: normalizePositiveInt(config.retryBackoffMs, 250),
    reporter,
    resolver,
    defaults: config.defaults,
    hooks: config.hooks || {},
    now: config.now || (() => Date.now()),
    sleep: config.sleep || ((ms: number) => new Promise((resolve) => setTimeout(resolve, ms))),
  };
}
