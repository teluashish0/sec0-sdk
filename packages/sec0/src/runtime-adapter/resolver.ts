import {
  RUNTIME_PROTOCOL_VERSION,
  type RuntimeAdapterConfig,
  type RuntimeAdapterMode,
  type RuntimeFailureMode,
  type ResolvedRuntimeAdapterConfig,
} from "./types";

function readMode(value: unknown): RuntimeAdapterMode | null {
  return value === "local" || value === "remote" ? value : null;
}

function readFailureMode(value: unknown): RuntimeFailureMode | null {
  return value === "local" || value === "allow" || value === "deny" ? value : null;
}

function readPositiveInt(value: unknown, fallback: number): number {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  const i = Math.floor(n);
  return i > 0 ? i : fallback;
}

function readNonNegativeInt(value: unknown, fallback: number): number {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  const i = Math.floor(n);
  return i >= 0 ? i : fallback;
}

function readHeaders(value: unknown): Record<string, string> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  const out: Record<string, string> = {};
  for (const [key, raw] of Object.entries(value)) {
    const k = String(key || "").trim();
    const v = String(raw ?? "").trim();
    if (!k || !v) continue;
    out[k] = v;
  }
  return out;
}

export function resolveRuntimeAdapterConfig(config?: RuntimeAdapterConfig): ResolvedRuntimeAdapterConfig {
  const envMode = readMode(process.env.SEC0_RUNTIME_MODE);
  const cfgMode = readMode(config?.mode);
  const mode = cfgMode ?? envMode ?? "local";

  const protocolVersion =
    typeof config?.protocolVersion === "string" && config.protocolVersion.trim()
      ? config.protocolVersion.trim()
      : RUNTIME_PROTOCOL_VERSION;

  const envFailureMode = readFailureMode(process.env.SEC0_RUNTIME_FAILURE_MODE);
  const cfgFailureMode = readFailureMode(config?.failureMode);
  const failureMode = cfgFailureMode ?? envFailureMode ?? "local";

  const cfgRemote = config?.remote || {};
  const endpointRaw =
    typeof cfgRemote.endpoint === "string" && cfgRemote.endpoint.trim()
      ? cfgRemote.endpoint.trim()
      : typeof process.env.SEC0_RUNTIME_REMOTE_URL === "string" && process.env.SEC0_RUNTIME_REMOTE_URL.trim()
        ? process.env.SEC0_RUNTIME_REMOTE_URL.trim()
        : undefined;

  const timeoutMs = readPositiveInt(cfgRemote.timeoutMs ?? process.env.SEC0_RUNTIME_TIMEOUT_MS, 1500);
  const maxRetries = readNonNegativeInt(cfgRemote.maxRetries ?? process.env.SEC0_RUNTIME_MAX_RETRIES, 1);
  const retryBackoffMs = readPositiveInt(cfgRemote.retryBackoffMs ?? process.env.SEC0_RUNTIME_RETRY_BACKOFF_MS, 150);
  const headers = readHeaders(cfgRemote.headers);

  const apiKey =
    typeof cfgRemote.apiKey === "string" && cfgRemote.apiKey.trim()
      ? cfgRemote.apiKey.trim()
      : typeof process.env.SEC0_RUNTIME_API_KEY === "string" && process.env.SEC0_RUNTIME_API_KEY.trim()
        ? process.env.SEC0_RUNTIME_API_KEY.trim()
        : undefined;

  return {
    mode,
    protocolVersion,
    failureMode,
    remote: {
      endpoint: endpointRaw,
      timeoutMs,
      maxRetries,
      retryBackoffMs,
      headers,
      ...(apiKey ? { apiKey } : {}),
    },
  };
}
