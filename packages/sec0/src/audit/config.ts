import { DEFAULT_CONTROL_PLANE_URL, DEFAULT_TIMEOUT_MS, LOG_PREFIX } from "./constants";
import type { PresignConfig, NormalizedPresignConfig } from "./types";

/**
 * Read an environment variable, returning undefined for missing or blank values.
 */
export function readEnv(name: string): string | undefined {
  try {
    const value = typeof process !== "undefined" ? process.env?.[name] : undefined;
    const trimmed = typeof value === "string" ? value.trim() : "";
    return trimmed || undefined;
  } catch {
    return undefined;
  }
}

/**
 * Resolve the control plane URL from an explicit value, environment variables, or the default.
 */
export function resolveControlPlaneUrl(explicit?: string): string {
  const envOverride =
    readEnv("SEC0_CONTROL_PLANE_URL") ||
    readEnv("CONTROL_PLANE_URL");
  const raw = String(explicit || "").trim() || envOverride || DEFAULT_CONTROL_PLANE_URL;
  const normalized = raw.replace(/\/+$/, "");
  if (!normalized) {
    throw new Error(`${LOG_PREFIX} controlPlaneUrl could not be resolved`);
  }
  return normalized;
}

/**
 * Validate and normalize presign configuration into a consistent internal shape.
 */
export function normalizePresignConfig(presign: PresignConfig): NormalizedPresignConfig {
  const auditKey = presign.auditKey?.trim();
  if (!auditKey) {
    throw new Error(`${LOG_PREFIX} presign.auditKey is required`);
  }

  const timeout = presign.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isFinite(timeout) || timeout <= 0) {
    throw new Error(`${LOG_PREFIX} presign.timeoutMs must be a positive number when provided`);
  }

  const trimOrUndefined = (v: string | undefined): string | undefined => {
    const trimmed = v?.trim();
    return trimmed || undefined;
  };

  return {
    apiBaseUrl: resolveControlPlaneUrl(trimOrUndefined(presign.apiBaseUrl)),
    auditKey,
    tenant: trimOrUndefined(presign.tenant),
    clientName: trimOrUndefined(presign.clientName),
    clientVersion: trimOrUndefined(presign.clientVersion),
    environment: trimOrUndefined(presign.environment),
    timeoutMs: timeout,
  };
}
