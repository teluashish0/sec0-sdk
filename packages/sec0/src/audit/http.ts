import { LOG_PREFIX } from "./constants";
import type { NormalizedPresignConfig, UploadUrlResponse } from "./types";

/**
 * Execute an async function with an AbortController-based timeout.
 */
export async function withTimeout<T>(
  timeoutMs: number,
  fn: (signal: AbortSignal) => Promise<T>
): Promise<T> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    return await fn(ctrl.signal);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Request a presigned upload URL from the control plane.
 */
export async function requestUploadUrl(
  cfg: NormalizedPresignConfig,
  body: Record<string, unknown>
): Promise<UploadUrlResponse> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Authorization: cfg.auditKey,
  };

  let response: Response;
  try {
    response = await withTimeout(cfg.timeoutMs, (signal) =>
      fetch(`${cfg.apiBaseUrl}/api/sec0/upload-url`, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
        signal,
      })
    );
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new Error(`${LOG_PREFIX} control-plane presign unreachable: ${reason}`);
  }

  if (!response.ok) {
    throw new Error(`${LOG_PREFIX} presign failed with status ${response.status}`);
  }

  const payload = (await response.json().catch(() => null)) as UploadUrlResponse | null;
  if (!payload?.url) {
    throw new Error(`${LOG_PREFIX} presign response missing upload URL`);
  }

  return payload;
}
