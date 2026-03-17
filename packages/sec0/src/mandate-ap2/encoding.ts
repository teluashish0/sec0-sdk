import { logger } from "./logger";

/**
 * Decode a base64url-encoded string to UTF-8.
 */
export function base64UrlDecode(input: string): string {
  try {
    const b64 = input.replace(/-/g, "+").replace(/_/g, "/");
    const pad = b64.length % 4 === 2 ? "==" : b64.length % 4 === 3 ? "=" : "";
    return Buffer.from(b64 + pad, "base64").toString("utf8");
  } catch (err) {
    logger.warn("base64url decode failed", { error: (err as Error)?.message });
    return "";
  }
}

/**
 * Safely parse a JSON string, returning undefined on failure.
 */
export function safeJsonParse<T = unknown>(s?: string): T | undefined {
  if (!s) return undefined;
  try {
    return JSON.parse(s) as T;
  } catch (err) {
    logger.warn("JSON parse failed", { error: (err as Error)?.message });
    return undefined;
  }
}
