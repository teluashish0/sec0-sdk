import { base64UrlDecode, safeJsonParse } from "./encoding";

/**
 * Decode the payload section of a compact JWS (header.payload.signature).
 */
export function decodeCompactJwsPayload(compact?: string): unknown | undefined {
  if (!compact) return undefined;
  const parts = compact.split(".");
  if (parts.length < 2) return undefined;
  const json = base64UrlDecode(parts[1]);
  return safeJsonParse(json);
}

/**
 * Decode a mandate value, trying JSON first, then compact JWS.
 */
export function decodeMandatePayload(raw?: string): unknown | undefined {
  if (!raw) return undefined;
  const parsed = safeJsonParse(raw);
  if (parsed && typeof parsed === "object") return parsed;
  return decodeCompactJwsPayload(raw);
}
