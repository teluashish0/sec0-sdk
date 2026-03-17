/**
 * Encode a JSON string into base64url form for safe header transport.
 */
export function encodeBase64Url(json: string): string {
  return Buffer.from(json, "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

/**
 * Decode a base64url string back to the original text.
 */
export function decodeBase64Url(encoded: string): string {
  const padded = encoded.replace(/-/g, "+").replace(/_/g, "/");
  const padLen = (4 - (padded.length % 4)) % 4;
  const paddedStr = padded + "=".repeat(padLen);
  return Buffer.from(paddedStr, "base64").toString("utf8");
}
