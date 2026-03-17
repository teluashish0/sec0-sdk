import crypto from "node:crypto";
import { logger } from "./logger";

/**
 * Deterministic JSON serialization with sorted keys, safe against circular references.
 */
export function canonicalizeJson(obj: unknown): string {
  const seen = new WeakSet();
  const sort = (v: unknown): unknown => {
    if (v === null || typeof v !== "object") return v;
    if (seen.has(v as object)) return null;
    seen.add(v as object);
    if (Array.isArray(v)) return v.map(sort);
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(v as Record<string, unknown>).sort()) {
      out[k] = sort((v as Record<string, unknown>)[k]);
    }
    return out;
  };
  return JSON.stringify(sort(obj));
}

/**
 * SHA-256 hex digest of a buffer.
 */
export function sha256Hex(buf: Buffer): string {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

/**
 * Compute a deterministic SHA-256 hex digest over canonicalized args.
 */
export function computeArgsDigest(args: unknown): string {
  try {
    const canonical = canonicalizeJson(args ?? {});
    return sha256Hex(Buffer.from(canonical));
  } catch (err) {
    logger.warn("Failed to compute args digest", { error: (err as Error)?.message });
    return "";
  }
}

/**
 * Compare an expected digest against the computed digest of the given args.
 */
export function compareArgsToDigest(
  expectedDigest: string | undefined,
  args: unknown
): { ok: boolean; reason?: string } {
  if (!expectedDigest) return { ok: true };
  const computed = computeArgsDigest(args);
  if (!computed) return { ok: false, reason: "ap2_digest_unavailable" };
  if (computed !== expectedDigest) return { ok: false, reason: "ap2_cart_mismatch" };
  return { ok: true };
}
