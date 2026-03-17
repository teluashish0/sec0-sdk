import { createHash } from "node:crypto";

// Helpers for constructing audit envelopes and redacting sensitive identity
// data before it leaves the gateway.

// Optional metadata that can be attached to an audit envelope before persist.
export type AugmentedFields = {
  tenant: string;
  user?: string;
  plan?: string;
  quotas?: { tool_ref: string; daily_remaining?: number; rate_remaining?: number; window_resets_at?: string };
  broker?: { name: string; key_id?: string };
  authz?: { decision: "allow" | "deny" | "would_deny"; reasons: string[] };
}

/**
 * Hash an identifier with SHA-256 and truncate for friendlier logging.
 */
export function hashIdentity(value: string): string {
  const h = createHash("sha256");
  h.update(value);
  return h.digest("hex").slice(0, 16);
}

/**
 * Conditionally hash/redact the provided identity to honor tenant privacy
 * settings while keeping deterministic identifiers for analytics.
 */
export function redactIfNeeded(identity: string | undefined, redact: boolean): string | undefined {
  if (!identity) return undefined;
  return redact ? hashIdentity(identity) : identity;
}


