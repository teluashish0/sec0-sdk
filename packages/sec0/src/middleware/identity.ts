// Utilities for constructing and encoding privacy-safe identity context that the
// middleware forwards to downstream sec0 services.
import { sha256Hex } from "../signer";

// Minimal identity payload that intentionally omits secrets but preserves
// routing details (tenant, roles, hashed identifiers, etc.).
export type IdentityContext = {
  scheme: "assertion" | "bearer" | "prehashed" | "none";
  // Privacy-safe fields
  user_hash?: string;          // SHA256 of stable user identifier (e.g., JWT sub)
  tenant?: string;
  roles?: string[];
  // When a bearer token was seen (not recommended to forward), only the hash is retained
  token_sha256?: string;
  // Safe subset of JWT claims (no signatures/secrets)
  jwt?: { sub?: string; iss?: string; aud?: string | string[]; exp?: number; iat?: number; email?: string; tenant?: string };
};

/**
 * Parse a compact JWS (header.payload.signature) without verification to extract safe claims.
 */
function tryParseJwtPayload(compact?: string): any | undefined {
  try {
    if (!compact || compact.split(".").length < 2) return undefined;
    const b64 = compact.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    const json = Buffer.from(b64, "base64").toString("utf8");
    return JSON.parse(json);
  } catch { return undefined; }
}

/**
 * Normalizes the various identity inputs a customer may provide into a single
 * privacy-safe structure that downstream scans can consume.
 */
export function buildIdentityContext(opts: {
  authorization?: string;     // "Bearer ..." (not preferred)
  tenant?: string;
  roles?: string[];
  userId?: string;            // raw user id to be hashed client-side (preferred)
  userHash?: string;          // precomputed SHA256 of user id (most preferred)
  assertion?: string;         // optional signed assertion payload (compact JWS or plain JSON)
}): IdentityContext {
  if (!opts) throw new Error("[sec0-identity] options are required");
  if (!opts.userHash && !opts.userId && !opts.authorization && !opts.assertion) {
    throw new Error("[sec0-identity] one of userHash, userId, assertion, or authorization must be provided");
  }
  if (opts.roles && !Array.isArray(opts.roles)) {
    throw new Error("[sec0-identity] roles must be an array when provided");
  }
  if (opts.roles && opts.roles.some((r) => typeof r !== "string" || !r.trim())) {
    throw new Error("[sec0-identity] roles array must contain non-empty strings");
  }
  if (opts.tenant !== undefined && (typeof opts.tenant !== "string" || !opts.tenant.trim())) {
    throw new Error("[sec0-identity] tenant must be a non-empty string when provided");
  }

  // Highest priority: provided pre-hashed identity
  if (opts.userHash) {
    return { scheme: "prehashed", user_hash: String(opts.userHash), tenant: opts.tenant, roles: opts.roles };
  }

  // Next: signed assertion (we do best-effort parse without verifying here)
  if (opts.assertion) {
    let payload: any = undefined;
    try {
      // Accept compact JWS or JSON string
      payload = tryParseJwtPayload(opts.assertion) ?? JSON.parse(opts.assertion);
    } catch { payload = undefined; }
    const user_hash = typeof payload?.user_hash === "string" ? payload.user_hash : (payload?.sub ? sha256Hex(Buffer.from(String(payload.sub))) : undefined);
    const roles = Array.isArray(payload?.roles) ? payload.roles.map((r: any) => String(r)) : undefined;
    const tenant = opts.tenant ?? (typeof payload?.tenant === "string" ? payload.tenant : undefined);
    return { scheme: "assertion", user_hash, tenant, roles };
  }

  // Next: raw user id (we hash it client-side)
  if (opts.userId) {
    const user_hash = sha256Hex(Buffer.from(String(opts.userId)));
    return { scheme: "prehashed", user_hash, tenant: opts.tenant, roles: opts.roles };
  }

  // Fallback: Authorization header (bearer). We only retain safe details.
  const hdr = opts.authorization;
  if (!hdr || !hdr.trim()) {
    throw new Error("[sec0-identity] Authorization header is required when no other identity is provided");
  }
  const parts = hdr.split(/\s+/);
  const rawScheme = (parts[0] || "").toLowerCase();
  const scheme: IdentityContext["scheme"] = rawScheme === "bearer" ? "bearer" : (rawScheme ? "none" : "none");
  const token = parts.slice(1).join(" ");
  if (!token) {
    throw new Error("[sec0-identity] Authorization header missing token portion");
  }
  const token_sha256 = sha256Hex(Buffer.from(token));
  const jwtPayload = tryParseJwtPayload(token);
  let jwt: IdentityContext["jwt"] | undefined;
  if (jwtPayload) {
    const { sub, iss, aud, exp, iat, email, tenant } = jwtPayload || {};
    jwt = { sub, iss, aud, exp, iat, email, tenant };
  }
  return { scheme, token_sha256, jwt, tenant: opts.tenant, roles: opts.roles };
}

/**
 * Encodes the identity context into a single HTTP header for easy forwarding.
 */
export function encodeIdentityContextHeader(id: IdentityContext): { name: string; value: string } {
  const safe: IdentityContext = {
    scheme: id.scheme,
    user_hash: id.user_hash,
    tenant: id.tenant,
    roles: id.roles,
    token_sha256: id.token_sha256,
    jwt: id.jwt ? { sub: id.jwt.sub, iss: id.jwt.iss, aud: id.jwt.aud, exp: id.jwt.exp, iat: id.jwt.iat, email: id.jwt.email, tenant: id.jwt.tenant } : undefined
  };
  return { name: "x-auth-context", value: JSON.stringify(safe) };
}

/**
 * Parses the identity context header back into a usable structure.
 */
export function parseIdentityContextHeader(value?: string): IdentityContext | undefined {
  try { if (!value) return undefined; return JSON.parse(value) as IdentityContext; } catch { return undefined; }
}


