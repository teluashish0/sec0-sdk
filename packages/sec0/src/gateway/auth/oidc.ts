import { createRemoteJWKSet, jwtVerify, JWTPayload } from "jose";

// Lightweight helpers for verifying OIDC ID tokens at the edge and projecting
// them into the gateway's internal identity shape.

// Fields required to validate an incoming OIDC token. Optional claim overrides
// let self-hosted tenants describe where their tenant/user/role data lives.
export type OIDCConfig = {
  issuer: string;
  audience: string;
  jwks_uri: string;
  tenantClaim?: string; 
  userClaim?: string;   // default email
  rolesClaim?: string; 
  subjectClaim?: string;
  clientIdClaim?: string;
}

// Canonical gateway identity extracted from a validated token.
export type AuthIdentity = {
  tenant: string;
  user?: string;
  userId?: string;
  roles?: string[];
  clientId?: string;
};

/**
 * Verify the provided bearer token against the tenant's JWKS and return a
 * normalized identity object for downstream authz/quota enforcement.
 */
export async function verifyOidcJWT(token: string, cfg: OIDCConfig): Promise<AuthIdentity> {
  const JWKS = createRemoteJWKSet(new URL(cfg.jwks_uri));
  const { payload } = await jwtVerify(token, JWKS, {
    issuer: cfg.issuer,
    audience: cfg.audience,
    clockTolerance: 60
  });
  return extractIdentity(payload, cfg);
}

/**
 * Map arbitrary JWT claim names to the gateway's identity tuple, falling back
 * to conservative defaults so misconfigured tenants still get meaningful data.
 */
function extractIdentity(payload: JWTPayload, cfg: OIDCConfig): AuthIdentity {
  const tenantClaim = cfg.tenantClaim ?? "org";
  const userClaim = cfg.userClaim ?? "email";
  const rolesClaim = cfg.rolesClaim ?? "roles";
  const subjectClaim = cfg.subjectClaim ?? "sub";
  const clientIdClaim = cfg.clientIdClaim ?? "azp";
  const rawTenant = (payload as any)[tenantClaim];
  const rawUser = (payload as any)[userClaim];
  const rawRoles = (payload as any)[rolesClaim];
  const rawUserId = (payload as any)[subjectClaim];
  const rawClientId = (payload as any)[clientIdClaim] ?? (payload as any)["client_id"];
  const tenant = toNonEmptyString(rawTenant) ?? "unknown";
  const user = toNonEmptyString(rawUser);
  const userId = toNonEmptyString(rawUserId);
  const clientId = toNonEmptyString(rawClientId);
  const roles = normalizeRoles(rawRoles);
  return { tenant, user, userId, roles, clientId };
}

function toNonEmptyString(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function normalizeRoles(value: unknown): string[] | undefined {
  if (Array.isArray(value)) {
    const out = value
      .map((entry) => (typeof entry === "string" ? entry.trim() : String(entry).trim()))
      .filter(Boolean);
    return out.length ? out : undefined;
  }
  if (typeof value === "string") {
    const single = value.trim();
    if (!single) return undefined;
    if (single.includes(",")) {
      const out = single.split(",").map((part) => part.trim()).filter(Boolean);
      return out.length ? out : undefined;
    }
    return [single];
  }
  return undefined;
}

