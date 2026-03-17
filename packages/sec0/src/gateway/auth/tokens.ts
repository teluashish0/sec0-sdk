import { createHmac, timingSafeEqual } from "node:crypto";

// Simple symmetric service-token utilities for local dev and trusted internal
// callers. Tokens are base64url payloads plus an HMAC signature.

// Claims carried inside a shared-secret service token.
export type ServiceToken = {
  tenant: string;
  user?: string;
  roles?: string[];
  exp: number;
}

/**
 * Validate an incoming service token using the shared secret and return the
 * decoded claims after checking integrity and basic expiration.
 */
export function verifyServiceToken(token: string, secretB64: string): ServiceToken {
  const secret = Buffer.from(secretB64, "base64");
  const [payloadB64, sigB64] = token.split(".");
  if (!payloadB64 || !sigB64) throw new Error("invalid token format");

  let providedSig: Buffer;
  try {
    providedSig = Buffer.from(sigB64, "base64url");
  } catch {
    throw new Error("invalid token signature");
  }

  const expectedSig = createHmac("sha256", secret).update(payloadB64).digest();
  if (providedSig.length !== expectedSig.length || !timingSafeEqual(expectedSig, providedSig)) {
    throw new Error("invalid token signature");
  }

  const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString());
  if (typeof payload.exp !== "number" || !Number.isFinite(payload.exp)) {
    throw new Error("invalid token payload: exp is required");
  }
  if (Date.now() / 1000 > payload.exp) throw new Error("token expired");
  return payload as ServiceToken;
}

