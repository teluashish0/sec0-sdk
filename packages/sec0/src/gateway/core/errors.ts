// Canonical error codes surfaced by the gateway so callers can display
// consistent messaging and apply retry logic.

// Machine-readable identifiers for every gateway failure mode.
export type ErrorCode =
  | "UNAUTHENTICATED"
  | "UNAUTHORIZED_TENANT"
  | "TOOL_NOT_ALLOWED"
  | "VERSION_UNPINNED"
  | "QUOTA_EXCEEDED"
  | "RATE_LIMITED"
  | "BROKER_UNAVAILABLE";

// Options for enriching a GatewayError with HTTP metadata.
export interface GatewayErrorOptions {
  code: ErrorCode;
  httpStatus?: number;
  retryAfterSec?: number;
  resetAt?: string;
  tip?: string;
}

/**
 * Error subclass that carries structured metadata alongside the human-friendly
 * message. Downstream code uses the fields to set HTTP headers/status codes.
 */
export class GatewayError extends Error {
  readonly code: ErrorCode;
  readonly httpStatus: number;
  readonly retryAfterSec?: number;
  readonly resetAt?: string;
  readonly tip?: string;
  constructor(message: string, opts: GatewayErrorOptions) {
    super(message);
    this.code = opts.code;
    this.httpStatus = opts.httpStatus ?? 500;
    this.retryAfterSec = opts.retryAfterSec;
    this.resetAt = opts.resetAt;
    this.tip = opts.tip;
  }
}

/**
 * Convenience helper for returning a 401 when identity material is missing.
 */
export function unauthenticated(msg = "missing or invalid credentials"): GatewayError {
  return new GatewayError(`UNAUTHENTICATED: ${msg}`, { code: "UNAUTHENTICATED", httpStatus: 401 });
}

/**
 * Helper for when a tenant attempts to invoke a tool outside its allowlist.
 */
export function unauthorizedTool(tool: string, tenant: string): GatewayError {
  return new GatewayError(
    `TOOL_NOT_ALLOWED: add ${tool} to tenant '${tenant}' allowlist`,
    { code: "TOOL_NOT_ALLOWED", httpStatus: 403, tip: "Update entitlements.allowlist" }
  );
}

/**
 * Emit when the short-term rate limiter rejects the request.
 */
export function rateLimited(retryAfterSec: number, resetAt?: string): GatewayError {
  return new GatewayError(`RATE_LIMITED: retry later`, { code: "RATE_LIMITED", httpStatus: 429, retryAfterSec, resetAt });
}

/**
 * Emit when the tenant exhausted its daily quota.
 */
export function quotaExceeded(resetAt?: string): GatewayError {
  return new GatewayError(`QUOTA_EXCEEDED: daily quota reached`, { code: "QUOTA_EXCEEDED", httpStatus: 429, resetAt });
}

/**
 * Emit when we cannot fetch vendor credentials or invoke the broker.
 */
export function brokerUnavailable(msg = "vendor broker unavailable"): GatewayError {
  return new GatewayError(`BROKER_UNAVAILABLE: ${msg}`, { code: "BROKER_UNAVAILABLE", httpStatus: 503 });
}


