import type { AgentVariableScope } from "./types";
import { LOG_PREFIX, SCOPE_ALIASES } from "./constants";

/**
 * Throw a consistently-prefixed error.
 */
export function fail(message: string): never {
  throw new Error(`${LOG_PREFIX} ${message}`);
}

/**
 * Type-safe wrapper around Object.hasOwn.
 */
export function hasOwn(obj: object, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(obj, key);
}

/**
 * Normalize any scope string (including aliases) into a canonical scope value.
 */
export function normalizeScope(scope: string | undefined | null): AgentVariableScope {
  const upper = (scope ?? "").trim().toUpperCase();
  if (!upper) {
    fail("Agent variable scope is required.");
  }
  const canonical = SCOPE_ALIASES[upper];
  if (!canonical) {
    fail(`Unknown agent variable scope: ${scope}`);
  }
  return canonical;
}

/**
 * Produce a deterministic, URL-safe identifier for node hops.
 */
export function normalizeNodeId(value: string | undefined | null): string {
  if (typeof value !== "string") {
    fail("Node ID is required.");
  }
  const trimmed = value.trim().toLowerCase();
  if (!trimmed) {
    fail("Node ID cannot be empty.");
  }
  const normalized = trimmed
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/-{2,}/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
  if (!normalized) {
    fail("Node ID cannot be empty.");
  }
  return normalized;
}

/**
 * Validate and sanitize run identifiers before they are stored or propagated.
 */
export function normalizeRunId(value: string): string {
  if (value == null || value === undefined || value === "") {
    fail("Agent runId cannot be null, undefined or empty.");
  }
  const trimmed = value.trim();
  if (!trimmed) {
    fail("Agent runId cannot be empty.");
  }
  const normalized = trimmed.replace(/[^A-Za-z0-9._:-]+/g, "_").slice(0, 120);
  if (!normalized) {
    fail("Agent runId cannot be empty.");
  }
  return normalized;
}

/**
 * Clone JSON-friendly structures while rejecting unserializable inputs.
 */
export function toPlainJson<T>(value: T): T {
  try {
    return JSON.parse(JSON.stringify(value)) as T;
  } catch {
    fail("Value must be JSON serializable.");
  }
}
