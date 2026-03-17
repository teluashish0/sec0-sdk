import { LOG_PREFIX } from "./constants";
import type { Ap2Config, NamedCandidate, ResolvedValue } from "./types";

/**
 * Read a header value from a headers object.
 * Handles both string and string[] values, case-insensitive lookup.
 */
export function getHeader(
  headers: Record<string, string | string[] | undefined>,
  name: string
): string | undefined {
  const lower = name.toLowerCase();
  const value = headers[name] ?? headers[lower];
  if (Array.isArray(value)) {
    const first = value[0];
    return typeof first === "string" && first.trim() ? first : undefined;
  }
  if (typeof value === "string" && value.trim()) return value;
  return undefined;
}

/**
 * Validate and normalize a header name from the config.
 */
export function requireHeaderName(value: string | undefined, label: string): string {
  if (typeof value !== "string") {
    throw new Error(`${LOG_PREFIX} Missing ${label}`);
  }
  const trimmed = value.trim();
  if (!trimmed) {
    throw new Error(`${LOG_PREFIX} Missing ${label}`);
  }
  return trimmed.toLowerCase();
}

/**
 * Collect candidate values from a parsed bundle object for the given keys.
 */
export function collectBundleCandidates(
  bundle: unknown,
  keys: Array<{ source: string; key: string }>
): NamedCandidate[] {
  if (!bundle || typeof bundle !== "object") return [];
  const candidates: NamedCandidate[] = [];
  for (const entry of keys) {
    const raw = (bundle as Record<string, unknown>)[entry.key];
    candidates.push({ source: entry.source, value: raw });
  }
  return candidates;
}

/**
 * Resolve a unique string value from multiple candidate sources.
 * Returns the value if all defined candidates agree, or a conflict message otherwise.
 */
export function resolveUniqueString(label: string, candidates: NamedCandidate[]): ResolvedValue {
  const defined: Array<{ source: string; value: string }> = [];
  for (const entry of candidates) {
    if (entry.value === undefined || entry.value === null) continue;
    const str = String(entry.value).trim();
    if (!str) continue;
    defined.push({ source: entry.source, value: str });
  }
  if (!defined.length) return {};
  const canonical = defined[0].value;
  for (let i = 1; i < defined.length; i += 1) {
    if (defined[i].value !== canonical) {
      return {
        conflict: `${LOG_PREFIX} conflicting ${label}: ${defined[0].source}=${canonical} vs ${defined[i].source}=${defined[i].value}`,
      };
    }
  }
  return { value: canonical };
}

/**
 * Validate and normalize allowed DID methods from trust config.
 */
export function normalizeAllowedDidMethods(trust?: Ap2Config["trust"]): string[] {
  if (!trust || !Array.isArray(trust.didMethods) || trust.didMethods.length === 0) {
    throw new Error(`${LOG_PREFIX} cfg.trust.didMethods must be a non-empty array`);
  }
  return trust.didMethods.map((method, idx) => {
    if (typeof method !== "string") {
      throw new Error(`${LOG_PREFIX} cfg.trust.didMethods[${idx}] must be a string`);
    }
    const trimmed = method.trim().toLowerCase();
    if (!trimmed) {
      throw new Error(`${LOG_PREFIX} cfg.trust.didMethods[${idx}] must not be empty`);
    }
    return trimmed.startsWith("did:") ? trimmed : `did:${trimmed}`;
  });
}
