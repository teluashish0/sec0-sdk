// Declarative metadata that sec0 attaches to handlers describing scan preferences.
export type Sec0Meta = {
  filePath?: string;
  repoRoot?: string;
  lang?: string;
  semgrepRuleset?: string | string[];
  dast?: {
    bin?: string;
    timeoutSec?: number;
    sandbox?: string;
    templates?: string;
    tags?: string[];
    excludeTags?: string[];
    severity?: Array<'low'|'medium'|'high'|'critical'>;
  };
};

/**
 * Attaches sec0 metadata to a handler in a non-enumerable property for later discovery.
 */
export function withSec0Meta<T extends Function>(fn: T, meta: Sec0Meta): T {
  try {
    Object.defineProperty(fn, '__sec0_meta', { value: meta, enumerable: false, configurable: false });
  } catch {}
  return fn;
}

/**
 * Retrieves the sec0 metadata previously attached to a handler, if any.
 */
export function getSec0Meta(fn: any): Sec0Meta | undefined {
  try { return fn && typeof fn === 'function' ? (fn as any).__sec0_meta as Sec0Meta : undefined; } catch { return undefined; }
}

/**
 * Ensures a string-like option is provided and returns its trimmed value.
 */
export function requireNonEmptyString(value: unknown, label: string): string {
  if (typeof value !== "string") {
    throw new Error(`[sec0-middleware][meta] ${label} must be a string`);
  }
  const trimmed = value.trim();
  if (!trimmed) {
    throw new Error(`[sec0-middleware][meta] ${label} is required`);
  }
  return trimmed;
}

/**
 * Coerces a numeric option and checks that it is a positive finite number.
 */
export function requirePositiveNumber(value: unknown, label: string): number {
  const numeric = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(numeric) || numeric <= 0) {
    throw new Error(`[sec0-middleware][meta] ${label} must be a positive number`);
  }
  return numeric;
}

/**
 * Verifies an option is a non-empty array, preserving its original type.
 */
export function requireNonEmptyArray<T>(value: T[] | undefined, label: string): T[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error(`[sec0-middleware][meta] ${label} must be a non-empty array`);
  }
  return value;
}


