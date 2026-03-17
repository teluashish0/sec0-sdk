// Severity primitives shared across SAST integrations.
export type Severity = "low" | "medium" | "high" | "critical";

export const severityRank: Record<Severity, number> = { low: 1, medium: 2, high: 3, critical: 4 };

// Normalized representation of a static analysis issue.
export type SastFinding = {
  code: string;
  title: string;
  severity: Severity;
  message: string;
  file?: string;
  startLine?: number;
  endLine?: number;
  suggest?: string;
  // Optional compliance metadata (if provided by adapter)
  tags?: string[];
  cwe?: string[];
  owasp?: string[];
  nist?: string[];
};

// Adapter contract SAST providers must satisfy when plugged into middleware.
export type SastHook = (info: {
  server: { name: string; version: string };
  tool: string;
  handlerHash: string;
  filePath?: string;
  source?: string;
  ruleset?: string | string[];
}) => Promise<{ status: "pass" | "fail" | "pending"; findings?: SastFinding[]; scanId?: string; raw?: any }>;

// Toggle knobs and policies governing SAST execution.
export type SastOptions = {
  enabled?: boolean;
  block_on_change?: boolean; // block while pending after change
  block_on_severity?: Severity; // block if max severity >= threshold
  cache_ttl_ms?: number;
  scan_all_on_server_change?: boolean;
  onScan?: SastHook;
};

export type SastStatus = "pass" | "fail" | "pending";

// Cached scan result keyed by handler hash to avoid redundant work.
export type SastCached = {
  status: SastStatus;
  findings?: SastFinding[];
  scanId?: string;
  updatedAt: number;
  raw?: any;
  raw_key?: string;
};

/**
 * Coordinates static analysis scans and answers enforcement questions.
 */
export class SastManager {
  private readonly opts: Required<Pick<SastOptions, "cache_ttl_ms">> & SastOptions;
  private readonly cache: Map<string, SastCached> = new Map();
  private readonly inflight: Map<string, Promise<void>> = new Map();

  constructor(opts: SastOptions) {
    if (!opts) {
      throw new Error("[sec0-middleware][sast] options are required");
    }
    const ttl = opts.cache_ttl_ms;
    if (typeof ttl !== "number" || !Number.isFinite(ttl) || ttl <= 0) {
      throw new Error("[sec0-middleware][sast] cache_ttl_ms must be a positive number");
    }
    if (!opts.onScan) {
      throw new Error("[sec0-middleware][sast] onScan hook is required");
    }
    this.opts = { ...opts, cache_ttl_ms: ttl };
  }

  // Returns a cached scan result when it is still within TTL.
  getCached(handlerHash: string): SastCached | undefined {
    const c = this.cache.get(handlerHash);
    if (!c) return undefined;
    if (Date.now() - c.updatedAt > (this.opts.cache_ttl_ms ?? 0)) {
      this.cache.delete(handlerHash);
      return undefined;
    }
    return c;
  }

  // Kicks off a background scan (if needed) and returns the latest cached data.
  ensureScan(handlerHash: string, meta: Parameters<SastHook>[0]): SastCached {
    const existing = this.getCached(handlerHash);
    if (existing && existing.status !== "pending") return existing;
    if (!this.inflight.has(handlerHash)) {
      // Mark pending and start
      const pending: SastCached = { status: "pending", updatedAt: Date.now() };
      this.cache.set(handlerHash, pending);
      const promise = (async () => {
        try {
          const scanHook = this.opts.onScan;
          if (!scanHook) throw new Error("[sec0-middleware][sast] onScan hook is missing");
          const res = await scanHook(meta);
          const cached: SastCached = {
            status: res.status,
            findings: res.findings,
            scanId: res.scanId,
            updatedAt: Date.now(),
            raw: (res as any)?.raw
          };
          this.cache.set(handlerHash, cached);
        } catch {
          // Conservative: mark fail with no findings
          this.cache.set(handlerHash, { status: "fail", updatedAt: Date.now(), findings: [] });
        } finally {
          this.inflight.delete(handlerHash);
        }
      })();
      this.inflight.set(handlerHash, promise);
    }
    return this.getCached(handlerHash)!;
  }

  // Applies policy thresholds to determine whether execution should halt based
  // on SAST findings.
  shouldBlock(cached: SastCached | undefined, blockOnChange: boolean | undefined, threshold?: Severity): { block: boolean; reason?: "sast_pending" | "sast_failed"; maxSeverity?: Severity } {
    if (!cached) return { block: false };
    if (cached.status === "pending") return { block: !!blockOnChange, reason: blockOnChange ? "sast_pending" : undefined };
    if (cached.status === "fail" && threshold) {
      const max = maxSeverityOf(cached.findings);
      if (max && severityRank[max] >= severityRank[threshold]) {
        return { block: true, reason: "sast_failed", maxSeverity: max };
      }
    }
    return { block: false };
  }
}

/**
 * Helper to compute the highest severity present in findings.
 */
export function maxSeverityOf(findings?: SastFinding[]): Severity | undefined {
  if (!findings || findings.length === 0) return undefined;
  let max: Severity = "low";
  for (const f of findings) {
    if (severityRank[f.severity] > severityRank[max]) max = f.severity;
  }
  return max;
}


