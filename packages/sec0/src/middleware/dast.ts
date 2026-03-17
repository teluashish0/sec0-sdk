// Minimal DAST primitives used across middleware adapters.
export type DastSeverity = "low" | "medium" | "high" | "critical";

export const dastSeverityRank: Record<DastSeverity, number> = { low: 1, medium: 2, high: 3, critical: 4 };

// Normalized shape for issues returned from heterogeneous DAST scanners.
export type DastFinding = {
  code: string;
  title: string;
  severity: DastSeverity;
  message: string;
  url?: string;
  method?: string;
  param?: string;
  location?: string; // path or resource id
  evidence?: string; // snippet or payload
  sources?: string[]; // scanners contributing
  tags?: string[];
  cwe?: string[];
  owasp?: string[];
  nist?: string[];
};

// Contract adapters must implement to plug external scanners into the manager.
export type DastHook = (info: {
  server: { name: string; version: string };
  tool: string;              // name@version
  handlerHash: string;
  sandboxUrl?: string;       // optional target where DAST runs
  // Optional scanner knobs (adapter may ignore)
  templates?: string;
  tags?: string[];
  excludeTags?: string[];
  severity?: DastSeverity[];
}) => Promise<{ status: "pass" | "fail" | "pending"; findings?: DastFinding[]; scanId?: string; raw?: any }>;

// Runtime configuration toggles for wiring DAST enforcement into middleware.
export type DastOptions = {
  enabled?: boolean;
  block_on_change?: boolean;
  block_on_severity?: DastSeverity;
  block_on_count?: number;
  rule_ttl_ms?: number; // dynamic runtime rules TTL
  sandbox_url?: string;
  onScan?: DastHook;
  // Centralized template controls (policy/env driven)
  templates?: string;
  tags?: string[];
  exclude_tags?: string[];
  severity?: DastSeverity[];
  // Execution mode: sync waits for scanner result on each call; async defers
  mode?: "sync" | "async";
  // Scope: run once per server snapshot or per tool invocation
  scope?: "server" | "tool";
};

export type DastStatus = "pass" | "fail" | "pending";

// Cached result persisted per handler hash to avoid redundant scans.
export type DastCached = {
  status: DastStatus;
  findings?: DastFinding[];
  scanId?: string;
  updatedAt: number;
  raw?: any;
  raw_key?: string;
};

/**
 * Coordinates DAST scans, caches results, and decides whether requests should
 * be blocked based on policy thresholds.
 */
export class DastManager {
  private readonly opts: Required<Pick<DastOptions, "rule_ttl_ms" | "sandbox_url">> & DastOptions;
  private readonly cache: Map<string, DastCached> = new Map();
  private readonly inflight: Map<string, Promise<void>> = new Map();
  // coarse dynamic block per tool (name@version) with expiry
  private readonly dynamicBlockUntil: Map<string, number> = new Map();

  constructor(opts: DastOptions) {
    if (!opts) {
      throw new Error('[sec0-middleware][dast] options are required');
    }
    if (typeof opts.rule_ttl_ms !== 'number' || !Number.isFinite(opts.rule_ttl_ms) || opts.rule_ttl_ms <= 0) {
      throw new Error('[sec0-middleware][dast] rule_ttl_ms must be a positive number');
    }
    const sandboxUrl = typeof opts.sandbox_url === 'string' ? opts.sandbox_url.trim() : '';
    if (!sandboxUrl) {
      throw new Error('[sec0-middleware][dast] sandbox_url is required and must be a non-empty string');
    }
    const mode = opts.mode;
    if (mode && mode !== 'sync' && mode !== 'async') {
      throw new Error('[sec0-middleware][dast] mode must be "sync" or "async" when provided');
    }
    this.opts = { ...opts, rule_ttl_ms: opts.rule_ttl_ms, sandbox_url: sandboxUrl, mode };
  }

  // Returns the cached scan result for a handler, if any.
  getCached(handlerHash: string): DastCached | undefined {
    const c = this.cache.get(handlerHash);
    if (!c) return undefined;
    // TTL for cache is implicit via last updated; do not auto-expire here to keep results until next change
    return c;
  }

  // Starts a scan in the background if one is not already in-flight, returning
  // the latest cached record (which may be pending).
  ensureScan(handlerHash: string, meta: Parameters<DastHook>[0]): DastCached {
    const existing = this.getCached(handlerHash);
    if (existing && existing.status !== "pending") return existing;
    if (!this.inflight.has(handlerHash)) {
      const pending: DastCached = { status: "pending", updatedAt: Date.now() };
      this.cache.set(handlerHash, pending);
      const promise = (async () => {
        try {
          if (!this.opts.onScan) {
            this.cache.set(handlerHash, { status: "pass", updatedAt: Date.now() });
            return;
          }
          const res = await this.opts.onScan({ ...meta, sandboxUrl: this.opts.sandbox_url });
          const cached: DastCached = { status: res.status, findings: res.findings, scanId: res.scanId, updatedAt: Date.now(), raw: (res as any)?.raw };
          this.cache.set(handlerHash, cached);
        } catch {
          this.cache.set(handlerHash, { status: "fail", updatedAt: Date.now(), findings: [] });
        } finally {
          this.inflight.delete(handlerHash);
        }
      })();
      this.inflight.set(handlerHash, promise);
    }
    return this.getCached(handlerHash)!;
  }

  // Runs the scan synchronously, awaiting completion before returning cached
  // status to the caller.
  async ensureScanSync(handlerHash: string, meta: Parameters<DastHook>[0]): Promise<DastCached> {
    const existing = this.getCached(handlerHash);
    if (existing && existing.status !== "pending") return existing;
    try {
      if (!this.opts.onScan) {
        const ok: DastCached = { status: "pass", updatedAt: Date.now() };
        this.cache.set(handlerHash, ok);
        return ok;
      }
      const res = await this.opts.onScan({ ...meta, sandboxUrl: this.opts.sandbox_url });
      const cached: DastCached = { status: (res.status === "pending" ? "fail" : res.status), findings: res.findings, scanId: res.scanId, updatedAt: Date.now(), raw: (res as any)?.raw };
      this.cache.set(handlerHash, cached);
      return cached;
    } catch {
      const fail: DastCached = { status: "fail", updatedAt: Date.now(), findings: [] };
      this.cache.set(handlerHash, fail);
      return fail;
    }
  }

  // Temporarily blocks a tool by name@version until the TTL expires.
  setDynamicBlock(toolNameAtVersion: string) {
    const until = Date.now() + this.opts.rule_ttl_ms;
    this.dynamicBlockUntil.set(toolNameAtVersion, until);
  }

  // Checks if the given tool is currently under a dynamic block.
  isDynamicallyBlocked(toolNameAtVersion: string): boolean {
    const until = this.dynamicBlockUntil.get(toolNameAtVersion);
    if (!until) return false;
    if (Date.now() > until) { this.dynamicBlockUntil.delete(toolNameAtVersion); return false; }
    return true;
  }

  // Applies severity/count/block-on-change rules to determine if execution
  // should be halted because of DAST findings.
  shouldBlock(
    cached: DastCached | undefined,
    blockOnChange: boolean | undefined,
    threshold?: DastSeverity,
    countThreshold?: number
  ): { block: boolean; reason?: "dast_pending" | "dast_failed"; maxSeverity?: DastSeverity; count?: number } {
    if (!cached) return { block: false };
    if (cached.status === "pending") return { block: !!blockOnChange, reason: blockOnChange ? "dast_pending" : undefined };
    const findings = cached.findings || [];
    if (findings.length === 0) return { block: false };
    const max = maxSeverityOf(findings);
    const overSeverity = threshold ? (max ? dastSeverityRank[max] >= dastSeverityRank[threshold] : false) : false;
    const overCount = countThreshold !== undefined ? findings.length >= countThreshold : false;
    if (overSeverity || overCount) return { block: true, reason: "dast_failed", maxSeverity: max, count: findings.length };
    return { block: false };
  }
}

/**
 * Returns the highest severity present in a set of findings.
 */
export function maxSeverityOf(findings?: DastFinding[]): DastSeverity | undefined {
  if (!findings || findings.length === 0) return undefined;
  let max: DastSeverity = "low";
  for (const f of findings) {
    if (dastSeverityRank[f.severity] > dastSeverityRank[max]) max = f.severity;
  }
  return max;
}


