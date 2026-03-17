// Protocol-agnostic scanning primitives for external skill artifacts.
export type SkillSeverity = "low" | "medium" | "high" | "critical";

export const skillSeverityRank: Record<SkillSeverity, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export type SkillFinding = {
  code: string;
  title: string;
  severity: SkillSeverity;
  message: string;
  location?: string;
  evidence?: string;
  tags?: string[];
  cwe?: string[];
  owasp?: string[];
  nist?: string[];
};

export type SkillDescriptor = {
  name: string;
  version: string;
  source?: string;
  author?: string;
  digest?: string;
  path?: string;
  metadata?: Record<string, unknown>;
};

export type SkillScanHook = (info: {
  skill: SkillDescriptor;
  skillRef: string;
  revisionRef: string;
}) => Promise<{ status: "pass" | "fail" | "pending"; findings?: SkillFinding[]; scanId?: string; raw?: any }>;

export type SkillScanOptions = {
  cache_ttl_ms?: number;
  onScan?: SkillScanHook;
};

export type SkillChange = {
  skillRef: string;
  revisionRef: string;
  firstSeen: boolean;
  versionChanged: boolean;
  codeChanged: boolean;
  changed: boolean;
  previousVersion?: string;
};

export type SkillScanCached = {
  status: "pass" | "fail" | "pending";
  findings?: SkillFinding[];
  scanId?: string;
  updatedAt: number;
  raw?: any;
};

type SkillBaseline = {
  version: string;
  digest?: string;
};

export class SkillScanManager {
  private readonly opts: Required<Pick<SkillScanOptions, "cache_ttl_ms">> & SkillScanOptions;
  private readonly baselines: Map<string, SkillBaseline> = new Map();
  private readonly cache: Map<string, SkillScanCached> = new Map();
  private readonly inflight: Map<string, Promise<void>> = new Map();

  constructor(opts?: SkillScanOptions) {
    const ttl = Number(opts?.cache_ttl_ms ?? 10 * 60 * 1000);
    this.opts = {
      ...opts,
      cache_ttl_ms: Number.isFinite(ttl) && ttl > 0 ? Math.floor(ttl) : 10 * 60 * 1000,
    };
  }

  private static safeToken(value?: string): string {
    const s = String(value || "").trim();
    return s || "unknown";
  }

  getSkillRef(skill: SkillDescriptor): string {
    const source = SkillScanManager.safeToken(skill.source);
    const author = SkillScanManager.safeToken(skill.author);
    const name = SkillScanManager.safeToken(skill.name);
    return `${source}/${author}/${name}`;
  }

  getRevisionRef(skill: SkillDescriptor): string {
    const skillRef = this.getSkillRef(skill);
    const version = SkillScanManager.safeToken(skill.version);
    const digest = SkillScanManager.safeToken(skill.digest);
    return `${skillRef}@${version}#${digest}`;
  }

  evaluateChange(skill: SkillDescriptor): SkillChange {
    const skillRef = this.getSkillRef(skill);
    const revisionRef = this.getRevisionRef(skill);
    const prev = this.baselines.get(skillRef);
    const firstSeen = !prev;
    const version = SkillScanManager.safeToken(skill.version);
    const digest = String(skill.digest || "").trim() || undefined;
    const versionChanged = Boolean(prev && prev.version !== version);
    const codeChanged = Boolean(prev && prev.digest && digest && prev.digest !== digest);
    return {
      skillRef,
      revisionRef,
      firstSeen,
      versionChanged,
      codeChanged,
      changed: firstSeen || versionChanged || codeChanged,
      previousVersion: prev?.version,
    };
  }

  commitBaseline(skill: SkillDescriptor): void {
    const skillRef = this.getSkillRef(skill);
    this.baselines.set(skillRef, {
      version: SkillScanManager.safeToken(skill.version),
      digest: String(skill.digest || "").trim() || undefined,
    });
  }

  getCached(revisionRef: string): SkillScanCached | undefined {
    const c = this.cache.get(revisionRef);
    if (!c) return undefined;
    if (Date.now() - c.updatedAt > this.opts.cache_ttl_ms) {
      this.cache.delete(revisionRef);
      return undefined;
    }
    return c;
  }

  ensureScan(revisionRef: string, meta: Parameters<SkillScanHook>[0]): SkillScanCached {
    const existing = this.getCached(revisionRef);
    if (existing && existing.status !== "pending") return existing;
    if (!this.inflight.has(revisionRef)) {
      const pending: SkillScanCached = { status: "pending", updatedAt: Date.now() };
      this.cache.set(revisionRef, pending);
      const promise = (async () => {
        try {
          if (!this.opts.onScan) {
            this.cache.set(revisionRef, { status: "pass", updatedAt: Date.now(), findings: [] });
            return;
          }
          const res = await this.opts.onScan(meta);
          this.cache.set(revisionRef, {
            status: res.status,
            findings: res.findings,
            scanId: res.scanId,
            raw: (res as any)?.raw,
            updatedAt: Date.now(),
          });
        } catch (err) {
          const errMsg = err instanceof Error ? err.message : String(err);
          this.cache.set(revisionRef, {
            status: "fail",
            updatedAt: Date.now(),
            findings: [
              {
                code: "skill_scan_hook_error",
                title: "Skill scan hook failed",
                severity: "high",
                message: errMsg.slice(0, 320) || "Skill scanner hook threw an error.",
                tags: ["kind:skill_scan_error"],
              },
            ],
            raw: { error: errMsg.slice(0, 2000) },
          });
        } finally {
          this.inflight.delete(revisionRef);
        }
      })();
      this.inflight.set(revisionRef, promise);
    }
    return this.getCached(revisionRef)!;
  }

  shouldBlock(
    cached: SkillScanCached | undefined,
    blockOnChange: boolean | undefined,
    threshold?: SkillSeverity
  ): { block: boolean; reason?: "skill_scan_pending" | "skill_scan_failed"; maxSeverity?: SkillSeverity } {
    if (!cached) return { block: false };
    if (cached.status === "pending") {
      return { block: !!blockOnChange, reason: blockOnChange ? "skill_scan_pending" : undefined };
    }
    if (cached.status === "fail" && threshold) {
      const max = maxSkillSeverityOf(cached.findings);
      if (max && skillSeverityRank[max] >= skillSeverityRank[threshold]) {
        return { block: true, reason: "skill_scan_failed", maxSeverity: max };
      }
    }
    return { block: false };
  }
}

export function maxSkillSeverityOf(findings?: SkillFinding[]): SkillSeverity | undefined {
  if (!findings || findings.length === 0) return undefined;
  let max: SkillSeverity = "low";
  for (const f of findings) {
    if (skillSeverityRank[f.severity] > skillSeverityRank[max]) max = f.severity;
  }
  return max;
}
