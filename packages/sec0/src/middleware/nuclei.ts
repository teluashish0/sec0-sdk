// Adapter utilities for invoking ProjectDiscovery Nuclei and normalizing its
// JSONL output into sec0's DAST interfaces.
import { spawn } from "node:child_process";
import path from "node:path";
import { requireNonEmptyArray, requireNonEmptyString, requirePositiveNumber } from "./meta";

// Severity scale produced by Nuclei templates.
type Severity = "low" | "medium" | "high" | "critical";

const sevMapFromNuclei: Record<string, Severity> = {
  info: "low",
  low: "low",
  medium: "medium",
  high: "high",
  critical: "critical"
};

// Normalized representation of a Nuclei finding surfaced to callers.
export type NucleiFinding = {
  code: string; // template id
  title: string;
  severity: Severity;
  message: string;
  url?: string;
  method?: string;
  evidence?: string;
  tags?: string[];
  cwe?: string[];
  owasp?: string[];
  nist?: string[];
};

// Options required to invoke the Nuclei CLI from the middleware.
type RunNucleiCliOptions = {
  target: string;
  templates: string;
  bin: string;
  timeoutSec: number;
  tags?: string[];
  excludeTags?: string[];
  severity: Array<Severity>;
};

// Trims optional string arrays and removes empty entries.
const normalizeList = (values?: string[]): string[] => {
  if (!values) return [];
  return values.map((value) => String(value).trim()).filter(Boolean);
};

const DEFAULT_NUCLEI_BINS = ["nuclei", "/usr/bin/nuclei", "/usr/local/bin/nuclei"];
const DEFAULT_NUCLEI_TEMPLATE_DIRS = [
  path.resolve(process.cwd(), "nuclei-templates"),
  path.resolve(process.cwd(), ".sec0/nuclei-templates"),
];

const parseCsv = (raw: string | undefined, fallback: string[]): string[] => {
  if (!raw || raw.trim().length === 0) return fallback;
  return raw.split(",").map((entry) => entry.trim()).filter(Boolean);
};

const isWithinAllowedDir = (candidate: string, allowedDir: string): boolean => {
  const rel = path.relative(allowedDir, candidate);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
};

const validateNucleiBinary = (value: string): string => {
  const bin = requireNonEmptyString(value, "nuclei binary");
  const allowed = parseCsv(process.env.SEC0_NUCLEI_ALLOWED_BINS, DEFAULT_NUCLEI_BINS);
  const allowedCommands = new Set(allowed.filter((entry) => !entry.includes("/") && !entry.includes("\\")));
  const allowedPaths = new Set(
    allowed.filter((entry) => entry.includes("/") || entry.includes("\\")).map((entry) => path.resolve(entry)),
  );
  const hasPathSep = bin.includes("/") || bin.includes("\\");
  if (hasPathSep) {
    const resolved = path.resolve(bin);
    if (!allowedPaths.has(resolved)) {
      throw new Error(
        `[sec0-middleware][dast] nuclei binary "${resolved}" is not in allowed list. Set SEC0_NUCLEI_ALLOWED_BINS to permit it.`,
      );
    }
    return resolved;
  }
  if (!allowedCommands.has(bin)) {
    throw new Error(
      `[sec0-middleware][dast] nuclei binary "${bin}" is not in allowed command list. Set SEC0_NUCLEI_ALLOWED_BINS to permit it.`,
    );
  }
  return bin;
};

const validateNucleiTemplatesPath = (value: string): string => {
  const templates = requireNonEmptyString(value, "nuclei templates path");
  const resolved = path.resolve(templates);
  const allowedRoots = parseCsv(process.env.SEC0_NUCLEI_TEMPLATE_DIRS, DEFAULT_NUCLEI_TEMPLATE_DIRS).map((entry) =>
    path.resolve(entry),
  );
  if (!allowedRoots.some((allowedRoot) => isWithinAllowedDir(resolved, allowedRoot))) {
    throw new Error(
      `[sec0-middleware][dast] nuclei templates path "${resolved}" is outside allowed directories. Set SEC0_NUCLEI_TEMPLATE_DIRS to permit it.`,
    );
  }
  return resolved;
};

/**
 * Executes the Nuclei binary, consuming JSONL output stream-by-stream to
 * produce normalized findings enriched with compliance tags.
 */
export async function runNucleiCLI(opts: RunNucleiCliOptions): Promise<{ status: "pass" | "fail"; findings: NucleiFinding[]; raw?: any }> {
  const bin = validateNucleiBinary(opts.bin);
  const target = requireNonEmptyString(opts.target, "nuclei target");
  const templates = validateNucleiTemplatesPath(opts.templates);
  const timeoutSec = requirePositiveNumber(opts.timeoutSec, "nuclei timeoutSec");
  const severity = requireNonEmptyArray(opts.severity, "nuclei severity list");
  const tags = normalizeList(opts.tags);
  const excludeTags = normalizeList(opts.excludeTags);
  const args: string[] = ["-u", target, "-jsonl", "-timeout", String(timeoutSec), "-t", templates];
  if (tags.length) args.push("-tags", tags.join(","));
  if (excludeTags.length) args.push("-exclude-tags", excludeTags.join(","));
  if (severity.length) args.push("-severity", severity.join(","));
  return new Promise((resolve) => {
    try {
      const p = spawn(bin, args, { stdio: ["ignore", "pipe", "pipe"], env: process.env });
      const findings: NucleiFinding[] = [];
      const rawRecords: any[] = [];
      let err = "";
      p.stdout.on("data", (d) => {
        const lines = d.toString("utf8").split(/\n+/).filter(Boolean);
        for (const line of lines) {
          try {
            const obj = JSON.parse(line);
            // Preserve the original nuclei JSON record in raw
            rawRecords.push(obj);
            const id = (obj?.["template-id"] ?? obj?.templateID ?? obj?.id ?? "unknown") as string;
            const name = (obj?.info?.name ?? id) as string;
            const sev = sevMapFromNuclei[String(obj?.info?.severity ?? "info").toLowerCase()] || "low";
            const url = (obj?.["matched-at"] ?? obj?.matchedAt ?? obj?.url ?? obj?.host) as (string|undefined);
            const evidence = (obj?.["extracted-results"]?.[0] ?? obj?.extracted_results?.[0] ?? obj?.["matcher-name"] ?? obj?.matcher_name) as (string|undefined);
            const info = obj?.info || {};
            const rawTags = (info as any)?.tags;
            const tags = Array.isArray(rawTags) ? rawTags.map((x:any)=>String(x)) : (rawTags ? String(rawTags).split(',').map((s)=>s.trim()).filter(Boolean) : []);

            // Derive compliance refs from tags/references/classification without requiring template edits
            const srcStrings: string[] = [];
            try {
              if (Array.isArray(tags)) srcStrings.push(...tags);
              const refs = (info as any)?.reference || (info as any)?.references;
              if (Array.isArray(refs)) srcStrings.push(...refs.map((x:any)=>String(x)));
              const cls = (info as any)?.classification || (obj as any)?.classification;
              if (cls && typeof cls === 'object') {
                Object.values(cls).forEach((v:any) => { if (v != null) srcStrings.push(String(v)); });
              }
              srcStrings.push(String(id), String(name));
            } catch {}
            const joined = srcStrings.join(' | ');
            const cwe = Array.from(new Set((joined.match(/CWE-?\d+/gi) || []).map(s => 'CWE-' + s.replace(/[^0-9]/g,'')))).filter(Boolean);
            const nist = Array.from(new Set((joined.match(/NIST[:\s-]?[A-Z]{2,}-[0-9A-Za-z:-]+/gi) || []).map(s => {
              const m = s.toUpperCase().replace(/NIST[:\s-]?/,'');
              return 'NIST:' + m;
            }))).filter(Boolean);
            const owasp: string[] = [];
            const addOWASP = (a:string, y?:string) => { const a2 = a.padStart(2,'0'); owasp.push('OWASP:A'+a2 + (y?(':'+y):'')); };
            // OWASP patterns: OWASP:A01:2021, A01:2021, OWASP:A01
            const o1 = joined.match(/OWASP[:\s-]?A(\d{2})(?::(20\d{2}))?/gi) || [];
            o1.forEach(s => { const m = s.match(/A(\d{2})(?::(20\d{2}))?/i); if (m) addOWASP(m[1], m[2]); });
            const o2 = joined.match(/\bA(\d{2}):(20\d{2})\b/g) || [];
            o2.forEach(s => { const m = s.match(/A(\d{2}):(20\d{2})/i); if (m) addOWASP(m[1], m[2]); });
            const o3 = joined.match(/\bA(\d{2})\b/g) || [];
            o3.forEach(s => { const m = s.match(/A(\d{2})/i); if (m) addOWASP(m[1]); });

            const owaspUniq = Array.from(new Set(owasp));

            // Keep tags passthrough and include derived compliance arrays
            findings.push({ code: String(id), title: String(name), severity: sev, message: String(name), url, evidence, tags, cwe, owasp: owaspUniq, nist });
          } catch {}
        }
      });
      p.stderr.on("data", (d) => { err += d.toString("utf8"); });
      p.on("error", () => resolve({ status: "fail", findings: [], raw: { error: "spawn_failed", stderr: err } }));
      p.on("close", (_code) => {
        // Return normalized findings AND the original nuclei JSONL objects in raw
        resolve({ status: findings.length ? "fail" : "pass", findings, raw: rawRecords });
      });
    } catch (e: any) {
      resolve({ status: "fail", findings: [], raw: { error: e?.message } });
    }
  });
}

// Input contract passed to the DAST manager's onScan hook.
type NucleiScanInfo = {
  server: { name: string; version: string };
  tool: string;
  handlerHash: string;
  sandboxUrl?: string;
  templates?: string;
  tags?: string[];
  excludeTags?: string[];
  severity?: Array<Severity>;
  bin?: string;
  timeoutSec?: number;
};

/**
 * Default DAST onScan handler that drives a local Nuclei invocation for the
 * given server snapshot.
 */
export async function nucleiOnScan(info: NucleiScanInfo): Promise<{ status: "pass" | "fail" | "pending"; findings?: NucleiFinding[]; scanId?: string; raw?: any }> {
  const target = requireNonEmptyString(info.sandboxUrl, "nuclei sandboxUrl");
  const templates = validateNucleiTemplatesPath(requireNonEmptyString(info.templates, "nuclei templates"));
  const severity = requireNonEmptyArray(info.severity, "nuclei severity list");
  const bin = validateNucleiBinary(requireNonEmptyString(info.bin, "nuclei binary"));
  const timeoutSec = requirePositiveNumber(info.timeoutSec, "nuclei timeoutSec");
  const scanId = `${info.handlerHash.slice(0, 12)}`;
  try {
    const res = await runNucleiCLI({ target, templates, timeoutSec, tags: info.tags, excludeTags: info.excludeTags, severity, bin });
    return { status: res.status, findings: res.findings, scanId, raw: res.raw };
  } catch {
    return { status: "fail", findings: [], scanId };
  }
}

