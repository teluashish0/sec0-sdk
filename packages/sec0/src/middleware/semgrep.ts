// Semgrep adapter responsible for executing scans locally or via a remote
// service and normalizing their findings.
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { requireNonEmptyArray, requireNonEmptyString, requirePositiveNumber } from "./meta";

// Shared severity scale produced by Semgrep scans.
type Severity = "low" | "medium" | "high" | "critical";

const sevMapFromSemgrep: Record<string, Severity> = {
  INFO: "low",
  WARNING: "medium",
  ERROR: "high",
  CRITICAL: "critical"
};

const DEFAULT_SEMGREP_BINS = ["semgrep", "/usr/bin/semgrep", "/usr/local/bin/semgrep"];

const parseCsv = (raw: string | undefined, fallback: string[]): string[] => {
  if (!raw || raw.trim().length === 0) return fallback;
  return raw.split(",").map((entry) => entry.trim()).filter(Boolean);
};

const validateSemgrepBinary = (value: string): string => {
  const bin = requireNonEmptyString(value, "semgrep binary");
  const allowed = parseCsv(process.env.SEC0_SEMGREP_ALLOWED_BINS, DEFAULT_SEMGREP_BINS);
  const allowedCommands = new Set(allowed.filter((entry) => !entry.includes("/") && !entry.includes("\\")));
  const allowedPaths = new Set(
    allowed.filter((entry) => entry.includes("/") || entry.includes("\\")).map((entry) => path.resolve(entry)),
  );
  const hasPathSep = bin.includes("/") || bin.includes("\\");
  if (hasPathSep) {
    const resolved = path.resolve(bin);
    if (!allowedPaths.has(resolved)) {
      throw new Error(
        `[sec0-middleware][sast] semgrep binary "${resolved}" is not in allowed list. Set SEC0_SEMGREP_ALLOWED_BINS to permit it.`,
      );
    }
    return resolved;
  }
  if (!allowedCommands.has(bin)) {
    throw new Error(
      `[sec0-middleware][sast] semgrep binary "${bin}" is not in allowed command list. Set SEC0_SEMGREP_ALLOWED_BINS to permit it.`,
    );
  }
  return bin;
};

// Normalized structure returned to the middleware and API clients.
export type SemgrepFinding = {
  code: string;
  title: string;
  severity: Severity;
  message: string;
  file?: string;
  startLine?: number;
  endLine?: number;
  suggest?: string;
  tags?: string[];
  cwe?: string[];
  owasp?: string[];
  nist?: string[];
};

/**
 * Converts the Semgrep CLI JSON payload into flattened findings.
 */
function parseSemgrepJson(jsonStr: string): SemgrepFinding[] {
  try {
    const obj = JSON.parse(jsonStr);
    const results = Array.isArray(obj?.results) ? obj.results : [];
    const findings: SemgrepFinding[] = [];
    for (const r of results) {
      const checkId = r?.check_id || "unknown";
      const title = r?.extra?.metadata?.cwe?.[0]?.name || checkId;
      const sevRaw = (r?.extra?.severity || "INFO").toUpperCase();
      const severity = sevMapFromSemgrep[sevRaw] || "low";
      const message = r?.extra?.message || "";
      const file = r?.path || undefined;
      const startLine = r?.start?.line || undefined;
      const endLine = r?.end?.line || undefined;
      const suggest = r?.extra?.fix || (Array.isArray(r?.extra?.metadata?.references) ? r.extra.metadata.references[0] : undefined);
      const md = r?.extra?.metadata || {};
      const tags = Array.isArray(md?.tags) ? md.tags.map((x:any)=>String(x)) : [];
      const cwe = (Array.isArray(md?.cwe) ? md.cwe.map((x:any)=>String(x?.id||x?.name||x)) : []).filter(Boolean);
      const owasp = (Array.isArray(md?.owasp) ? md.owasp.map((x:any)=>String(x)) : []).filter(Boolean);
      const nist = (Array.isArray(md?.nist) ? md.nist.map((x:any)=>String(x)) : []).filter(Boolean);
      findings.push({ code: checkId, title, severity, message, file, startLine, endLine, suggest, tags, cwe, owasp, nist });
    }
    return findings;
  } catch {
    return [];
  }
}

// Accepts cli/onScan ruleset configuration in any supported format.
const normalizeRuleset = (ruleset: string | string[] | undefined): string[] => {
  if (!ruleset) {
    throw new Error("[sec0-middleware][sast] semgrep ruleset is required");
  }
  const list = Array.isArray(ruleset) ? ruleset : [ruleset];
  const cleaned = list
    .map((entry, idx) => requireNonEmptyString(entry, `semgrep ruleset[${idx}]`))
    .filter(Boolean);
  if (!cleaned.length) {
    throw new Error("[sec0-middleware][sast] semgrep ruleset cannot be empty");
  }
  return cleaned;
};

/**
 * Executes the Semgrep binary locally, writing inline source to a temp file when
 * necessary, and returns normalized findings.
 */
export async function runSemgrepCLI(opts: { filePath?: string; source?: string; ruleset: string[]; timeoutSec: number; bin: string }): Promise<{ status: "pass" | "fail"; findings: SemgrepFinding[]; raw?: any }> {
  const bin = validateSemgrepBinary(opts.bin);
  const timeoutSec = requirePositiveNumber(opts.timeoutSec, "semgrep timeoutSec");
  const rules = requireNonEmptyArray(opts.ruleset, "semgrep ruleset");
  if (!opts.filePath && !opts.source) {
    throw new Error("[sec0-middleware][sast] semgrep CLI requires filePath or source");
  }
  const args: string[] = ["--json", "--timeout", String(timeoutSec), "--quiet"];
  const addConfig = (c: string) => args.push("--config", c);
  rules.forEach(addConfig);
  let tmpFile: string | undefined = undefined;
  if (opts.filePath) {
    const filePath = requireNonEmptyString(opts.filePath, "semgrep filePath");
    args.push(filePath);
  } else if (opts.source) {
    // Write to a temporary file to avoid EPIPE issues with --stdin
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "worm-sast-"));
    tmpFile = path.join(dir, "handler.ts");
    const source = requireNonEmptyString(opts.source, "semgrep source");
    fs.writeFileSync(tmpFile, source, "utf8");
    args.push(tmpFile);
  }
  return new Promise((resolve) => {
    try {
      const p = spawn(bin, args, { stdio: ["ignore", "pipe", "pipe"], env: process.env });
      let out = ""; let err = "";
      if (p.stdout) p.stdout.on("data", (d) => { out += d.toString("utf8"); });
      if (p.stderr) p.stderr.on("data", (d) => { err += d.toString("utf8"); });
      p.on("error", () => { resolve({ status: "fail", findings: [], raw: { error: "spawn_failed", stderr: err } }); });
      p.on("close", () => {
        const findings = parseSemgrepJson(out);
        try { if (tmpFile) { fs.unlinkSync(tmpFile); fs.rmdirSync(path.dirname(tmpFile)); } } catch {}
        resolve({ status: findings.length ? "fail" : "pass", findings, raw: out || err });
      });
      // no stdin path
    } catch (e: any) {
      resolve({ status: "fail", findings: [], raw: { error: e?.message } });
    }
  });
}

/**
 * Delegates scanning to the remote Semgrep service, keeping the middleware API
 * consistent regardless of execution mode.
 */
export async function runSemgrepRemote(opts: { serviceUrl: string; filePath?: string; source?: string; ruleset: string[]; timeoutSec: number }): Promise<{ status: "pass" | "fail"; findings: SemgrepFinding[]; raw?: any }> {
  const serviceUrl = requireNonEmptyString(opts.serviceUrl, "semgrep serviceUrl").replace(/\/$/, "");
  const timeoutSec = requirePositiveNumber(opts.timeoutSec, "semgrep timeoutSec");
  const rules = requireNonEmptyArray(opts.ruleset, "semgrep ruleset");
  if (!opts.filePath && !opts.source) {
    throw new Error("[sec0-middleware][sast] semgrep remote scan requires filePath or source");
  }
  try {
    const res = await fetch(serviceUrl + "/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ filePath: opts.filePath, source: opts.source, ruleset: rules, timeoutSec })
    });
    const data = await res.json().catch(() => ({}));
    const findings = Array.isArray(data?.findings) ? data.findings : [];
    // Assume findings already normalized
    return { status: findings.length ? "fail" : "pass", findings, raw: data };
  } catch (e: any) {
    return { status: "fail", findings: [], raw: { error: e?.message } };
  }
}

/**
 * Default onScan implementation that bridges the SAST manager with Semgrep via
 * either the local CLI or a remote scanning service.
 */
export async function semgrepOnScan(info: { server: { name: string; version: string }; tool: string; handlerHash: string; filePath?: string; source?: string; ruleset?: string | string[]; timeoutSec?: number; bin?: string; serviceUrl?: string }): Promise<{ status: "pass" | "fail" | "pending"; findings?: SemgrepFinding[]; scanId?: string; raw?: any }> {
  const ruleset = normalizeRuleset(info.ruleset);
  const timeoutSec = requirePositiveNumber(info.timeoutSec, "semgrep timeoutSec");
  if (!info.filePath && !info.source) {
    throw new Error("[sec0-middleware][sast] semgrep scan requires filePath or source");
  }
  // Generate a unique scan identifier per invocation to avoid storage key collisions
  // Format: <hash12>-<unix_ms>-<rand4>
  const scanId = `${info.handlerHash.slice(0, 12)}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
  try {
    if (info.serviceUrl) {
      const serviceUrl = requireNonEmptyString(info.serviceUrl, "semgrep serviceUrl");
      const res = await runSemgrepRemote({ serviceUrl, filePath: info.filePath, source: info.source, ruleset, timeoutSec });
      return { status: res.status, findings: res.findings, scanId, raw: res.raw };
    }
    const bin = validateSemgrepBinary(requireNonEmptyString(info.bin, "semgrep binary"));
    const res = await runSemgrepCLI({ filePath: info.filePath, source: info.source, ruleset, timeoutSec, bin });
    return { status: res.status, findings: res.findings, scanId, raw: res.raw };
  } catch {
    return { status: "fail", findings: [], scanId };
  }
}

