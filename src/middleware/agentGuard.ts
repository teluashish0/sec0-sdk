// Lightweight prompt/content guard that runs before and after agent handlers.
export type Severity = "unknown" | "low" | "medium" | "high" | "critical";

// Normalized issue returned when prompts or outputs violate policy.
export type AgentGuardFinding = {
  source?: "rule" | "evaluator";
  code:
    | "agent_prompt_injection"
    | "agent_pii"
    | "agent_secret"
    | "agent_command_unsafe"
    | "agent_toxic_content"
    | "agent_malicious_code"
    | "agent_policy_violation"
    | "agent_data_exfil"
    | "agent_unknown"
    | "contextual_evaluator";
  severity: Severity;
  location: "input" | "output" | "run";
  message: string;
  evidence?: string;
  path?: string; // JSON path
  // Optional tags for indexing/filtering (e.g., pack ids, control ids).
  tags?: string[];
  // Optional compliance metadata (best-effort; ignored by base AgentGuard).
  pack_id?: string;
  pack_name?: string;
  policy_id?: string;
  policy_name?: string;
  rule_id?: string;
  confidence?: number;
  principles?: string[];
  fingerprint?: string;
  summary?: string;
  reasoning?: string;
  snapshot?: Record<string, unknown>;
};

// Runtime knobs for tuning AgentGuard sensitivity and overrides.
export type AgentGuardOptions = {
  enabled?: boolean;
  block_on_severity?: Severity; // block if any finding >= severity
  block_on_count?: number;      // block if findings count >= N
  // override patterns
  pii_patterns?: string[];   
  secret_patterns?: string[];
  prompt_injection_patterns?: string[]; 
  dangerous_commands?: string[];      
  toxicity_patterns?: string[];        
  malicious_code_patterns?: string[]; 
  policy_violation_patterns?: string[]; 
  data_exfiltration_patterns?: string[];
  onScanPrompt?: (text: string) => Promise<AgentGuardFinding[]> | AgentGuardFinding[];
  onScanOutput?: (text: string) => Promise<AgentGuardFinding[]> | AgentGuardFinding[];
  onScanRun?: (text: string) => Promise<AgentGuardFinding[]> | AgentGuardFinding[];
};

const DEFAULT_PII = [
  // email, phone, SSN-like, credit card-like (simple heuristics)
  /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i.source,
  /\b\+?\d{1,3}[ -]?\(?\d{2,4}\)?[ -]?\d{3,4}[ -]?\d{3,4}\b/.source,
  /\b\d{3}-\d{2}-\d{4}\b/.source,
  /\b(?:\d[ -]*?){13,16}\b/.source
];

const DEFAULT_SECRETS = [
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/.source,
  /-----BEGIN (?:RSA|EC|OPENSSH) PRIVATE KEY-----/.source,
  /xox[baprs]-[A-Za-z0-9-]+/i.source,
  /ghp_[A-Za-z0-9]{36}/.source
];

const DEFAULT_INJECTION = [
  /(ignore|bypass) (all|previous) (instructions|rules)/i.source,
  /(exfiltrate|leak|share) (data|secrets|keys)/i.source,
  /(begin|show) (system|hidden) prompt/i.source,
  /(prompt|policy) (injection|override)/i.source
];

const DEFAULT_DANGEROUS = [
  /rm\s+-rf\s+\//.source,
  /curl\s+[^|]+\|\s*(sh|bash)/i.source,
  /bash\s+-c\s+/i.source,
  /powershell\s+-enc\s+/i.source
];

const DEFAULT_TOXICITY = [
  /\bkill yourself\b/i.source,
  /\b(?:i|we)\s+hate\s+(?:you|them|everyone)\b/i.source,
  /\byou\s+are\s+(?:worthless|stupid|idiot)\b/i.source,
  /\b(?:violence|bloodbath|genocide)\b/i.source
];

const DEFAULT_MALICIOUS = [
  /subprocess\.run\([^)]*["']rm\s+-rf\s+\/["']/i.source,
  /system\(\s*["']rm\s+-rf\s+\/["']\s*\)/i.source,
  /Invoke-WebRequest\s+[^|]+\|\s*IEX/i.source,
  /curl\s+[^|]+\|\s*(?:bash|sh)/i.source,
  /New-Object\s+Net\.WebClient/i.source
];

const DEFAULT_POLICY_VIOLATIONS = [
  /\bignore\s+(?:all\s+)?(?:safety|security|compliance)\s+(?:rules|policies)\b/i.source,
  /\bprovide\s+(?:medical|financial|legal)\s+advice\b/i.source,
  /\bperform\s+actions\s+that\s+violate\s+company\s+policy\b/i.source
];

const DEFAULT_DATA_EXFIL = [
  /\bdump\s+(?:all\s+)?(?:customer|user|client)\s+(?:data|records|tables)\b/i.source,
  /\bexport\s+(?:database|table|records)\b/i.source,
  /\bexfiltrat(?:e|ion)\b/i.source,
  /\bcopy\s+all\s+files\s+(?:offsite|to\s+external)\b/i.source
];

const rank: Record<Severity, number> = { unknown: 0, low: 1, medium: 2, high: 3, critical: 4 };

/**
 * Performs lightweight regex-based guarding of agent prompts/outputs and
 * surfaces a consolidated block/no-block decision.
 */
export class AgentGuard {
  private opts: AgentGuardOptions;
  private pii: RegExp[];
  private secrets: RegExp[];
  private inj: RegExp[];
  private cmds: RegExp[];
  private toxic: RegExp[];
  private malware: RegExp[];
  private policy: RegExp[];
  private exfil: RegExp[];

  constructor(opts?: AgentGuardOptions) {
    this.opts = opts || {};
    this.pii = (this.opts.pii_patterns || DEFAULT_PII).map((s) => new RegExp(s, 'i'));
    this.secrets = (this.opts.secret_patterns || DEFAULT_SECRETS).map((s) => new RegExp(s, 'i'));
    this.inj = (this.opts.prompt_injection_patterns || DEFAULT_INJECTION).map((s) => new RegExp(s, 'i'));
    this.cmds = (this.opts.dangerous_commands || DEFAULT_DANGEROUS).map((s) => new RegExp(s, 'i'));
    this.toxic = (this.opts.toxicity_patterns || DEFAULT_TOXICITY).map((s) => new RegExp(s, 'i'));
    this.malware = (this.opts.malicious_code_patterns || DEFAULT_MALICIOUS).map((s) => new RegExp(s, 'i'));
    this.policy = (this.opts.policy_violation_patterns || DEFAULT_POLICY_VIOLATIONS).map((s) => new RegExp(s, 'i'));
    this.exfil = (this.opts.data_exfiltration_patterns || DEFAULT_DATA_EXFIL).map((s) => new RegExp(s, 'i'));
  }

  // Scans inbound prompt payloads for risky patterns.
  async scanInput(obj: any): Promise<AgentGuardFinding[]> {
    if (!this.opts.enabled) return [];
    const textParts: Array<{ value: string; path: string }> = [];
    this.collectStrings(obj, '$', textParts);
    const findings: AgentGuardFinding[] = [];
    for (const part of textParts) {
      const value = part.value;
      for (const r of this.inj) if (r.test(value)) findings.push({ code: 'agent_prompt_injection', severity: 'high', location: 'input', message: 'Prompt injection pattern', evidence: snippet(value, r), path: part.path });
      for (const r of this.pii) if (r.test(value)) findings.push({ code: 'agent_pii', severity: 'medium', location: 'input', message: 'Possible PII', evidence: snippet(value, r), path: part.path });
      for (const r of this.secrets) if (r.test(value)) findings.push({ code: 'agent_secret', severity: 'critical', location: 'input', message: 'Possible secret', evidence: snippet(value, r), path: part.path });
      for (const r of this.cmds) if (r.test(value)) findings.push({ code: 'agent_command_unsafe', severity: 'high', location: 'input', message: 'Dangerous command detected', evidence: snippet(value, r), path: part.path });
      for (const r of this.toxic) if (r.test(value)) findings.push({ code: 'agent_toxic_content', severity: 'medium', location: 'input', message: 'Toxic or abusive language', evidence: snippet(value, r), path: part.path });
      for (const r of this.malware) if (r.test(value)) findings.push({ code: 'agent_malicious_code', severity: 'high', location: 'input', message: 'Potential malware or exploit code', evidence: snippet(value, r), path: part.path });
      for (const r of this.policy) if (r.test(value)) findings.push({ code: 'agent_policy_violation', severity: 'medium', location: 'input', message: 'Policy violation request', evidence: snippet(value, r), path: part.path });
      for (const r of this.exfil) if (r.test(value)) findings.push({ code: 'agent_data_exfil', severity: 'high', location: 'input', message: 'Data exfiltration intent', evidence: snippet(value, r), path: part.path });
    }
    if (this.opts.onScanPrompt) {
      try { const extra = await this.opts.onScanPrompt(textParts.map(p => p.value).join('\n')); findings.push(...(extra || [])); } catch {}
    }
    return findings;
  }

  // Scans agent responses for sensitive leakage or policy breakage.
  async scanOutput(obj: any): Promise<AgentGuardFinding[]> {
    if (!this.opts.enabled) return [];
    const textParts: Array<{ value: string; path: string }> = [];
    this.collectStrings(obj, '$', textParts);
    const findings: AgentGuardFinding[] = [];
    for (const part of textParts) {
      const value = part.value;
      for (const r of this.pii) if (r.test(value)) findings.push({ code: 'agent_pii', severity: 'medium', location: 'output', message: 'Possible PII', evidence: snippet(value, r), path: part.path });
      for (const r of this.secrets) if (r.test(value)) findings.push({ code: 'agent_secret', severity: 'critical', location: 'output', message: 'Possible secret', evidence: snippet(value, r), path: part.path });
      for (const r of this.toxic) if (r.test(value)) findings.push({ code: 'agent_toxic_content', severity: 'medium', location: 'output', message: 'Toxic or abusive language', evidence: snippet(value, r), path: part.path });
      for (const r of this.malware) if (r.test(value)) findings.push({ code: 'agent_malicious_code', severity: 'high', location: 'output', message: 'Potential malware or exploit code', evidence: snippet(value, r), path: part.path });
      for (const r of this.policy) if (r.test(value)) findings.push({ code: 'agent_policy_violation', severity: 'medium', location: 'output', message: 'Policy violation content', evidence: snippet(value, r), path: part.path });
      for (const r of this.exfil) if (r.test(value)) findings.push({ code: 'agent_data_exfil', severity: 'high', location: 'output', message: 'Data exfiltration content', evidence: snippet(value, r), path: part.path });
    }
    if (this.opts.onScanOutput) {
      try { const extra = await this.opts.onScanOutput(textParts.map(p => p.value).join('\n')); findings.push(...(extra || [])); } catch {}
    }
    return findings;
  }

  // Scans aggregated run context (multi-hop) using custom adapters/rules.
  async scanRun(text: string): Promise<AgentGuardFinding[]> {
    if (!this.opts.enabled) return [];
    if (!this.opts.onScanRun) return [];
    const safe = typeof text === 'string' ? text : String(text ?? '');
    if (!safe.trim()) return [];
    try {
      const extra = await this.opts.onScanRun(safe);
      return Array.isArray(extra) ? extra : [];
    } catch {
      return [];
    }
  }

  // Applies severity/count thresholds to decide whether to block execution.
  shouldBlock(findings: AgentGuardFinding[]): { block: boolean; reason?: string; maxSeverity?: Severity; count: number } {
    if (!this.opts.enabled) return { block: false, count: 0 };
    const count = findings.length;
    const max = maxSeverity(findings);
    const sev = this.opts.block_on_severity;
    const cnt = this.opts.block_on_count;
    if (count && sev && max && rank[max] >= rank[sev]) return { block: true, reason: 'agent_guard_failed', maxSeverity: max, count };
    if (count && typeof cnt === 'number' && count >= cnt) return { block: true, reason: 'agent_guard_failed', maxSeverity: max, count };
    return { block: false, count };
  }

  // Walks arbitrary payloads collecting string values for regex scanning.
  private collectStrings(obj: any, path: string, out: Array<{ value: string; path: string }>, seen = new Set<any>()) {
    if (obj == null) return;
    if (seen.has(obj)) return; seen.add(obj);
    const t = typeof obj;
    if (t === 'string') { out.push({ value: obj as string, path }); return; }
    if (t === 'number' || t === 'boolean') { return; }
    if (Array.isArray(obj)) {
      obj.forEach((v, i) => this.collectStrings(v, `${path}[${i}]`, out, seen));
      return;
    }
    if (t === 'object') {
      for (const [k, v] of Object.entries(obj)) this.collectStrings(v, `${path}.${k}`, out, seen);
    }
  }
}

/**
 * Helper returning the maximum severity across findings.
 */
export function maxSeverity(findings?: AgentGuardFinding[]): Severity | undefined {
  if (!findings || findings.length === 0) return undefined;
  let max: Severity = 'unknown';
  for (const f of findings) { if (rank[f.severity] > rank[max]) max = f.severity; }
  return max;
}

/**
 * Returns a short substring around the regex match for human review.
 */
function snippet(text: string, re: RegExp): string {
  try {
    const m = text.match(re); if (!m) return '';
    const i = m.index ?? 0; const start = Math.max(0, i - 20); const end = Math.min(text.length, i + (m[0]?.length || 0) + 20);
    return text.slice(start, end);
  } catch { return ''; }
}

