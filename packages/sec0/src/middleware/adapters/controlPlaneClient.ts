import { resolveControlPlaneUrl } from "../controlPlane";

export interface ControlPlaneClientDiscoveryResult {
  controlPlaneUrl: string;
  tenant?: string;
  env?: string;
  clientName?: string;
  clientVersion?: string;
  cacheTtlSeconds?: number;
}

export interface ControlPlaneClientValidationResult {
  tenant: string;
  env: "prod" | "staging" | "dev";
  clientName: string;
  clientVersion: string;
  userId?: string;
}

export interface ControlPlanePolicyFetchResult {
  yaml: string;
  etag: string | null;
}

export interface ControlPlaneUploadUrlResponse {
  url: string;
  key?: string;
  headers?: Record<string, string>;
}

export interface ControlPlaneCreateEscalationPayload {
  content: string;
  violation: string;
  rule_id?: string | null;
  message?: string | null;
  severity?: "low" | "medium" | "high" | "critical" | null;
  node_id?: string | null;
  agent_ref?: string | null;
  metadata?: Record<string, unknown> | null;
  finding_source?: "rule" | "evaluator" | null;
  evaluator_fingerprint?: string | null;
  evaluator_confidence?: number | null;
  evaluator_principles?: string[] | null;
  evaluator_snapshot?: Record<string, unknown> | null;
  ttl_seconds?: number;
  timeout_action?: "auto_approve" | "auto_reject";
  approval_strategy?: "auto_allow" | "single_approver" | "human_quorum";
  approval_set_id?: string | null;
  min_approvals?: number | null;
  min_rejections?: number | null;
  required_roles?: string[] | null;
  veto_roles?: string[] | null;
}

export interface ControlPlaneCreateEscalationResult {
  id: string;
  status: string;
  expiresAt?: string;
  createdAt?: string;
  requesterStatusMessage?: string;
}

export interface ControlPlaneEscalationStatusResult {
  id: string;
  status: string;
  expiresAt?: string;
  createdAt?: string;
  resolvedAt?: string;
  finalizationReason?: string | null;
  requesterStatusMessage?: string;
  metadata?: Record<string, unknown> | null;
}

export interface ControlPlaneEscalationResolveResult {
  escalation: ControlPlaneEscalationStatusResult;
}

export interface ControlPlaneContextualEvaluatorResult {
  decision: "allow" | "escalate" | "deny";
  confidence: number;
  principles: string[];
  summary: string;
  reasoning: string;
  evidence: Array<{
    label: string;
    detail: string;
    path?: string;
  }>;
  suggestedSeverity: "low" | "medium" | "high" | "critical";
  suggestedRemediation: {
    summary: string;
    steps: string[];
  };
  normalizedFingerprint: string;
}

export interface ControlPlaneClientOptions {
  baseUrl?: string;
}

function normalizeAuthToken(token: string): string {
  const trimmed = String(token || "").trim();
  if (!trimmed) {
    throw new Error("[sec0-middleware] auth token is required");
  }
  if (/^bearer\s+/i.test(trimmed)) return trimmed;
  return `Bearer ${trimmed}`;
}

export class ControlPlaneClient {
  readonly baseUrl: string;

  constructor(opts: ControlPlaneClientOptions = {}) {
    this.baseUrl = resolveControlPlaneUrl(opts.baseUrl);
  }

  private withTimeout<T>(timeoutMs: number, run: (signal: AbortSignal) => Promise<T>): Promise<T> {
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
      return run(new AbortController().signal);
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    return run(controller.signal).finally(() => {
      clearTimeout(timer);
    });
  }

  async discover(apiKey: string, timeoutMs = 4000): Promise<ControlPlaneClientDiscoveryResult> {
    const key = String(apiKey || "").trim();
    if (!key) {
      throw new Error("[sec0-middleware] API key is required for discovery");
    }
    const url = `${this.baseUrl}/api/discover`;
    const response = await this.withTimeout(timeoutMs, (signal) =>
      fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-api-key": key,
        },
        body: JSON.stringify({ apiKey: key }),
        signal,
      } as any),
    );
    if (!response.ok) {
      const body = await response.text().catch(() => "");
      throw new Error(`[sec0-middleware] discovery_failed:${response.status}:${body || "empty"}`);
    }
    const payload = (await response.json().catch(() => null)) as ControlPlaneClientDiscoveryResult | null;
    if (!payload || !payload.controlPlaneUrl) {
      throw new Error("[sec0-middleware] discovery response missing controlPlaneUrl");
    }
    return payload;
  }

  async validateKey(apiKey: string, timeoutMs = 4000): Promise<ControlPlaneClientValidationResult> {
    const key = String(apiKey || "").trim();
    if (!key) {
      throw new Error("[sec0-middleware] API key is required for validation");
    }
    const url = `${this.baseUrl}/api/auth/validate-key`;
    const response = await this.withTimeout(timeoutMs, (signal) =>
      fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-api-key": key,
        },
        body: JSON.stringify({ apiKey: key }),
        signal,
      } as any),
    );
    if (!response.ok) {
      const body = await response.text().catch(() => "");
      throw new Error(`[sec0-middleware] validate_key_failed:${response.status}:${body || "empty"}`);
    }
    const payload = (await response.json().catch(() => null)) as any;
    const tenant = String(payload?.tenant || "").trim();
    const env = String(payload?.env || "").trim();
    const clientName = String(payload?.clientName || "").trim();
    const clientVersion = String(payload?.clientVersion || "").trim();
    if (!tenant || !env || !clientName || !clientVersion) {
      throw new Error("[sec0-middleware] validate-key response missing hierarchy metadata");
    }
    return {
      tenant,
      env: env as ControlPlaneClientValidationResult["env"],
      clientName,
      clientVersion,
      ...(typeof payload?.userId === "string" ? { userId: payload.userId } : {}),
    };
  }

  async fetchPolicy(opts: {
    tenant: string;
    level: "gateway" | "middleware";
    authToken: string;
    nodeId?: string | null;
    replayJobId?: string;
    replayRunnerId?: string;
  }): Promise<ControlPlanePolicyFetchResult> {
    const tenant = String(opts.tenant || "").trim();
    if (!tenant) {
      throw new Error("[sec0-middleware] tenant is required to fetch policy");
    }
    const url =
      `${this.baseUrl}/api/policy/${encodeURIComponent(tenant)}` +
      `?level=${encodeURIComponent(opts.level)}` +
      (opts.nodeId ? `&nodeId=${encodeURIComponent(opts.nodeId)}` : "");
    const response = await fetch(url, {
      method: "GET",
      headers: {
        Accept: "text/yaml",
        Authorization: normalizeAuthToken(opts.authToken),
        ...(opts.replayJobId && opts.replayRunnerId
          ? {
              "x-sec0-replay-job-id": opts.replayJobId,
              "x-sec0-replay-runner-id": opts.replayRunnerId,
            }
          : {}),
      },
      cache: "no-store",
    } as any);
    const yaml = await response.text().catch(() => "");
    if (!response.ok) {
      throw new Error(`[sec0-middleware] policy_fetch_failed:${response.status}:${yaml || "empty"}`);
    }
    return {
      yaml,
      etag: response.headers.get("etag"),
    };
  }

  async putPolicy(opts: {
    tenant: string;
    level: "gateway" | "middleware";
    authToken: string;
    yaml: string;
    urlOverride?: string;
  }): Promise<void> {
    const tenant = String(opts.tenant || "").trim();
    if (!tenant) {
      throw new Error("[sec0-middleware] tenant is required to publish policy");
    }
    const url =
      String(opts.urlOverride || "").trim() ||
      `${this.baseUrl}/api/policy/${encodeURIComponent(tenant)}?level=${encodeURIComponent(opts.level)}`;
    const response = await fetch(url, {
      method: "PUT",
      headers: {
        "Content-Type": "text/yaml",
        Authorization: normalizeAuthToken(opts.authToken),
      },
      body: opts.yaml,
    } as any);
    if (!response.ok) {
      const txt = await response.text().catch(() => "");
      throw new Error(`policy_publish_failed:${response.status}:${txt}`);
    }
  }

  async requestUploadUrl(opts: {
    authToken: string;
    body: Record<string, unknown>;
  }): Promise<ControlPlaneUploadUrlResponse> {
    const response = await fetch(`${this.baseUrl}/api/sec0/upload-url`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: normalizeAuthToken(opts.authToken),
      },
      body: JSON.stringify(opts.body || {}),
    } as any);
    if (!response.ok) {
      throw new Error(`presign_failed:${response.status}`);
    }
    const payload = (await response.json().catch(() => null)) as ControlPlaneUploadUrlResponse | null;
    if (!payload?.url) {
      throw new Error("presign_missing_url");
    }
    return payload;
  }

  async uploadToPresignedUrl(opts: {
    url: string;
    body: string | Buffer;
    headers?: Record<string, string>;
  }): Promise<void> {
    const response = await fetch(opts.url, {
      method: "PUT",
      headers: opts.headers as any,
      body: typeof opts.body === "string" ? Buffer.from(opts.body, "utf8") : opts.body,
    } as any);
    if (!response.ok) {
      throw new Error(`upload_failed:${response.status}`);
    }
  }

  async evaluateComplianceNl(opts: {
    authToken: string;
    instruction: string;
    text: string;
    threshold: number;
    provider?: "openai" | "anthropic";
    apiKey?: string;
    model?: string;
    timeoutMs?: number;
  }): Promise<{ score: number; evidence?: string }> {
    const response = await this.withTimeout(opts.timeoutMs ?? 4000, (signal) =>
      fetch(`${this.baseUrl}/api/compliance/nl-eval`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: normalizeAuthToken(opts.authToken),
        },
        body: JSON.stringify({
          instruction: opts.instruction,
          text: opts.text,
          threshold: opts.threshold,
          ...(opts.provider ? { provider: opts.provider } : {}),
          ...(opts.apiKey ? { api_key: opts.apiKey } : {}),
          ...(opts.model ? { model: opts.model } : {}),
        }),
        signal: signal as any,
      } as any),
    );
    if (!response.ok) {
      const body = await response.text().catch(() => "");
      throw new Error(`nl_eval_failed:${response.status}:${body || "empty"}`);
    }
    const payload = (await response.json().catch(() => null)) as any;
    return {
      score: Number(payload?.score) || 0,
      ...(typeof payload?.evidence === "string" ? { evidence: payload.evidence } : {}),
    };
  }

  async evaluateContextualEvaluator(opts: {
    authToken: string;
    input: Record<string, unknown>;
    timeoutMs?: number;
  }): Promise<ControlPlaneContextualEvaluatorResult> {
    const response = await this.withTimeout(opts.timeoutMs ?? 4000, (signal) =>
      fetch(`${this.baseUrl}/api/evaluator/contextual`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: normalizeAuthToken(opts.authToken),
        },
        body: JSON.stringify(opts.input || {}),
        signal: signal as any,
      } as any),
    );
    if (!response.ok) {
      const body = await response.text().catch(() => "");
      throw new Error(`contextual_evaluator_failed:${response.status}:${body || "empty"}`);
    }
    return (await response.json().catch(() => null)) as ControlPlaneContextualEvaluatorResult;
  }

  async verifyApproval(opts: {
    authToken: string;
    token: string;
    toolRef: string;
    nodeId?: string;
    agentRef?: string;
    timeoutMs?: number;
  }): Promise<{ valid: boolean; approval?: unknown }> {
    const response = await this.withTimeout(opts.timeoutMs ?? 2500, (signal) =>
      fetch(`${this.baseUrl}/api/compliance/approvals/verify`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: normalizeAuthToken(opts.authToken),
        },
        body: JSON.stringify({
          token: opts.token,
          context: {
            tool_ref: opts.toolRef,
            node_id: opts.nodeId || undefined,
            agent_ref: opts.agentRef || undefined,
          },
        }),
        signal: signal as any,
      } as any),
    );
    if (!response.ok) {
      const body = await response.text().catch(() => "");
      throw new Error(`approval_verify_failed:${response.status}:${body || "empty"}`);
    }
    const payload = (await response.json().catch(() => null)) as any;
    return {
      valid: payload?.valid === true,
      ...(payload?.approval !== undefined ? { approval: payload.approval } : {}),
    };
  }

  async createEscalation(opts: {
    authToken: string;
    payload: ControlPlaneCreateEscalationPayload;
    tenant?: string;
    timeoutMs?: number;
  }): Promise<ControlPlaneCreateEscalationResult> {
    const endpoint =
      `${this.baseUrl}/api/escalations` +
      (typeof opts.tenant === "string" && opts.tenant.trim()
        ? `?tenant=${encodeURIComponent(opts.tenant.trim())}`
        : "");
    const response = await this.withTimeout(opts.timeoutMs ?? 2500, (signal) =>
      fetch(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: normalizeAuthToken(opts.authToken),
        },
        body: JSON.stringify(opts.payload || {}),
        signal: signal as any,
      } as any),
    );
    if (!response.ok) {
      const body = await response.text().catch(() => "");
      throw new Error(`escalation_create_failed:${response.status}:${body || "empty"}`);
    }
    const data = (await response.json().catch(() => null)) as any;
    const escalation = data?.escalation;
    const id = typeof escalation?.id === "string" ? escalation.id : "";
    const status = typeof escalation?.status === "string" ? escalation.status : "";
    if (!id || !status) {
      throw new Error("escalation_create_invalid_response");
    }
    return {
      id,
      status,
      ...(typeof escalation?.expires_at === "string" ? { expiresAt: escalation.expires_at } : {}),
      ...(typeof escalation?.created_at === "string" ? { createdAt: escalation.created_at } : {}),
      ...(typeof escalation?.requester_status_message === "string"
        ? { requesterStatusMessage: escalation.requester_status_message }
        : {}),
    };
  }

  async getEscalation(opts: {
    authToken: string;
    id: string;
    tenant?: string;
    timeoutMs?: number;
  }): Promise<ControlPlaneEscalationStatusResult> {
    const escalationId = String(opts.id || "").trim();
    if (!escalationId) {
      throw new Error("escalation_id_required");
    }
    const endpoint =
      `${this.baseUrl}/api/escalations/${encodeURIComponent(escalationId)}` +
      (typeof opts.tenant === "string" && opts.tenant.trim()
        ? `?tenant=${encodeURIComponent(opts.tenant.trim())}`
        : "");
    const response = await this.withTimeout(opts.timeoutMs ?? 2500, (signal) =>
      fetch(endpoint, {
        method: "GET",
        headers: {
          Accept: "application/json",
          Authorization: normalizeAuthToken(opts.authToken),
        },
        signal: signal as any,
      } as any),
    );
    if (!response.ok) {
      const body = await response.text().catch(() => "");
      throw new Error(`escalation_get_failed:${response.status}:${body || "empty"}`);
    }
    const data = (await response.json().catch(() => null)) as any;
    const escalation = data?.escalation;
    const id = typeof escalation?.id === "string" ? escalation.id : "";
    const status = typeof escalation?.status === "string" ? escalation.status : "";
    if (!id || !status) {
      throw new Error("escalation_get_invalid_response");
    }
    return {
      id,
      status,
      ...(typeof escalation?.expires_at === "string" ? { expiresAt: escalation.expires_at } : {}),
      ...(typeof escalation?.created_at === "string" ? { createdAt: escalation.created_at } : {}),
      ...(typeof escalation?.resolved_at === "string" ? { resolvedAt: escalation.resolved_at } : {}),
      ...(typeof escalation?.finalization_reason === "string"
        ? { finalizationReason: escalation.finalization_reason }
        : {}),
      ...(typeof escalation?.requester_status_message === "string"
        ? { requesterStatusMessage: escalation.requester_status_message }
        : {}),
      ...(escalation?.metadata && typeof escalation.metadata === "object" && !Array.isArray(escalation.metadata)
        ? { metadata: escalation.metadata as Record<string, unknown> }
        : {}),
    };
  }

  async resolveEscalation(opts: {
    authToken: string;
    id: string;
    action: "approve" | "reject";
    tenant?: string;
    notes?: string | null;
    timeoutMs?: number;
  }): Promise<ControlPlaneEscalationResolveResult> {
    const escalationId = String(opts.id || "").trim();
    if (!escalationId) {
      throw new Error("escalation_id_required");
    }
    const endpoint =
      `${this.baseUrl}/api/escalations/${encodeURIComponent(escalationId)}` +
      (typeof opts.tenant === "string" && opts.tenant.trim()
        ? `?tenant=${encodeURIComponent(opts.tenant.trim())}`
        : "");
    const response = await this.withTimeout(opts.timeoutMs ?? 2500, (signal) =>
      fetch(endpoint, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          Authorization: normalizeAuthToken(opts.authToken),
        },
        body: JSON.stringify({
          action: opts.action,
          ...(typeof opts.notes === "string" && opts.notes.trim() ? { notes: opts.notes.trim() } : {}),
        }),
        signal: signal as any,
      } as any),
    );
    if (!response.ok) {
      const body = await response.text().catch(() => "");
      throw new Error(`escalation_resolve_failed:${response.status}:${body || "empty"}`);
    }
    const data = (await response.json().catch(() => null)) as any;
    const escalation = data?.escalation;
    const id = typeof escalation?.id === "string" ? escalation.id : "";
    const status = typeof escalation?.status === "string" ? escalation.status : "";
    if (!id || !status) {
      throw new Error("escalation_resolve_invalid_response");
    }
    return {
      escalation: {
        id,
        status,
        ...(typeof escalation?.expires_at === "string" ? { expiresAt: escalation.expires_at } : {}),
        ...(typeof escalation?.created_at === "string" ? { createdAt: escalation.created_at } : {}),
        ...(typeof escalation?.resolved_at === "string" ? { resolvedAt: escalation.resolved_at } : {}),
        ...(typeof escalation?.finalization_reason === "string"
          ? { finalizationReason: escalation.finalization_reason }
          : {}),
        ...(typeof escalation?.requester_status_message === "string"
          ? { requesterStatusMessage: escalation.requester_status_message }
          : {}),
        ...(escalation?.metadata && typeof escalation.metadata === "object" && !Array.isArray(escalation.metadata)
          ? { metadata: escalation.metadata as Record<string, unknown> }
          : {}),
      },
    };
  }
}

export function createControlPlaneClient(opts: ControlPlaneClientOptions = {}): ControlPlaneClient {
  return new ControlPlaneClient(opts);
}
