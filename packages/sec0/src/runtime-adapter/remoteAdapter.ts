import {
  RUNTIME_PROTOCOL_VERSION,
  type RuntimeAdapter,
  type RuntimeDecisionInput,
  type RuntimeDecisionOutput,
  type ResolvedRuntimeAdapterConfig,
} from "./types";
import { normalizeRuntimeDecisionInput, parseRuntimeProtocolResponse, withEvaluationSource } from "./shared";

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function shouldRetry(error: unknown, statusCode: number | null): boolean {
  if (typeof statusCode === "number") {
    return statusCode === 429 || statusCode >= 500;
  }
  if (!error || typeof error !== "object") return false;
  const e = error as any;
  if (e?.name === "AbortError") return true;
  if (typeof e?.code === "string" && ["ECONNRESET", "ECONNREFUSED", "ETIMEDOUT", "EAI_AGAIN"].includes(e.code)) return true;
  return true;
}

function shouldRetryAttempt(attempt: number, maxRetries: number): boolean {
  return attempt <= maxRetries;
}

export class RemoteRuntimeAdapter implements RuntimeAdapter {
  private readonly localAdapter: RuntimeAdapter;

  constructor(
    private readonly config: ResolvedRuntimeAdapterConfig,
    localAdapter: RuntimeAdapter,
  ) {
    this.localAdapter = localAdapter;
  }

  async evaluate(input: RuntimeDecisionInput): Promise<RuntimeDecisionOutput> {
    const normalized = normalizeRuntimeDecisionInput(input, this.config.protocolVersion);
    const endpoint = this.config.remote.endpoint;
    if (!endpoint) {
      const local = await this.localAdapter.evaluate(normalized);
      return withEvaluationSource({ ...local, adapterMode: "remote" }, "fallback-local");
    }

    const headers: Record<string, string> = {
      "content-type": "application/json",
      accept: "application/json",
      ...this.config.remote.headers,
    };
    if (this.config.remote.apiKey) {
      headers.authorization = this.config.remote.apiKey.startsWith("Bearer ")
        ? this.config.remote.apiKey
        : `Bearer ${this.config.remote.apiKey}`;
    }

    const maxAttempts = Math.max(1, this.config.remote.maxRetries + 1);
    let lastError: unknown;
    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      let statusCode: number | null = null;
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), this.config.remote.timeoutMs);
        try {
          const response = await fetch(endpoint, {
            method: "POST",
            headers,
            body: JSON.stringify(normalized),
            signal: controller.signal,
          } as any);
          statusCode = response.status;
          if (!response.ok) {
            const body = await response.text().catch(() => "");
            throw Object.assign(new Error(`runtime_remote_http_${response.status}:${body.slice(0, 256)}`), {
              statusCode: response.status,
            });
          }

          const payload = (await response.json().catch(() => {
            throw new Error("runtime_response_not_json");
          })) as any;
          const parsed = parseRuntimeProtocolResponse(payload, "remote");
          return {
            ...parsed,
            protocolVersion: parsed.protocolVersion || normalized.protocolVersion || RUNTIME_PROTOCOL_VERSION,
            adapterMode: "remote",
            evaluationSource: "remote",
          };
        } finally {
          clearTimeout(timeout);
        }
      } catch (error: unknown) {
        lastError = error;
        const statusFromError = typeof (error as any)?.statusCode === "number" ? Number((error as any).statusCode) : statusCode;
        const mayRetry = shouldRetry(error, statusFromError);
        if (mayRetry && shouldRetryAttempt(attempt, this.config.remote.maxRetries)) {
          const backoffMs = this.config.remote.retryBackoffMs * attempt;
          await sleep(backoffMs);
          continue;
        }
        break;
      }
    }

    return this.fallbackDecision(normalized, lastError);
  }

  private async fallbackDecision(input: RuntimeDecisionInput, _error: unknown): Promise<RuntimeDecisionOutput> {
    if (this.config.failureMode === "allow") {
      return {
        protocolVersion: this.config.protocolVersion,
        adapterMode: "remote",
        evaluationSource: "fallback-allow",
        decision: "allow",
        reason: "runtime_remote_unavailable_fallback_allow",
        reasons: input.input.reasons || [],
        obligations: [],
        auditRefs: [],
      };
    }
    if (this.config.failureMode === "deny") {
      return {
        protocolVersion: this.config.protocolVersion,
        adapterMode: "remote",
        evaluationSource: "fallback-deny",
        decision: "deny",
        reason: "runtime_remote_unavailable_fallback_deny",
        reasons: input.input.reasons || [],
        obligations: [],
        auditRefs: [],
      };
    }

    const local = await this.localAdapter.evaluate(input);
    return withEvaluationSource({ ...local, adapterMode: "remote" }, "fallback-local");
  }
}
