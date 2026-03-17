import { createReadStream, existsSync, statSync } from "node:fs";
import { CONTENT_TYPE_NDJSON, LOG_PREFIX } from "./constants";
import { requestUploadUrl, withTimeout } from "./http";
import { ensureString, sanitizeSegment } from "./validation";
import { normalizePresignConfig } from "./config";
import { logger } from "./logger";
import type { Sec0Config, ResolvedPresignConfig } from "./types";
import type { UploadStateManager } from "./upload-state";
import type { FileManager } from "./file-manager";
import type { DiscoveryService } from "./discovery";

interface UploaderDeps {
  config: Sec0Config;
  fileManager: FileManager;
  uploadState: UploadStateManager;
  discovery: DiscoveryService;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isRetryableUploadError(error: unknown): boolean {
  const text = String((error as any)?.message || error || "").toLowerCase();
  if (!text) return false;
  return (
    text.includes("aborterror") ||
    text.includes("this operation was aborted") ||
    text.includes("timed out") ||
    text.includes("timeout") ||
    text.includes("unreachable") ||
    text.includes("fetch failed") ||
    text.includes("econnreset") ||
    text.includes("socket hang up") ||
    text.includes("status 429") ||
    text.includes("status 500") ||
    text.includes("status 502") ||
    text.includes("status 503") ||
    text.includes("status 504")
  );
}

/**
 * Orchestrates presigned uploads for audit, raw, and agent log files.
 * All upload types share a single uploadDelta code path.
 */
export class Uploader {
  private static readonly inFlightByFilePath = new Map<string, Promise<void>>();
  private static readonly maxUploadAttempts = Number.isFinite(Number(process.env.SEC0_AUDIT_UPLOAD_MAX_ATTEMPTS))
    ? Math.max(1, Math.floor(Number(process.env.SEC0_AUDIT_UPLOAD_MAX_ATTEMPTS)))
    : 3;
  private static readonly retryBaseDelayMs = Number.isFinite(Number(process.env.SEC0_AUDIT_UPLOAD_RETRY_DELAY_MS))
    ? Math.max(100, Math.floor(Number(process.env.SEC0_AUDIT_UPLOAD_RETRY_DELAY_MS)))
    : 750;
  private readonly config: Sec0Config;
  private readonly files: FileManager;
  private readonly state: UploadStateManager;
  private readonly discovery: DiscoveryService;

  constructor(deps: UploaderDeps) {
    this.config = deps.config;
    this.files = deps.fileManager;
    this.state = deps.uploadState;
    this.discovery = deps.discovery;
  }

  async uploadAudit(date: string): Promise<void> {
    const cfg = await this.resolveConfig();
    const filePath = this.files.auditFilePath(date);
    const key = this.buildIngestKey(cfg, date);

    await this.uploadDelta({
      filePath,
      getLastOffset: () => this.state.getAuditOffset(date),
      key,
      cfg,
      onSuccess: (newOffset) => this.state.setAuditOffset(date, newOffset),
    });
  }

  async uploadRaw(date: string): Promise<void> {
    const cfg = await this.resolveConfig();
    const filePath = this.files.rawFilePath(date);
    const key = this.buildRawKey(cfg, date);

    await this.uploadDelta({
      filePath,
      getLastOffset: () => this.state.getRawOffset(date),
      key,
      cfg,
      extraBody: { mode: "raw", date },
      onSuccess: (newOffset) => this.state.setRawOffset(date, newOffset),
    });
  }

  async uploadAgent(nodeId: string, date: string, ref: string): Promise<void> {
    const cfg = await this.resolveConfig();
    const filePath = this.files.agentFilePath(nodeId, date, ref);
    const agentStateKey = `${sanitizeSegment(nodeId)}/${date}/${sanitizeSegment(ref)}`;
    const key = this.buildAgentKey(cfg, nodeId, date, ref);

    await this.uploadDelta({
      filePath,
      getLastOffset: () => this.state.getAgentOffset(agentStateKey),
      key,
      cfg,
      onSuccess: (newOffset) => this.state.setAgentOffset(agentStateKey, newOffset),
    });
  }

  // Fire-and-forget wrapper that surfaces failures via logging and the optional error hook.
  fireAndForget(work: Promise<unknown>): void {
    work.catch((err) => {
      const error = err instanceof Error ? err : new Error(String(err));
      try {
        this.config.onAsyncError?.(error);
      } catch { /* never propagate hook errors */ }
      logger.error("Async upload failed", { error: error.message });
    });
  }

  private async resolveConfig(): Promise<ResolvedPresignConfig> {
    if (!this.config.presign) {
      throw new Error(`${LOG_PREFIX} presign configuration is required`);
    }
    const normalized = normalizePresignConfig(this.config.presign);
    return this.discovery.resolveHierarchy(normalized);
  }

  // Unified upload-delta logic: compute byte range, request presigned URL, PUT new bytes.
  private async uploadDelta(params: {
    filePath: string;
    getLastOffset: () => number;
    key: string;
    cfg: ResolvedPresignConfig;
    extraBody?: Record<string, unknown>;
    onSuccess: (newOffset: number) => void;
  }): Promise<void> {
    const { filePath, getLastOffset, key, cfg, extraBody, onSuccess } = params;
    const existing = Uploader.inFlightByFilePath.get(filePath);
    if (existing) {
      await existing;
    }

    const work = (async () => {
      if (!existsSync(filePath)) return;
      const stat = statSync(filePath);
      const lastOffset = getLastOffset();
      const delta = this.state.computeDelta(stat.size, lastOffset);
      if (!delta) return;

      let lastError: Error | null = null;
      for (let attempt = 1; attempt <= Uploader.maxUploadAttempts; attempt += 1) {
        try {
          const payload = await requestUploadUrl(cfg, {
            key,
            tenant: cfg.tenant,
            env: cfg.environment,
            contentType: CONTENT_TYPE_NDJSON,
            clientName: cfg.clientName,
            clientVersion: cfg.clientVersion,
            ...extraBody,
          });

          const uploadHeaders = {
            ...(payload.headers || {}),
            "Content-Length": String(delta.deltaBytes),
            "Content-Type": CONTENT_TYPE_NDJSON,
          };

          const stream = createReadStream(filePath, {
            start: delta.start,
            end: stat.size - 1,
          });

          const uploadResp = await withTimeout(cfg.timeoutMs, (signal) =>
            fetch(payload.url, {
              method: "PUT",
              headers: uploadHeaders,
              body: stream as unknown as BodyInit,
              signal,
              // @ts-expect-error Node.js fetch requires duplex for streaming bodies
              duplex: "half",
            })
          );

          if (!uploadResp.ok) {
            throw new Error(`${LOG_PREFIX} upload failed with status ${uploadResp.status}`);
          }

          onSuccess(stat.size);
          return;
        } catch (error) {
          lastError = error instanceof Error ? error : new Error(String(error));
          if (attempt >= Uploader.maxUploadAttempts || !isRetryableUploadError(lastError)) {
            throw lastError;
          }
          logger.warn("Retrying async upload after transient failure", {
            filePath,
            attempt,
            maxAttempts: Uploader.maxUploadAttempts,
            error: lastError.message,
          });
          await sleep(Uploader.retryBaseDelayMs * attempt);
        }
      }

      if (lastError) throw lastError;
    })();

    Uploader.inFlightByFilePath.set(filePath, work);
    try {
      await work;
    } finally {
      if (Uploader.inFlightByFilePath.get(filePath) === work) {
        Uploader.inFlightByFilePath.delete(filePath);
      }
    }
  }

  private buildIngestKey(cfg: ResolvedPresignConfig, date: string): string {
    const safeTs = new Date().toISOString().replace(/[:]/g, "-");
    const nonce = Math.random().toString(16).slice(2, 10);
    return [
      "tenants",
      ensureString(cfg.tenant, "tenant"),
      ensureString(cfg.environment, "environment"),
      "clients",
      ensureString(cfg.clientName, "clientName"),
      ensureString(cfg.clientVersion, "clientVersion"),
      "ingest",
      date,
      `audit-${date}-${safeTs}-${nonce}.ndjson`,
    ].join("/");
  }

  private buildRawKey(cfg: ResolvedPresignConfig, date: string): string {
    const year = date.slice(0, 4);
    const month = date.slice(5, 7);
    const day = date.slice(8, 10);
    if (!year || !month || !day) {
      throw new Error(`${LOG_PREFIX} raw payload date is invalid`);
    }
    const safeTs = new Date().toISOString().replace(/[:]/g, "-");
    return [
      "tenants",
      ensureString(cfg.tenant, "tenant"),
      ensureString(cfg.environment, "environment"),
      "clients",
      ensureString(cfg.clientName, "clientName"),
      ensureString(cfg.clientVersion, "clientVersion"),
      "raw",
      year,
      month,
      day,
      `raw-${safeTs}.ndjson`,
    ].join("/");
  }

  private buildAgentKey(
    cfg: ResolvedPresignConfig,
    nodeId: string,
    date: string,
    ref: string
  ): string {
    const safeTs = new Date().toISOString().replace(/[:]/g, "-");
    return [
      "tenants",
      ensureString(cfg.tenant, "tenant"),
      ensureString(cfg.environment, "environment"),
      "clients",
      ensureString(cfg.clientName, "clientName"),
      ensureString(cfg.clientVersion, "clientVersion"),
      "agents",
      sanitizeSegment(nodeId),
      date,
      sanitizeSegment(ref),
      `agent-${safeTs}.ndjson`,
    ].join("/");
  }
}
