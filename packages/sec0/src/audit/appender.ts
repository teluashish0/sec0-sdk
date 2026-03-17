import { canonicalize, toBase64 } from "../signer";
import type { Signer } from "../signer";
import type { Sec0Config, AuditEnvelopeMinimal, RawPayloadEvent, Sec0AppenderOptions } from "./types";
import { LOG_PREFIX } from "./constants";
import { normalizeRawEvent } from "./validation";
import { FileManager } from "./file-manager";
import { UploadStateManager } from "./upload-state";
import { DiscoveryService } from "./discovery";
import { Uploader } from "./uploader";

/**
 * Append-only NDJSON audit log writer with daily rotation and optional presigned uploads.
 *
 * Public API:
 *   append(envelope)       - sign and write an audit envelope
 *   appendRawPayload(event) - write a raw payload event
 *   flush()                - drain buffered writes and trigger pending uploads
 */
export class Sec0Appender {
  private readonly config: Sec0Config;
  private readonly signer: Signer;
  private readonly files: FileManager;
  private readonly uploader: Uploader;

  constructor(opts: Sec0AppenderOptions) {
    this.config = opts.config;
    this.signer = opts.signer;

    this.files = new FileManager(this.config.dir);
    const uploadState = UploadStateManager.shared(this.config.dir);
    const discovery = new DiscoveryService();
    this.uploader = new Uploader({
      config: this.config,
      fileManager: this.files,
      uploadState,
      discovery,
    });
  }

  // Sign and append an audit envelope to the daily log file.
  // When nodeId and agentRef are present, also writes to the per-agent log.
  async append(envelope: AuditEnvelopeMinimal & { sig?: string }): Promise<void> {
    const date = envelope.ts.slice(0, 10);

    const previousDate = this.files.rotateAuditStream(date);
    if (previousDate && this.config.presign) {
      this.uploader.fireAndForget(this.uploader.uploadAudit(previousDate));
    }

    const toSign = canonicalize(envelope);
    const signature = await Promise.resolve(this.signer.sign(Buffer.from(toSign)));
    const row = { ...envelope, sig: `ed25519:${toBase64(signature)}` };
    const line = JSON.stringify(row) + "\n";

    this.files.writeAuditLine(line);

    if (row.nodeId && row.agentRef) {
      const nodeId = String(row.nodeId);
      const ref = String(row.agentRef);
      this.files.writeAgentLine(nodeId, date, ref, line);
      if (this.config.presign) {
        this.uploader.fireAndForget(this.uploader.uploadAgent(nodeId, date, ref));
      }
    }
  }

  // Append a raw payload event to the daily raw log file.
  // Requires presign configuration for tenant/environment metadata.
  async appendRawPayload(event: RawPayloadEvent): Promise<void> {
    if (!this.config.presign) {
      throw new Error(`${LOG_PREFIX} presign configuration is required before recording raw payloads`);
    }

    const normalized = normalizeRawEvent(event, this.config.presign);
    const date = normalized.ts.slice(0, 10);

    const previousDate = this.files.rotateRawStream(date);
    if (previousDate && this.config.presign) {
      this.uploader.fireAndForget(this.uploader.uploadRaw(previousDate));
    }

    const line = JSON.stringify(normalized) + "\n";
    this.files.writeRawLine(line);
  }

  // Flush buffered writes and trigger presigned uploads for current files.
  async flush(): Promise<void> {
    await this.files.drainAuditStream();
    const auditDate = this.files.currentAuditDate;
    if (auditDate && this.config.presign) {
      await this.uploader.uploadAudit(auditDate);
    }

    await this.files.drainRawStream();
    const rawDate = this.files.currentRawDate;
    if (rawDate && this.config.presign) {
      await this.uploader.uploadRaw(rawDate);
    }
  }
}
