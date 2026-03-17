import { createWriteStream, existsSync, mkdirSync, appendFileSync } from "node:fs";
import { join } from "node:path";
import { sanitizeSegment } from "./validation";
import { LOG_PREFIX } from "./constants";

type WriteStream = ReturnType<typeof createWriteStream>;

/**
 * Manages audit file paths, directory creation, and daily-rotating write streams.
 */
export class FileManager {
  private readonly baseDir: string;
  private auditDate: string | null = null;
  private auditStream: WriteStream | null = null;
  private rawDate: string | null = null;
  private rawStream: WriteStream | null = null;

  constructor(baseDir: string) {
    if (!baseDir.trim()) {
      throw new Error(`${LOG_PREFIX} config.dir is required`);
    }
    this.baseDir = baseDir;
    if (!existsSync(this.baseDir)) {
      mkdirSync(this.baseDir, { recursive: true });
    }
  }

  // Current audit stream date (if active).
  get currentAuditDate(): string | null {
    return this.auditDate;
  }

  // Current raw stream date (if active).
  get currentRawDate(): string | null {
    return this.rawDate;
  }

  auditFilePath(date: string): string {
    return join(this.baseDir, `audit-${date}.ndjson`);
  }

  rawFilePath(date: string): string {
    const rawDir = join(this.baseDir, "raw");
    if (!existsSync(rawDir)) {
      mkdirSync(rawDir, { recursive: true });
    }
    return join(rawDir, `raw-${date}.ndjson`);
  }

  agentFilePath(nodeId: string, date: string, ref: string): string {
    const safeNodeId = sanitizeSegment(nodeId);
    const agentDir = join(this.baseDir, "agents", safeNodeId, date);
    if (!existsSync(agentDir)) {
      mkdirSync(agentDir, { recursive: true });
    }
    return join(agentDir, `${sanitizeSegment(ref)}.ndjson`);
  }

  // Ensure the audit stream targets the given date.
  // Returns the previous date if rotation occurred, or null otherwise.
  rotateAuditStream(date: string): string | null {
    if (this.auditDate === date && this.auditStream) return null;
    const previousDate = this.auditDate;
    this.closeStream(this.auditStream);
    this.auditDate = date;
    this.auditStream = this.openStream(this.auditFilePath(date));
    return previousDate;
  }

  // Ensure the raw stream targets the given date.
  // Returns the previous date if rotation occurred, or null otherwise.
  rotateRawStream(date: string): string | null {
    if (this.rawDate === date && this.rawStream) return null;
    const previousDate = this.rawDate;
    this.closeStream(this.rawStream);
    this.rawDate = date;
    this.rawStream = this.openStream(this.rawFilePath(date));
    return previousDate;
  }

  writeAuditLine(line: string): void {
    if (!this.auditStream) {
      throw new Error(`${LOG_PREFIX} audit stream is not initialized`);
    }
    this.auditStream.write(line);
  }

  writeRawLine(line: string): void {
    if (!this.rawStream) {
      throw new Error(`${LOG_PREFIX} raw payload stream is not initialized`);
    }
    this.rawStream.write(line);
  }

  writeAgentLine(nodeId: string, date: string, ref: string, line: string): string {
    const filePath = this.agentFilePath(nodeId, date, ref);
    appendFileSync(filePath, line, { encoding: "utf8" });
    return filePath;
  }

  async drainAuditStream(): Promise<void> {
    if (this.auditStream && !this.auditStream.writable) {
      await new Promise<void>((resolve) => this.auditStream?.once("drain", () => resolve()));
    }
  }

  async drainRawStream(): Promise<void> {
    if (this.rawStream && !this.rawStream.writable) {
      await new Promise<void>((resolve) => this.rawStream?.once("drain", () => resolve()));
    }
  }

  // Close all active streams and release resources.
  close(): void {
    this.closeStream(this.auditStream);
    this.auditStream = null;
    this.auditDate = null;
    this.closeStream(this.rawStream);
    this.rawStream = null;
    this.rawDate = null;
  }

  private openStream(filePath: string): WriteStream {
    const stream = createWriteStream(filePath, { flags: "a" });
    stream.on("error", () => {
      // Suppress stream errors (e.g. ENOENT after destroy) to prevent uncaught exceptions.
    });
    return stream;
  }

  private closeStream(stream: WriteStream | null): void {
    if (stream) {
      try {
        stream.destroy();
      } catch {
        // Best-effort cleanup; never propagate.
      }
    }
  }
}
