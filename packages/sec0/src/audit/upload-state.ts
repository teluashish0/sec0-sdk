import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { logger } from "./logger";
import type { UploadState } from "./types";

const STATE_FILE_NAME = ".sec0-presign-state.json";
const SHARED_UPLOAD_STATE = new Map<string, UploadStateManager>();

/**
 * Manages persisted upload offsets to support incremental (delta) uploads.
 */
export class UploadStateManager {
  private readonly statePath: string;
  private state: UploadState = {
    auditOffsetsByDate: {},
    agentOffsetsByKey: {},
    rawOffsetsByDate: {},
  };

  constructor(baseDir: string) {
    this.statePath = join(baseDir, STATE_FILE_NAME);
    this.load();
  }

  static shared(baseDir: string): UploadStateManager {
    const statePath = join(baseDir, STATE_FILE_NAME);
    const existing = SHARED_UPLOAD_STATE.get(statePath);
    if (existing) return existing;
    const created = new UploadStateManager(baseDir);
    SHARED_UPLOAD_STATE.set(statePath, created);
    return created;
  }

  getAuditOffset(date: string): number {
    return this.safeOffset(this.state.auditOffsetsByDate[date]);
  }

  setAuditOffset(date: string, offset: number): void {
    this.state.auditOffsetsByDate[date] = offset;
    this.persist();
  }

  getRawOffset(date: string): number {
    return this.safeOffset(this.state.rawOffsetsByDate[date]);
  }

  setRawOffset(date: string, offset: number): void {
    this.state.rawOffsetsByDate[date] = offset;
    this.persist();
  }

  getAgentOffset(key: string): number {
    return this.safeOffset(this.state.agentOffsetsByKey[key]);
  }

  setAgentOffset(key: string, offset: number): void {
    this.state.agentOffsetsByKey[key] = offset;
    this.persist();
  }

  // Compute the byte range to upload: { start, deltaBytes }.
  // Returns null if there are no new bytes to upload.
  computeDelta(fileSize: number, lastOffset: number): { start: number; deltaBytes: number } | null {
    const safeLast = lastOffset > fileSize ? 0 : lastOffset;
    const deltaBytes = fileSize - safeLast;
    if (deltaBytes <= 0) return null;
    return { start: safeLast, deltaBytes };
  }

  private load(): void {
    try {
      if (!existsSync(this.statePath)) return;
      const raw = readFileSync(this.statePath, { encoding: "utf8" });
      if (!raw.trim()) return;
      const parsed = JSON.parse(raw);
      this.state = {
        auditOffsetsByDate: this.parseOffsets(parsed?.auditOffsetsByDate),
        agentOffsetsByKey: this.parseOffsets(parsed?.agentOffsetsByKey),
        rawOffsetsByDate: this.parseOffsets(parsed?.rawOffsetsByDate),
      };
    } catch (err) {
      logger.warn("Failed to load upload state; starting fresh", {
        error: (err as Error)?.message,
      });
    }
  }

  private persist(): void {
    try {
      writeFileSync(
        this.statePath,
        JSON.stringify(this.state, null, 2) + "\n",
        { encoding: "utf8" }
      );
    } catch (err) {
      logger.warn("Failed to persist upload state", {
        error: (err as Error)?.message,
      });
    }
  }

  private parseOffsets(value: unknown): Record<string, number> {
    return value && typeof value === "object" ? (value as Record<string, number>) : {};
  }

  private safeOffset(value: unknown): number {
    const n = Number(value ?? 0);
    return Number.isFinite(n) && n >= 0 ? Math.floor(n) : 0;
  }
}
