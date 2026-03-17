import { LOG_PREFIX } from "./constants";

export type LogLevel = "info" | "warn" | "error";

export interface LogEntry {
  level: LogLevel;
  message: string;
  context?: Record<string, unknown>;
}

/**
 * Structured logger for the sec0-audit package.
 * Outputs JSON-formatted log lines to stderr/stdout.
 */
export class AuditLogger {
  info(message: string, context?: Record<string, unknown>): void {
    this.emit("info", message, context);
  }

  warn(message: string, context?: Record<string, unknown>): void {
    this.emit("warn", message, context);
  }

  error(message: string, context?: Record<string, unknown>): void {
    this.emit("error", message, context);
  }

  private emit(level: LogLevel, message: string, context?: Record<string, unknown>): void {
    const entry: LogEntry = {
      level,
      message: `${LOG_PREFIX} ${message}`,
      ...(context ? { context } : {}),
    };
    try {
      const line = JSON.stringify(entry);
      if (level === "error") {
        console.error(line);   // eslint-disable-line no-console
      } else if (level === "warn") {
        console.warn(line);    // eslint-disable-line no-console
      } else {
        console.log(line);     // eslint-disable-line no-console
      }
    } catch {
      // Never let logging failures propagate.
    }
  }
}

// Shared package-level logger instance.
export const logger = new AuditLogger();
