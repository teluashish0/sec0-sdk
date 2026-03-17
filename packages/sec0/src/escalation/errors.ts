import type { EscalationResolution } from "./config";

export const TERMINAL_STATUSES = new Set(["approved", "rejected", "expired"]);

export class Sec0EscalationError extends Error {
  readonly details?: Record<string, unknown>;

  constructor(message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = "Sec0EscalationError";
    this.details = details;
  }
}

export class Sec0EscalationCreateError extends Sec0EscalationError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, details);
    this.name = "Sec0EscalationCreateError";
  }
}

export class Sec0EscalationGetError extends Sec0EscalationError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, details);
    this.name = "Sec0EscalationGetError";
  }
}

export class Sec0EscalationResolveError extends Sec0EscalationError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, details);
    this.name = "Sec0EscalationResolveError";
  }
}

export class Sec0EscalationWaitError extends Sec0EscalationError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, details);
    this.name = "Sec0EscalationWaitError";
  }
}

export class Sec0EscalationAbortError extends Sec0EscalationWaitError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, details);
    this.name = "Sec0EscalationAbortError";
  }
}

export function mapResolutionStatus(status: string): EscalationResolution["status"] | null {
  const normalized = String(status || "").trim().toLowerCase();
  if (normalized === "approved" || normalized === "rejected" || normalized === "expired") {
    return normalized;
  }
  return null;
}

export function isEscalationTerminal(status: string | null | undefined): boolean {
  return TERMINAL_STATUSES.has(String(status || "").trim().toLowerCase());
}
