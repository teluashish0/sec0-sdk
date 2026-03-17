export type GuardErrorCode =
  | "SEC0_GUARD_CONFIG_INVALID"
  | "SEC0_GUARD_POLICY_UNAVAILABLE"
  | "SEC0_GUARD_POLICY_INVALID"
  | "SEC0_GUARD_PROVIDER_ERROR"
  | "SEC0_GUARD_BLOCKED"
  | "SEC0_GUARD_ESCALATION_FAILED"
  | "SEC0_GUARD_ESCALATION_TIMEOUT"
  | "SEC0_GUARD_ABORTED";

export class Sec0GuardError extends Error {
  readonly code: GuardErrorCode;
  readonly details?: Record<string, unknown>;

  constructor(code: GuardErrorCode, message: string, details?: Record<string, unknown>) {
    super(message);
    this.code = code;
    this.details = details;
  }
}

export class GuardConfigError extends Sec0GuardError {
  constructor(message: string, details?: Record<string, unknown>) {
    super("SEC0_GUARD_CONFIG_INVALID", message, details);
  }
}

export class GuardPolicyUnavailableError extends Sec0GuardError {
  constructor(message: string, details?: Record<string, unknown>) {
    super("SEC0_GUARD_POLICY_UNAVAILABLE", message, details);
  }
}

export class GuardPolicyInvalidError extends Sec0GuardError {
  constructor(message: string, details?: Record<string, unknown>) {
    super("SEC0_GUARD_POLICY_INVALID", message, details);
  }
}

export class GuardProviderError extends Sec0GuardError {
  constructor(message: string, details?: Record<string, unknown>) {
    super("SEC0_GUARD_PROVIDER_ERROR", message, details);
  }
}

export class GuardBlockedError extends Sec0GuardError {
  constructor(message: string, details?: Record<string, unknown>) {
    super("SEC0_GUARD_BLOCKED", message, details);
  }
}

export class GuardEscalationError extends Sec0GuardError {
  constructor(message: string, details?: Record<string, unknown>) {
    super("SEC0_GUARD_ESCALATION_FAILED", message, details);
  }
}

export class GuardEscalationTimeoutError extends Sec0GuardError {
  constructor(message: string, details?: Record<string, unknown>) {
    super("SEC0_GUARD_ESCALATION_TIMEOUT", message, details);
  }
}

export class GuardAbortError extends Sec0GuardError {
  constructor(message: string, details?: Record<string, unknown>) {
    super("SEC0_GUARD_ABORTED", message, details);
  }
}
