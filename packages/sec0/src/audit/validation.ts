import { MAX_SEGMENT_LENGTH, LOG_PREFIX } from "./constants";
import type { RawPayloadEvent, PresignConfig } from "./types";

/**
 * Assert that a value is a non-empty string, returning the trimmed result.
 */
export function ensureString(value: unknown, label: string): string {
  if (value === undefined || value === null) {
    throw new Error(`${LOG_PREFIX} ${label} is required`);
  }
  if (typeof value !== "string") {
    throw new Error(`${LOG_PREFIX} ${label} must be a string`);
  }
  const trimmed = value.trim();
  if (!trimmed) {
    throw new Error(`${LOG_PREFIX} ${label} cannot be empty`);
  }
  return trimmed;
}

/**
 * Assert that a value is a hex string of the expected length.
 */
export function ensureHex(value: unknown, length: number, label: string): string {
  const str = ensureString(value, label);
  const re = new RegExp(`^[0-9a-fA-F]{${length}}$`);
  if (!re.test(str)) {
    throw new Error(`${LOG_PREFIX} ${label} must be a ${length}-character hex string`);
  }
  return str.toLowerCase();
}

/**
 * Validate and normalize an ISO timestamp string.
 */
export function normalizeIsoTimestamp(value: string): string {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`${LOG_PREFIX} timestamp is required`);
  }
  const ms = Date.parse(value);
  if (Number.isNaN(ms)) {
    throw new Error(`${LOG_PREFIX} timestamp is invalid`);
  }
  return new Date(ms).toISOString();
}

/**
 * Validate and normalize direction to "input" or "output".
 */
export function normalizeDirection(value: unknown): "input" | "output" {
  const str = ensureString(value, "direction").toLowerCase();
  if (str !== "input" && str !== "output") {
    throw new Error(`${LOG_PREFIX} direction must be 'input' or 'output'`);
  }
  return str;
}

/**
 * Deep-clone a value via JSON round-trip, ensuring it is serializable.
 */
export function cloneJson<T>(value: T): T {
  if (value === undefined) return value;
  try {
    const json = JSON.stringify(value);
    if (json === undefined) return undefined as T;
    return JSON.parse(json) as T;
  } catch (err) {
    throw new Error(
      `${LOG_PREFIX} values must be JSON serializable (${(err as Error)?.message || err})`
    );
  }
}

/**
 * Sanitize a string for use as a file-system or object-key path segment.
 */
export function sanitizeSegment(value: string): string {
  const sanitized = value
    .toString()
    .trim()
    .replace(/[^A-Za-z0-9._-]+/g, "_")
    .replace(/_{2,}/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, MAX_SEGMENT_LENGTH);
  if (!sanitized) {
    throw new Error(`${LOG_PREFIX} sanitized segment resolved to an empty string`);
  }
  return sanitized;
}

/**
 * Validate a positive finite number.
 */
export function ensurePositiveBytes(value: unknown, label: string): number {
  const num = Number(value);
  if (!Number.isFinite(num) || num < 0) {
    throw new Error(`${LOG_PREFIX} ${label} must be a positive number when provided`);
  }
  return num;
}

/**
 * Normalize a raw payload event, filling defaults from the presign config where appropriate.
 */
export function normalizeRawEvent(event: RawPayloadEvent, presign: PresignConfig): RawPayloadEvent {
  if (!event || typeof event !== "object") {
    throw new Error(`${LOG_PREFIX} raw payload event is required`);
  }

  const ts = normalizeIsoTimestamp(event.ts);
  const trace_id = ensureHex(event.trace_id, 32, "trace_id");
  const span_id = ensureHex(event.span_id, 16, "span_id");
  const runId = ensureString(event.runId, "runId");
  const tenant = ensureString(event.tenant ?? presign.tenant, "tenant");
  const environment = ensureString(event.environment ?? presign.environment, "environment");
  const client = ensureString(event.client ?? presign.clientName, "client");
  const clientVersion = ensureString(event.clientVersion ?? presign.clientVersion, "clientVersion");
  const direction = normalizeDirection(event.direction);
  const nodeId = event.nodeId ? ensureString(event.nodeId, "nodeId") : undefined;
  const tool = event.tool ? ensureString(event.tool, "tool") : undefined;
  const payload = cloneJson(event.payload);
  const payload_preview = cloneJson(event.payload_preview);
  const metadata = cloneJson(event.metadata);
  const agent_state = cloneJson(event.agent_state);
  const payloadBytes =
    event.payload_bytes !== undefined
      ? ensurePositiveBytes(event.payload_bytes, "payload_bytes")
      : undefined;

  return {
    ts,
    trace_id,
    span_id,
    runId,
    tenant,
    environment,
    client,
    clientVersion,
    direction,
    ...(nodeId ? { nodeId } : {}),
    ...(tool ? { tool } : {}),
    ...(payload !== undefined ? { payload } : {}),
    ...(payload_preview !== undefined ? { payload_preview } : {}),
    ...(event.payload_truncated !== undefined ? { payload_truncated: !!event.payload_truncated } : {}),
    ...(payloadBytes !== undefined ? { payload_bytes: payloadBytes } : {}),
    ...(metadata ? { metadata } : {}),
    ...(agent_state ? { agent_state } : {}),
  };
}
