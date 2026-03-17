// Default Sec0 control plane URL.
export const DEFAULT_CONTROL_PLANE_URL = "https://api.sec0.ai";

// Default HTTP request timeout in milliseconds.
export const DEFAULT_TIMEOUT_MS = 5_000;

// Cache TTL for presign hierarchy resolution (milliseconds).
export const HIERARCHY_CACHE_TTL_MS = 60_000;

// Default discovery cache TTL when server does not specify (seconds).
export const DEFAULT_DISCOVERY_CACHE_TTL_SECONDS = 300;

// Content type for NDJSON files.
export const CONTENT_TYPE_NDJSON = "application/x-ndjson";

// Max length for sanitized path segments.
export const MAX_SEGMENT_LENGTH = 120;

// Log prefix for all audit package messages.
export const LOG_PREFIX = "[sec0-audit]";
