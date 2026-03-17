import type { Signer } from "../signer";

export interface PresignConfig {
  // Control plane URL override (defaults to SEC0_CONTROL_PLANE_URL env or https://api.sec0.ai).
  apiBaseUrl?: string;
  // API credential header value (e.g. "Bearer worm_...").
  auditKey: string;
  // Workspace/tenant slug (resolved from API key when omitted).
  tenant?: string;
  // Logical client name (resolved from API key when omitted).
  clientName?: string;
  // Client version string (resolved from API key when omitted).
  clientVersion?: string;
  // Environment identifier: dev | staging | prod (resolved from API key when omitted).
  environment?: string;
  // HTTP request timeout in milliseconds (default: 5 000).
  timeoutMs?: number;
}

export interface Sec0Config {
  // Local directory for staging audit files (required).
  dir: string;
  // Data retention period in days (informational; not enforced by this package).
  retentionDays?: number;
  // Optional presign-based upload configuration.
  presign?: PresignConfig;
  // Optional callback invoked when a background upload fails.
  onAsyncError?: (error: Error) => void;
}

export interface AuditEnvelopeMinimal {
  ts: string;
  trace_id: string;
  span_id: string;
  tenant: string;
  server: string;
  tool: string;
  status: "ok" | "error";
  latency_ms: number;
  retries: number;
  input_sha256: string | null;
  output_sha256: string | null;
  policy: { decision: "allow" | "deny"; retention: string };
  idempotency_key: string | null;
  nodeId?: string | null;
  agentRef?: string | null;
  agentVariables?: Record<string, unknown> | null;
}

export interface RawPayloadEvent {
  ts: string;
  trace_id: string;
  span_id: string;
  runId: string;
  tenant: string;
  environment?: string;
  client?: string;
  clientVersion?: string;
  nodeId?: string;
  tool?: string;
  direction: "input" | "output";
  payload?: unknown;
  payload_preview?: string;
  payload_truncated?: boolean;
  payload_bytes?: number;
  metadata?: Record<string, unknown>;
  agent_state?: Record<string, unknown>;
}

export interface Sec0AppenderOptions {
  config: Sec0Config;
  signer: Signer;
}

export interface NormalizedPresignConfig {
  apiBaseUrl: string;
  auditKey: string;
  tenant?: string;
  clientName?: string;
  clientVersion?: string;
  environment?: string;
  timeoutMs: number;
}

export type ResolvedPresignConfig = Required<NormalizedPresignConfig>;

export interface UploadState {
  auditOffsetsByDate: Record<string, number>;
  agentOffsetsByKey: Record<string, number>;
  rawOffsetsByDate: Record<string, number>;
}

export interface UploadUrlResponse {
  url: string;
  headers?: Record<string, string>;
}

export interface DiscoveryResult {
  controlPlaneUrl: string;
  tenant: string;
  environment: string;
  clientName: string;
  clientVersion: string;
  expiresAtMs: number;
}

export interface HierarchyResult {
  tenant: string;
  env: string;
  clientName: string;
  clientVersion: string;
}
