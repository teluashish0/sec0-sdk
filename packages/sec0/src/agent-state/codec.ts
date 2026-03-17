import type { AgentStatePayload, AgentStateVariables } from "./types";
import {
  NODE_ID_HEADER,
  AGENT_REF_HEADER,
  AGENT_PARENT_REF_HEADER,
  AGENT_STATE_HEADER,
  AGENT_STATE_VERSION,
} from "./constants";
import { fail, normalizeNodeId, normalizeRunId } from "./validation";
import { encodeBase64Url, decodeBase64Url } from "./encoding";
import { normalizeAgentStatePayload } from "./payload";

/**
 * Normalize and serialize an agent state payload into HTTP headers.
 * Callers set these headers on outbound requests so downstream services
 * can reconstruct the exact state via decodeAgentStateHeader.
 */
export function encodeAgentStateHeaders(payload: AgentStatePayload): Record<string, string> {
  const normalized = normalizeAgentStatePayload(payload);
  const headers: Record<string, string> = {
    [NODE_ID_HEADER]: normalized.nodeId,
  };
  if (normalized.runId) headers[AGENT_REF_HEADER] = normalized.runId;
  if (normalized.parentRef) headers[AGENT_PARENT_REF_HEADER] = normalized.parentRef;

  const statePayload: {
    version: typeof AGENT_STATE_VERSION;
    nodeId: string;
    runId?: string;
    parentRef?: string;
    variables?: AgentStateVariables;
    metadata?: Record<string, unknown>;
  } = {
    version: AGENT_STATE_VERSION,
    nodeId: normalized.nodeId,
  };
  if (normalized.runId) statePayload.runId = normalized.runId;
  if (normalized.parentRef) statePayload.parentRef = normalized.parentRef;
  if (normalized.variables) statePayload.variables = normalized.variables;
  if (normalized.metadata) statePayload.metadata = normalized.metadata;
  headers[AGENT_STATE_HEADER] = encodeBase64Url(JSON.stringify(statePayload));
  return headers;
}

/**
 * Decode and normalize the base64url agent state header emitted by
 * encodeAgentStateHeaders. Throws when the header is missing or when the
 * payload cannot be trusted.
 */
export function decodeAgentStateHeader(value: string | undefined | null): AgentStatePayload {
  if (!value) {
    fail(`Missing required header "${AGENT_STATE_HEADER}".`);
  }
  let decoded: string;
  try {
    decoded = decodeBase64Url(value);
  } catch {
    fail("Failed to decode agent state header.");
  }
  let json: unknown;
  try {
    json = JSON.parse(decoded);
  } catch {
    fail("Failed to parse agent state header JSON.");
  }
  if (!json || typeof json !== "object") {
    fail("Agent state header must contain a JSON object.");
  }
  return normalizeAgentStatePayload(json as AgentStatePayload);
}

/**
 * Case-insensitive header reader that also flattens array-based values.
 */
function getHeader(headers: Record<string, unknown> | undefined, name: string): string | undefined {
  if (!headers) return undefined;
  const lower = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() !== lower) continue;
    if (Array.isArray(value)) {
      const first = value[0];
      if (first == null) return undefined;
      return String(first);
    }
    if (value == null) return undefined;
    return String(value);
  }
  return undefined;
}

/**
 * Reconstruct agent state from raw HTTP headers by combining the explicit
 * node/ref headers with the serialized state blob, rejecting inconsistencies.
 */
export function extractAgentStateFromHeaders(headers?: Record<string, unknown>): AgentStatePayload {
  if (!headers) {
    fail("Headers are required to extract agent state.");
  }
  const nodeIdHeader = getHeader(headers, NODE_ID_HEADER);
  if (!nodeIdHeader) {
    fail(`Missing required header "${NODE_ID_HEADER}".`);
  }
  const nodeId = normalizeNodeId(nodeIdHeader);

  const stateHeader = getHeader(headers, AGENT_STATE_HEADER);
  const decoded = stateHeader ? decodeAgentStateHeader(stateHeader) : undefined;
  if (decoded && decoded.nodeId !== nodeId) {
    fail("Node ID header mismatch with encoded state.");
  }

  const refHeader = getHeader(headers, AGENT_REF_HEADER);
  const ref = refHeader !== undefined ? normalizeRunId(refHeader) : undefined;
  if (decoded?.runId) {
    const decodedRunId = normalizeRunId(decoded.runId);
    if (!ref) {
      fail(`Missing required header "${AGENT_REF_HEADER}" while encoded state includes a runId.`);
    }
    if (decodedRunId !== ref) {
      fail("Agent runId header mismatch with encoded state.");
    }
  }

  const parentHeader = getHeader(headers, AGENT_PARENT_REF_HEADER);
  const parentRef = parentHeader !== undefined ? normalizeRunId(parentHeader) : undefined;
  if (decoded?.parentRef) {
    const decodedParentRef = normalizeRunId(decoded.parentRef);
    if (!decodedParentRef) {
      fail("Encoded agent parent ref must not be empty.");
    }
    if (!parentRef) {
      fail(`Missing required header "${AGENT_PARENT_REF_HEADER}" while encoded state includes a parent ref.`);
    }
    if (decodedParentRef !== parentRef) {
      fail("Agent parent ref header mismatch with encoded state.");
    }
  }

  const result: AgentStatePayload = { nodeId };
  if (ref) result.runId = ref;
  if (parentRef) result.parentRef = parentRef;
  if (decoded?.variables) result.variables = decoded.variables;
  if (decoded?.metadata !== undefined) result.metadata = decoded.metadata;

  return normalizeAgentStatePayload(result);
}
