import type { AgentStatePayload, AgentStateVariables, AgentVariableScope } from "./types";
import { fail, hasOwn, normalizeNodeId, normalizeRunId, normalizeScope, toPlainJson } from "./validation";

/**
 * Strictly normalize a user-supplied payload so all downstream consumers
 * operate on sanitized node IDs, refs, metadata, and variables.
 */
export function normalizeAgentStatePayload(input: AgentStatePayload): AgentStatePayload {
  if (!input) {
    fail("Agent state payload is required.");
  }
  const nodeId = normalizeNodeId(input.nodeId);
  const rawInput = input as Record<string, unknown>;
  const normalized: AgentStatePayload = { nodeId };

  let resolvedRunId: unknown;
  if (hasOwn(rawInput, "runId")) {
    resolvedRunId = rawInput.runId;
  } else if (hasOwn(rawInput, "ref")) {
    resolvedRunId = (rawInput as Record<string, unknown>).ref;
  }
  if (resolvedRunId !== undefined) {
    if (resolvedRunId == null) {
      fail("Agent runId cannot be null or undefined. Omit the field entirely if it is not set.");
    }
    if (typeof resolvedRunId !== "string") {
      fail("Agent runId must be a string.");
    }
    normalized.runId = normalizeRunId(resolvedRunId);
  }

  if (hasOwn(rawInput, "parentRef")) {
    const rawParentRef = rawInput.parentRef;
    if (rawParentRef == null) {
      fail("Agent parentRef cannot be null or undefined. Omit the field entirely if it is not set.");
    }
    if (typeof rawParentRef !== "string") {
      fail("Agent parentRef must be a string.");
    }
    normalized.parentRef = normalizeRunId(rawParentRef);
  }

  if (hasOwn(rawInput, "variables")) {
    const rawVariables = rawInput.variables;
    if (!rawVariables || typeof rawVariables !== "object" || Array.isArray(rawVariables)) {
      fail("Agent variables must be provided as a plain object when present.");
    }
    const variables: AgentStateVariables = {};
    for (const [scopeKey, vars] of Object.entries(rawVariables as AgentStateVariables)) {
      const scope = normalizeScope(scopeKey as AgentVariableScope);
      if (!vars || typeof vars !== "object" || Array.isArray(vars)) {
        fail(`Agent state variables for scope "${scopeKey}" must be a plain object.`);
      }
      const plain = toPlainJson(vars);
      if (!plain || typeof plain !== "object" || Array.isArray(plain)) {
        fail(`Agent state variables for scope "${scopeKey}" must be JSON serializable plain objects.`);
      }
      variables[scope] = plain as Record<string, unknown>;
    }
    if (Object.keys(variables).length > 0) {
      normalized.variables = variables;
    }
  }

  if (hasOwn(rawInput, "metadata")) {
    const rawMetadata = rawInput.metadata;
    if (rawMetadata == null) {
      fail("Agent metadata cannot be null or undefined. Omit the field entirely if it is not set.");
    }
    if (typeof rawMetadata !== "object" || Array.isArray(rawMetadata)) {
      fail("Agent metadata must be a plain JSON-serializable object.");
    }
    const metadata = toPlainJson(rawMetadata);
    if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) {
      fail("Agent metadata must be a plain JSON-serializable object.");
    }
    normalized.metadata = metadata as Record<string, unknown>;
  }

  return normalized;
}

/**
 * Merge plain-object additions into the specified scope, validating inputs.
 */
export function mergeAgentVariables(
  base: AgentStateVariables | undefined,
  scope: AgentVariableScope,
  additions: Record<string, unknown>
): AgentStateVariables {
  const result: AgentStateVariables = { ...(base || {}) };
  if (!additions || typeof additions !== "object" || Array.isArray(additions)) {
    fail("Agent variable additions must be a plain object.");
  }
  const plain = toPlainJson(additions);
  if (!plain || typeof plain !== "object" || Array.isArray(plain)) {
    fail("Agent variable additions must be JSON-serializable plain objects.");
  }
  const scoped = normalizeScope(scope);
  const existing = result[scoped] || {};
  if (typeof existing !== "object" || Array.isArray(existing)) {
    fail(`Existing agent variables for scope "${scoped}" must be a plain object.`);
  }
  result[scoped] = { ...(existing as Record<string, unknown>), ...(plain as Record<string, unknown>) };
  return result;
}

/**
 * Ensure a payload carries a valid run identifier (no fallbacks allowed).
 */
export function ensureRunId(payload: AgentStatePayload): string {
  if (!payload) {
    fail("Agent state payload is required to ensure a runId.");
  }
  const rawRunId = payload.runId;
  if (rawRunId == null || rawRunId === "") {
    fail("Agent runId is required and fallbacks are not permitted.");
  }
  return normalizeRunId(rawRunId);
}
