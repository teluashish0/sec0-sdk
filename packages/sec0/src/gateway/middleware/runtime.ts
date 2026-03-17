import { randomBytes } from "node:crypto";
import {
  createRuntimeAdapter,
  mapRuntimeDecisionRequest,
  mapRuntimeDecisionToLegacy,
} from "../../runtime-adapter";
import type { MiddlewareConfig } from "./config";

export type GatewayDecisionInput = {
  reasons: string[];
  denyOn?: string[];
  strategy?: "deny_on_match" | "deny_on_any";
  forceDeny?: boolean;
  riskTags?: string[];
  requestIdSuffix: string;
};

export type GatewayDecisionEvaluator = (input: GatewayDecisionInput) => Promise<{ shouldDeny: boolean }>;

export function createGatewayTraceIds(): { traceId: string; spanId: string } {
  const traceId = (() => {
    try {
      return randomBytes(16).toString("hex");
    } catch {
      return `${Date.now()}0000000000000000`;
    }
  })();
  const spanId = (() => {
    try {
      return randomBytes(8).toString("hex");
    } catch {
      return String(Date.now()).slice(0, 16).padEnd(16, "0");
    }
  })();
  return { traceId, spanId };
}

export function createGatewayDecisionEvaluator(input: {
  cfg: MiddlewareConfig;
  effectiveTenant: string;
  serverName: string;
  toolNameAtVersion: string;
  nodeId: string;
  agentRunId: string;
  mode: "observe" | "enforce";
}): GatewayDecisionEvaluator {
  const runtimeAdapter = createRuntimeAdapter(input.cfg.runtime?.enforcement);
  const toolRef = `mcp://${input.serverName}/${input.toolNameAtVersion}`;
  return async (params: GatewayDecisionInput) => {
    const decision = await runtimeAdapter.evaluate(
      mapRuntimeDecisionRequest({
        executionLayer: "gateway",
        tenant: input.effectiveTenant,
        server: input.serverName,
        tool: input.toolNameAtVersion,
        nodeId: input.nodeId,
        runId: input.agentRunId,
        mode: input.mode,
        strategy: params.strategy ?? "deny_on_match",
        denyOn: params.denyOn,
        reasons: params.reasons,
        riskTags: params.riskTags,
        requestId: `${toolRef}:${params.requestIdSuffix}`,
      }),
    );
    return mapRuntimeDecisionToLegacy(decision);
  };
}
