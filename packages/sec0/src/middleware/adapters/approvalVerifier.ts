import type { ApprovalVerifier } from "../../core/contracts";
import { extractApiKey } from "../apiKeyResolver";
import type { ControlPlaneClient } from "./controlPlaneClient";

export function createNoopApprovalVerifier(): ApprovalVerifier {
  return {
    async verify() {
      return null;
    },
  };
}

export function createControlPlaneApprovalVerifier(opts: {
  auth?: { apiKey?: string; bearerToken?: string };
  client: ControlPlaneClient;
  timeoutMs?: number;
}): ApprovalVerifier {
  return {
    async verify(input) {
      const token = String(input.token || "").trim();
      if (!token) return null;
      let apiKey = "";
      try {
        apiKey = extractApiKey({
          "x-api-key": opts.auth?.apiKey,
          authorization: opts.auth?.bearerToken ? `Bearer ${opts.auth.bearerToken}` : undefined,
        } as any);
      } catch {
        return null;
      }
      if (!apiKey) return null;
      try {
        return await opts.client.verifyApproval({
          authToken: apiKey,
          token,
          toolRef: input.toolRef,
          nodeId: input.nodeId,
          agentRef: input.agentRef,
          timeoutMs: opts.timeoutMs,
        });
      } catch {
        return null;
      }
    },
  };
}
