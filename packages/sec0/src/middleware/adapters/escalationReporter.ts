import type { EscalationReporter } from "../../core/contracts";
import { extractApiKey } from "../apiKeyResolver";
import type { ControlPlaneClient } from "./controlPlaneClient";

export function createNoopEscalationReporter(): EscalationReporter {
  return {
    async create() {
      return null;
    },
  };
}

export function createControlPlaneEscalationReporter(opts: {
  auth?: { apiKey?: string; bearerToken?: string };
  client: ControlPlaneClient;
  timeoutMs?: number;
}): EscalationReporter {
  return {
    async create(input) {
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
      return opts.client.createEscalation({
        authToken: apiKey,
        tenant: input.tenant,
        timeoutMs: opts.timeoutMs,
        payload: {
          content: input.content,
          violation: input.violation,
          rule_id: input.ruleId,
          message: input.message,
          severity: input.severity,
          node_id: input.nodeId,
          agent_ref: input.agentRef,
          metadata: input.metadata,
          finding_source: input.findingSource,
          evaluator_fingerprint: input.evaluatorFingerprint,
          evaluator_confidence: input.evaluatorConfidence,
          evaluator_principles: input.evaluatorPrinciples,
          evaluator_snapshot: input.evaluatorSnapshot,
          ttl_seconds: input.ttlSeconds,
          timeout_action: input.timeoutAction,
          approval_strategy: input.approvalStrategy,
          approval_set_id: input.approvalSetId,
          min_approvals: input.minApprovals,
          min_rejections: input.minRejections,
          required_roles: input.requiredRoles,
          veto_roles: input.vetoRoles,
        },
      });
    },
  };
}
