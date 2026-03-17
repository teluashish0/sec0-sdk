import { createHmac, randomUUID } from "node:crypto";
import type {
  GuardApprovalAction,
  GuardApprovalTransport,
  GuardTransportPendingEvent,
  GuardTransportResolvedEvent,
} from "./types";

type ApprovalsBridgeEventType =
  | "escalation.created"
  | "escalation.vote_recorded"
  | "escalation.finalized";

type ApprovalsBridgeEvent = {
  event_id: string;
  event_type: ApprovalsBridgeEventType;
  emitted_at: string;
  tenant_id: string;
  escalation: Record<string, unknown>;
};

export function createNoopApprovalTransport(): GuardApprovalTransport {
  return {
    platform: "none",
    capabilities: {
      interactiveActions: false,
      cards: false,
    },
    async sendPending() {},
    async sendResolved() {},
    parseApprovalAction(): GuardApprovalAction | null {
      return null;
    },
  };
}

export interface ApprovalsBridgeTransportConfig {
  bridgeUrl: string;
  tenantId: string;
  bearerToken?: string;
  sharedSecret?: string;
  fetchImpl?: typeof fetch;
}

function normalizeBearerToken(token?: string): string | null {
  const raw = String(token || "").trim();
  if (!raw) return null;
  return /^bearer\s+/i.test(raw) ? raw : `Bearer ${raw}`;
}

function buildSignedHeaders(rawBody: string, sharedSecret?: string): Record<string, string> {
  const secret = String(sharedSecret || "").trim();
  if (!secret) return {};
  const timestamp = String(Math.floor(Date.now() / 1000));
  const nonce = randomUUID().replace(/-/g, "");
  const canonical = `${timestamp}.${nonce}.${rawBody}`;
  const digest = createHmac("sha256", secret).update(canonical).digest("hex");
  return {
    "x-sec0-bridge-timestamp": timestamp,
    "x-sec0-bridge-nonce": nonce,
    "x-sec0-bridge-signature": `v1=${digest}`,
  };
}

async function postBridgeEvent(config: ApprovalsBridgeTransportConfig, event: ApprovalsBridgeEvent): Promise<void> {
  const bridgeUrl = String(config.bridgeUrl || "").trim();
  if (!bridgeUrl) return;
  const fetchImpl = config.fetchImpl || fetch;
  const rawBody = JSON.stringify(event);
  const bearer = normalizeBearerToken(config.bearerToken);
  const response = await fetchImpl(`${bridgeUrl.replace(/\/+$/, "")}/webhooks/escalations`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(bearer ? { authorization: bearer } : {}),
      ...buildSignedHeaders(rawBody, config.sharedSecret),
    },
    body: rawBody,
  } as any);
  if (!response.ok) {
    const body = await response.text().catch(() => "");
    throw new Error(`approvals_bridge_post_failed:${response.status}:${body || "empty"}`);
  }
}

export function createApprovalsBridgeTransport(config: ApprovalsBridgeTransportConfig): GuardApprovalTransport {
  const tenantId = String(config.tenantId || "").trim();
  return {
    platform: "approvals-bridge",
    capabilities: {
      interactiveActions: true,
      cards: true,
    },
    async sendPending(event: GuardTransportPendingEvent) {
      if (!tenantId) return;
      const payload: ApprovalsBridgeEvent = {
        event_id: randomUUID(),
        event_type: "escalation.created",
        emitted_at: new Date().toISOString(),
        tenant_id: tenantId,
        escalation: {
          id: event.escalationId,
          status: event.createResult.status,
          violation: event.decision.violation || event.decision.reason || "policy_violation",
          severity: event.payload.severity || "medium",
          content: event.payload.content,
          rule_id: event.payload.ruleId || null,
          message: event.payload.message || null,
          node_id: event.payload.nodeId || null,
          agent_ref: event.payload.agentRef || null,
          metadata: event.payload.metadata || null,
          expires_at: event.createResult.expiresAt || null,
          requester_status_message: event.createResult.requesterStatusMessage || null,
        },
      };
      await postBridgeEvent(config, payload);
    },
    async sendResolved(event: GuardTransportResolvedEvent) {
      if (!tenantId) return;
      const payload: ApprovalsBridgeEvent = {
        event_id: randomUUID(),
        event_type: "escalation.finalized",
        emitted_at: new Date().toISOString(),
        tenant_id: tenantId,
        escalation: {
          id: event.escalationId,
          status: event.resolution.status,
          finalization_reason: event.resolution.metadata.finalizationReason || null,
          requester_status_message: event.resolution.details?.requesterStatusMessage || null,
          violation: event.decision.violation || event.decision.reason || "policy_violation",
          metadata: event.resolution.details?.metadata || null,
          expires_at: event.resolution.details?.expiresAt || null,
          resolved_at: event.resolution.details?.resolvedAt || null,
        },
      };
      await postBridgeEvent(config, payload);
    },
    parseApprovalAction(payload: unknown): GuardApprovalAction | null {
      if (!payload || typeof payload !== "object" || Array.isArray(payload)) return null;
      const raw = payload as Record<string, unknown>;
      const escalationId = typeof raw.escalationId === "string" ? raw.escalationId.trim() : "";
      const action = typeof raw.action === "string" ? raw.action.trim().toLowerCase() : "";
      if (!escalationId) return null;
      if (action !== "approve" && action !== "reject") return null;
      return {
        escalationId,
        action: action as "approve" | "reject",
        ...(typeof raw.actorId === "string" && raw.actorId.trim() ? { actorId: raw.actorId.trim() } : {}),
        ...(typeof raw.notes === "string" && raw.notes.trim() ? { notes: raw.notes.trim() } : {}),
      };
    },
  };
}
