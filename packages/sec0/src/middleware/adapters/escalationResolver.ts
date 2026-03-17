import type { EscalationResolver } from "../../core/contracts";
import { extractApiKey } from "../apiKeyResolver";
import type { ControlPlaneClient } from "./controlPlaneClient";

export function createNoopEscalationResolver(): EscalationResolver {
  return {
    async get() {
      return null;
    },
  };
}

export function createControlPlaneEscalationResolver(opts: {
  auth?: { apiKey?: string; bearerToken?: string };
  client: ControlPlaneClient;
  timeoutMs?: number;
}): EscalationResolver {
  return {
    async get(input) {
      const id = String(input.id || "").trim();
      if (!id) return null;
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
        return await opts.client.getEscalation({
          authToken: apiKey,
          id,
          tenant: input.tenant,
          timeoutMs: opts.timeoutMs,
        });
      } catch {
        return null;
      }
    },
    async resolve(input) {
      const id = String(input.id || "").trim();
      if (!id) return null;
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
        const resolved = await opts.client.resolveEscalation({
          authToken: apiKey,
          id,
          action: input.action,
          tenant: input.tenant,
          notes: input.notes,
          timeoutMs: opts.timeoutMs,
        });
        return resolved.escalation;
      } catch {
        return null;
      }
    },
  };
}
