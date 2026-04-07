import { afterEach, describe, expect, it, vi } from "vitest";

import { createSec0Guard } from "../src/guard";

const originalFetch = globalThis.fetch;

function jsonResponse(body: unknown, init?: ResponseInit): Response {
  return new Response(JSON.stringify(body), {
    status: init?.status ?? 200,
    headers: {
      "content-type": "application/json",
      ...(init?.headers || {}),
    },
  });
}

function textResponse(body: string, init?: ResponseInit): Response {
  return new Response(body, {
    status: init?.status ?? 200,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      ...(init?.headers || {}),
    },
  });
}

afterEach(() => {
  globalThis.fetch = originalFetch;
  vi.restoreAllMocks();
});

describe("hosted guard wiring", () => {
  it("fetches dashboard policy from the hosted control plane", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === "https://guard.sec0.local/api/auth/validate-key") {
        expect(init?.headers).toMatchObject({
          "Content-Type": "application/json",
          "x-api-key": "worm_test_key",
        });
        return jsonResponse({
          tenant: "tenant-a",
          env: "dev",
          clientName: "@coreax/sdk",
          clientVersion: "0.2.3",
        });
      }
      if (url === "https://guard.sec0.local/api/policy/tenant-a?level=middleware") {
        expect(init?.headers).toMatchObject({
          Accept: "text/yaml",
          Authorization: "Bearer worm_test_key",
        });
        return textResponse(
          [
            "security_level: middleware",
            "default_retention: 30d",
            "tools:",
            "  allowlist:",
            "    - '*'",
            "  deny_if_unpinned_version: false",
            "security:",
            "  egress_allowlist:",
            "    - api.allowed.com",
            "enforcement:",
            "  deny_on:",
            "    - egress_violation",
            "  circuit_breakers: {}",
          ].join("\n"),
        );
      }
      throw new Error(`unexpected_fetch:${url}`);
    });
    globalThis.fetch = fetchMock as typeof fetch;

    const guard = createSec0Guard({
      mode: "dashboard",
      provider: {
        remote: {
          auth: { apiKey: "worm_test_key" },
          controlPlaneUrl: "https://guard.sec0.local",
          source: { source: "control-plane", level: "middleware", scope: "base" },
        },
      },
    });

    const decision = await guard.check({
      kind: "api_call",
      target: "https://evil.example/path",
      content: { body: "payload" },
      context: { nodeId: "merchant-agent" },
    });

    expect(decision.outcome).toBe("block");
    expect(decision.reason).toBe("egress_violation");
    expect(decision.provider.source).toBe("remote");
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("inherits hosted control-plane auth for escalations without bridge transport config", async () => {
    let escalationReads = 0;
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === "https://guard.sec0.local/api/escalations?tenant=tenant-a") {
        expect(init?.method).toBe("POST");
        expect(init?.headers).toMatchObject({
          "Content-Type": "application/json",
          Authorization: "Bearer worm_test_key",
        });
        return jsonResponse({
          escalation: {
            id: "esc-1",
            status: "pending",
            created_at: "2026-03-31T00:00:00.000Z",
          },
        });
      }
      if (url === "https://guard.sec0.local/api/escalations/esc-1?tenant=tenant-a") {
        escalationReads += 1;
        expect(init?.method).toBe("GET");
        expect(init?.headers).toMatchObject({
          Accept: "application/json",
          Authorization: "Bearer worm_test_key",
        });
        return jsonResponse({
          escalation: {
            id: "esc-1",
            status: escalationReads > 1 ? "approved" : "pending",
            created_at: "2026-03-31T00:00:00.000Z",
            resolved_at: escalationReads > 1 ? "2026-03-31T00:00:01.000Z" : undefined,
          },
        });
      }
      throw new Error(`unexpected_fetch:${url}`);
    });
    globalThis.fetch = fetchMock as typeof fetch;

    const guard = createSec0Guard({
      mode: "hybrid",
      provider: {
        precedence: "local-first",
        remote: {
          auth: { apiKey: "worm_test_key" },
          controlPlaneUrl: "https://guard.sec0.local",
          source: { source: "control-plane", level: "middleware", scope: "base" },
        },
        local: {
          policy: {
            defaultOutcome: "allow",
            rules: [
              {
                kind: "message_outbound",
                target: "email:finance",
                outcome: "escalate",
                reason: "finance_messages_require_review",
              },
            ],
          },
        },
      },
      escalation: {
        tenant: "tenant-a",
        waitForResolutionByDefault: true,
        timeoutMs: 1_000,
        pollIntervalMs: 1,
      },
    });

    const result = await guard.execute(
      {
        kind: "message_outbound",
        target: "email:finance",
        content: "approve transfer",
      },
      async () => "sent",
    );

    expect(result.value).toBe("sent");
    expect(result.decision.outcome).toBe("escalate");
    expect(result.escalation?.status).toBe("approved");
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });
});
