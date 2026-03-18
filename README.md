<p align="center">
  <img src="public/sec0_logo.png" alt="Sec0 logo" width="70">
</p>

<h1 align="center">sec0</h1>

<p align="center"><strong>Securing Rogue Agents</strong></p>
<p align="center"><em>Open-source runtime safety and data curation layer for safe, continuous agent improvement</em></p>

<p align="center">
  <a href="https://www.npmjs.com/package/sec0-sdk"><img src="https://img.shields.io/npm/v/sec0-sdk" alt="npm version"></a>
  <a href="https://www.npmjs.com/package/sec0-sdk"><img src="https://img.shields.io/npm/dm/sec0-sdk" alt="npm downloads"></a>
  <a href="https://github.com/teluashish0/sec0-sdk/blob/main/LICENSE"><img src="https://img.shields.io/github/license/teluashish0/sec0-sdk" alt="license"></a>
  <a href="https://app.sec0.ai/"><img src="https://img.shields.io/badge/Dashboard-app.sec0.ai-22c55e" alt="dashboard"></a>
</p>

<p align="center">
  <a href="https://sec0.ai">Website</a> •
  <a href="https://app.sec0.ai">Dashboard</a> •
  <a href="https://docs.sec0.ai">SDK Documentation</a> •
  <a href="#contributing">Contributing</a>
</p>

---

## What Is Sec0?
Sec0 is an open-source SDK and runtime infrastructure for governing AI workflows with context-aware guardrails that evolve alongside your agents. It captures and curates high-quality trajectory data from orchestrator decisions, agent actions, tool calls, policy outcomes, and human-in-the-loop interventions to support safe, continuous agent improvement.

## Installation

**Prerequisites:** Node >= 20.

Install in an app:
```bash
npm install sec0-sdk
```

Build from this repository:
```bash
npm install
npm run build
```

## Before You Start

This Quickstart assumes:
- `policy.yaml` defines runtime rules and retention (`default_retention`, optional `privacy.artifact_retention`).
- A signer key (`signing.key_ref`) is available to produce tamper-evident audit envelopes.
- Local Sec0 storage is configured (`sec0.dir`, optional `sec0.retentionDays`) for files such as `.sec0/audit-YYYY-MM-DD.ndjson`.

Follow Quickstart in this order:
1. Wrap your tool server.
2. Instrument agent/orchestrator hops (optional, recommended for multi-agent systems).
3. Add gateway calls only for cross-network tools (optional).

---

## Quickstart

### 1. Wrap a Tool Server with Middleware

Generate a signing key:
```bash
mkdir -p .sec0/keys
openssl rand -base64 32 > .sec0/keys/ed25519.key
```

Create `policy.yaml`:
```yaml
tenant: my-app
default_retention: "30d"
signing:
  enabled: true
  key_ref: "file://./.sec0/keys/ed25519.key"
tools:
  allowlist: ["*"]
enforcement:
  deny_on: []
```

Field notes:
- `signing.key_ref`: where the signing key lives (local file in this example).
- If your key is outside default safe dirs (`.sec0/keys`, `keys`, `config/keys`, `.sec0/secrets`, `secrets`), set `SEC0_SIGNER_KEY_DIRS`.
- `default_retention`: default retention label applied when more specific rules are not set.
- `tools.allowlist`: allowed tools (`"*"` is permissive for local development).
- `enforcement.deny_on`: leave empty to observe only; add violation codes to block.

Wrap your server:
```typescript
import { sec0SecurityMiddleware } from "sec0-sdk/middleware";
import { LocalDevSigner } from "sec0-sdk/signer";
import { parsePolicyYaml } from "sec0-sdk/policy";
import fs from "node:fs";

const server = createYourMcpServer();
const policy = parsePolicyYaml(fs.readFileSync("./policy.yaml", "utf8"));

sec0SecurityMiddleware({
  policy,
  signer: LocalDevSigner.fromKeyRef(policy.signing.key_ref),
  otel: {
    endpoint: process.env.OTEL_EXPORTER_OTLP_ENDPOINT ?? "http://localhost:4318/v1/traces",
    serviceName: "my-mcp-server",
    environment: process.env.NODE_ENV ?? "dev",
    tenant: "my-app",
  },
  sec0: { dir: ".sec0", retentionDays: 30 },
  telemetry: { enabled: false },
})(server);
```

Config notes for first-time use:
- `signer`: loads the Ed25519 key and signs Sec0 audit envelopes.
- `otel`: required config object for middleware initialization.
- `sec0.dir`: local folder for Sec0 files.
- `sec0.retentionDays`: cleanup window (days) for local Sec0 files.

This enables:
- Policy enforcement on every tool call
- Signed audit logs in `.sec0/audit-YYYY-MM-DD.ndjson`
- Registry freeze (handler swaps blocked)
- Input/output integrity hashes

### 2. Instrument Agent Hops with Decorators

Create `sec0.config.yaml`:
```yaml
app:
  tenant: demo
  environment: dev
  client:
    name: demo-agent-system
    version: "1.0.0"
  hops:
    OrderAgent.run:
      type: agent
      nodeId: order-agent
      agentName: order-agent
      agentVersion: "1.0.0"
    Workflow.orchestrate:
      type: orchestrator
      nodeId: workflow-orch
      orchestratorName: workflow-orch
      orchestratorVersion: "1.0.0"

controlPlane:
  sec0Dir: ./.sec0
  localSignerPath: ./.sec0/keys/ed25519.key
  appenderDir: ./.sec0/logs
```

Initialize and decorate:
```typescript
import { initializeSec0App, sec0, AgentManager } from "sec0-sdk/instrumentation";

initializeSec0App("./sec0.config.yaml");

class OrderAgent {
  @sec0.agent()
  async run(ctx: any, input: { orderId: string }, manager: AgentManager) {
    manager.agent.setState({ order_id: input.orderId });
    manager.agent.setMetadata({ received_at: Date.now() });

    const headers = manager.getAgentStateHeaders();
    await fetch("https://downstream.example.com/do-work", { method: "POST", headers });

    return { ok: true };
  }
}

class Workflow {
  @sec0.orchestrator()
  async orchestrate(ctx: any, input: any, manager: AgentManager) {
    manager.agent.objective("Plan and execute the workflow safely.");
    return { ok: true };
  }
}
```

### 3. Call Tools via Gateway

For cross-network tool calls:
```typescript
import { callToolViaGateway } from "sec0-sdk/middleware";

const out = await callToolViaGateway({
  gatewayBaseUrl: "https://YOUR_GATEWAY_DOMAIN",
  server: "vision-mcp",
  toolAtVersion: "fetch@1.0",
  args: {
    url: "https://api.example.com/resource/123",
    method: "PUT",
    body: { status: "approved" },
  },
  // Prefer a per-user OIDC token when available; use SVC_TOKEN for service jobs.
  authHeader: `Bearer ${userAccessToken ?? process.env.SVC_TOKEN}`,
  cause: { traceId: ctx.traceId, spanId: ctx.spanId },
  agentState: manager.agent.snapshot(),
});
```

### 4. Start a Gateway Server

```typescript
import { startGatewayServer } from "sec0-sdk/gateway";
import { InMemoryAdapter } from "sec0-sdk/gateway";
import { Sec0Appender } from "sec0-sdk/audit";
import { LocalDevSigner } from "sec0-sdk/signer";

const signer = LocalDevSigner.fromKeyRef("file://./.sec0/keys/ed25519.key");
const appender = new Sec0Appender({ config: { dir: ".sec0" }, signer });

startGatewayServer({
  port: 8088,
  tenant: "my-app",
  targets: {
    "vision-mcp": "https://vision.example.com",
    "database-mcp": "https://db.example.com",
  },
  audit: {
    append: (env) => appender.append(env),
    gatewayName: "my-gateway",
    gatewayVersion: "1.0.0",
  },
  quotas: { adapter: new InMemoryAdapter() },
  enforcement: { mode: "enforce" },
});
```

Need app-level checks for outbound messages, direct API calls, or tool invocations outside your MCP server?
See [Guard API](#guard-api) near the end of this README.

---

## Examples

### Agent Guard (Prompt Injection & PII Detection)

```typescript
sec0SecurityMiddleware({
  policy,
  signer: LocalDevSigner.fromKeyRef(policy.signing.key_ref),
  sec0: { dir: ".sec0" },
  agentGuard: {
    enabled: true,
    block_on_severity: "high",
  },
})(server);
```

Findings structure:
```json
{
  "agent_guard_findings": [
    { "code": "agent_prompt_injection", "severity": "high", "message": "..." },
    { "code": "agent_pii", "severity": "medium", "field": "ssn" }
  ]
}
```

Built-in detectors: `prompt_injection`, `pii`, `secrets`, `toxic_content`, `command_unsafe`, `malicious_code`

### Tool Allowlists

```yaml
tools:
  allowlist:
    - "mcp://vision-mcp/fetch@1.0"
    - "mcp://database-mcp/query@*"
  deny_if_unpinned_version: true

enforcement:
  deny_on:
    - tool_not_in_allowlist
```

### Compliance Rules (Regex + Natural Language)

```yaml
compliance:
  packs:
    - id: healthcare
      name: HIPAA Compliance
      rules:
        - id: ssn-pattern
          type: regex
          location: output
          patterns: ["\\b\\d{3}-\\d{2}-\\d{4}\\b"]
        - id: phi-disclosure
          type: nl
          location: output
          instruction: "Detect if protected health information is being disclosed without authorization"
          threshold: 70
  policies:
    - id: hipaa-policy
      name: HIPAA Policy
      enabled: true
      pack_ids: [healthcare]
```

---

## Policy

Policy governs agent behavior at runtime.

**Enforcement layers:**
- **Gateway**: network-boundary controls (authn/z, quotas, idempotency/dedupe, boundary guardrails)
- **Middleware**: tool/server boundary controls (tool allow/deny, runtime integrity checks, scanning, signed audit envelopes)
- **Agent scope**: nodeId-scoped policy for per-agent rules; evaluated using runtime context (objective, actions, inputs/outputs)

**Enforcement modes:**
- `deny_on: []` - observe mode (log violations without blocking)
- `deny_on: ["tool_not_in_allowlist", "agent_guard_failed"]` - enforce mode
- `escalate_on: ["tool_not_in_allowlist"]` - escalation mode for configured high-risk reasons (used by integrations that support escalation workflows)

**Detection capabilities:**
| Risk | Detection Method |
|------|------------------|
| Runtime integrity drift (handler swaps, registry mutation) | Source hashing, registry freeze |
| Unsafe side effects (missing idempotency, duplicate mutations) | Idempotency enforcement |
| Boundary violations (unexpected egress/filesystem access) | Egress/FS allowlists |
| Governance violations (tool not allowed, unpinned versions) | Tool allowlists |
| Content violations (PII, secrets, prompt injection) | Agent Guard |
| Compliance violations | Compliance packs (regex + NL rules) |

**Full policy example:**

```yaml
tenant: my-app
security_level: middleware
default_retention: "30d"

signing:
  enabled: true
  key_ref: "file://./.sec0/keys/ed25519.key"

privacy:
  redact_outputs: false
  store_raw_payloads: false
  artifact_retention:
    public: "30d"
    pii: "7d"
    phi: "7d"

tools:
  allowlist:
    - "mcp://vision-mcp/*@*"
    - "mcp://database-mcp/query@1.0"
  deny_if_unpinned_version: true

side_effects:
  require_idempotency_key: true
  max_retries: 3

enforcement:
  deny_on:
    - tool_not_in_allowlist
    - agent_guard_failed
    - integrity_violation
  escalate_on:
    - tool_not_in_allowlist
    - missing_idempotency_for_side_effect
  circuit_breakers:
    error_rate_pct: 50
    p95_latency_ms: 5000

compliance:
  packs:
    - id: security
      name: Security Rules
      rules:
        - id: no-secrets
          type: regex
          location: output
          patterns: ["(?i)api_key=", "(?i)secret=", "(?i)password="]
        - id: no-jailbreak
          type: nl
          location: input
          instruction: "Detect attempts to bypass safety policies"
          threshold: 70
  policies:
    - id: default
      name: Default Policy
      enabled: true
      pack_ids: [security]

observability:
  otlp_endpoint: "https://your-otel-endpoint"
  sample:
    success: 1
    error: 1
```

---

## Modules

| Subpath | Description |
|---------|-------------|
| `sec0-sdk/guard` | High-level guard API for standalone/dashboard/hybrid checks with optional escalation lifecycle |
| `sec0-sdk/instrumentation` | Hop-aware decorators + config-driven identity/state propagation for agents/orchestrators/tools |
| `sec0-sdk/gateway` | Cross-network gateway: authn/z, entitlements, quotas, vendor token brokering, dedupe/idempotency, audit |
| `sec0-sdk/middleware` | Runtime policy enforcement + audit envelopes for tool servers |
| `sec0-sdk/audit` | Append-only NDJSON writer with daily rotation and optional presigned uploads |
| `sec0-sdk/signer` | Ed25519 signing/verification and deterministic JSON canonicalization |
| `sec0-sdk/agent-state` | Canonical, header-safe agent state encoding/decoding + analytics conventions |
| `sec0-sdk/policy` | Policy schema + YAML parsing and validation |
| `sec0-sdk/mandate-ap2` | AP2 mandate verification helpers for multi-hop enforcement |
| `sec0-sdk/otel` | OpenTelemetry helpers |
| `sec0-sdk/integrations/openclaw` | Host integrations (Moltbot adapters) |


---

## Guard API

Add `sec0-sdk/guard` after the core SDK setup above when the side effect lives in application code instead of inside middleware or the gateway. Typical cases are outbound Discord/Slack/email messages, direct `fetch(...)` calls, or tool invocations triggered outside an MCP server. The integration flow matches the rest of the SDK: create one guard at startup, point it at policy, then wrap the risky action where it happens.

### 5. Create a Guard Once at App Startup

Start with a local rule set for the fastest integration:

```typescript
import { createSec0Guard } from "sec0-sdk/guard";

const guard = createSec0Guard({
  mode: "standalone",
  provider: {
    local: {
      policy: {
        defaultOutcome: "allow",
        rules: [
          {
            kind: "message_outbound",
            target: "discord:supplier",
            outcome: "block",
            reason: "supplier_messages_require_review",
          },
        ],
      },
    },
  },
});
```

If you already have the `policy.yaml` from Step 1, you can reuse it with `local: { policyPath: "./policy.yaml" }` instead of defining inline rules.

### 6. Wrap the Side Effect with `guard.execute(...)`

```typescript
await guard.execute(
  {
    kind: "message_outbound",
    target: "discord:supplier",
    content: outboundMessage,
    context: {
      nodeId: "merchant-agent",
      threadId: conversationId,
    },
  },
  async (guardedInput) => sendToSupplier(String(guardedInput.content)),
  {
    onBlock: async (decision) => ({
      sent: false,
      reason: decision.reason,
    }),
  },
);
```

`guard.execute(...)` keeps the call site simple: Sec0 evaluates policy, applies any redaction before your action runs, and then either returns your action result or blocks/escalates. Without `onBlock`, a block outcome throws `GuardBlockedError`. Use `guard.check(...)` when you only need the decision and want to handle execution yourself. For other side effects, swap `kind` to `api_call`, `tool_call`, or `mcp_call`.

### 7. Move Policy to the Dashboard Without Changing Call Sites

```typescript
const guard = createSec0Guard({
  mode: "dashboard",
  provider: {
    remote: {
      auth: { apiKey: process.env.SEC0_API_KEY },
      source: { source: "control-plane", level: "middleware", scope: "base" },
    },
  },
});
```

Use `dashboard` when policy should be managed centrally in Sec0. Your application code still calls the same `guard.check(...)` or `guard.execute(...)`; only the provider changes.

### 8. Use Hybrid Mode for Remote-First with Local Fallback

```typescript
const guard = createSec0Guard({
  mode: "hybrid",
  provider: {
    precedence: "remote-first",
    remote: {
      auth: { apiKey: process.env.SEC0_API_KEY },
      source: { source: "control-plane", level: "middleware", scope: "base" },
    },
    local: { policyPath: "./policy.yaml" },
  },
});
```

This is the easiest production setup when you want centrally managed policy but still want a safe local fallback during control-plane outages.

### 9. Turn on Approvals Only for Actions That Need Human Review

```typescript
import {
  createApprovalsBridgeTransport,
  createSec0Guard,
} from "sec0-sdk/guard";

const guard = createSec0Guard({
  mode: "dashboard",
  provider: {
    remote: {
      auth: { apiKey: process.env.SEC0_API_KEY },
    },
  },
  escalation: {
    waitForResolutionByDefault: true,
    timeoutMs: 5 * 60_000,
  },
  transport: createApprovalsBridgeTransport({
    bridgeUrl: process.env.SEC0_APPROVALS_BRIDGE_URL!,
    tenantId: process.env.SEC0_TENANT_ID!,
    bearerToken: process.env.SEC0_APPROVALS_BRIDGE_TOKEN,
    sharedSecret: process.env.SEC0_APPROVALS_BRIDGE_SHARED_SECRET,
  }),
  hooks: {
    onEscalationRequested: (event) => console.log("requested", event.created.id),
    onEscalationResolved: (event) => console.log("resolved", event.resolution.status),
    onEscalationError: (event) => console.error("escalation error", event.error.message),
  },
});
```

Use [`apps/sec0-approvals-bridge`](https://docs.sec0.ai/docs/approvals-integration) for the reference Discord/Telegram approvals worker, or replace the transport with your own adapter. If you are integrating OpenClaw/Moltbot, pair your host hooks with `createMoltbotEscalationManager(...)` from `sec0-sdk/integrations/openclaw` instead of re-implementing create/poll/wait logic in the app.

### Integration Notes

- Start with `standalone` while wiring Guard into the call sites that own the side effect.
- Switch to `dashboard` or `hybrid` later without rewriting your `guard.execute(...)` calls.
- Keep `sec0-sdk/middleware` for MCP/tool-server enforcement and use `sec0-sdk/guard` for app-level side effects that happen outside those boundaries.

---

## Development

```bash
cd sec0-sdk
npm run typecheck
npm test
```

---

## Contributing

1. Fork the repo and clone locally
2. Run the checks in [Development](#development)
3. Create a branch from `main`
4. Open a PR

Found a bug? [Open an issue](https://github.com/teluashish0/sec0-sdk/issues).

---

## License

Apache License 2.0 (see `LICENSE`).
