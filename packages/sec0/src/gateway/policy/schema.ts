import { z } from "zod";
import type { Entitlements } from "../entitlements/model";

// Zod schemas that keep the gateway policy file validated and type-safe.

// Authentication configuration block: OIDC, service tokens, etc.
export const AuthNSchema = z.object({
  mode: z.enum(["oidc","service_token","disabled"]).default("disabled"),
  oidc: z.object({
    issuer: z.string(),
    audience: z.string(),
    jwks_uri: z.string(),
    tenantClaim: z.string().optional(),
    userClaim: z.string().optional(),
    rolesClaim: z.string().optional(),
    subjectClaim: z.string().optional(),
    clientIdClaim: z.string().optional(),
  }).partial().optional(),
  allowUnauthenticated: z.boolean().optional(),
  allow_unauthenticated: z.boolean().optional(),
  service_token: z.object({ jwk_ref: z.string() }).partial().optional()
}).partial();

// Broker configuration keyed by upstream server name.
export const BrokersSchema = z.record(z.object({
  type: z.enum(["vendor_key_pool","oidc_on_behalf","static"]),
  key_refs: z.array(z.string()).optional(),
  inject: z.object({ header: z.string(), format: z.enum(["raw","bearer","template"]) })
}));

// Enforcement guardrails toggling observe/enforce modes.
export const EnforcementSchema = z.object({
  mode: z.enum(["observe","enforce"]).default("observe"),
  deny_on: z.array(z.string()).optional(),
  escalate_on: z.array(z.string()).optional(),
}).partial();

const HumanEscalationSchema = z.object({
  approval_strategy: z.enum(["auto_allow", "single_approver", "human_quorum"]).optional(),
  timeout_action: z.enum(["auto_approve", "auto_reject"]).optional(),
  min_approvals: z.number().int().positive().optional(),
  min_rejections: z.number().int().positive().optional(),
  required_roles: z.array(z.string()).optional(),
  veto_roles: z.array(z.string()).optional(),
  approval_set_id: z.string().optional(),
}).partial();

export const SecuritySchema = z.object({
  allow_versions: z.record(z.array(z.string())).optional(),
  egress_allowlist: z.array(z.string()).optional(),
  fs_allowlist: z.array(z.string()).optional(),
  limits: z.object({
    max_payload_kb: z.number().int().positive().optional(),
    max_duration_ms: z.number().int().positive().optional(),
  }).partial().optional(),
  side_effects: z.object({
    require_idempotency_key: z.boolean().optional(),
    approve_high_risk: z.boolean().optional(),
    human_escalation: HumanEscalationSchema.optional(),
    humanEscalation: HumanEscalationSchema.optional(),
  }).partial().optional(),
}).partial();

export const RuntimeEnforcementSchema = z.object({
  mode: z.enum(["local", "remote"]).optional(),
  failureMode: z.enum(["local", "allow", "deny"]).optional(),
  remote: z.object({
    endpoint: z.string().optional(),
    apiKey: z.string().optional(),
    timeoutMs: z.number().int().positive().optional(),
    maxRetries: z.number().int().nonnegative().optional(),
    retryBackoffMs: z.number().int().positive().optional(),
    headers: z.record(z.string()).optional(),
  }).partial().optional(),
}).partial();

// Full policy augmentation schema consumed by the gateway bootstrapper.
export const PolicyAugSchema = z.object({
  authn: AuthNSchema.optional(),
  entitlements: z.any().optional(),
  brokers: BrokersSchema.optional(),
  security: SecuritySchema.optional(),
  privacy: z.object({ redact_identities: z.boolean().default(false) }).partial().optional(),
  enforcement: EnforcementSchema.optional(),
  runtime: z.object({
    enforcement: RuntimeEnforcementSchema.optional(),
  }).partial().optional(),
});

// Parsed policy object with optional entitlements hydrated at runtime.
export type PolicyAugmented = z.infer<typeof PolicyAugSchema> & { entitlements?: Entitlements };
