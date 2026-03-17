// Shared entitlement data structures that gate tool execution per tenant/user.

// Per-principal policy that can narrow or explicitly deny tool access.
export type PrincipalEntitlement = {
  allowlist?: string[];
  denylist?: string[];
};

// Per-tenant policy describing plans, allowlists, and optional per-tool caps.
export type TenantEntitlement = {
  plan: string;
  allowlist: string[];
  denylist?: string[];
  per_tool?: Record<string, { rate_per_sec?: number; calls_per_day?: number }>;
  users?: Record<string, PrincipalEntitlement>;
  user_ids?: Record<string, PrincipalEntitlement>;
  roles?: Record<string, PrincipalEntitlement>;
  agents?: Record<string, PrincipalEntitlement>;
  agent_nodes?: Record<string, PrincipalEntitlement>;
}

// Aggregate entitlements doc loaded at startup (global + tenant overrides).
export type Entitlements = {
  default_plan: string;
  plans: Record<string, { calls_per_day: number }>;
  tenants: Record<string, TenantEntitlement>;
}

