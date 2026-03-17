import type { Entitlements, PrincipalEntitlement } from "./model";

// Entitlement evaluation: determines whether a tenant/user may call a tool and
// returns any rate/volume limits to enforce.

// Inputs required to perform an authorization check.
export type AuthZInput = {
  tenant: string;
  user?: string;
  userId?: string;
  roles?: string[];
  agent?: string;
  agentNode?: string;
  toolRef: string;
};

// Structured outcome of entitlements evaluation.
export type AuthZResult = {
  allowed: boolean;
  reason?: string;
  plan: string;
  limits: { rate?: number; daily?: number };
  matchedAllow?: string;
  matchedDeny?: string;
}

/**
 * Basic case-insensitive wildcard matcher (`*` → any sequence).
 */
function wildcardMatch(pattern: string, value: string): boolean {
  if (pattern === value) return true;
  // very simple wildcard: '*' matches any characters
  const re = new RegExp('^' + pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$');
  return re.test(value);
}

/**
 * Evaluate tenant/global allowlists and compute applicable per-tool limits.
 * Returns both the decision and the plan metadata needed downstream.
 */
export function checkEntitlements(ent: Entitlements, input: AuthZInput): AuthZResult {
  const t = ent.tenants[input.tenant];
  const plan = t?.plan ?? ent.default_plan;
  const planDaily = ent.plans[plan]?.calls_per_day;
  const allowPatterns: string[] = [];
  const denyPatterns: string[] = [];
  appendPatterns(allowPatterns, t?.allowlist);
  appendPatterns(denyPatterns, t?.denylist);

  appendPrincipalPatterns(t?.users, input.user, allowPatterns, denyPatterns);
  appendPrincipalPatterns(t?.user_ids, input.userId, allowPatterns, denyPatterns);
  appendPrincipalPatterns(t?.agents, input.agent, allowPatterns, denyPatterns);
  appendPrincipalPatterns(t?.agent_nodes, input.agentNode, allowPatterns, denyPatterns);

  if (Array.isArray(input.roles)) {
    for (const role of input.roles) {
      appendPrincipalPatterns(t?.roles, role, allowPatterns, denyPatterns);
    }
  }

  let matchedDeny: string | undefined;
  const isDenied = denyPatterns.some((p) => {
    const ok = wildcardMatch(p, input.toolRef);
    if (ok) matchedDeny = p;
    return ok;
  });
  if (isDenied) {
    const perToolDenied = t?.per_tool?.[input.toolRef] ?? undefined;
    const deniedLimits = { rate: perToolDenied?.rate_per_sec, daily: perToolDenied?.calls_per_day ?? planDaily };
    return {
      allowed: false,
      reason: "tool_in_denylist",
      plan,
      limits: deniedLimits,
      matchedDeny,
    };
  }

  let matchedAllow: string | undefined;
  const isAllowed = allowPatterns.some((p) => {
    const ok = wildcardMatch(p, input.toolRef);
    if (ok) matchedAllow = p;
    return ok;
  });
  const perTool = t?.per_tool?.[input.toolRef] ?? undefined;
  const limits = { rate: perTool?.rate_per_sec, daily: perTool?.calls_per_day ?? planDaily };
  return {
    allowed: isAllowed,
    reason: isAllowed ? undefined : "tool_not_in_allowlist",
    plan,
    limits,
    matchedAllow,
  };
}

function appendPatterns(target: string[], patterns?: string[]): void {
  if (!patterns || !Array.isArray(patterns) || patterns.length === 0) return;
  for (const pattern of patterns) {
    if (typeof pattern !== "string") continue;
    const trimmed = pattern.trim();
    if (!trimmed) continue;
    target.push(trimmed);
  }
}

function appendPrincipalPatterns(
  principals: Record<string, PrincipalEntitlement> | undefined,
  principalRaw: string | undefined,
  allowTarget: string[],
  denyTarget: string[]
): void {
  const principal = normalizePrincipal(principalRaw);
  if (!principal || !principals) return;
  const resolved = resolvePrincipalEntitlement(principals, principal);
  if (!resolved) return;
  appendPatterns(allowTarget, resolved.allowlist);
  appendPatterns(denyTarget, resolved.denylist);
}

function normalizePrincipal(value: string | undefined): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  return trimmed;
}

function resolvePrincipalEntitlement(
  principals: Record<string, PrincipalEntitlement>,
  principal: string
): PrincipalEntitlement | undefined {
  if (Object.prototype.hasOwnProperty.call(principals, principal)) {
    return principals[principal];
  }
  const loweredPrincipal = principal.toLowerCase();
  const entries = Object.entries(principals);
  for (const [key, policy] of entries) {
    if (normalizePrincipal(key)?.toLowerCase() === loweredPrincipal) return policy;
  }
  return undefined;
}
