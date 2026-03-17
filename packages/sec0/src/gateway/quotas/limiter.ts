import type { QuotaAdapter } from "./adapters";
import { quotaExceeded, rateLimited } from "../core/errors";

// High-level quota evaluator that joins daily + per-second limits and emits
// typed errors when thresholds are exceeded.

// Outcome of quota evaluation, mirroring the headers we expose downstream.
export type LimitEval = {
  dailyRemaining?: number;
  rateRemaining?: number;
  resetAt?: string;
}

/**
 * Check both rate and daily quotas with the configured adapter. Throws branded
 * GatewayErrors so callers can translate to HTTP 429s automatically.
 */
export async function evaluateLimits(
  store: QuotaAdapter,
  tenant: string,
  tool: string,
  opts: { daily?: number; rate?: number }
): Promise<LimitEval> {
  const now = new Date();
  let dailyRemaining: number | undefined;
  let rateRemaining: number | undefined;
  let resetAt: string | undefined;

  if (opts.rate && opts.rate > 0) {
    const { tokens, resetAt: rAt } = await store.takeToken(tenant, tool, opts.rate, opts.rate * 2, now);
    rateRemaining = tokens;
    resetAt = rAt;
    if (tokens < 0) throw rateLimited(1, resetAt);
  }
  if (opts.daily && opts.daily > 0) {
    const { count, resetAt: dAt } = await store.incrDaily(tenant, tool, opts.daily, now);
    dailyRemaining = Math.max(0, opts.daily - count);
    resetAt = resetAt ?? dAt;
    if (count > opts.daily) throw quotaExceeded(dAt);
  }
  return { dailyRemaining, rateRemaining, resetAt };
}


