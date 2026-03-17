import { Span } from "@opentelemetry/api";

// Small helpers to keep OpenTelemetry attribute names consistent across the
// gateway codebase.

/**
 * Attach tenant/user/plan info (with redaction already applied) to the span.
 */
export function attachAuthAttrs(span: Span, auth: { tenant?: string; userHash?: string; plan?: string }) {
  if (auth.tenant) span.setAttribute("auth.tenant", auth.tenant);
  if (auth.userHash) span.setAttribute("auth.user.hash", auth.userHash);
  if (auth.plan) span.setAttribute("auth.plan", auth.plan);
}

/**
 * Record the outcome of entitlement/policy evaluation for observability.
 */
export function attachAuthZ(span: Span, res: { decision: string; reasons?: string[]; matched?: string }) {
  span.setAttribute("authz.decision", res.decision);
  if (res.reasons?.length) span.setAttribute("authz.reasons", res.reasons.join(","));
  if (res.matched) span.setAttribute("authz.allow.match", res.matched);
}

/**
 * Record remaining quota tokens so alerts can be built from traces.
 */
export function attachQuota(span: Span, q: { rateRemaining?: number; dailyRemaining?: number }) {
  if (q.rateRemaining !== undefined) span.setAttribute("quota.rate.remaining", q.rateRemaining);
  if (q.dailyRemaining !== undefined) span.setAttribute("quota.daily.remaining", q.dailyRemaining);
}

/**
 * Mark which vendor/broker was used for the call, if any.
 */
export function attachBroker(span: Span, b: { name?: string }) {
  if (b.name) span.setAttribute("broker.name", b.name);
}


