import { SpanKind, SpanStatusCode, context, trace } from '@opentelemetry/api'
import { getMeter, getTracer } from '../otel/bootstrap'

// Instrumentation hooks abstract tracing/metrics so the core pipeline does not
// need to depend on OpenTelemetry directly.

export interface InstrumentationHooks {
  // Fired when the gateway first receives a request; returns the root span.
  onInvokeStart(ctx: { server: string; version: string; tool: string; op?: string; tenant?: string; userHash?: string }): any;
  // Fired after policy/entitlements evaluation completes.
  onPolicyEvaluated(parentSpan: any, decision: string, reasons: string[]): void;
  // Fired immediately before invoking the upstream tool.
  onExecStart(parentSpan: any): any;
  // Fired once the upstream invocation returns to record tool-specific attrs.
  onExecEnd(execSpan: any, summary: Record<string,any>): void;
  // Fired when the gateway writes the audit envelope.
  onAuditWrite(parentSpan: any, hashes: { input_sha256?: string; output_sha256?: string; retention?: string }): void;
  // Fired when the gateway denies a request for any reason.
  onDeny(parentSpan: any, reason: string): void;
  // Fired at the very end with the overall status + latency.
  onFinally(parentSpan: any, outcome: 'ok'|'error'|'deny', latencyMs?: number): void;
}

/**
 * Minimal implementation that keeps the pipeline running when OTel is off.
 */
export class NoopHooks implements InstrumentationHooks {
  onInvokeStart() { return { setAttribute() {}, spanContext() { return { traceId: '', spanId: '' } } } }
  onPolicyEvaluated() {}
  onExecStart() { return { setAttribute() {}, end() {} } }
  onExecEnd() {}
  onAuditWrite() {}
  onDeny() {}
  onFinally() {}
}

/**
 * Full OpenTelemetry-backed implementation used in production deployments.
 */
export class OtelHooks implements InstrumentationHooks {
  private calls = getMeter().createCounter('sec0_gateway_calls_total')
  private denials = getMeter().createCounter('sec0_gateway_denials_total')
  private latency = getMeter().createHistogram('sec0_gateway_latency_ms')
  onInvokeStart(ctx: { server: string; version: string; tool: string; op?: string; tenant?: string; userHash?: string }) {
    const span = getTracer().startSpan('sec0.gateway.invoke', { kind: SpanKind.SERVER })
    span.setAttribute('sec0.gateway.server', ctx.server)
    span.setAttribute('sec0.gateway.version', ctx.version)
    span.setAttribute('sec0.gateway.tool', ctx.tool)
    if (ctx.op) span.setAttribute('sec0.gateway.op', ctx.op)
    if (ctx.tenant) span.setAttribute('sec0.gateway.tenant', ctx.tenant)
    if (ctx.userHash) span.setAttribute('sec0.gateway.user_hash', ctx.userHash)
    return span
  }
  onPolicyEvaluated(parentSpan: any, decision: string, reasons: string[]) {
    parentSpan.setAttribute('policy.decision', decision)
    if (reasons?.length) parentSpan.setAttribute('authz.reasons', reasons.join(','))
  }
  onExecStart(parentSpan: any) { return getTracer().startSpan('sec0.gateway.exec', undefined, trace.setSpan(context.active(), parentSpan)) }
  onExecEnd(execSpan: any, summary: Record<string,any>) { for (const [k,v] of Object.entries(summary||{})) execSpan.setAttribute(k, v as any); execSpan.end() }
  onAuditWrite(parentSpan: any, hashes: { input_sha256?: string; output_sha256?: string; retention?: string }) {
    const s = getTracer().startSpan('sec0.gateway.audit', undefined, trace.setSpan(context.active(), parentSpan))
    if (hashes.input_sha256) s.setAttribute('audit.input_sha256', hashes.input_sha256)
    if (hashes.output_sha256) s.setAttribute('audit.output_sha256', hashes.output_sha256)
    if (hashes.retention) s.setAttribute('retention.class', hashes.retention)
    s.end()
  }
  onDeny(parentSpan: any, reason: string) { this.denials.add(1, { reason }); parentSpan.recordException(new Error(`deny:${reason}`)); parentSpan.setStatus({ code: SpanStatusCode.ERROR, message: reason }) }
  onFinally(parentSpan: any, outcome: 'ok'|'error'|'deny', latencyMs?: number) { this.calls.add(1, { outcome }); if (latencyMs !== undefined) this.latency.record(latencyMs); parentSpan.end() }
}


