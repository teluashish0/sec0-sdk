import { diag, DiagConsoleLogger, DiagLogLevel, context, trace, Span, SpanKind, SpanStatusCode, propagation, Context } from "@opentelemetry/api";
import { NodeTracerProvider } from "@opentelemetry/sdk-trace-node";
import { ParentBasedSampler, TraceIdRatioBasedSampler } from "@opentelemetry/sdk-trace-base";
import { BatchSpanProcessor } from "@opentelemetry/sdk-trace-base";
import { Resource } from "@opentelemetry/resources";
import { SemanticResourceAttributes } from "@opentelemetry/semantic-conventions";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-grpc";

const TRACER_NAME = "sec0";
const LOG_PREFIX = "[sec0-otel]";

export interface OTelConfig {
  // OTLP/GRPC collector endpoint (must be reachable).
  endpoint: string;
  // Canonical name for the emitting service (displayed in traces).
  serviceName: string;
  // Semantic version of the service (required for determinism).
  serviceVersion?: string;
  // Deployment environment identifier, e.g. prod/dev.
  environment?: string;
  // Tenant identifier so multi-tenant traces can be filtered.
  tenant?: string;
  // Sampling configuration expressed as a ratio (0-1).
  sample?: { success?: number; error?: number };
}

let provider: NodeTracerProvider | undefined;

function requireNonEmptyString(value: unknown, fieldName: string): string {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`${LOG_PREFIX} ${fieldName} is required`);
  }
  return value.trim();
}

function requireSampleRatio(value: unknown, fieldName: string): number {
  if (typeof value !== "number" || Number.isNaN(value)) {
    throw new Error(`${LOG_PREFIX} ${fieldName} must be a number between 0 and 1`);
  }
  if (value < 0 || value > 1) {
    throw new Error(`${LOG_PREFIX} ${fieldName} must be between 0 and 1`);
  }
  return value;
}

/**
 * Initialize OTEL once per process with enforced config.
 */
export function initTracing(cfg: OTelConfig): void {
  if (provider) {
    throw new Error(`${LOG_PREFIX} tracing has already been initialized`);
  }
  const endpoint = requireNonEmptyString(cfg.endpoint, "cfg.endpoint");
  const serviceName = requireNonEmptyString(cfg.serviceName, "cfg.serviceName");
  const serviceVersion = requireNonEmptyString(cfg.serviceVersion, "cfg.serviceVersion");
  const environment = requireNonEmptyString(cfg.environment, "cfg.environment");
  const tenant = requireNonEmptyString(cfg.tenant, "cfg.tenant");
  const successSample = requireSampleRatio(cfg.sample?.success, "cfg.sample.success");
  diag.setLogger(new DiagConsoleLogger(), DiagLogLevel.ERROR);
  const resource = new Resource({
    [SemanticResourceAttributes.SERVICE_NAME]: serviceName,
    [SemanticResourceAttributes.SERVICE_VERSION]: serviceVersion,
    [SemanticResourceAttributes.DEPLOYMENT_ENVIRONMENT]: environment,
    tenant,
  });
  const sampler = new ParentBasedSampler({ root: new TraceIdRatioBasedSampler(successSample) });
  provider = new NodeTracerProvider({ resource, sampler });
  const exporter = new OTLPTraceExporter({ url: endpoint });
  provider.addSpanProcessor(new BatchSpanProcessor(exporter));
  provider.register();
}

export function getTracer() {
  return trace.getTracer(TRACER_NAME);
}

export type CanonicalAttributes = {
  [key: string]: string | number | boolean | undefined | null;
};

/**
 * Fail loudly when span metadata is missing or malformed.
 */
export function setSpanAttributes(span: Span, attrs: CanonicalAttributes): void {
  if (!attrs || Object.keys(attrs).length === 0) {
    throw new Error(`${LOG_PREFIX} span attributes are required`);
  }
  for (const [k, v] of Object.entries(attrs)) {
    const key = k?.trim();
    if (!key) {
      throw new Error(`${LOG_PREFIX} span attribute key is required`);
    }
    if (v === undefined || v === null) {
      throw new Error(`${LOG_PREFIX} span attribute "${key}" is required`);
    }
    span.setAttribute(key, v as string | number | boolean);
  }
}

/**
 * Pull a parent context from arbitrary headers if provided.
 */
export function extractContextFromHeaders(headers: Record<string, string> | undefined): Context | undefined {
  if (!headers) return undefined;
  try {
    const carrier: Record<string, string> = {};
    for (const [k, v] of Object.entries(headers)) carrier[k.toLowerCase()] = v;
    return propagation.extract(context.active(), carrier);
  } catch {
    return undefined;
  }
}

/**
 * Server hop span: caller supplies an explicit operation name + attrs.
 */
export function startInvokeSpan(spanName: string, attrs: CanonicalAttributes = {}, parentCtx?: Context): Span {
  const operation = requireNonEmptyString(spanName, "span name");
  const tracer = getTracer();
  const span = tracer.startSpan(operation, { kind: SpanKind.SERVER }, parentCtx ?? undefined);
  setSpanAttributes(span, attrs);
  return span;
}

/**
 * Internal hop span: also requires caller-provided operation + attrs.
 */
export function startExecSpan(spanName: string, attrs: CanonicalAttributes): Span {
  const operation = requireNonEmptyString(spanName, "span name");
  const tracer = getTracer();
  const span = tracer.startSpan(operation, { kind: SpanKind.INTERNAL });
  setSpanAttributes(span, attrs);
  return span;
}

/**
 * Mark span success while annotating deterministic latency.
 */
export function endSpanOk(span: Span, latencyMs?: number) {
  if (latencyMs !== undefined) span.setAttribute("latency_ms", latencyMs);
  span.setStatus({ code: SpanStatusCode.OK });
  span.end();
}

/**
 * Record failures with rich error status + latency.
 */
export function endSpanErr(span: Span, err: Error, latencyMs?: number) {
  if (latencyMs !== undefined) span.setAttribute("latency_ms", latencyMs);
  span.recordException(err);
  span.setStatus({ code: SpanStatusCode.ERROR, message: err.message });
  span.end();
}
