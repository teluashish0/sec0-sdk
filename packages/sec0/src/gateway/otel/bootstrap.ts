// OpenTelemetry bootstrap for sec0-gateway.
import { diag, DiagConsoleLogger, DiagLogLevel, context, propagation, trace, metrics } from '@opentelemetry/api'
import { NodeTracerProvider } from '@opentelemetry/sdk-trace-node'
import { PeriodicExportingMetricReader, MeterProvider } from '@opentelemetry/sdk-metrics'
import { Resource } from '@opentelemetry/resources'
import { SemanticResourceAttributes } from '@opentelemetry/semantic-conventions'
import { BatchSpanProcessor, ParentBasedSampler, TraceIdRatioBasedSampler } from '@opentelemetry/sdk-trace-base'
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-grpc'

// Required, explicit OTel configuration for the gateway.
// All string fields must be non-empty; successRatio is optional but validated.
// Strictly typed config object for initializing OpenTelemetry once.
type GatewayOTelConfig = {
  serviceName: string
  serviceVersion: string
  environment: string
  otlp: string
  successRatio?: number
}

// Global init guard and canonical instrument names.
let inited = false
const TRACER_NAME = 'sec0-gateway'
const METER_NAME = 'sec0-gateway'

/**
 * Initialize OpenTelemetry for the gateway.
 * Must be called exactly once with a fully-populated config; throws loudly on any missing/invalid field.
 */
export function initOTel(opts: GatewayOTelConfig) {
  if (inited) return

  if (!opts || typeof opts !== 'object') {
    throw new Error('[sec0-gateway][otel] initOTel requires a configuration object')
  }

  const name = typeof opts.serviceName === 'string' ? opts.serviceName.trim() : ''
  const version = typeof opts.serviceVersion === 'string' ? opts.serviceVersion.trim() : ''
  const environment = typeof opts.environment === 'string' ? opts.environment.trim() : ''
  const endpoint = typeof opts.otlp === 'string' ? opts.otlp.trim() : ''

  if (!name) {
    throw new Error('[sec0-gateway][otel] serviceName is required and must be a non-empty string')
  }
  if (!version) {
    throw new Error('[sec0-gateway][otel] serviceVersion is required and must be a non-empty string')
  }
  if (!environment) {
    throw new Error('[sec0-gateway][otel] environment is required and must be a non-empty string')
  }
  if (!endpoint) {
    throw new Error('[sec0-gateway][otel] otlp endpoint is required and must be a non-empty string')
  }

  let ratio = opts.successRatio
  if (ratio === undefined) {
    ratio = 1.0
  } else if (!Number.isFinite(ratio) || ratio <= 0 || ratio > 1) {
    throw new Error('[sec0-gateway][otel] successRatio must be a finite number in the range (0, 1]')
  }

  diag.setLogger(new DiagConsoleLogger(), DiagLogLevel.ERROR)
  const resource = new Resource({
    [SemanticResourceAttributes.SERVICE_NAME]: name,
    [SemanticResourceAttributes.SERVICE_VERSION]: version,
    [SemanticResourceAttributes.DEPLOYMENT_ENVIRONMENT]: environment,
  })

  const provider = new NodeTracerProvider({
    resource,
    sampler: new ParentBasedSampler({ root: new TraceIdRatioBasedSampler(ratio) }),
  })
  provider.addSpanProcessor(new BatchSpanProcessor(new OTLPTraceExporter({ url: endpoint })))
  provider.register()
  inited = true
}

/**
 * Get the gateway tracer; requires that initOTel has run.
 * Throws if called before initialization to avoid silent no-op spans.
 */
export function getTracer() {
  if (!inited) {
    throw new Error('[sec0-gateway][otel] initOTel must be called before getTracer')
  }
  return trace.getTracer(TRACER_NAME)
}

/**
 * Get the gateway meter; requires that initOTel has run.
 * Throws if called before initialization to keep metrics wiring explicit.
 */
export function getMeter() {
  if (!inited) {
    throw new Error('[sec0-gateway][otel] initOTel must be called before getMeter')
  }
  return metrics.getMeter(METER_NAME)
}

/**
 * Logger helper for components that want a console-like logger.
 */
export function getLogger() { return console as any }

/**
 * Fast check to see if OTel has been initialized for this process.
 */
export function isEnabled() { return inited }

/**
 * Extract an OpenTelemetry context from HTTP headers with a lowercase-normalized
 * carrier so downstream spans join the caller's trace.
 */
export function extractCtx(headers: Record<string,string> | undefined) { if (!headers) return context.active(); const carrier: Record<string,string> = {}; for (const [k,v] of Object.entries(headers)) carrier[k.toLowerCase()] = String(v); return propagation.extract(context.active(), carrier) }

/**
 * Wrapper for internal IO that could later suppress instrumentation; currently
 * executes the function directly but centralizes the call site.
 */
export async function suppressForInternalIO<T>(fn: () => Promise<T> | T) { return fn() }


