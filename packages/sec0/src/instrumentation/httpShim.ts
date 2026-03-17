import type { IncomingMessage, ServerResponse } from 'http'
import type { AgentManager } from './agentManager'
import type { AgentStatePayload } from '../agent-state'

export type HttpHeaderBag = Record<string, string>

export interface HttpToolInvocationContext<TArgs> {
  args: TArgs
  headers: HttpHeaderBag
  idempotencyKey?: string
  // Agent state extracted from headers for @sec0.agent() decorator
  agentState?: AgentStatePayload
  // Trace context for linking spans
  traceId?: string
  spanId?: string
  cause?: { traceId: string; spanId: string }
}

export type HttpBodyParser<TArgs> = (req: IncomingMessage) => Promise<TArgs>

export type ToolLogic<TArgs> = (ctx: HttpToolInvocationContext<TArgs>) => Promise<any>
export type ToolLogicWithManager<TArgs> = (
  ctx: HttpToolInvocationContext<TArgs>,
  manager: AgentManager
) => Promise<any>

export interface HttpToolHandlerOptions {
  onSuccess?(res: ServerResponse, result: any): void
  onError?(res: ServerResponse, error: unknown): void
}

export type NodeHttpToolHandler = (req: IncomingMessage, res: ServerResponse) => Promise<void>

export function createHttpToolHandler<TArgs>(
  parseArgs: HttpBodyParser<TArgs>,
  handler: ToolLogic<TArgs>,
  options?: HttpToolHandlerOptions,
): NodeHttpToolHandler
export function createHttpToolHandler<TArgs>(
  parseArgs: HttpBodyParser<TArgs>,
  handler: ToolLogicWithManager<TArgs>,
  options?: HttpToolHandlerOptions,
): NodeHttpToolHandler
export function createHttpToolHandler<TArgs>(
  parseArgs: HttpBodyParser<TArgs>,
  handler: ToolLogic<TArgs> | ToolLogicWithManager<TArgs>,
  options?: HttpToolHandlerOptions,
): NodeHttpToolHandler {
  return async (req, res) => {
    const headers = normalizeHeaders(req.headers)
    try {
      const args = await parseArgs(req)
      // Extract agent state from headers for @sec0.agent() decorator
      const agentState = extractAgentStateFromHeaders(headers)
      // Extract trace context from headers
      const traceId = headers['x-cause-trace'] || headers['traceparent']?.split('-')?.[1]
      const spanId = headers['x-cause-span'] || headers['traceparent']?.split('-')?.[2]
      const context: HttpToolInvocationContext<TArgs> = {
        args,
        headers,
        idempotencyKey: headers['x-idempotency-key'],
        agentState,
        traceId,
        spanId,
        // Cause format expected by decorators: { traceId, spanId }
        cause: traceId && spanId ? { traceId, spanId } : undefined,
      }
      const invoke = handler as ToolLogic<TArgs>
      const result = await invoke(context)
      if (options?.onSuccess) {
        options.onSuccess(res, result)
        return
      }
      sendJson(res, 200, result ?? {})
    } catch (error: any) {
      if (options?.onError) {
        options.onError(res, error)
        return
      }
      const statusCode = deriveStatusCode(error)
      sendJson(res, statusCode, {
        error: statusCode === 400 ? 'bad_request' : 'internal_error',
        message: error instanceof Error ? error.message : String(error),
      })
    }
  }
}

export function jsonBodyParser<TArgs = Record<string, any>>(): HttpBodyParser<TArgs> {
  return async (req) => {
    const raw = await readRequestBody(req)
    if (!raw) {
      return {} as TArgs
    }
    try {
      return JSON.parse(raw) as TArgs
    } catch {
      const error: any = new Error('Invalid JSON body')
      error.statusCode = 400
      throw error
    }
  }
}

function normalizeHeaders(headers: IncomingMessage['headers']): HttpHeaderBag {
  const result: HttpHeaderBag = {}
  if (!headers) return result
  for (const [key, value] of Object.entries(headers)) {
    if (!value) continue
    const normalizedKey = key.toLowerCase()
    if (Array.isArray(value) && value.length) {
      result[normalizedKey] = String(value[0])
    } else {
      result[normalizedKey] = String(value)
    }
  }
  return result
}

/**
 * Extract agent state from HTTP headers for use with @sec0.agent() decorator.
 * The decorator expects agentState to either:
 * 1. Not be provided (decorator uses defaults from config)
 * 2. Have a matching nodeId (for validation)
 * We pass runId via a different mechanism - through the context.
 * The httpShim should NOT populate agentState from headers as each hop
 * uses its own configured nodeId.
 */
function extractAgentStateFromHeaders(_headers: HttpHeaderBag): AgentStatePayload | undefined {
  // Don't extract agent state from headers - each hop uses its own config
  // The runId for tracing is passed through cause context, not agentState
  return undefined
}

async function readRequestBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = []
  for await (const chunk of req) {
    if (typeof chunk === 'string') {
      chunks.push(Buffer.from(chunk))
    } else if (chunk instanceof Buffer) {
      chunks.push(chunk)
    } else {
      chunks.push(Buffer.from(chunk as Uint8Array))
    }
  }
  if (!chunks.length) {
    return ''
  }
  return Buffer.concat(chunks).toString('utf8')
}

function deriveStatusCode(error: any): number {
  const candidate = error?.statusCode
  if (typeof candidate === 'number' && candidate >= 400 && candidate <= 599) {
    return candidate
  }
  if (error instanceof SyntaxError) {
    return 400
  }
  return 500
}

function sendJson(res: ServerResponse, statusCode: number, payload: unknown): void {
  if (res.writableEnded) {
    return
  }
  res.statusCode = statusCode
  res.setHeader('Content-Type', 'application/json')
  res.end(JSON.stringify(payload ?? {}))
}


