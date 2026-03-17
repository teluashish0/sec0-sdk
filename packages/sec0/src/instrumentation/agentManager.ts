import { encodeAgentStateHeaders, type AgentStatePayload } from '../agent-state'
import { buildIdempotencyKey, callToolViaGateway } from '../middleware'
import { HopTransporter } from './hopTransports'
import { getLocalHopHandler } from './localHopRegistry'

type HopKind = 'agent' | 'gateway' | 'orchestrator' | 'server' | 'tool' | 'middleware' | 'skill'

export type ManagedHopDescriptor =
  | ManagedGatewayHop
  | ManagedGenericHop

export interface ManagedGatewayHop {
  key: string
  type: 'gateway'
  config: {
    nodeId: string
    gatewayBaseUrl: string
    tenant: string
    authHeader?: string
  }
}

export interface ManagedGenericHop {
  key: string
  type: Exclude<HopKind, 'gateway'>
  config: {
    nodeId: string
    remoteUrl?: string
  }
}

export type AgentManagerDependencies = {
  resolveHop(hopKey: string): ManagedHopDescriptor
  transporter: HopTransporter
  cause?: { traceId: string; spanId: string }
}

export type AgentStateHelperAdapter = {
  hopType: HopKind
  hopKey?: string
  readonly runId: string
  readonly nodeId?: string
  setVars(entries: AgentStateVarInput): AgentStateHelperAdapter
  setScopeData(data: Record<string, any>): AgentStateHelperAdapter
  snapshot(): AgentStatePayload
  buildAgentState(
    hopType: HopKind,
    hopKey: string,
    initial?: AgentStatePayload
  ): AgentStatePayload
}

type AgentStateVarInput = Record<string, string | number | boolean | null | undefined>

function requireNonEmptyString(value: unknown, label: string): string {
  const s = typeof value === 'string' ? value.trim() : ''
  if (!s) {
    throw new Error(`[sec0-node] ${label} must be a non-empty string.`)
  }
  return s
}

class AgentStateFacade {
  constructor(private readonly helper: AgentStateHelperAdapter) {}

  setState(entries: AgentStateVarInput): this {
    this.helper.setVars(entries)
    return this
  }

  // Return canonical Sec0 agent-state headers for the current hop state.
  // This is the recommended way for application authors to propagate Sec0 context
  // (x-node-id / x-agent-ref / x-agent-state) across process boundaries.
  // `extra` headers are allowed (e.g. approval tokens), but Sec0 headers win if there
  // is an accidental collision.
  headers(extra?: Record<string, string>): Record<string, string> {
    // Default to minimal propagation to avoid unintentionally shipping variables/metadata
    // across process boundaries. Authors can still explicitly encode a full snapshot
    // via sec0-agent-state if needed.
    const snapshot = this.helper.snapshot()
    const runId = requireNonEmptyString(snapshot?.runId, 'agent.runId')
    const nodeId = requireNonEmptyString(snapshot?.nodeId, 'agent.nodeId')
    const base = encodeAgentStateHeaders({ nodeId, runId })
    return { ...(extra || {}), ...base }
  }

  objective(value: string): this {
    if (typeof value !== 'string') {
      throw new Error('[sec0-node] manager.agent.objective(value) requires a string input.')
    }
    const normalized = value.trim()
    if (!normalized) {
      throw new Error('[sec0-node] manager.agent.objective(value) requires a non-empty string.')
    }
    this.helper.setVars({ objective: normalized })
    return this
  }

  setMetadata(data: Record<string, any>): this {
    this.helper.setScopeData(data)
    return this
  }

  snapshot(): AgentStatePayload {
    return this.helper.snapshot()
  }
}

export class AgentManager implements AgentStateHelperAdapter {
  readonly agent: AgentStateFacade

  constructor(
    private readonly helper: AgentStateHelperAdapter,
    private readonly deps: AgentManagerDependencies,
  ) {
    this.agent = new AgentStateFacade(helper)
  }

  get hopType(): HopKind {
    return this.helper.hopType
  }

  get hopKey(): string | undefined {
    return this.helper.hopKey
  }

  get runId(): string {
    return this.helper.runId
  }

  get nodeId(): string | undefined {
    return this.helper.nodeId
  }

  // Deterministic idempotency key helper.
  // Most authors should prefer enabling `automation.idempotency: true` on the hop config,
  // which auto-stamps `x-idempotency-key` and `params.idKey` for decorated hops.
  // This helper exists for cases where you want an explicit key value (e.g. storing it,
  // or passing it into a non-decorated transport).
  getIdempotencyKey(input: { toolAtVersion: string; args?: any; salt?: string }): string {
    const toolAtVersion = requireNonEmptyString(input?.toolAtVersion, 'input.toolAtVersion')
    return buildIdempotencyKey({
      runId: requireNonEmptyString(this.runId, 'manager.runId'),
      nodeId: requireNonEmptyString(this.nodeId, 'manager.nodeId'),
      toolAtVersion,
      args: input?.args,
      salt: input?.salt,
    })
  }

  static getIdempotencyKeyFor(input: { runId: string; nodeId: string; toolAtVersion: string; args?: any; salt?: string }): string {
    const toolAtVersion = requireNonEmptyString(input?.toolAtVersion, 'input.toolAtVersion')
    return buildIdempotencyKey({
      runId: requireNonEmptyString(input?.runId, 'input.runId'),
      nodeId: requireNonEmptyString(input?.nodeId, 'input.nodeId'),
      toolAtVersion,
      args: input?.args,
      salt: input?.salt,
    })
  }

  // Minimal Sec0 propagation headers for the current hop.
  // This avoids pushing arbitrary agent variables/metadata across boundaries.
  getAgentStateHeaders(extra?: Record<string, string>): Record<string, string> {
    return AgentManager.getAgentStateHeadersFor(
      requireNonEmptyString(this.nodeId, 'manager.nodeId'),
      requireNonEmptyString(this.runId, 'manager.runId'),
      extra
    )
  }

  // Minimal Sec0 propagation headers from explicit nodeId/runId.
  // Use this when you have identifiers but are not inside a decorated hop.
  static getAgentStateHeadersFor(nodeId: string, runId: string, extra?: Record<string, string>): Record<string, string> {
    const base = encodeAgentStateHeaders({
      nodeId: requireNonEmptyString(nodeId, 'nodeId'),
      runId: requireNonEmptyString(runId, 'runId'),
    })
    return { ...(extra || {}), ...base }
  }

  // @deprecated Use getAgentStateHeaders()
  sec0Headers(extra?: Record<string, string>): Record<string, string> {
    return this.getAgentStateHeaders(extra)
  }

  // @deprecated Use getAgentStateHeadersFor()
  static sec0HeadersFor(nodeId: string, runId: string, extra?: Record<string, string>): Record<string, string> {
    return AgentManager.getAgentStateHeadersFor(nodeId, runId, extra)
  }

  setVars(entries: AgentStateVarInput): this {
    this.helper.setVars(entries)
    return this
  }

  setScopeData(data: Record<string, any>): this {
    this.helper.setScopeData(data)
    return this
  }

  snapshot(): AgentStatePayload {
    return this.helper.snapshot()
  }

  buildAgentState(hopType: HopKind, hopKey: string, initial?: AgentStatePayload): AgentStatePayload {
    return this.helper.buildAgentState(hopType, hopKey, initial)
  }

  async invoke(hopKey: string, params: Record<string, any>): Promise<any> {
    const hop = this.deps.resolveHop(hopKey)
    switch (hop.type) {
      case 'gateway':
        return this.invokeGateway(hop, params as GatewayInvokeParams)
      default:
        return this.invokeGeneric(hop, params)
    }
  }

  private async invokeGateway(hop: ManagedGatewayHop, params: GatewayInvokeParams) {
    if (!hop.config.gatewayBaseUrl) {
      throw new Error('[sec0] Gateway hop missing gatewayBaseUrl.')
    }
    if (!hop.config.tenant) {
      throw new Error('[sec0] Gateway hop missing tenant.')
    }
    const snapshot = this.helper.snapshot()
    const agentState = this.helper.buildAgentState('gateway', hop.key, snapshot)
    // Require cause for trace linking - it should be provided via dependencies
    if (!this.deps.cause) {
      throw new Error('[sec0] Gateway invoke requires trace context (cause). Ensure the calling decorator propagates traceId/spanId.')
    }
    return callToolViaGateway({
      gatewayBaseUrl: params.gatewayBaseUrl ?? hop.config.gatewayBaseUrl,
      server: params.server,
      toolAtVersion: params.toolAtVersion,
      args: params.args,
      authHeader: params.authHeader ?? hop.config.authHeader,
      tenant: params.tenant ?? hop.config.tenant,
      runId: params.runId ?? agentState.runId,
      nodeId: params.nodeId ?? hop.config.nodeId,
      agentState,
      cause: params.cause ?? this.deps.cause,
    })
  }

  private async invokeGeneric(hop: ManagedGenericHop, params: Record<string, any>) {
    const snapshot = this.helper.snapshot()
    const agentState = this.helper.buildAgentState(hop.type, hop.key, snapshot)
    if (hop.config.remoteUrl) {
      return this.deps.transporter.invokeRemote(hop, params, agentState)
    }
    const handler = getLocalHopHandler(hop.key)
    if (!handler) {
      throw new Error(`[sec0] No local handler registered for hop "${hop.key}".`)
    }
    return handler(params, agentState)
  }
}

export type GatewayInvokeParams = {
  server: string
  toolAtVersion: string
  args: Record<string, any>
  nodeId?: string
  runId?: string
  tenant?: string
  gatewayBaseUrl?: string
  authHeader?: string
  cause?: { traceId: string; spanId: string }
}
