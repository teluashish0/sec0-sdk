import { Sec0Appender } from '../audit'
import type { EscalationCreateResult, EscalationReporter } from '../core/contracts'
import type { PolicyObject } from '../policy'
import { LocalDevSigner, sha256Hex } from '../signer'
import * as fs from 'node:fs'
import * as path from 'node:path'
import * as os from 'node:os'
import { randomBytes } from 'node:crypto'
import * as yaml from 'js-yaml'
import { AsyncLocalStorage } from 'node:async_hooks'
import {
  NodeIdentity,
  normalizeAgent,
  normalizeOrchestrator,
  resolveNodeIdentity,
  baseEnvelope,
  finalizeIdentity
} from './identity'
import { AgentManager, type ManagedHopDescriptor } from './agentManager'
import { HopTransporter } from './hopTransports'
export { AgentManager } from './agentManager'
export { registerLocalHopHandler, unregisterLocalHopHandler } from './localHopRegistry'
export type { GatewayInvokeParams } from './agentManager'
export { createHttpToolHandler, jsonBodyParser } from './httpShim'
export type { HttpToolInvocationContext, NodeHttpToolHandler, HttpBodyParser } from './httpShim'

const hopTransporter = new HopTransporter()
import {
  normalizeAgentStatePayload,
  mergeAgentVariables,
  ensureRunId,
  type AgentStatePayload,
  type AgentStateVariables,
  type OrchestratorPlanState,
  type AgentExecutionState,
} from '../agent-state'
import { compareArgsToDigest } from '../mandate-ap2'
import { createControlPlaneClient } from '../middleware/adapters/controlPlaneClient'
import { createControlPlaneEscalationReporter } from '../middleware/adapters/escalationReporter'
import { createControlPlanePolicyManager, type ControlPlanePolicySource } from '../middleware/controlPlanePolicy'

// Control plane resolution defaults (SaaS-first with optional overrides).
const DEFAULT_CONTROL_PLANE_URL = 'https://api.sec0.ai'

function readEnv(name: string): string | undefined {
  try {
    const value = typeof process !== 'undefined' ? process.env?.[name] : undefined
    const trimmed = typeof value === 'string' ? value.trim() : ''
    return trimmed ? trimmed : undefined
  } catch {
    return undefined
  }
}

function resolveControlPlaneUrlValue(explicit?: string | null): string {
  const envOverride =
    readEnv('SEC0_CONTROL_PLANE_URL') ||
    readEnv('CONTROL_PLANE_URL') ||
    readEnv('API_BASE_URL')
  const raw = (explicit ?? '').trim() || envOverride || DEFAULT_CONTROL_PLANE_URL
  const normalized = String(raw || '').trim().replace(/\/+$/, '')
  if (!normalized) {
    throw new Error('[sec0-node] controlPlaneUrl could not be resolved')
  }
  return normalized
}

// Sec0 SDK Configuration
export interface Sec0Config {
  // Local directory for storing keys, audit logs, and cache
  localDir?: string
  // Default tenant identifier
  tenant?: string
  // Control plane base URL used for API key validation (defaults to Sec0 control plane).
  controlPlaneUrl?: string
  // API key used to resolve tenant/client/env metadata
  apiKey?: string
  // Path to local signer key file
  localSignerPath: string
  // Custom appender configuration
  appender?: {
    // Directory for audit logs
    dir?: string
    // Custom appender options
    [key: string]: any
  }
}

// Global configuration state
let globalConfig: Sec0Config | null = null

/**
 * Get the current global configuration
 */
export function getConfig(): Sec0Config | null {
  return globalConfig
}

/**
 * Initialize Sec0 SDK with configuration
 * @param configPathOrObject - Path to YAML config file or config object
 * @returns The loaded configuration
 * @example
 * // Load from YAML file
 * initSec0('./sec0.config.yaml')
 * @example
 * // Load from object
 * initSec0({
 *   localDir: '/var/sec0-data',
 *   tenant: 'my-company'
 * })
 */
export function initSec0(configPathOrObject: string | Sec0Config): Sec0Config {
  let config: Partial<Sec0Config> = {}

  if (typeof configPathOrObject === 'string') {
    // Load from YAML file
    const configPath = path.isAbsolute(configPathOrObject) 
      ? configPathOrObject 
      : path.resolve(configPathOrObject)
    
    if (!fs.existsSync(configPath)) {
      throw new Error(`[sec0] Config file not found: ${configPath}`)
    }

    try {
      const fileContents = fs.readFileSync(configPath, 'utf8')
      const parsed = yaml.load(fileContents) as Sec0Config
      
      if (!parsed || typeof parsed !== 'object') {
        throw new Error(`[sec0] Invalid config file: ${configPath}`)
      }

      config = parsed
      console.log(`[sec0] Loaded configuration from: ${configPath}`)
    } catch (error) {
      const errMsg = error instanceof Error ? error.message : String(error)
      console.error(`[sec0] Failed to load config: ${errMsg}`)
      throw error
    }
  } else if (configPathOrObject && typeof configPathOrObject === 'object') {
    // Use provided config object
    config = configPathOrObject
    console.log('[sec0] Initialized with provided configuration')
  } else {
    throw new Error(
      '[sec0] Configuration required. Please provide a config file path or config object. ' +
      'Example: initSec0({ localDir: "/var/sec0-data", tenant: "my-company" })'
    )
  }

  // Validate required configuration
  if (!config.localDir) {
    throw new Error(
      '[sec0] localDir is required in configuration. ' +
      'Example: initSec0({ localDir: "/var/sec0-data", tenant: "my-company" })'
    )
  }

  // Ensure localDir is absolute
  if (!path.isAbsolute(config.localDir)) {
    config.localDir = path.resolve(config.localDir)
  }

  // Require and ensure localSignerPath is absolute and exists
  if (!config.localSignerPath) {
    throw new Error('[sec0] localSignerPath is required in configuration (absolute path to ED25519 base64 key file)')
  }
  if (!path.isAbsolute(config.localSignerPath)) {
    config.localSignerPath = path.resolve(config.localSignerPath)
  }
  if (!fs.existsSync(config.localSignerPath)) {
    throw new Error(`[sec0] Signing key file not found at: ${config.localSignerPath}`)
  }

  // Ensure appender dir is absolute if provided
  if (config.appender?.dir && !path.isAbsolute(config.appender.dir)) {
    config.appender.dir = path.resolve(config.appender.dir)
  }

  // Store as global config
  globalConfig = config as Sec0Config

  console.log(`[sec0] Configuration initialized: localDir=${globalConfig.localDir}`)

  return globalConfig
}

/**
 * Helper for deep merging configuration objects.
 * - Objects are merged recursively.
 * - Arrays are replaced (last one wins).
 * - Primitives are replaced.
 */
function deepMerge(target: any, source: any): any {
  if (typeof target !== 'object' || target === null || typeof source !== 'object' || source === null) {
    return source
  }
  if (Array.isArray(target) || Array.isArray(source)) {
    return source
  }
  const result = { ...target }
  for (const key of Object.keys(source)) {
    if (key in result) {
      result[key] = deepMerge(result[key], source[key])
    } else {
      result[key] = source[key]
    }
  }
  return result
}

export interface AppConfigOptions<T> {
  // Default configuration object provided by the application
  defaults?: T
  // Name of the configuration file to look for (e.g. 'acme.config.yaml')
  configName?: string
  // Function to map the merged application config to the required Sec0Config
  sec0Mapping?: (config: T) => Partial<Sec0Config>
}

/**
 * Load application configuration, merge with defaults, and initialize Sec0 SDK in one step.
 * This utility eliminates the need for applications to write their own config loaders.
 * @param options Configuration options including defaults and mapping strategy
 * @returns The fully merged application configuration
 */
export function loadAndInitSec0<T extends Record<string, any>>(options: AppConfigOptions<T>): T {
  // 1. Find config file
  const configName = options.configName || 'sec0.config.yaml'
  const configPath = path.resolve(process.cwd(), configName)
  let loadedConfig: any = {}

  if (fs.existsSync(configPath)) {
    try {
      const fileContents = fs.readFileSync(configPath, 'utf8')
      loadedConfig = yaml.load(fileContents)
      console.log(`[sec0] Loaded application config from: ${configPath}`)
    } catch (error) {
      console.warn(`[sec0] Failed to load config file ${configPath}:`, error)
    }
  }

  // 2. Merge defaults and loaded config
  const defaults = options.defaults || {}
  const merged = deepMerge(defaults, loadedConfig) as T

  // 3. Extract Sec0 config
  let sec0Config: Partial<Sec0Config> = {}
  if (options.sec0Mapping) {
    sec0Config = options.sec0Mapping(merged)
  } else {
    // Default strategy: look for a 'sec0' block
    sec0Config = (merged as any).sec0 || {}
  }

  // 4. Initialize Sec0
  // We call initSec0 with the object, which handles validation and global state
  initSec0(sec0Config as Sec0Config)

  return merged
}

const STANDARD_APP_ENVIRONMENTS = new Set(['dev', 'staging', 'prod'])

function enforceStandardAppMetadata<T extends StandardAppConfig>(cfg: T): void {
  if (!cfg?.app) {
    throw new Error('[sec0] app configuration block is required.')
  }

  const rawEnv = cfg.app.environment
  if (typeof rawEnv !== 'string' || !rawEnv.trim()) {
    throw new Error('[sec0] app.environment must be set to one of dev, staging, or prod.')
  }

  const normalizedEnv = rawEnv.trim().toLowerCase()
  if (!STANDARD_APP_ENVIRONMENTS.has(normalizedEnv)) {
    throw new Error(`[sec0] app.environment "${rawEnv}" is invalid. Expected dev, staging, or prod.`)
  }
  cfg.app.environment = normalizedEnv as T['app']['environment']

  const client = cfg.app.client
  if (!client) {
    return
  }

  if (client.version === undefined || client.version === null) {
    console.warn('[sec0] app.client.version is not set; continuing without client version metadata.')
    delete (client as any).version
    return
  }

  if (typeof client.version !== 'string') {
    console.warn('[sec0] app.client.version must be a string; continuing without client version metadata.')
    delete (client as any).version
    return
  }

  const trimmedVersion = client.version.trim()
  if (!trimmedVersion) {
    console.warn('[sec0] app.client.version is empty; continuing without client version metadata.')
    delete (client as any).version
    return
  }

  client.version = trimmedVersion
}

export interface StandardAppConfig {
  app: {
    tenant: string
    environment: string
    client?: { name: string; version?: string }
    // Declarative per-hop metadata consumed by SDK decorators
    hops?: Record<string, HopConfig>
  }
  auth?: {
    svcToken?: string
    sec0ApiKey?: string
  }
  controlPlane: {
    apiBaseUrl?: string
    sec0Dir: string
    localSignerPath: string
    appenderDir?: string
    otlpEndpoint?: string
    presign?: { enabled: boolean }
  }
  [key: string]: any
}

// Shared configuration structure for the Sec0 Reference Implementation (ACME).
// Included in the SDK to facilitate the reference architecture components.
export interface ReferenceAppConfig extends StandardAppConfig {
  orchestrator: {
    gatewayBaseUrl: string
  }
  gateway: {
    port: number
    targets: {
      orders: string
      payments: string
      stripe: string
    }
  }
  services: {
    orders: {
      port: number
      storefrontUrl: string
    }
    payments: {
      port: number
      stripeGatewayServer: string
      ordersGatewayServer: string
      stripeApiKey: string
    }
    stripe: {
      port: number
      transactionsPath: string
    }
  }
  proxy?: {
    defaultTarget: string
  }
}

type HopKind = 'agent' | 'orchestrator' | 'gateway' | 'server' | 'tool' | 'middleware' | 'skill'

type HopEnforcementOptions = {
  enabled?: boolean
  mode?: 'observe' | 'enforce'
  strategy?: 'deny_on_match' | 'deny_on_any'
  deny_on?: string[]
  denyOn?: string[]
  escalate_on?: string[]
  escalateOn?: string[]
  policy_level?: 'gateway' | 'middleware'
  policyLevel?: 'gateway' | 'middleware'
  policy_scope?: 'auto' | 'base' | 'agent'
  policyScope?: 'auto' | 'base' | 'agent'
  policy_node_id?: string
  policyNodeId?: string
  refresh_ttl_ms?: number
  refreshTtlMs?: number
  fallback_to_base?: boolean
  fallbackToBase?: boolean
}

type HopConfigBase = {
  type: HopKind
  nodeId?: string
  automation?: HopAutomationOptions
  enforcement?: HopEnforcementOptions
  remoteUrl?: string
}

type GatewayHopConfig = HopConfigBase & {
  type: 'gateway'
  gateway: string
  gatewayBaseUrl?: string
  tenant?: string
  authHeader?: string
}

type OrchestratorHopConfig = HopConfigBase & {
  type: 'orchestrator'
  orchestratorName?: string
  orchestratorVersion?: string
}

type AgentHopConfig = HopConfigBase & {
  type: 'agent'
  agentName?: string
  agentVersion?: string
}

type ServerHopConfig = HopConfigBase & {
  type: 'server'
  server: string
}

type MiddlewareHopConfig = HopConfigBase & {
  type: 'middleware'
  // Logical middleware identity (name@version recommended)
  middleware: string
  // Logical operation inside the middleware (pinned name@version recommended)
  op: string
}

type ToolHopConfig = HopConfigBase & {
  type: 'tool'
  server: string
  tool: string
  toolRef?: string
}

type SkillHopConfig = HopConfigBase & {
  type: 'skill'
  skill: string
  source?: string
  skillRef?: string
}

type HopConfig =
  | GatewayHopConfig
  | OrchestratorHopConfig
  | AgentHopConfig
  | ServerHopConfig
  | MiddlewareHopConfig
  | ToolHopConfig
  | SkillHopConfig

type RegisteredHop =
  | (GatewayHopConfig & { key: string })
  | (OrchestratorHopConfig & { key: string })
  | (AgentHopConfig & { key: string })
  | (ServerHopConfig & { key: string })
  | (MiddlewareHopConfig & { key: string })
  | (ToolHopConfig & { key: string })
  | (SkillHopConfig & { key: string })

export type AppProfile = {
  tenant: string
  apiKey?: string
  controlPlaneUrl: string
  client?: { name?: string; version?: string }
  environment?: string
}

const hopRegistry = new Map<string, RegisteredHop>()
let currentAppProfile: AppProfile | null = null
let cachedAppConfig: StandardAppConfig | null = null

/**
 * Cache application-wide Sec0 context (tenant/api key/control-plane URL) and every
 * hop defined in app.hops so decorators can auto-resolve their node metadata.
 */
function registerHopConfigs(config: StandardAppConfig) {
  cachedAppConfig = config
  currentAppProfile = {
    tenant: config.app.tenant,
    apiKey: config.auth?.sec0ApiKey,
    controlPlaneUrl: resolveControlPlaneUrlValue(config.controlPlane.apiBaseUrl),
    client: config.app.client,
    environment: config.app.environment,
  }
  hopRegistry.clear()
  const hops = config.app?.hops
  if (!hops) return
  for (const [key, hop] of Object.entries(hops)) {
    hopRegistry.set(key, normalizeHopConfig(key, hop, config))
  }
}

/**
 * @internal Testing hook to seed hop configs without loading YAML.
 */
export function __registerTestHop(key: string, hop: RegisteredHop) {
  hopRegistry.set(key, hop)
}

/**
 * @internal Testing hook to seed the current app profile.
 */
export function __setTestAppProfile(profile: AppProfile) {
  currentAppProfile = profile
}

function normalizeReasonListFromValue(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined
  const normalized = value
    .map((entry) => normalizePolicyReasonToken(entry))
    .filter(Boolean)
  return normalized.length ? Array.from(new Set(normalized)) : undefined
}

function normalizeHopEnforcementOptions(value: unknown): ResolvedHopEnforcementOptions | undefined {
  if (!value || typeof value !== 'object') return undefined
  const raw = value as HopEnforcementOptions
  const mode = raw.mode === 'observe' ? 'observe' : 'enforce'
  const strategy = raw.strategy === 'deny_on_any' ? 'deny_on_any' : 'deny_on_match'
  const denyOn = normalizeReasonListFromValue(raw.denyOn ?? raw.deny_on)
  const escalateOn = normalizeReasonListFromValue(raw.escalateOn ?? raw.escalate_on)
  const policyLevel =
    raw.policyLevel === 'gateway' || raw.policy_level === 'gateway'
      ? 'gateway'
      : raw.policyLevel === 'middleware' || raw.policy_level === 'middleware'
        ? 'middleware'
        : undefined
  const policyScope =
    raw.policyScope === 'base' || raw.policy_scope === 'base'
      ? 'base'
      : raw.policyScope === 'agent' || raw.policy_scope === 'agent'
        ? 'agent'
        : raw.policyScope === 'auto' || raw.policy_scope === 'auto'
          ? 'auto'
          : undefined
  const policyNodeIdCandidate = String(raw.policyNodeId ?? raw.policy_node_id ?? '').trim()
  const refreshTtlRaw = Number(raw.refreshTtlMs ?? raw.refresh_ttl_ms)
  const refreshTtlMs =
    Number.isFinite(refreshTtlRaw) && refreshTtlRaw >= 0
      ? Math.floor(refreshTtlRaw)
      : undefined
  return {
    enabled: raw.enabled !== false,
    mode,
    strategy,
    ...(denyOn ? { denyOn } : {}),
    ...(escalateOn ? { escalateOn } : {}),
    ...(policyLevel ? { policyLevel } : {}),
    ...(policyScope ? { policyScope } : {}),
    ...(policyNodeIdCandidate ? { policyNodeId: policyNodeIdCandidate } : {}),
    ...(refreshTtlMs !== undefined ? { refreshTtlMs } : {}),
    ...(raw.fallbackToBase !== undefined || raw.fallback_to_base !== undefined
      ? { fallbackToBase: raw.fallbackToBase ?? raw.fallback_to_base }
      : {}),
  }
}

function normalizeHopConfig(key: string, hop: HopConfig, config: StandardAppConfig): RegisteredHop {
  if (!hop || typeof hop !== 'object') {
    throw new Error(`[sec0] Invalid hop configuration for "${key}". Expected an object with type information.`)
  }
  if (!hop.type) {
    throw new Error(`[sec0] Hop "${key}" is missing required field 'type'.`)
  }
  const normalizedEnforcement = normalizeHopEnforcementOptions(hop.enforcement)
  switch (hop.type) {
    case 'gateway': {
      if (!hop.gateway?.trim()) {
        throw new Error(`[sec0] Hop "${key}" requires a non-empty 'gateway' value.`)
      }
      if (!hop.nodeId?.trim()) {
        throw new Error(`[sec0] Hop "${key}" requires a non-empty 'nodeId' value.`)
      }
      const gatewayBaseUrl =
        hop.gatewayBaseUrl?.trim() ||
        config.orchestrator?.gatewayBaseUrl?.trim()
      if (!gatewayBaseUrl) {
        throw new Error(
          `[sec0] Hop "${key}" requires 'gatewayBaseUrl'. Provide it in app.hops or orchestrator.gatewayBaseUrl.`
        )
      }
      const tenant = hop.tenant?.trim() || config.app.tenant?.trim()
      if (!tenant) {
        throw new Error(`[sec0] Hop "${key}" requires a tenant value.`)
      }
      const authHeader =
        hop.authHeader === undefined
          ? (config.auth?.svcToken ? `Bearer ${config.auth.svcToken}` : undefined)
          : hop.authHeader.trim() || undefined
      return {
        ...hop,
        gateway: hop.gateway.trim(),
        nodeId: hop.nodeId.trim(),
        gatewayBaseUrl,
        tenant,
        authHeader,
        key,
        enforcement: normalizedEnforcement,
        remoteUrl: hop.remoteUrl?.trim() || undefined,
      }
    }
    case 'orchestrator': {
      if (!hop.nodeId?.trim()) {
        throw new Error(`[sec0] Hop "${key}" requires a non-empty 'nodeId' value.`)
      }
      const orchestratorName = hop.orchestratorName?.trim() || config.app.client?.name?.trim()
      const orchestratorVersion = hop.orchestratorVersion?.trim() || config.app.client?.version?.trim()
      if (!orchestratorName || !orchestratorVersion) {
        throw new Error(
          `[sec0] Hop "${key}" requires orchestratorName and orchestratorVersion (either in app.hops or app.client).`
        )
      }
      return {
        ...hop,
        nodeId: hop.nodeId.trim(),
        orchestratorName,
        orchestratorVersion,
        key,
        enforcement: normalizedEnforcement,
        remoteUrl: hop.remoteUrl?.trim() || undefined,
      }
    }
    case 'agent': {
      if (!hop.nodeId?.trim()) {
        throw new Error(`[sec0] Hop "${key}" requires a non-empty 'nodeId' value.`)
      }
      return {
        ...hop,
        nodeId: hop.nodeId.trim(),
        key,
        enforcement: normalizedEnforcement,
        remoteUrl: hop.remoteUrl?.trim() || undefined,
      }
    }
    case 'server': {
      if (!hop.server?.trim()) {
        throw new Error(`[sec0] Hop "${key}" requires a non-empty 'server' value.`)
      }
      if (!hop.nodeId?.trim()) {
        throw new Error(`[sec0] Hop "${key}" requires a non-empty 'nodeId' value.`)
      }
      return {
        ...hop,
        server: hop.server.trim(),
        nodeId: hop.nodeId.trim(),
        key,
        enforcement: normalizedEnforcement,
        remoteUrl: hop.remoteUrl?.trim() || undefined,
      }
    }
    case 'middleware': {
      if (!hop.middleware?.trim()) {
        throw new Error(`[sec0] Hop "${key}" requires a non-empty 'middleware' value.`)
      }
      if (!hop.op?.trim()) {
        throw new Error(`[sec0] Hop "${key}" requires a non-empty 'op' value.`)
      }
      if (!hop.nodeId?.trim()) {
        throw new Error(`[sec0] Hop "${key}" requires a non-empty 'nodeId' value.`)
      }
      return {
        ...hop,
        middleware: hop.middleware.trim(),
        op: hop.op.trim(),
        nodeId: hop.nodeId.trim(),
        key,
        enforcement: normalizedEnforcement,
        remoteUrl: hop.remoteUrl?.trim() || undefined,
      }
    }
    case 'tool': {
      if (!hop.server?.trim()) {
        throw new Error(`[sec0] Hop "${key}" requires a non-empty 'server' value.`)
      }
      if (!hop.tool?.trim()) {
        throw new Error(`[sec0] Hop "${key}" requires a non-empty 'tool' value.`)
      }
      if (!hop.nodeId?.trim()) {
        throw new Error(`[sec0] Hop "${key}" requires a non-empty 'nodeId' value.`)
      }
      return {
        ...hop,
        server: hop.server.trim(),
        tool: hop.tool.trim(),
        nodeId: hop.nodeId.trim(),
        key,
        enforcement: normalizedEnforcement,
        remoteUrl: hop.remoteUrl?.trim() || undefined,
      }
    }
    case 'skill': {
      if (!hop.skill?.trim()) {
        throw new Error(`[sec0] Hop "${key}" requires a non-empty 'skill' value.`)
      }
      if (!hop.nodeId?.trim()) {
        throw new Error(`[sec0] Hop "${key}" requires a non-empty 'nodeId' value.`)
      }
      return {
        ...hop,
        skill: hop.skill.trim(),
        source: hop.source?.trim() || undefined,
        skillRef: hop.skillRef?.trim() || undefined,
        nodeId: hop.nodeId.trim(),
        key,
        enforcement: normalizedEnforcement,
        remoteUrl: hop.remoteUrl?.trim() || undefined,
      }
    }
    default:
      throw new Error(`[sec0] Hop "${key}" has unknown type "${(hop as any).type}".`)
  }
}

function requireAppProfile(context: string): AppProfile {
  if (!currentAppProfile) {
    throw new Error(`[sec0] ${context} requires loadStandardConfig() or initSec0() to run first.`)
  }
  return currentAppProfile
}

/**
 * Load standard application configuration for Sec0 enabled apps.
 * This is a type-safe wrapper around loadAndInitSec0 that enforces the
 * standard configuration structure used by most Sec0 applications.
 * @param configName Name of the configuration file (default: 'sec0.config.yaml')
 * @param sec0Mapping Optional custom mapping function for Sec0 config
 * @returns The fully merged application configuration
 */
export function loadStandardConfig<T extends StandardAppConfig = StandardAppConfig>(
  configName: string = 'sec0.config.yaml',
  sec0Mapping?: (cfg: T) => Partial<Sec0Config>
): T {
  const config = loadAndInitSec0<T>({
    configName,
    sec0Mapping: sec0Mapping || ((cfg) => {
      const sec0Dir = cfg.controlPlane.sec0Dir
      if (!sec0Dir) throw new Error('[sec0] controlPlane.sec0Dir is required')
      
      const tenant = cfg.app.tenant
      if (!tenant) throw new Error('[sec0] app.tenant is required')

      const localSignerPath = cfg.controlPlane.localSignerPath
      if (!localSignerPath) throw new Error('[sec0] controlPlane.localSignerPath is required')

      const apiKey = cfg.auth?.sec0ApiKey
      const controlPlaneUrl = cfg.controlPlane.apiBaseUrl ? resolveControlPlaneUrlValue(cfg.controlPlane.apiBaseUrl) : undefined
      const appenderDir = cfg.controlPlane.appenderDir ? path.resolve(cfg.controlPlane.appenderDir) : undefined
      
      // Build appender config with optional presign for automatic upload.
      // The control plane URL is auto-discovered from the API key via /api/discover.
      const appenderConfig: { dir?: string; presign?: { apiBaseUrl?: string; auditKey: string } } = {
        dir: appenderDir,
      }
      
      // When apiKey is provided, enable automatic audit upload to control plane
      if (apiKey) {
        const apiKeyStr = String(apiKey).trim()
        if (apiKeyStr) {
          appenderConfig.presign = {
            // Only set apiBaseUrl if explicitly configured; otherwise let sec0-audit auto-discover
            apiBaseUrl: controlPlaneUrl || undefined,
            auditKey: apiKeyStr.startsWith('Bearer ') ? apiKeyStr : `Bearer ${apiKeyStr}`,
          }
        }
      }
      
      return {
        localDir: path.resolve(sec0Dir),
        tenant: tenant,
        apiKey,
        controlPlaneUrl: controlPlaneUrl || resolveControlPlaneUrlValue(undefined),
        localSignerPath: path.resolve(localSignerPath),
        appender: appenderConfig,
      }
    })
  })

  enforceStandardAppMetadata(config)
  registerHopConfigs(config)

  return config
}

/**
 * Retrieve the cached Sec0 application config (lazy-loading sec0.config.yaml if needed).
 */
export function getSec0AppConfig<T extends StandardAppConfig = StandardAppConfig>(): T {
  if (cachedAppConfig) {
    return cachedAppConfig as T
  }
  return loadStandardConfig<T>()
}

/**
 * Explicitly initialize the Sec0 application config (idempotent).
 */
export function initializeSec0App(configPath: string = 'sec0.config.yaml'): void {
  loadStandardConfig(configPath)
}

/**
 * Resolve Sec0 directories defined in sec0.config.yaml.
 */
export function getSec0Directories(): { sec0Dir: string; appenderDir?: string } {
  const config = getSec0AppConfig<StandardAppConfig>()
  const sec0Dir = path.resolve(config.controlPlane.sec0Dir)
  const appenderDir = config.controlPlane.appenderDir
    ? path.resolve(config.controlPlane.appenderDir)
    : undefined
  return { sec0Dir, appenderDir }
}

// Standard application configuration strategy for Sec0 enabled apps.
// This is a drop-in replacement for getAppConfig that:
// 1. Merges defaults with a YAML config file
// 2. Resolves standard Sec0 paths (sec0Dir, etc)
// 3. Initializes the SDK automatically
let standardAppConfigCache: Record<string, any> | null = null

export function getStandardAppConfig<T extends { 
  controlPlane: { sec0Dir: string; apiBaseUrl?: string; localSignerPath: string; appenderDir: string };
  app: { tenant: string };
  auth?: { sec0ApiKey?: string };
}>(defaults: T, configName: string = 'sec0.config.yaml', customResolvers?: (cfg: T) => void): T {

  if (standardAppConfigCache) return standardAppConfigCache as T;

  // Helper to enforce non-empty string configuration values
  const requireString = (value: unknown, field: string): string => {
    if (typeof value !== 'string' || !value.trim()) {
      throw new Error(`[sec0] Missing or invalid configuration value for '${field}'.`);
    }
    return value;
  };
  const requireAbsolutePath = (value: string, field: string): string => {
    if (!path.isAbsolute(value)) {
      throw new Error(`[sec0] ${field} must be an absolute path. Received: ${value}`);
    }
    return value;
  };

  standardAppConfigCache = loadAndInitSec0<T>({
    defaults,
    configName,
    sec0Mapping: (cfg) => {
      
      // Allow custom resolvers to run (e.g. for other service paths)
      if (customResolvers) {
        customResolvers(cfg)
      }
      
      const sec0Dir = requireAbsolutePath(requireString(cfg.controlPlane.sec0Dir, 'controlPlane.sec0Dir'), 'controlPlane.sec0Dir');
      const tenant = requireString(cfg.app.tenant, 'app.tenant');
      const controlPlaneUrl = cfg.controlPlane.apiBaseUrl ? resolveControlPlaneUrlValue(cfg.controlPlane.apiBaseUrl) : undefined;
      const apiKey = requireString(cfg.auth?.sec0ApiKey, 'auth.sec0ApiKey');
      const localSignerPath = requireAbsolutePath(requireString(cfg.controlPlane.localSignerPath, 'controlPlane.localSignerPath'), 'controlPlane.localSignerPath');
      const appenderDir = requireAbsolutePath(requireString(cfg.controlPlane.appenderDir, 'controlPlane.appenderDir'), 'controlPlane.appenderDir');
      
      // Build appender config with presign for automatic upload (apiKey is required in this path).
      // The control plane URL is auto-discovered from the API key via /api/discover.
      const appenderConfig: { dir: string; presign?: { apiBaseUrl?: string; auditKey: string } } = {
        dir: appenderDir,
      }
      
      // Enable automatic audit upload when apiKey is present
      const apiKeyStr = String(apiKey).trim()
      if (apiKeyStr) {
        appenderConfig.presign = {
          // Only set apiBaseUrl if explicitly configured; otherwise let sec0-audit auto-discover
          apiBaseUrl: controlPlaneUrl || undefined,
          auditKey: apiKeyStr.startsWith('Bearer ') ? apiKeyStr : `Bearer ${apiKeyStr}`,
        }
      }
      
      return {
        localDir: sec0Dir,
        tenant,
        apiKey,
        controlPlaneUrl: controlPlaneUrl || resolveControlPlaneUrlValue(undefined),
        localSignerPath,
        appender: appenderConfig,
      }
    }
  })

  return standardAppConfigCache as T;
}

type HierarchyMetadata = {
  tenant: string
  env: string
  clientName: string
  clientVersion: string
}

type HierarchyResolutionOptions = {
  tenant?: string
  apiKey?: string
  controlPlaneUrl?: string
}

type CauseLink = {
  traceId: string
  spanId: string
}

const causeContext = new AsyncLocalStorage<{ cause?: CauseLink }>()

function ensureStandardId(value: any, label: string): string {
  if (typeof value !== 'string') {
    throw new Error(`[sec0-node] ${label} must be a non-empty string.`)
  }
  const trimmed = value.trim()
  if (!trimmed) {
    throw new Error(`[sec0-node] ${label} must be a non-empty string.`)
  }
  return trimmed
}

function deriveCauseFromValue(value: any, label: string): CauseLink {
  if (!value || typeof value !== 'object') {
    throw new Error(`[sec0-node] ${label} must be an object that includes traceId and spanId.`)
  }
  const traceId = ensureStandardId((value as any).traceId, `${label}.traceId`)
  const spanId = ensureStandardId((value as any).spanId, `${label}.spanId`)
  return {
    traceId,
    spanId,
  }
}

function maybeDeriveCause(value: any, label: string): CauseLink | undefined {
  if (value === undefined || value === null) {
    return undefined
  }
  return deriveCauseFromValue(value, label)
}

function hasStandardCauseFields(value: any): boolean {
  if (!value || typeof value !== 'object') return false
  const traceId = (value as any).traceId
  const spanId = (value as any).spanId
  return (
    typeof traceId === 'string' &&
    traceId.trim().length > 0 &&
    typeof spanId === 'string' &&
    spanId.trim().length > 0
  )
}

function withCauseScope<T>(initial: CauseLink | undefined, fn: () => Promise<T>): Promise<T> {
  const existing = causeContext.getStore()
  if (existing) {
    if (initial) existing.cause = initial
    return fn()
  }
  return causeContext.run({ cause: initial }, fn)
}

function getCurrentCause(): CauseLink | undefined {
  return causeContext.getStore()?.cause
}

function seedCauseFromParams(params: any) {
  if (!params || typeof params !== 'object') return
  const explicit = maybeDeriveCause(params.cause, 'params.cause')
  if (explicit) {
    params.cause = { ...explicit }
    const store = causeContext.getStore()
    if (store) {
      store.cause = explicit
    }
    return
  }
  const store = causeContext.getStore()
  if (store?.cause && !params.cause) {
    params.cause = { ...store.cause }
  }
}

function updateCauseFromResult(value: any) {
  const store = causeContext.getStore()
  if (!store || !hasStandardCauseFields(value)) return
  store.cause = deriveCauseFromValue(value, 'result')
}

type RunContextStore = { runId?: string }
const runContext = new AsyncLocalStorage<RunContextStore>()

type AgentStateScope = { helper: AgentStateHelperImpl }
const agentStateContext = new AsyncLocalStorage<AgentStateScope>()

function withAgentStateScope<T>(helper: AgentStateHelperImpl, fn: () => Promise<T> | T): Promise<T> | T {
  return agentStateContext.run({ helper }, fn)
}

function requireAgentStateScope(action: string): AgentStateHelperImpl {
  const scope = agentStateContext.getStore()
  if (!scope?.helper) {
    throw new Error(
      `[sec0] ${action} can only be used inside a @sec0.* decorated method. ` +
        'Each decorator now injects an AgentStateHelper as the last argument; use that helper instead.'
    )
  }
  return scope.helper
}

function getCurrentRunId(): string | undefined {
  return runContext.getStore()?.runId
}

function resolveRunId(candidate?: string): string {
  const trimmed = typeof candidate === 'string' ? candidate.trim() : ''
  if (trimmed) return trimmed
  const active = getCurrentRunId()
  if (active) return active
  return generateRunRef()
}

function withRunScope<T>(runId: string, fn: () => T): T {
  const store = runContext.getStore()
  if (store) {
    if (!store.runId) {
      store.runId = runId
    }
    return fn()
  }
  return runContext.run({ runId }, fn)
}

export function seedSec0Run<T>(runId: string, fn: () => T): T {
  const resolved = ensureStandardId(runId, 'seedSec0Run.runId')
  return withRunScope(resolved, fn)
}

function attachRunId(container: any, label: string): string {
  if (!container || typeof container !== 'object') {
    throw new Error(`[sec0] ${label} must be an object when attaching runId.`)
  }
  const resolved = resolveRunId(container.runId)
  container.runId = resolved
  return resolved
}

type HierarchyResolver = () => Promise<HierarchyMetadata>

const HIERARCHY_CACHE_TTL_MS = 60_000
const hierarchyCache = new Map<string, { metadata: HierarchyMetadata; expiresAt: number }>()

function requireHierarchyInputs(label: string, options: HierarchyResolutionOptions): { apiKey: string; controlPlaneUrl: string } {
  const apiKey = resolveApiKey(options)
  if (!apiKey) {
    throw new Error(
      `[sec0-node] Missing apiKey for ${label}. ` +
      `Set SEC0_API_KEY, define auth.sec0ApiKey in your config, or pass options.apiKey.`
    )
  }
  const controlPlaneUrl = resolveControlPlaneUrl(options)
  return { apiKey, controlPlaneUrl }
}

function createHierarchyResolver(label: string, options: HierarchyResolutionOptions): HierarchyResolver {
  // Fail fast during setup if required credentials are missing
  requireHierarchyInputs(label, options)
  let memo: Promise<HierarchyMetadata> | null = null
  return () => {
    if (!memo) {
      memo = resolveHierarchyFor(label, options)
    }
    return memo
  }
}

async function resolveHierarchyFor(label: string, options: HierarchyResolutionOptions): Promise<HierarchyMetadata> {
  const { apiKey, controlPlaneUrl } = requireHierarchyInputs(label, options)
  return fetchHierarchyFromApiKey(apiKey, controlPlaneUrl)
}

function resolveApiKey(options: HierarchyResolutionOptions): string | null {
  const candidate =
    options.apiKey ??
    globalConfig?.apiKey ??
    null
  if (candidate && candidate.trim()) {
    return candidate.trim()
  }
  return null
}

function resolveControlPlaneUrl(options: HierarchyResolutionOptions): string {
  const candidate =
    options.controlPlaneUrl ??
    globalConfig?.controlPlaneUrl ??
    null
  return resolveControlPlaneUrlValue(candidate)
}

async function fetchHierarchyFromApiKey(apiKey: string, controlPlaneUrl: string): Promise<HierarchyMetadata> {
  const cached = hierarchyCache.get(apiKey)
  if (cached && cached.expiresAt > Date.now()) {
    return cached.metadata
  }
  const fetchImpl: typeof fetch | undefined = (globalThis as any).fetch
  if (typeof fetchImpl !== 'function') {
    throw new Error('[sec0-node] Global fetch() is not available. Provide a compatible runtime (Node 18+) or polyfill.')
  }
  const url = `${controlPlaneUrl.replace(/\/$/, '')}/api/auth/validate-key`
  const res = await fetchImpl(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': apiKey,
    },
    body: JSON.stringify({ apiKey }),
  }).catch((err: any) => {
    throw new Error(`[sec0-node] API key validation request failed: ${err?.message || err}`)
  })

  if (!res?.ok) {
    throw new Error(`[sec0-node] API key validation failed with status ${res?.status ?? 'unknown'}`)
  }

  const data = await res.json().catch(() => null) as any
  const tenant = typeof data?.tenant === 'string' && data.tenant.trim() ? data.tenant.trim() : ''
  const env = typeof data?.env === 'string' && data.env.trim() ? data.env.trim() : ''
  const clientName = typeof data?.clientName === 'string' && data.clientName.trim() ? data.clientName.trim() : ''
  const clientVersion = typeof data?.clientVersion === 'string' && data.clientVersion.trim() ? data.clientVersion.trim() : ''

  if (!tenant || !env || !clientName || !clientVersion) {
    throw new Error('[sec0-node] Control plane response missing tenant/client/env metadata')
  }

  const metadata: HierarchyMetadata = { tenant, env, clientName, clientVersion }
  hierarchyCache.set(apiKey, { metadata, expiresAt: Date.now() + HIERARCHY_CACHE_TTL_MS })
  return metadata
}

const resolveLocalDir = (): string => {
  if (!globalConfig?.localDir) {
    throw new Error(
      '[sec0-node] No configuration found. ' +
      'Please call initSec0() with a config file or object before using the SDK. ' +
      'Example: initSec0({ localDir: "/var/sec0-data", tenant: "my-company" })'
    )
  }

  const dir = globalConfig.localDir
  // Ensure it's an absolute path
  return path.isAbsolute(dir) ? dir : path.resolve(dir)
}

// Agent audit options:
// - agent: precomputed agent identity label "name@version" (else derived from agentName/agentVersion)
// - agentName / agentVersion: compose the identity label if 'agent' not provided
// - nodeId: logical node identifier for state (state.nodeId)
// - runId: concrete run identifier for state at the specific hop (state.runId)
// - agentState: base agent state to merge with per-call overrides
// - tenant: default tenant to stamp on audit records
// - appender: custom appender instance (overrides default)
export type AgentAuditOptions = {
  agent?: string
  agentName?: string
  agentVersion?: string
  nodeId?: string
  agentRef?: string
  agentState?: AgentStatePayload
  tenant?: string
  apiKey?: string
  controlPlaneUrl?: string
  enforcement?: ResolvedHopEnforcementOptions
  analytics?: {
    includeExecution?: boolean
  }
}

// Orchestrator audit options:
// - agent_orchestrator: precomputed orchestrator label "name@version" (else derived from orchestratorName/orchestratorVersion)
// - orchestratorName / orchestratorVersion: compose the label if 'agent_orchestrator' not provided
// - nodeId: orchestrator state.nodeId for this hop
// - runId: orchestrator state.runId for this hop
// - agentState: base orchestrator state to merge with per-call overrides
// - tenant: default tenant to stamp on audit records
// - appender: custom appender instance (overrides default)
export type OrchestratorAuditOptions = {
  agent_orchestrator?: string
  orchestratorName?: string
  orchestratorVersion?: string
  nodeId?: string
  agentRef?: string
  agentState?: AgentStatePayload
  tenant?: string
  apiKey?: string
  controlPlaneUrl?: string
  enforcement?: ResolvedHopEnforcementOptions
  analytics?: {
    includePlan?: boolean
  }
}

type HopAutomationOptions = {
  ap2?: boolean
  identityContext?: boolean
  idempotency?: boolean
  auth?: boolean
  cause?: boolean
}

type ResolvedHopEnforcementOptions = {
  enabled: boolean
  mode: 'observe' | 'enforce'
  strategy: 'deny_on_match' | 'deny_on_any'
  denyOn?: string[]
  escalateOn?: string[]
  policyLevel?: 'gateway' | 'middleware'
  policyScope?: 'auto' | 'base' | 'agent'
  policyNodeId?: string
  refreshTtlMs?: number
  fallbackToBase?: boolean
}

type BaseNodeOptions = {
  tenant?: string
  apiKey?: string
  controlPlaneUrl?: string
  nodeId?: string
  agentRef?: string
  agentState?: AgentStatePayload
  enforcement?: ResolvedHopEnforcementOptions
}

export type GatewayAuditOptions = BaseNodeOptions & {
  gateway: string
  options?: HopAutomationOptions
}

export type ServerAuditOptions = BaseNodeOptions & {
  server: string
  options?: HopAutomationOptions
}

export type MiddlewareAuditOptions = BaseNodeOptions & {
  // Middleware identity (name@version recommended)
  middleware: string
  // Operation inside the middleware (name@version recommended)
  op: string
  options?: HopAutomationOptions
}

export type ToolAuditOptions = BaseNodeOptions & {
  server: string
  tool: string
  toolRef?: string
  options?: HopAutomationOptions
}

export type SkillAuditOptions = BaseNodeOptions & {
  skill: string
  source?: string
  skillRef?: string
  options?: HopAutomationOptions
}

type NodeWrapperOptions = BaseNodeOptions & {
  identity: NodeIdentity
  automation?: HopAutomationOptions
  nodeLabel: string
}

/**
 * Resolve the signer configured for this process.
 * Throws when the key path is missing or unreadable.
 */
function resolveLocalSigner(): LocalDevSigner {
  if (!globalConfig) {
    throw new Error('[sec0-node] Missing global configuration. Call initSec0() before using the SDK.')
  }
  const { localSignerPath } = globalConfig
  if (!localSignerPath) {
    throw new Error('[sec0-node] localSignerPath is required; define it in your sec0 config file.')
  }
  if (!path.isAbsolute(localSignerPath)) {
    throw new Error(`[sec0-node] localSignerPath must be absolute. Received: ${localSignerPath}`)
  }
  if (!fs.existsSync(localSignerPath)) {
    throw new Error(`[sec0-node] Signing key file not found at: ${localSignerPath}`)
  }
  return LocalDevSigner.fromKeyRef(`file://${localSignerPath}`)
}

/**
 * Build the configured Sec0Appender (signing + storage backend).
 * Requires initSec0 to have populated local signer and appender.dir.
 */
function buildAppender(): Sec0Appender {
  const signer = resolveLocalSigner()
  const appenderConfig = globalConfig?.appender
  if (!appenderConfig?.dir) {
    throw new Error('[sec0-node] Missing appender.dir in configuration')
  }
  return new Sec0Appender({ config: appenderConfig, signer } as any)
}

/**
 * Merge a base agent state with an overlay. Explicit runId wins; missing data throws.
 * NOTE: The override may not have a nodeId (e.g., when receiving state from upstream
 * via HTTP headers). In that case, we use the base's nodeId and only extract
 * non-nodeId fields from the override.
 */
function combineAgentStates(base?: AgentStatePayload, override?: AgentStatePayload): AgentStatePayload {
  const baseState = base ? normalizeAgentStatePayload(base) : undefined;
  // Only normalize override if it has a nodeId; otherwise extract fields manually
  let overrideState: AgentStatePayload | undefined = undefined;
  if (override && typeof override.nodeId === 'string' && override.nodeId.trim()) {
    overrideState = normalizeAgentStatePayload(override);
  }
  if (!baseState && !overrideState) {
    throw new Error('[sec0-node] combineAgentStates requires at least one agent state.');
  }
  // Use override nodeId if present and normalized, otherwise use base
  const nodeId = overrideState?.nodeId ?? baseState!.nodeId;
  let variables: AgentStateVariables | undefined = undefined;
  if (baseState?.variables) {
    for (const [scopeKey, vars] of Object.entries(baseState.variables)) {
      variables = mergeAgentVariables(variables, scopeKey as any, vars || {});
    }
  }
  // Merge variables from override (works even if override wasn't normalized)
  if (overrideState?.variables) {
    for (const [scopeKey, vars] of Object.entries(overrideState.variables)) {
      variables = mergeAgentVariables(variables, scopeKey as any, vars || {});
    }
  } else if (override?.variables && !overrideState) {
    // Handle un-normalized override with variables
    for (const [scopeKey, vars] of Object.entries(override.variables)) {
      variables = mergeAgentVariables(variables, scopeKey as any, vars || {});
    }
  }
  const metadata = overrideState?.metadata ?? override?.metadata ?? baseState?.metadata;
  const parentRef = overrideState?.parentRef ?? override?.parentRef ?? baseState?.parentRef;
  // Get runId from override (normalized or not), then base
  const runIdSource = overrideState?.runId ?? override?.runId ?? baseState?.runId;
  // Compute runId from explicit sources only; no implicit fallbacks.
  const computedRunId = runIdSource ? ensureRunId({ nodeId, runId: runIdSource } as AgentStatePayload) : undefined;
  const state: AgentStatePayload = { nodeId, ...(computedRunId ? { runId: computedRunId } : {}) };
  if (parentRef) state.parentRef = parentRef;
  if (variables && Object.keys(variables).length) state.variables = variables;
  if (metadata) state.metadata = metadata;
  return state;
}

/**
 * Helper class to compose setup-time agent state while preserving
 * merge semantics (base first, then setup-time overlays like nodeId/runId).
 * Merge precedence (per combineAgentStates):
 * - nodeId:    overlay.nodeId > base.nodeId (required; missing nodeId throws)
 * - runId:     overlay.runId > base.runId
 * - variables: merged per scope; overlay keys win within a scope
 * - metadata:  overlay.metadata > base.metadata
 * - parentRef: overlay.parentRef > base.parentRef
 */
class AgentStateBuilder {
  private baseLayer?: AgentStatePayload;
  private overlayLayers: Array<AgentStatePayload | undefined> = [];

  // Set the long-lived defaults to apply across calls (lower precedence than overrides).
  withBase(state?: AgentStatePayload): this {
    this.baseLayer = state ?? undefined;
    return this;
    }

  // Add an overlay layer (e.g., per-call override) applied after the base.
  withOverride(state?: AgentStatePayload): this {
    this.overlayLayers.push(state ?? undefined);
    return this;
  }

  withRunId(nodeId?: string, runId?: string): this {
    if (nodeId && nodeId.trim()) {
      this.overlayLayers.push({ nodeId, ...(runId ? { runId } : {}) } as AgentStatePayload);
    }
    return this;
  }

  // Produce the final AgentStatePayload by applying base first, then overlays.
  build(): AgentStatePayload {
    const layers: AgentStatePayload[] = [];
    if (this.baseLayer) layers.push(this.baseLayer);
    for (const layer of this.overlayLayers) {
      if (layer) layers.push(layer);
    }
    if (layers.length === 0) {
      throw new Error('[sec0-node] No agent state layers have been provided.');
    }
    let acc = normalizeAgentStatePayload(layers[0]);
    for (let i = 1; i < layers.length; i++) {
      acc = combineAgentStates(acc, layers[i]);
    }
    return acc;
  }
}

type HopScope = 'ORCHESTRATOR' | 'GATEWAY' | 'AGENT' | 'SERVER' | 'TOOL'

export class AgentStateManager {
  private scopeData: Record<string, any> = {}
  private vars: Record<string, string> = {}

  constructor(private scope: HopScope, private builder: AgentStateBuilder) {}

  setVars(entries: Record<string, string | undefined | null>): this {
    for (const [key, value] of Object.entries(entries || {})) {
      if (value === undefined || value === null) {
        delete this.vars[key]
        continue
      }
      const normalized = String(value).trim()
      if (normalized) {
        this.vars[key] = normalized
      } else {
        delete this.vars[key]
      }
    }
    return this
  }

  setScopeData(data: Record<string, any>): this {
    if (data && typeof data === 'object') {
      this.scopeData = { ...this.scopeData, ...data }
    }
    return this
  }

  toAgentState(): AgentStatePayload {
    const state = this.builder.build()
    const payload: Record<string, any> = { ...this.scopeData }
    if (Object.keys(this.vars).length) {
      payload.vars = { ...this.vars }
    }
    if (Object.keys(payload).length) {
      state.variables = mergeAgentVariables(state.variables, this.scope as any, payload)
    }
    return state
  }

  getVars(): Record<string, string> {
    return { ...this.vars }
  }
}

export type AgentStateManagerConfigurator = (manager: AgentStateManager) => AgentStateManager | void
type AgentStateVarInput = Record<string, string | number | boolean | null | undefined>

export interface AgentStateHelper {
  readonly hopType: AgentStateManagerHopType
  readonly hopKey?: string
  readonly runId: string
  readonly nodeId?: string
  snapshot(): AgentStatePayload
  setVars(entries: AgentStateVarInput): this
  setScopeData(data: Record<string, any>): this
  buildAgentState(
    hopType: AgentStateManagerHopType,
    hopKey: string,
    initial?: PartialAgentStatePayload,
    configure?: AgentStateManagerConfigurator
  ): AgentStatePayload
}

class AgentStateHelperImpl implements AgentStateHelper {
  constructor(
    public readonly hopType: AgentStateManagerHopType,
    public readonly hopKey: string | undefined,
    private readonly manager: AgentStateManager
  ) {}

  setVars(entries: AgentStateVarInput): this {
    const normalized: Record<string, string | undefined> = {}
    for (const [key, value] of Object.entries(entries || {})) {
      if (value === undefined || value === null) {
        normalized[key] = undefined
      } else {
        normalized[key] = String(value)
      }
    }
    this.manager.setVars(normalized)
    return this
  }

  setScopeData(data: Record<string, any>): this {
    this.manager.setScopeData(data)
    return this
  }

  snapshot(): AgentStatePayload {
    return this.manager.toAgentState()
  }

  buildAgentState(
    hopType: AgentStateManagerHopType,
    hopKey: string,
    initial?: PartialAgentStatePayload,
    configure?: AgentStateManagerConfigurator
  ): AgentStatePayload {
    return buildAgentStateInternal(hopType, hopKey, initial, configure)
  }

  get runId(): string {
    return this.snapshot().runId ?? ''
  }

  get nodeId(): string | undefined {
    return this.snapshot().nodeId
  }

  getManager(): AgentStateManager {
    return this.manager
  }
}

function createAgentStateHelper(
  hopType: AgentStateManagerHopType,
  baseState: AgentStatePayload,
  hopKey?: string
): AgentStateHelperImpl {
  const builder = new AgentStateBuilder().withBase(baseState)
  const manager = new AgentStateManager(hopTypeToScopeMap[hopType], builder)
  return new AgentStateHelperImpl(hopType, hopKey, manager)
}

function createAgentManager(helper: AgentStateHelper, cause?: { traceId: string; spanId: string }): AgentManager {
  return new AgentManager(helper as any, {
    resolveHop: resolveHopForManager,
    transporter: hopTransporter,
    cause,
  })
}

// Utility for generating a unique run/inference identifier.
// Call this when you need a fresh value for agentRef or per-call state overrides.
let runCounter = 0
const runHost = (() => {
  try {
    return os.hostname()
  } catch {
    return 'unknown-host'
  }
})()

/**
 * Generate a unique run/inference identifier based on host, pid, time, counter.
 */
export function generateRunRef(): string {
  runCounter = (runCounter + 1) >>> 0
  const ts = Date.now()
  let pid = process.pid
  if (typeof pid !== 'number' || !Number.isFinite(pid) || pid <= 0) {
    pid = 0
    // eslint-disable-next-line no-console
    console.warn('[sec0-node] process.pid unavailable; defaulting to 0 for runRef generation')
  }
  return `${runHost}:${pid}:${ts}:${runCounter}`
}

function randomHex(bytes: number): string {
  try {
    return randomBytes(bytes).toString('hex')
  } catch {
    const fallback = Array.from({ length: bytes }, () => Math.floor(Math.random() * 256))
    return Buffer.from(fallback).toString('hex')
  }
}

export function generateTraceId(): string {
  return randomHex(16)
}

export function generateSpanId(): string {
  return randomHex(8)
}

function ensureTraceContext(container: any, label: string): { traceId: string; spanId: string } {
  if (!container || typeof container !== 'object') {
    throw new Error(`[sec0-node] ${label} must be an object when ensuring trace/span.`)
  }
  const traceId =
    typeof container.traceId === 'string' && container.traceId.trim()
      ? container.traceId.trim()
      : generateTraceId()
  const spanId =
    typeof container.spanId === 'string' && container.spanId.trim()
      ? container.spanId.trim()
      : generateSpanId()
  container.traceId = traceId
  container.spanId = spanId
  return { traceId, spanId }
}

/**
 * Normalize user-supplied plan metadata into the canonical OrchestratorPlanState.
 */
function normalizeOrchestratorPlanState(plan: any): OrchestratorPlanState | undefined {
  if (!plan) return undefined
  const rawSteps = Array.isArray(plan) ? plan : (Array.isArray(plan?.steps) ? plan.steps : undefined)
  if (!rawSteps || rawSteps.length === 0) return undefined
  const steps = rawSteps.map((step: any, idx: number) => {
    if (!step || typeof step !== 'object') return undefined
    const id = typeof step.id === 'string' && step.id.trim() ? step.id.trim() : `step-${idx}`
    const type = step.type === 'agent' || step.type === 'action' ? step.type : 'tool'
    const normalized: any = { id, type }
    if (step.target_tool) normalized.target_tool = String(step.target_tool)
    if (step.target_node_id) normalized.target_node_id = String(step.target_node_id)
    if (step.expected_args_sha256) normalized.expected_args_sha256 = String(step.expected_args_sha256)
    if (step.metadata && typeof step.metadata === 'object' && !Array.isArray(step.metadata)) {
      normalized.metadata = { ...step.metadata }
    }
    return normalized
  }).filter(Boolean)
  if (!steps.length) return undefined
  return { version: 1, steps }
}

/**
 * Normalize execution reflections into the canonical AgentExecutionState.
 */
function normalizeAgentExecutionState(execution: any): AgentExecutionState | undefined {
  if (!execution) return undefined
  const rawRuns = Array.isArray(execution)
    ? execution
    : Array.isArray(execution?.runs)
      ? execution.runs
      : [execution]
  const runs = rawRuns.map((run: any) => {
    if (!run || typeof run !== 'object') return undefined
    const normalized: any = {}
    if (run.plan_step_id) normalized.plan_step_id = String(run.plan_step_id)
    if (run.tool_invoked) normalized.tool_invoked = String(run.tool_invoked)
    if (run.actual_args_sha256) normalized.actual_args_sha256 = String(run.actual_args_sha256)
    if (run.status) normalized.status = String(run.status)
    if (run.deviation_reason) normalized.deviation_reason = String(run.deviation_reason)
    if (run.metadata && typeof run.metadata === 'object' && !Array.isArray(run.metadata)) {
      normalized.metadata = { ...run.metadata }
    }
    return normalized
  }).filter(Boolean)
  if (!runs.length) return undefined
  return { version: 1, runs }
}

function extractGatewayCartDigest(state?: AgentStatePayload): string | undefined {
  try {
    const gatewayVars = state?.variables?.GATEWAY as Record<string, any> | undefined
    const analytics = gatewayVars?.analytics as Record<string, any> | undefined
    return typeof analytics?.ap2?.cart_sha256 === 'string' ? analytics.ap2.cart_sha256 : undefined
  } catch {
    return undefined
  }
}

const POLICY_REASON_TOKEN = /^[a-z][a-z0-9_]{1,127}$/
const HOP_POLICY_REFRESH_TTL_MS = 60_000

type ResolvedHumanEscalationConfig = {
  approvalStrategy?: 'auto_allow' | 'single_approver' | 'human_quorum'
  timeoutAction?: 'auto_approve' | 'auto_reject'
  minApprovals?: number
  minRejections?: number
  requiredRoles?: string[]
  vetoRoles?: string[]
  approvalSetId?: string
}

type HopPolicyRuntime = {
  manager: ReturnType<typeof createControlPlanePolicyManager>
  escalationReporter: EscalationReporter
}

type HopEnforcementInput = {
  hopType: HopKind
  identity: NodeIdentity
  params?: any
  result?: any
  error?: any
  tenant?: string
  nodeId?: string
  runId?: string
  traceId?: string
  spanId?: string
  apiKey?: string
  controlPlaneUrl?: string
  enforcement?: ResolvedHopEnforcementOptions
}

type HopEnforcementOutcome = {
  decision: 'allow' | 'deny'
  retention: string
  reasons: string[]
  denialReason?: string
  escalationResult?: EscalationCreateResult | null
  escalationFailure?: string | null
  policyHash?: string
  errorToThrow?: any
}

const hopPolicyRuntimeCache = new Map<string, HopPolicyRuntime>()

function normalizePolicyReasonToken(value: unknown): string {
  const normalized = String(value || '').trim().toLowerCase()
  if (!normalized) return ''
  if (normalized === 'idempotency_missing') return 'missing_idempotency_for_side_effect'
  if (normalized === 'tool_in_denylist') return 'tool_not_in_allowlist'
  return normalized
}

function isLikelyPolicyReason(value: unknown): boolean {
  const token = normalizePolicyReasonToken(value)
  return !!token && POLICY_REASON_TOKEN.test(token)
}

function normalizePolicyReasonArray(values: unknown): string[] {
  if (!Array.isArray(values)) return []
  const out: string[] = []
  for (const value of values) {
    const normalized = normalizePolicyReasonToken(value)
    if (!normalized || !POLICY_REASON_TOKEN.test(normalized)) continue
    out.push(normalized)
  }
  return Array.from(new Set(out))
}

function asOptionalPositiveInt(value: unknown): number | undefined {
  const parsed = Number(value)
  if (!Number.isFinite(parsed)) return undefined
  const floored = Math.floor(parsed)
  return floored > 0 ? floored : undefined
}

function asOptionalStringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined
  const out: string[] = []
  for (const entry of value) {
    const normalized = String(entry || '').trim()
    if (!normalized) continue
    out.push(normalized)
  }
  return out.length ? Array.from(new Set(out)) : undefined
}

function resolveHumanEscalationConfig(policyObj?: PolicyObject | null): ResolvedHumanEscalationConfig {
  const security = (policyObj as any)?.security
  const sideEffects = security && typeof security === 'object' ? (security as any).side_effects : undefined
  const humanRaw =
    sideEffects && typeof sideEffects === 'object'
      ? ((sideEffects as any).human_escalation && typeof (sideEffects as any).human_escalation === 'object'
          ? (sideEffects as any).human_escalation
          : (sideEffects as any).humanEscalation && typeof (sideEffects as any).humanEscalation === 'object'
            ? (sideEffects as any).humanEscalation
            : undefined)
      : undefined
  const strategyRaw = String(humanRaw?.approval_strategy || '').trim().toLowerCase()
  const approvalStrategy =
    strategyRaw === 'auto_allow' || strategyRaw === 'single_approver' || strategyRaw === 'human_quorum'
      ? (strategyRaw as ResolvedHumanEscalationConfig['approvalStrategy'])
      : undefined
  const timeoutRaw = String(humanRaw?.timeout_action || '').trim().toLowerCase()
  const timeoutAction =
    timeoutRaw === 'auto_approve' || timeoutRaw === 'auto_reject'
      ? (timeoutRaw as ResolvedHumanEscalationConfig['timeoutAction'])
      : undefined
  return {
    ...(approvalStrategy ? { approvalStrategy } : {}),
    ...(timeoutAction ? { timeoutAction } : {}),
    ...(asOptionalPositiveInt(humanRaw?.min_approvals) ? { minApprovals: asOptionalPositiveInt(humanRaw?.min_approvals)! } : {}),
    ...(asOptionalPositiveInt(humanRaw?.min_rejections) ? { minRejections: asOptionalPositiveInt(humanRaw?.min_rejections)! } : {}),
    ...(asOptionalStringArray(humanRaw?.required_roles) ? { requiredRoles: asOptionalStringArray(humanRaw?.required_roles)! } : {}),
    ...(asOptionalStringArray(humanRaw?.veto_roles) ? { vetoRoles: asOptionalStringArray(humanRaw?.veto_roles)! } : {}),
    ...(typeof humanRaw?.approval_set_id === 'string' && humanRaw.approval_set_id.trim()
      ? { approvalSetId: humanRaw.approval_set_id.trim() }
      : {}),
  }
}

function severityForViolation(violation: string): 'low' | 'medium' | 'high' | 'critical' {
  const normalized = normalizePolicyReasonToken(violation)
  if (
    normalized === 'registry_mutation' ||
    normalized === 'handler_swap' ||
    normalized === 'server_code_changed' ||
    normalized === 'tool_code_changed' ||
    normalized === 'subprocess_blocked'
  ) {
    return 'critical'
  }
  if (
    normalized === 'agent_guard_failed' ||
    normalized === 'tool_not_in_allowlist' ||
    normalized === 'version_unpinned' ||
    normalized === 'skill_scan_failed' ||
    normalized === 'skill_code_changed' ||
    normalized === 'skill_version_changed'
  ) {
    return 'high'
  }
  if (
    normalized === 'egress_violation' ||
    normalized === 'fs_violation' ||
    normalized === 'missing_idempotency_for_side_effect' ||
    normalized === 'payload_too_large' ||
    normalized === 'missing_audit_signature'
  ) {
    return 'medium'
  }
  return 'low'
}

function inferPolicyLevelForHop(hopType: HopKind): 'gateway' | 'middleware' {
  return hopType === 'gateway' ? 'gateway' : 'middleware'
}

function buildHopPolicyRuntimeCacheKey(input: {
  apiKey: string
  controlPlaneUrl: string
  level: 'gateway' | 'middleware'
  scope: 'auto' | 'base' | 'agent'
  nodeId?: string
  refreshTtlMs: number
  fallbackToBase: boolean
}): string {
  const nodeId = input.nodeId ? input.nodeId.trim() : ''
  return [
    input.controlPlaneUrl,
    input.apiKey,
    input.level,
    input.scope,
    nodeId,
    String(input.refreshTtlMs),
    input.fallbackToBase ? '1' : '0',
  ].join('|')
}

function getHopPolicyRuntime(input: {
  apiKey: string
  controlPlaneUrl: string
  level: 'gateway' | 'middleware'
  scope: 'auto' | 'base' | 'agent'
  nodeId?: string
  refreshTtlMs: number
  fallbackToBase: boolean
}): HopPolicyRuntime {
  const key = buildHopPolicyRuntimeCacheKey(input)
  const cached = hopPolicyRuntimeCache.get(key)
  if (cached) return cached
  const client = createControlPlaneClient({ baseUrl: input.controlPlaneUrl })
  const source: ControlPlanePolicySource = {
    source: 'control-plane',
    level: input.level,
    scope: input.scope,
    nodeId: input.nodeId,
    refreshTtlMs: input.refreshTtlMs,
    fallbackToBase: input.fallbackToBase,
  }
  const manager = createControlPlanePolicyManager({
    source,
    auth: { apiKey: input.apiKey },
    controlPlaneUrl: input.controlPlaneUrl,
    client,
  })
  const escalationReporter = createControlPlaneEscalationReporter({
    auth: { apiKey: input.apiKey },
    client,
  })
  const runtime: HopPolicyRuntime = { manager, escalationReporter }
  hopPolicyRuntimeCache.set(key, runtime)
  return runtime
}

function resolveIdentityFields(identity: NodeIdentity): { server: string; tool: string; toolRef: string } {
  const serverRaw = String(identity.server || identity.gateway || identity.middleware || 'sec0-runtime').trim()
  const toolRaw = String(identity.tool || identity.skill || identity.agent || identity.agent_orchestrator || 'invoke').trim()
  const toolRefRaw = String(identity.tool_ref || identity.skill_ref || `${serverRaw} ${toolRaw}`).trim()
  return {
    server: serverRaw || 'sec0-runtime',
    tool: toolRaw || 'invoke',
    toolRef: toolRefRaw || `${serverRaw || 'sec0-runtime'} ${toolRaw || 'invoke'}`,
  }
}

function collectPolicyReasons(...sources: any[]): string[] {
  const visited = new WeakSet<object>()
  const seen = new Set<string>()
  const reasonKeys = ['violation', 'denial_reason', 'policy_violation', 'policy_breach', 'reason']
  const listKeys = ['violations', 'reasons', 'denial_reasons', 'policy_violations', 'policy_breaches']
  const nestedKeys = ['policy', 'enforcement', 'sec0', 'error', 'details', 'data', 'meta', 'metadata']

  const visit = (value: any, depth: number, keyHint?: string) => {
    if (value === undefined || value === null || depth > 4) return
    if (typeof value === 'string') {
      const normalized = normalizePolicyReasonToken(value)
      if (!normalized || !POLICY_REASON_TOKEN.test(normalized)) return
      const hint = String(keyHint || '').toLowerCase()
      if (
        !hint ||
        hint === 'reason' ||
        hint === 'reasons' ||
        hint.includes('violation') ||
        hint.includes('breach') ||
        hint.includes('denial')
      ) {
        seen.add(normalized)
      }
      return
    }
    if (Array.isArray(value)) {
      for (const entry of value) {
        visit(entry, depth + 1, keyHint)
      }
      return
    }
    if (typeof value !== 'object') return
    if (visited.has(value)) return
    visited.add(value)

    const obj = value as Record<string, any>
    for (const key of reasonKeys) {
      visit(obj[key], depth + 1, key)
    }
    for (const key of listKeys) {
      visit(obj[key], depth + 1, key)
    }
    if (String(obj.code || '').toUpperCase() === 'POLICY_DENIED') {
      visit(obj.violation, depth + 1, 'violation')
      visit(obj.denial_reason, depth + 1, 'denial_reason')
    }
    for (const key of nestedKeys) {
      const nested = obj[key]
      if (nested && typeof nested === 'object') {
        visit(nested, depth + 1, key)
      }
    }
  }

  for (const source of sources) {
    visit(source, 0)
  }
  return Array.from(seen)
}

function isPolicyDeniedErrorLike(value: any): boolean {
  if (!value || typeof value !== 'object') return false
  if (String((value as any).code || '').toUpperCase() === 'POLICY_DENIED') return true
  if (isLikelyPolicyReason((value as any).violation)) return true
  if (isLikelyPolicyReason((value as any).denial_reason)) return true
  return false
}

function extractEscalationResult(value: any): EscalationCreateResult | null {
  if (!value || typeof value !== 'object') return null
  const escalationObj = (value as any).escalation
  if (escalationObj && typeof escalationObj === 'object') {
    const id = String((escalationObj as any).id || '').trim()
    const status = String((escalationObj as any).status || '').trim()
    if (id && status) {
      return {
        id,
        status,
        ...(typeof (escalationObj as any).expiresAt === 'string' ? { expiresAt: (escalationObj as any).expiresAt } : {}),
        ...(typeof (escalationObj as any).createdAt === 'string' ? { createdAt: (escalationObj as any).createdAt } : {}),
      }
    }
  }
  const id = String((value as any).escalation_id || '').trim()
  const status = String((value as any).escalation_status || '').trim()
  if (!id || !status) return null
  return { id, status }
}

function extractEscalationFailure(value: any): string | null {
  if (!value || typeof value !== 'object') return null
  const err = (value as any).escalation_error
  if (typeof err === 'string' && err.trim()) return err.trim()
  return null
}

function applyDenialMetadata(target: any, input: {
  reason: string
  reasons: string[]
  escalationResult?: EscalationCreateResult | null
  escalationFailure?: string | null
}) {
  if (!target || typeof target !== 'object') return
  const typed = target as Record<string, any>
  typed.code = 'POLICY_DENIED'
  typed.violation = input.reason
  typed.denial_reason = input.reason
  typed.denial_level = 'decorator'
  typed.denial_type = 'policy'
  typed.__sec0_enforcement_applied = true
  if (input.reasons.length) typed.reasons = input.reasons
  const escalated = input.escalationResult
  if (escalated?.id) {
    typed.escalation = escalated
    typed.escalation_id = escalated.id
    typed.escalation_status = escalated.status
  }
  if (input.escalationFailure) {
    typed.escalation_error = input.escalationFailure
  }
}

function createPolicyDeniedError(reason: string): any {
  const err: any = new Error(`Denied by policy: ${reason}`)
  err.name = 'PolicyDeniedError'
  err.code = 'POLICY_DENIED'
  err.violation = reason
  err.denial_reason = reason
  err.denial_level = 'decorator'
  err.denial_type = 'policy'
  err.__sec0_enforcement_applied = true
  return err
}

function evaluatePolicyDecision(input: {
  reasons: string[]
  denyOn: string[]
  strategy: 'deny_on_match' | 'deny_on_any'
}): { shouldDeny: boolean; reason?: string } {
  if (!input.reasons.length) return { shouldDeny: false }
  if (input.strategy === 'deny_on_any') {
    return { shouldDeny: true, reason: input.reasons[0] }
  }
  const denyOnSet = new Set(input.denyOn)
  if (!denyOnSet.size) {
    return { shouldDeny: false }
  }
  const matched = input.reasons.find((reason) => denyOnSet.has(reason))
  if (!matched) {
    return { shouldDeny: false }
  }
  return { shouldDeny: true, reason: matched }
}

async function enforceHopPolicy(input: HopEnforcementInput): Promise<HopEnforcementOutcome> {
  const enforcement = input.enforcement ?? { enabled: true, mode: 'enforce', strategy: 'deny_on_match' }
  const reasons = collectPolicyReasons(input.params, input.result, input.error)
  const incomingDenied = isPolicyDeniedErrorLike(input.error)
  const incomingReason = normalizePolicyReasonToken((input.error as any)?.violation || (input.error as any)?.denial_reason)
  const existingEscalation = extractEscalationResult(input.error) ?? extractEscalationResult(input.result)
  const existingEscalationFailure = extractEscalationFailure(input.error) ?? extractEscalationFailure(input.result)
  const retentionDefault = 'standard'
  if (enforcement.enabled === false) {
    return {
      decision: incomingDenied ? 'deny' : 'allow',
      retention: retentionDefault,
      reasons,
      ...(incomingReason ? { denialReason: incomingReason } : {}),
      ...(existingEscalation ? { escalationResult: existingEscalation } : {}),
      ...(existingEscalationFailure ? { escalationFailure: existingEscalationFailure } : {}),
    }
  }

  let policyObj: PolicyObject | null = null
  let policyHash: string | undefined
  let escalationReporter: EscalationReporter | null = null
  const fallbackToBase = enforcement.fallbackToBase !== false
  const refreshTtlMs = enforcement.refreshTtlMs ?? HOP_POLICY_REFRESH_TTL_MS
  const policyScope = enforcement.policyScope ?? 'auto'
  const policyLevel = enforcement.policyLevel ?? inferPolicyLevelForHop(input.hopType)
  const policyNodeId = (enforcement.policyNodeId || input.nodeId || '').trim() || undefined
  const apiKey = resolveApiKey({ apiKey: input.apiKey, controlPlaneUrl: input.controlPlaneUrl })
  if (apiKey) {
    try {
      const controlPlaneUrl = resolveControlPlaneUrl({ apiKey: input.apiKey, controlPlaneUrl: input.controlPlaneUrl })
      const runtime = getHopPolicyRuntime({
        apiKey,
        controlPlaneUrl,
        level: policyLevel,
        scope: policyScope,
        nodeId: policyNodeId,
        refreshTtlMs,
        fallbackToBase,
      })
      const resolved = await runtime.manager.getPolicy({ nodeId: policyNodeId || null })
      policyObj = resolved.policy
      policyHash = resolved.hash
      escalationReporter = runtime.escalationReporter
    } catch {}
  }

  const mode = enforcement.mode === 'observe' ? 'observe' : 'enforce'
  const strategy = enforcement.strategy === 'deny_on_any' ? 'deny_on_any' : 'deny_on_match'
  const denyOn = normalizePolicyReasonArray(enforcement.denyOn ?? (policyObj as any)?.enforcement?.deny_on)
  const evaluated = evaluatePolicyDecision({ reasons, denyOn, strategy })
  const shouldDenyByPolicy = mode === 'enforce' && evaluated.shouldDeny
  const denialReason = normalizePolicyReasonToken(evaluated.reason || incomingReason || reasons[0])
  const effectiveDenied = incomingDenied || shouldDenyByPolicy

  const escalateOn = normalizePolicyReasonArray(
    enforcement.escalateOn ?? (policyObj as any)?.enforcement?.escalate_on ?? denyOn
  )
  const escalateOnSet = new Set(escalateOn)
  const approveHighRisk = (policyObj as any)?.security?.side_effects?.approve_high_risk === true
  const human = resolveHumanEscalationConfig(policyObj)

  let escalationResult: EscalationCreateResult | null = existingEscalation
  let escalationFailure: string | null = existingEscalationFailure
  if (
    !escalationResult?.id &&
    effectiveDenied &&
    denialReason &&
    approveHighRisk &&
    escalateOnSet.has(denialReason) &&
    escalationReporter
  ) {
    const tenantForEscalation = String(input.tenant || '').trim() || undefined
    const runId = String(input.runId || '').trim() || null
    const nodeId = String(input.nodeId || '').trim() || null
    const identityFields = resolveIdentityFields(input.identity)
    try {
      escalationResult = await escalationReporter.create({
        tenant: tenantForEscalation,
        content: `Policy denied ${identityFields.toolRef} due to ${denialReason}.`,
        violation: denialReason,
        message: denialReason.replace(/_/g, ' '),
        severity: severityForViolation(denialReason),
        nodeId,
        agentRef: runId,
        metadata: {
          source: 'sec0-sdk',
          layer: 'instrumentation',
          hop: input.hopType,
          server: identityFields.server,
          tool: identityFields.tool,
          tool_ref: identityFields.toolRef,
          trace_id: input.traceId || null,
          span_id: input.spanId || null,
          reasons,
          policy_hash: policyHash || null,
          human_escalation: {
            ...(human.approvalStrategy ? { approval_strategy: human.approvalStrategy } : {}),
            ...(human.timeoutAction ? { timeout_action: human.timeoutAction } : {}),
            ...(typeof human.minApprovals === 'number' ? { min_approvals: human.minApprovals } : {}),
            ...(typeof human.minRejections === 'number' ? { min_rejections: human.minRejections } : {}),
            ...(Array.isArray(human.requiredRoles) ? { required_roles: human.requiredRoles } : {}),
            ...(Array.isArray(human.vetoRoles) ? { veto_roles: human.vetoRoles } : {}),
            ...(typeof human.approvalSetId === 'string' ? { approval_set_id: human.approvalSetId } : {}),
          },
        },
        ...(human.timeoutAction ? { timeoutAction: human.timeoutAction } : {}),
        ...(human.approvalStrategy ? { approvalStrategy: human.approvalStrategy } : {}),
        ...(typeof human.minApprovals === 'number' ? { minApprovals: human.minApprovals } : {}),
        ...(typeof human.minRejections === 'number' ? { minRejections: human.minRejections } : {}),
        ...(Array.isArray(human.requiredRoles) ? { requiredRoles: human.requiredRoles } : {}),
        ...(Array.isArray(human.vetoRoles) ? { vetoRoles: human.vetoRoles } : {}),
        ...(typeof human.approvalSetId === 'string' ? { approvalSetId: human.approvalSetId } : {}),
      })
    } catch (escalationErr: any) {
      escalationFailure = escalationErr instanceof Error ? escalationErr.message : String(escalationErr || 'unknown')
    }
  }

  let errorToThrow = input.error
  if (shouldDenyByPolicy && denialReason) {
    if (!errorToThrow) {
      errorToThrow = createPolicyDeniedError(denialReason)
    }
    applyDenialMetadata(errorToThrow, {
      reason: denialReason,
      reasons,
      escalationResult,
      escalationFailure,
    })
  } else if (incomingDenied && input.error && denialReason) {
    applyDenialMetadata(input.error, {
      reason: denialReason,
      reasons,
      escalationResult,
      escalationFailure,
    })
    errorToThrow = input.error
  }

  const retention = (() => {
    const raw = String((policyObj as any)?.default_retention || '').trim()
    return raw || retentionDefault
  })()

  return {
    decision: effectiveDenied ? 'deny' : 'allow',
    retention,
    reasons,
    ...(denialReason ? { denialReason } : {}),
    ...(escalationResult ? { escalationResult } : {}),
    ...(escalationFailure ? { escalationFailure } : {}),
    ...(policyHash ? { policyHash } : {}),
    ...(errorToThrow ? { errorToThrow } : {}),
  }
}

/**
 * Wrap an agent hop with auditing, tracing, and state propagation.
 */
function wrapAgentFunction<T extends (...args:any[]) => Promise<any> | any>(fn: T, opts: AgentAuditOptions): T {
  const app = buildAppender()
  const agentId = normalizeAgent(opts)
  if (!agentId) {
    throw new Error("[sec0-node] Missing agent identity in withAgentAudit. Provide 'agent' or 'agentName' and 'agentVersion'.")
  }
  // Agents can opt in to record execution reflections per hop.
  const includeAgentExecution = !!opts.analytics?.includeExecution
  // Ingest-friendly identity: include stable server/tool fields so EnvelopeIndex can index agent hops.
  const base = baseEnvelope({
    node_type: 'agent',
    agent: agentId,
    server: 'sec0-agent',
    tool: agentId,
    tool_ref: `sec0-agent ${agentId}`,
  })
  const enforcementIdentity: NodeIdentity = {
    node_type: 'agent',
    agent: agentId,
    server: 'sec0-agent',
    tool: agentId,
    tool_ref: `sec0-agent ${agentId}`,
  }
  const baseState = new AgentStateBuilder()
    .withBase(opts.agentState)
    .withRunId(opts.nodeId, opts.agentRef)
    .build()
  if (!baseState || !baseState.runId) {
    throw new Error(
      "[sec0-node] Missing runId at setup in withAgentAudit. " +
      "Provide a stable run identifier via 'agentState.runId' to ensure consistency across hops."
    )
  }
  const hierarchyResolver = createHierarchyResolver('sec0-agent', {
    tenant: opts.tenant,
    apiKey: opts.apiKey,
    controlPlaneUrl: opts.controlPlaneUrl,
  })
  return (async function wrapped(this: any, ...incoming: any[]) {
    const args = [...incoming]
    if (!args[0] || typeof args[0] !== 'object') {
      throw new Error("[sec0-node] First argument must be a context object for withAgentAudit.")
    }
    const ctxArg: any = args[0]
    ensureTraceContext(ctxArg, 'context')
    const runId = attachRunId(ctxArg, 'ctxArg.runId')
    const runner = async () => {
      if (ctxArg.agentState?.nodeId && ctxArg.agentState.nodeId !== baseState.nodeId) {
        throw new Error("[sec0-node] ctxArg.agentState.nodeId must match the setup-time nodeId.")
      }
      if (ctxArg.agentState && !ctxArg.agentState.runId) {
        ctxArg.agentState.runId = runId
      } else if (!ctxArg.agentState) {
        ctxArg.agentState = { runId }
      }
      const callAgentState = new AgentStateBuilder()
        .withBase(baseState)
        .withOverride(ctxArg.agentState)
        .build()
      if (!callAgentState || !callAgentState.runId) {
        throw new Error("[sec0-node] Missing agentState.runId for this call. Provide ctxArg.agentState.runId or use generateRunRef().")
      }
      const gatewayCartDigest = extractGatewayCartDigest(callAgentState)
      if (gatewayCartDigest) {
        const digestCheck = compareArgsToDigest(gatewayCartDigest, ctxArg?.args)
        if (!digestCheck.ok) {
          const err = new Error(digestCheck.reason || 'ap2_cart_mismatch')
          ;(err as any).code = 'AP2_VIOLATION'
          throw err
        }
      }
      if (includeAgentExecution) {
        const initialExecution = normalizeAgentExecutionState(ctxArg.agentExecution)
        if (initialExecution) {
          callAgentState.variables = mergeAgentVariables(callAgentState.variables, 'AGENT', {
            agent_execution: initialExecution,
          })
        }
      }
      const hierarchy = await hierarchyResolver()
      const tenant = hierarchy.tenant
      ctxArg.agentState = callAgentState
      const helper = createAgentStateHelper('agent', callAgentState, opts.nodeId)
      // Extract cause for trace linking before creating manager
      const causeTrace = ctxArg?.cause?.trace || ctxArg?.traceId
      const causeSpan = ctxArg?.cause?.span || ctxArg?.spanId
      const cause = causeTrace && causeSpan ? { traceId: causeTrace, spanId: causeSpan } : undefined
      const manager = createAgentManager(helper, cause)
      const argsWithHelper = [...args, manager]
      const start = Date.now()
      let status: 'ok'|'error' = 'ok'
      let agentStateForEnvelope: AgentStatePayload | null = callAgentState
      let policyDecision: 'allow' | 'deny' = 'allow'
      let policyRetention = 'standard'
      let policyReason: string | undefined
      let policyHash: string | undefined
      let escalationResult: EscalationCreateResult | null = null
      let escalationFailure: string | null = null
      try {
        const res = await withAgentStateScope(helper, () => fn.apply(this, argsWithHelper))
        const enforcementOutcome = await enforceHopPolicy({
          hopType: 'agent',
          identity: enforcementIdentity,
          params: ctxArg,
          result: res,
          tenant,
          nodeId: callAgentState.nodeId,
          runId: callAgentState.runId,
          traceId: ctxArg.traceId,
          spanId: ctxArg.spanId,
          apiKey: opts.apiKey,
          controlPlaneUrl: opts.controlPlaneUrl,
          enforcement: opts.enforcement,
        })
        policyDecision = enforcementOutcome.decision
        policyRetention = enforcementOutcome.retention
        policyReason = enforcementOutcome.denialReason
        policyHash = enforcementOutcome.policyHash
        escalationResult = enforcementOutcome.escalationResult ?? null
        escalationFailure = enforcementOutcome.escalationFailure ?? null
        if (enforcementOutcome.errorToThrow) {
          status = 'error'
          throw enforcementOutcome.errorToThrow
        }
        return res
      } catch (e) {
        if ((e as any)?.__sec0_enforcement_applied) {
          status = 'error'
          throw e
        }
        const enforcementOutcome = await enforceHopPolicy({
          hopType: 'agent',
          identity: enforcementIdentity,
          params: ctxArg,
          error: e,
          tenant,
          nodeId: callAgentState.nodeId,
          runId: callAgentState.runId,
          traceId: ctxArg.traceId,
          spanId: ctxArg.spanId,
          apiKey: opts.apiKey,
          controlPlaneUrl: opts.controlPlaneUrl,
          enforcement: opts.enforcement,
        })
        policyDecision = enforcementOutcome.decision
        policyRetention = enforcementOutcome.retention
        policyReason = enforcementOutcome.denialReason
        policyHash = enforcementOutcome.policyHash
        escalationResult = enforcementOutcome.escalationResult ?? null
        escalationFailure = enforcementOutcome.escalationFailure ?? null
        status = 'error'
        throw enforcementOutcome.errorToThrow ?? e
      } finally {
        agentStateForEnvelope = helper.snapshot()
        ctxArg.agentState = agentStateForEnvelope
        const latency = Date.now() - start
        if (app) {
          const env: any = {
            ts: new Date().toISOString(),
            trace_id: ctxArg.traceId,
            span_id: ctxArg.spanId,
            tenant,
            environment: hierarchy.env,
            client_name: hierarchy.clientName,
            client_version: hierarchy.clientVersion,
            ...base,
            ...(causeTrace ? { cause_trace_id: causeTrace } : {}),
            ...(causeSpan ? { cause_span_id: causeSpan } : {}),
            status,
            latency_ms: latency,
            retries: 0,
            input_sha256: null,
            output_sha256: null,
            policy: { decision: policyDecision, retention: policyRetention },
            ...(policyReason ? { denial_reason: policyReason } : {}),
            ...(policyHash ? { policy_hash: policyHash } : {}),
            ...(escalationResult?.id ? { escalation_id: escalationResult.id } : {}),
            ...(escalationResult?.status ? { escalation_status: escalationResult.status } : {}),
            ...(escalationFailure ? { escalation_error: escalationFailure } : {}),
          }
          if (ctxArg?.idempotencyKey) env.idempotency_key = ctxArg.idempotencyKey
          if (agentStateForEnvelope) {
            let agentVars = agentStateForEnvelope.variables;
            const executionState = includeAgentExecution ? normalizeAgentExecutionState(ctxArg.agentExecution) : undefined
            const agentScopeAdditions: Record<string, unknown> = { status, latency_ms: latency }
            if (executionState) {
              agentScopeAdditions.agent_execution = executionState
            }
            agentVars = mergeAgentVariables(agentVars, 'AGENT', agentScopeAdditions);
            env.nodeId = agentStateForEnvelope.nodeId;
            env.agentRef = agentStateForEnvelope.runId;
            if (agentVars && Object.keys(agentVars).length) {
              env.agentVariables = agentVars;
            }
          }
          try { await app.append(env) } catch {}
        }
      }
    }
    return withRunScope(runId, runner)
  }) as any as T
}

/**
 * Wrap an orchestrator hop with auditing and tracing semantics.
 */
function wrapOrchestratorFunction<T extends (...args:any[]) => Promise<any> | any>(fn: T, opts: OrchestratorAuditOptions): T {
  const app = buildAppender()
  const orchId = normalizeOrchestrator(opts)
  if (!orchId) {
    throw new Error("[sec0-node] Missing orchestrator identity in withOrchestratorAudit. Provide 'agent_orchestrator' or 'orchestratorName' and 'orchestratorVersion'.")
  }
  // Orchestrators can opt in to record their planned intent chain.
  const includePlanAnalytics = !!opts.analytics?.includePlan
  // Ingest-friendly identity: include stable server/tool fields so EnvelopeIndex can index orchestrator hops.
  const base = baseEnvelope({
    node_type: 'agent_orchestrator',
    agent_orchestrator: orchId,
    server: 'sec0-orchestrator',
    tool: orchId,
    tool_ref: `sec0-orchestrator ${orchId}`,
  })
  const enforcementIdentity: NodeIdentity = {
    node_type: 'agent_orchestrator',
    agent_orchestrator: orchId,
    server: 'sec0-orchestrator',
    tool: orchId,
    tool_ref: `sec0-orchestrator ${orchId}`,
  }
  const baseState = new AgentStateBuilder()
    .withBase(opts.agentState)
    .withRunId(opts.nodeId, opts.agentRef)
    .build()
  if (!baseState || !baseState.runId) {
    throw new Error(
      "[sec0-node] Missing runId at setup in withOrchestratorAudit. " +
      "Provide a stable run identifier via 'agentState.runId' to ensure consistency across hops."
    )
  }
  const hierarchyResolver = createHierarchyResolver('sec0-orchestrator', {
    tenant: opts.tenant,
    apiKey: opts.apiKey,
    controlPlaneUrl: opts.controlPlaneUrl,
  })
  return (async function wrapped(this: any, ...incoming: any[]) {
    const args = [...incoming]
    if (!args[0] || typeof args[0] !== 'object') {
      throw new Error("[sec0-node] First argument must be a context object for withOrchestratorAudit.")
    }
    const ctxArg: any = args[0]
    ensureTraceContext(ctxArg, 'context')
    const runId = attachRunId(ctxArg, 'context.runId')
    const runner = async () => {
      if (ctxArg.agentState?.nodeId && ctxArg.agentState.nodeId !== baseState.nodeId) {
        throw new Error("[sec0-node] ctxArg.agentState.nodeId must match the setup-time nodeId.")
      }
      if (ctxArg.agentState && !ctxArg.agentState.runId) {
        ctxArg.agentState.runId = runId
      } else if (!ctxArg.agentState) {
        ctxArg.agentState = { runId }
      }
      const callAgentState = new AgentStateBuilder()
        .withBase(baseState)
        .withOverride(ctxArg.agentState)
        .build()
      if (!callAgentState || !callAgentState.runId) {
        throw new Error("[sec0-node] Missing agentState.runId for this call. Provide ctxArg.agentState.runId or use generateRunRef().")
      }
      const gatewayCartDigest = extractGatewayCartDigest(callAgentState)
      if (gatewayCartDigest) {
        const digestCheck = compareArgsToDigest(gatewayCartDigest, ctxArg?.args)
        if (!digestCheck.ok) {
          const err = new Error(digestCheck.reason || 'ap2_cart_mismatch')
          ;(err as any).code = 'AP2_VIOLATION'
          throw err
        }
      }
      if (includePlanAnalytics) {
        const planState = normalizeOrchestratorPlanState(ctxArg.orchestratorPlan)
        if (planState) {
          callAgentState.variables = mergeAgentVariables(callAgentState.variables, 'ORCHESTRATOR', {
            orchestrator_plan: planState,
          })
        }
      }
      const seededCause =
        maybeDeriveCause(ctxArg.cause, 'context.cause') ??
        deriveCauseFromValue({ traceId: ctxArg.traceId, spanId: ctxArg.spanId }, 'context')
      const helper = createAgentStateHelper('orchestrator', callAgentState, opts.nodeId)
      // Pass cause for downstream gateway invocations
      const cause = seededCause ? { traceId: seededCause.traceId, spanId: seededCause.spanId } : undefined
      const manager = createAgentManager(helper, cause)
      const argsWithHelper = [...args, manager]
      const run = async () => {
        const hierarchy = await hierarchyResolver()
        ctxArg.agentState = callAgentState
        const activeCause = getCurrentCause()
        if (activeCause) {
          ctxArg.cause = activeCause
        } else if (seededCause) {
          ctxArg.cause = seededCause
        }
        const causeTrace = ctxArg?.cause?.traceId
        const causeSpan = ctxArg?.cause?.spanId
        const tenant = hierarchy.tenant
        const start = Date.now()
        let status: 'ok'|'error' = 'ok'
        let agentStateForEnvelope: AgentStatePayload | null = callAgentState
        let policyDecision: 'allow' | 'deny' = 'allow'
        let policyRetention = 'standard'
        let policyReason: string | undefined
        let policyHash: string | undefined
        let escalationResult: EscalationCreateResult | null = null
        let escalationFailure: string | null = null
        try {
          const res = await withAgentStateScope(helper, () => fn.apply(this, argsWithHelper))
          updateCauseFromResult(res)
          const enforcementOutcome = await enforceHopPolicy({
            hopType: 'orchestrator',
            identity: enforcementIdentity,
            params: ctxArg,
            result: res,
            tenant,
            nodeId: callAgentState.nodeId,
            runId: callAgentState.runId,
            traceId: ctxArg.traceId,
            spanId: ctxArg.spanId,
            apiKey: opts.apiKey,
            controlPlaneUrl: opts.controlPlaneUrl,
            enforcement: opts.enforcement,
          })
          policyDecision = enforcementOutcome.decision
          policyRetention = enforcementOutcome.retention
          policyReason = enforcementOutcome.denialReason
          policyHash = enforcementOutcome.policyHash
          escalationResult = enforcementOutcome.escalationResult ?? null
          escalationFailure = enforcementOutcome.escalationFailure ?? null
          if (enforcementOutcome.errorToThrow) {
            status = 'error'
            throw enforcementOutcome.errorToThrow
          }
          return res
        } catch (e) {
          if ((e as any)?.__sec0_enforcement_applied) {
            status = 'error'
            throw e
          }
          const enforcementOutcome = await enforceHopPolicy({
            hopType: 'orchestrator',
            identity: enforcementIdentity,
            params: ctxArg,
            error: e,
            tenant,
            nodeId: callAgentState.nodeId,
            runId: callAgentState.runId,
            traceId: ctxArg.traceId,
            spanId: ctxArg.spanId,
            apiKey: opts.apiKey,
            controlPlaneUrl: opts.controlPlaneUrl,
            enforcement: opts.enforcement,
          })
          policyDecision = enforcementOutcome.decision
          policyRetention = enforcementOutcome.retention
          policyReason = enforcementOutcome.denialReason
          policyHash = enforcementOutcome.policyHash
          escalationResult = enforcementOutcome.escalationResult ?? null
          escalationFailure = enforcementOutcome.escalationFailure ?? null
          status = 'error'
          throw enforcementOutcome.errorToThrow ?? e
        } finally {
          agentStateForEnvelope = helper.snapshot()
          ctxArg.agentState = agentStateForEnvelope
          const latency = Date.now() - start
          if (app) {
            const env: any = {
              ts: new Date().toISOString(),
              trace_id: ctxArg.traceId,
              span_id: ctxArg.spanId,
              tenant,
              environment: hierarchy.env,
              client_name: hierarchy.clientName,
              client_version: hierarchy.clientVersion,
              ...base,
              ...(causeTrace ? { cause_trace_id: causeTrace } : {}),
              ...(causeSpan ? { cause_span_id: causeSpan } : {}),
              status,
              latency_ms: latency,
              retries: 0,
              input_sha256: null,
              output_sha256: null,
              policy: { decision: policyDecision, retention: policyRetention },
              ...(policyReason ? { denial_reason: policyReason } : {}),
              ...(policyHash ? { policy_hash: policyHash } : {}),
              ...(escalationResult?.id ? { escalation_id: escalationResult.id } : {}),
              ...(escalationResult?.status ? { escalation_status: escalationResult.status } : {}),
              ...(escalationFailure ? { escalation_error: escalationFailure } : {}),
            }
            if (ctxArg?.idempotencyKey) env.idempotency_key = ctxArg.idempotencyKey
            if (agentStateForEnvelope) {
              let agentVars = agentStateForEnvelope.variables;
              if (includePlanAnalytics) {
                const latestPlan = normalizeOrchestratorPlanState(ctxArg.orchestratorPlan)
                if (latestPlan) {
                  agentVars = mergeAgentVariables(agentVars, 'ORCHESTRATOR', { orchestrator_plan: latestPlan })
                }
              }
              agentVars = mergeAgentVariables(agentVars, 'ORCHESTRATOR', {
                status,
                latency_ms: latency,
                run_id: ctxArg?.runId,
                node_id: ctxArg?.nodeId,
              });
              env.nodeId = agentStateForEnvelope.nodeId;
              env.agentRef = agentStateForEnvelope.runId;
              if (agentVars && Object.keys(agentVars).length) {
                env.agentVariables = agentVars;
              }
            }
            try { await app.append(env) } catch {}
          }
        }
      }
      return withCauseScope(seededCause, run)
    }
    return withRunScope(runId, runner)
  }) as any as T
}

/**
 * Shared wrapper for gateway/server/tool hops that emit envelopes via wrapNodeFunction.
 */
function wrapNodeFunction<T extends (opts: any, manager?: AgentManager) => Promise<any>>(call: T, nodeOpts: NodeWrapperOptions) {
  const app = buildAppender()
  const baseState = new AgentStateBuilder()
    .withBase(nodeOpts.agentState)
    .withRunId(nodeOpts.nodeId, nodeOpts.agentRef)
    .build()
  if (!baseState || !baseState.runId) {
    throw new Error(
      "[sec0-node] Missing runId at setup. " +
      "Provide a stable run identifier via 'agentState.runId' to ensure consistency across hops."
    )
  }
  const hierarchyResolver = createHierarchyResolver(nodeOpts.nodeLabel, {
    tenant: nodeOpts.tenant,
    apiKey: nodeOpts.apiKey,
    controlPlaneUrl: nodeOpts.controlPlaneUrl,
  })
  // IMPORTANT: preserve `this` for decorated class methods.
  return (async function wrapped(this: any, params: any) {
    const targetParams = params && typeof params === 'object' ? params : {}
    const runId = attachRunId(targetParams, 'params.runId')
    const exec = async () => {
      seedCauseFromParams(targetParams)
      const start = Date.now()
      let status: 'ok'|'error' = 'ok'
      let ret: any
      let hierarchy: HierarchyMetadata | null = null
      if (targetParams?.agentState?.nodeId && targetParams.agentState.nodeId !== baseState.nodeId) {
        throw new Error("[sec0-node] params.agentState.nodeId must match the setup-time nodeId.")
      }
      if (targetParams.agentState && !targetParams.agentState.runId) {
        targetParams.agentState.runId = runId
      } else if (!targetParams.agentState) {
        targetParams.agentState = { runId }
      }
      const callAgentState = new AgentStateBuilder()
        .withBase(baseState)
        .withOverride(targetParams?.agentState)
        .build()
      if (!callAgentState || !callAgentState.runId) {
        throw new Error("[sec0-node] Missing agentState.runId for this call. Provide params.agentState.runId or use generateRunRef().")
      }
      hierarchy = await hierarchyResolver()
      targetParams.agentState = callAgentState
      const hopType: AgentStateManagerHopType =
        nodeOpts.identity.node_type === 'server'
          ? 'server'
          : nodeOpts.identity.node_type === 'tool'
            ? 'tool'
            : nodeOpts.identity.node_type === 'skill'
              ? 'skill'
            : nodeOpts.identity.node_type === 'middleware'
              ? 'middleware'
              : 'gateway'
      const helper = createAgentStateHelper(hopType, callAgentState, nodeOpts.nodeId)
      // Get cause from params or current context for downstream gateway invocations
      const activeCause = getCurrentCause()
      const cause = activeCause ? { traceId: activeCause.traceId, spanId: activeCause.spanId } : undefined
      const manager = createAgentManager(helper, cause)
      const tenant = hierarchy.tenant
      if (nodeOpts.automation) {
        applyHopAutomation(targetParams, nodeOpts.automation, {
          tenant,
          identity: nodeOpts.identity,
        })
      }
      const resolvedIdentity = finalizeIdentity(nodeOpts.identity)
      let agentStateForEnvelope: AgentStatePayload | null = callAgentState
      let policyDecision: 'allow' | 'deny' = 'allow'
      let policyRetention = 'standard'
      let policyReason: string | undefined
      let policyHash: string | undefined
      let escalationResult: EscalationCreateResult | null = null
      let escalationFailure: string | null = null
      try {
        ret = await withAgentStateScope(helper, () => call.call(this, targetParams, manager))
        updateCauseFromResult(ret)
        const enforcementOutcome = await enforceHopPolicy({
          hopType: hopType as HopKind,
          identity: resolvedIdentity,
          params: targetParams,
          result: ret,
          tenant,
          nodeId: callAgentState.nodeId,
          runId: callAgentState.runId,
          traceId: ret?.trace || targetParams?.traceId || targetParams?.cause?.traceId,
          spanId: ret?.span || targetParams?.spanId || targetParams?.cause?.spanId,
          apiKey: nodeOpts.apiKey,
          controlPlaneUrl: nodeOpts.controlPlaneUrl,
          enforcement: nodeOpts.enforcement,
        })
        policyDecision = enforcementOutcome.decision
        policyRetention = enforcementOutcome.retention
        policyReason = enforcementOutcome.denialReason
        policyHash = enforcementOutcome.policyHash
        escalationResult = enforcementOutcome.escalationResult ?? null
        escalationFailure = enforcementOutcome.escalationFailure ?? null
        if (enforcementOutcome.errorToThrow) {
          status = 'error'
          throw enforcementOutcome.errorToThrow
        }
        return ret
      } catch (e) {
        if ((e as any)?.__sec0_enforcement_applied) {
          status = 'error'
          throw e
        }
        const enforcementOutcome = await enforceHopPolicy({
          hopType: hopType as HopKind,
          identity: resolvedIdentity,
          params: targetParams,
          error: e,
          tenant,
          nodeId: callAgentState.nodeId,
          runId: callAgentState.runId,
          traceId: targetParams?.traceId || targetParams?.cause?.traceId,
          spanId: targetParams?.spanId || targetParams?.cause?.spanId,
          apiKey: nodeOpts.apiKey,
          controlPlaneUrl: nodeOpts.controlPlaneUrl,
          enforcement: nodeOpts.enforcement,
        })
        policyDecision = enforcementOutcome.decision
        policyRetention = enforcementOutcome.retention
        policyReason = enforcementOutcome.denialReason
        policyHash = enforcementOutcome.policyHash
        escalationResult = enforcementOutcome.escalationResult ?? null
        escalationFailure = enforcementOutcome.escalationFailure ?? null
        status = 'error'
        throw enforcementOutcome.errorToThrow ?? e
      } finally {
        agentStateForEnvelope = helper.snapshot()
        targetParams.agentState = agentStateForEnvelope
        const latency = Date.now() - start
        const resolvedHierarchy = hierarchy ?? await hierarchyResolver()
        const tenantForEnv = resolvedHierarchy.tenant
        if (app) {
          const baseIdentity = nodeOpts.identity
          const identity = resolvedIdentity
          const env: any = {
            ts: new Date().toISOString(),
            tenant: tenantForEnv,
            environment: resolvedHierarchy.env,
            client_name: resolvedHierarchy.clientName,
            client_version: resolvedHierarchy.clientVersion,
            ...baseEnvelope(identity),
            ...(targetParams?.cause?.traceId ? { cause_trace_id: targetParams.cause.traceId } : {}),
            ...(targetParams?.cause?.spanId ? { cause_span_id: targetParams.cause.spanId } : {}),
            status,
            latency_ms: latency,
            retries: 0,
            input_sha256: null,
            output_sha256: null,
            policy: { decision: policyDecision, retention: policyRetention },
            ...(policyReason ? { denial_reason: policyReason } : {}),
            ...(policyHash ? { policy_hash: policyHash } : {}),
            ...(escalationResult?.id ? { escalation_id: escalationResult.id } : {}),
            ...(escalationResult?.status ? { escalation_status: escalationResult.status } : {}),
            ...(escalationFailure ? { escalation_error: escalationFailure } : {}),
          }
          // Custody identifiers and identity fields (only if present)
          try { if (ret?.trace) env.trace_id = ret.trace } catch {}
          try { if (ret?.span) env.span_id = ret.span } catch {}
          if (identity.server) env.server = identity.server
          if (identity.tool) env.tool = identity.tool
          if (targetParams?.idKey) env.idempotency_key = targetParams.idKey
          if (agentStateForEnvelope) {
            const scope =
              baseIdentity.node_type === 'gateway' ? 'GATEWAY' :
              baseIdentity.node_type === 'server' ? 'SERVER' :
              baseIdentity.node_type === 'middleware' ? 'SERVER' :
              baseIdentity.node_type === 'skill' ? 'TOOL' :
              baseIdentity.node_type === 'tool' ? 'TOOL' :
              'ORCHESTRATOR'
            let agentVars = agentStateForEnvelope.variables;
            agentVars = mergeAgentVariables(agentVars, scope, {
              status,
              latency_ms: latency,
              run_id: targetParams?.runId,
              node_id: targetParams?.nodeId,
              tool: targetParams?.toolAtVersion,
            });
            env.nodeId = agentStateForEnvelope.nodeId;
            env.agentRef = agentStateForEnvelope.runId;
            if (agentVars && Object.keys(agentVars).length) {
              env.agentVariables = agentVars;
            }
          }
          try { await app.append(env) } catch {}
        }
      }
    }
    const runWrapped = () => {
      const existingStore = causeContext.getStore()
      if (existingStore) {
        return exec()
      }
      return causeContext.run({}, exec)
    }
    return withRunScope(runId, runWrapped)
  }) as any as T
}

type RegisteredHopOf<T extends HopKind> = Extract<RegisteredHop, { type: T }>
type PartialAgentStatePayload = Omit<AgentStatePayload, 'nodeId'> & { nodeId?: string }

function inferHopKey(target: any, propertyKey: string | symbol): string {
  const ctor = target?.constructor
  const className = typeof ctor?.name === 'string' && ctor.name.trim()
    ? ctor.name.trim()
    : null
  if (!className) {
    throw new Error(
      '[sec0] Unable to infer hop configuration key. Ensure the decorated class has a stable name or provide a hop entry that matches it.'
    )
  }
  return `${className}.${String(propertyKey)}`
}

function getRegisteredHop<T extends HopKind>(hopKey: string, expected: T): RegisteredHopOf<T> {
  const trimmedKey = hopKey.trim()
  const entry = hopRegistry.get(trimmedKey)
  if (!entry) {
    throw new Error(
      `[sec0] No hop configuration found for "${trimmedKey}". Define app.hops["${trimmedKey}"] in your config file.`
    )
  }
  if (entry.type !== expected) {
    throw new Error(
      `[sec0] Hop "${trimmedKey}" is configured as "${entry.type}" but the decorator expects "${expected}".`
    )
  }
  return entry as RegisteredHopOf<T>
}

function getRegisteredHopAny(hopKey: string): RegisteredHop {
  const trimmedKey = hopKey.trim()
  const entry = hopRegistry.get(trimmedKey)
  if (!entry) {
    throw new Error(
      `[sec0] No hop configuration found for "${trimmedKey}". Define app.hops["${trimmedKey}"] in your config file.`
    )
  }
  return entry
}

function resolveHopForManager(hopKey: string): ManagedHopDescriptor {
  const entry = getRegisteredHopAny(hopKey)
  switch (entry.type) {
    case 'gateway': {
      if (!entry.nodeId) {
        throw new Error(`[sec0] Gateway hop "${hopKey}" is missing nodeId in sec0.config.yaml.`)
      }
      if (!entry.gatewayBaseUrl) {
        throw new Error(`[sec0] Gateway hop "${hopKey}" is missing gatewayBaseUrl in sec0.config.yaml.`)
      }
      const tenant = entry.tenant ?? currentAppProfile?.tenant
      if (!tenant) {
        throw new Error(`[sec0] Gateway hop "${hopKey}" cannot resolve tenant.`)
      }
      return {
        key: entry.key,
        type: 'gateway',
        config: {
          nodeId: entry.nodeId,
          gatewayBaseUrl: entry.gatewayBaseUrl,
          tenant,
          authHeader: entry.authHeader,
        },
      }
    }
    default:
      return {
        key: entry.key,
        type: entry.type as Exclude<HopKind, 'gateway'>,
        config: {
          nodeId: entry.nodeId!,
          remoteUrl: entry.remoteUrl,
        },
      }
  }
}

export function getGatewayHopConfig(
  hopKey: string
): RegisteredHopOf<'gateway'> & { nodeId: string; gatewayBaseUrl: string } {
  const entry = getRegisteredHop(hopKey, 'gateway')
  if (!entry.nodeId) {
    throw new Error(`[sec0] Gateway hop "${hopKey}" is missing nodeId in sec0.config.yaml.`)
  }
  if (!entry.gatewayBaseUrl) {
    throw new Error(`[sec0] Gateway hop "${hopKey}" is missing gatewayBaseUrl in sec0.config.yaml.`)
  }
  return entry as RegisteredHopOf<'gateway'> & { nodeId: string; gatewayBaseUrl: string }
}

export function getOrchestratorHopConfig(
  hopKey: string
): RegisteredHopOf<'orchestrator'> & { nodeId: string; orchestratorName: string; orchestratorVersion: string } {
  const entry = getRegisteredHop(hopKey, 'orchestrator')
  if (!entry.nodeId) {
    throw new Error(`[sec0] Orchestrator hop "${hopKey}" is missing nodeId in sec0.config.yaml.`)
  }
  if (!entry.orchestratorName || !entry.orchestratorVersion) {
    throw new Error(`[sec0] Orchestrator hop "${hopKey}" must define orchestratorName and orchestratorVersion.`)
  }
  return entry as RegisteredHopOf<'orchestrator'> & {
    nodeId: string
    orchestratorName: string
    orchestratorVersion: string
  }
}

const AGENT_STATE_MANAGER_ALLOWED_TYPES = ['agent', 'gateway', 'orchestrator', 'server', 'tool', 'middleware', 'skill'] as const
export type AgentStateManagerHopType = (typeof AGENT_STATE_MANAGER_ALLOWED_TYPES)[number]

const hopTypeToScopeMap: Record<AgentStateManagerHopType, HopScope> = {
  agent: 'AGENT',
  gateway: 'GATEWAY',
  orchestrator: 'ORCHESTRATOR',
  server: 'SERVER',
  tool: 'TOOL',
  // Middleware behaves most like a server-side enforcement layer.
  middleware: 'SERVER',
  // Skills are modeled as execution-level units alongside tool hops.
  skill: 'TOOL',
}

function createAgentStateManagerInternal(
  hopType: AgentStateManagerHopType,
  hopKey: string,
  initial?: PartialAgentStatePayload
): AgentStateManager {
  const normalizedHopType = String(hopType).toLowerCase() as AgentStateManagerHopType
  if (!AGENT_STATE_MANAGER_ALLOWED_TYPES.includes(normalizedHopType)) {
    throw new Error(
      `[sec0] createAgentStateManager expected hop type to be one of ${AGENT_STATE_MANAGER_ALLOWED_TYPES.join(
        ', '
      )}, got "${hopType}".`
    )
  }

  const hop = getRegisteredHop(hopKey, normalizedHopType)
  if (!hop.nodeId) {
    throw new Error(`[sec0] Hop "${hopKey}" is missing nodeId in sec0.config.yaml.`)
  }

  const builder = new AgentStateBuilder()
    .withRunId(hop.nodeId, initial?.runId)
    .withOverride(initial as AgentStatePayload | undefined)

  return new AgentStateManager(hopTypeToScopeMap[normalizedHopType], builder)
}

export function createAgentStateManager(
  hopType: AgentStateManagerHopType,
  hopKey: string,
  initial?: PartialAgentStatePayload
): AgentStateManager {
  requireAgentStateScope('createAgentStateManager')
  return createAgentStateManagerInternal(hopType, hopKey, initial)
}

function buildAgentStateInternal(
  hopType: AgentStateManagerHopType,
  hopKey: string,
  initial?: PartialAgentStatePayload,
  configure?: AgentStateManagerConfigurator
): AgentStatePayload {
  const manager = createAgentStateManagerInternal(hopType, hopKey, initial)
  const configured = configure ? configure(manager) : undefined
  const finalManager = configured ?? manager
  if (!(finalManager instanceof AgentStateManager)) {
    throw new Error('[sec0] buildAgentState configurator must return the provided AgentStateManager instance.')
  }
  return finalManager.toAgentState()
}

export function buildAgentState(
  hopType: AgentStateManagerHopType,
  hopKey: string,
  initial?: PartialAgentStatePayload,
  configure?: AgentStateManagerConfigurator
): AgentStatePayload {
  requireAgentStateScope('buildAgentState')
  return buildAgentStateInternal(hopType, hopKey, initial, configure)
}

/**
 * @deprecated Use createAgentStateManager('orchestrator', hopKey, initial)
 */
export function createOrchestratorStateController(
  hopKey: string,
  initial?: PartialAgentStatePayload
): AgentStateManager {
  return createAgentStateManager('orchestrator', hopKey, initial)
}

/**
 * @deprecated Use createAgentStateManager('gateway', hopKey, initial)
 */
export function createGatewayStateController(
  hopKey: string,
  initial?: PartialAgentStatePayload
): AgentStateManager {
  return createAgentStateManager('gateway', hopKey, initial)
}

export function getGatewayIdentity(hopKey: string): {
  nodeId: string
  gateway: string
  gatewayBaseUrl: string
} {
  const hop = getGatewayHopConfig(hopKey)
  return {
    nodeId: hop.nodeId,
    gateway: hop.gateway,
    gatewayBaseUrl: hop.gatewayBaseUrl,
  }
}

export function getOrchestratorIdentity(hopKey: string): {
  nodeId: string
  name: string
  version: string
  label: string
} {
  const hop = getOrchestratorHopConfig(hopKey)
  const label = `${hop.orchestratorName}@${hop.orchestratorVersion}`
  return {
    nodeId: hop.nodeId,
    name: hop.orchestratorName,
    version: hop.orchestratorVersion,
    label,
  }
}

export function buildOrchestratorAgentState(
  hopKey: string,
  state?: PartialAgentStatePayload
): AgentStatePayload {
  return buildAgentState('orchestrator', hopKey, state)
}

export function buildGatewayAgentState(
  hopKey: string,
  state?: PartialAgentStatePayload
): AgentStatePayload {
  return buildAgentState('gateway', hopKey, state)
}

function buildGatewayOptionsFromConfig(entry: RegisteredHopOf<'gateway'>): GatewayAuditOptions {
  const profile = currentAppProfile
  return {
    gateway: entry.gateway,
    nodeId: entry.nodeId!,
    // Prefer hop-specific tenant, else fall back to config/app profile. When absent, downstream
    // hierarchy resolution will derive the effective tenant from the API key.
    tenant: entry.tenant ?? profile?.tenant ?? globalConfig?.tenant,
    apiKey: profile?.apiKey ?? globalConfig?.apiKey,
    controlPlaneUrl: profile?.controlPlaneUrl ?? globalConfig?.controlPlaneUrl,
    agentRef: generateRunRef(),
    enforcement: normalizeHopEnforcementOptions(entry.enforcement),
    options: entry.automation,
  }
}

function buildAgentOptionsFromConfig(entry: RegisteredHopOf<'agent'>): AgentAuditOptions {
  const profile = currentAppProfile
  const agentName = entry.agentName?.trim()
  const agentVersion = entry.agentVersion?.trim()
  if (!agentName || !agentVersion) {
    throw new Error(
      `[sec0] Agent hop "${entry.key}" requires 'agentName' and 'agentVersion' in app.hops.`
    )
  }
  if (!entry.nodeId) {
    throw new Error(`[sec0] Agent hop "${entry.key}" requires a non-empty nodeId.`)
  }
  return {
    agentName,
    agentVersion,
    nodeId: entry.nodeId,
    tenant: profile?.tenant ?? globalConfig?.tenant,
    apiKey: profile?.apiKey ?? globalConfig?.apiKey,
    controlPlaneUrl: profile?.controlPlaneUrl ?? globalConfig?.controlPlaneUrl,
    enforcement: normalizeHopEnforcementOptions(entry.enforcement),
    agentRef: generateRunRef(),
  }
}

function buildServerOptionsFromConfig(entry: RegisteredHopOf<'server'>): ServerAuditOptions {
  const profile = currentAppProfile
  if (!entry.server) {
    throw new Error(`[sec0] Server hop "${entry.key}" requires a non-empty server name.`)
  }
  if (!entry.nodeId) {
    throw new Error(`[sec0] Server hop "${entry.key}" requires a non-empty nodeId.`)
  }
  return {
    server: entry.server,
    nodeId: entry.nodeId,
    tenant: profile?.tenant ?? globalConfig?.tenant,
    apiKey: profile?.apiKey ?? globalConfig?.apiKey,
    controlPlaneUrl: profile?.controlPlaneUrl ?? globalConfig?.controlPlaneUrl,
    enforcement: normalizeHopEnforcementOptions(entry.enforcement),
    options: entry.automation,
    agentRef: generateRunRef(),
  }
}

function buildMiddlewareOptionsFromConfig(entry: RegisteredHopOf<'middleware'>): MiddlewareAuditOptions {
  const profile = currentAppProfile
  if (!entry.middleware) {
    throw new Error(`[sec0] Middleware hop "${entry.key}" requires a non-empty middleware name.`)
  }
  if (!entry.op) {
    throw new Error(`[sec0] Middleware hop "${entry.key}" requires a non-empty op value.`)
  }
  if (!entry.nodeId) {
    throw new Error(`[sec0] Middleware hop "${entry.key}" requires a non-empty nodeId.`)
  }
  return {
    middleware: entry.middleware,
    op: entry.op,
    nodeId: entry.nodeId,
    tenant: profile?.tenant ?? globalConfig?.tenant,
    apiKey: profile?.apiKey ?? globalConfig?.apiKey,
    controlPlaneUrl: profile?.controlPlaneUrl ?? globalConfig?.controlPlaneUrl,
    enforcement: normalizeHopEnforcementOptions(entry.enforcement),
    options: entry.automation,
    agentRef: generateRunRef(),
  }
}

function buildToolOptionsFromConfig(entry: RegisteredHopOf<'tool'>): ToolAuditOptions {
  const profile = currentAppProfile
  if (!entry.server || !entry.tool) {
    throw new Error(`[sec0] Tool hop "${entry.key}" requires both 'server' and 'tool' values.`)
  }
  if (!entry.nodeId) {
    throw new Error(`[sec0] Tool hop "${entry.key}" requires a non-empty nodeId.`)
  }
  return {
    server: entry.server,
    tool: entry.tool,
    toolRef: entry.toolRef,
    nodeId: entry.nodeId,
    tenant: profile?.tenant ?? globalConfig?.tenant,
    apiKey: profile?.apiKey ?? globalConfig?.apiKey,
    controlPlaneUrl: profile?.controlPlaneUrl ?? globalConfig?.controlPlaneUrl,
    enforcement: normalizeHopEnforcementOptions(entry.enforcement),
    options: entry.automation,
    agentRef: generateRunRef(),
  }
}

function buildSkillOptionsFromConfig(entry: RegisteredHopOf<'skill'>): SkillAuditOptions {
  const profile = currentAppProfile
  if (!entry.skill) {
    throw new Error(`[sec0] Skill hop "${entry.key}" requires a non-empty 'skill' value.`)
  }
  if (!entry.nodeId) {
    throw new Error(`[sec0] Skill hop "${entry.key}" requires a non-empty nodeId.`)
  }
  return {
    skill: entry.skill,
    source: entry.source,
    skillRef: entry.skillRef,
    nodeId: entry.nodeId,
    tenant: profile?.tenant ?? globalConfig?.tenant,
    apiKey: profile?.apiKey ?? globalConfig?.apiKey,
    controlPlaneUrl: profile?.controlPlaneUrl ?? globalConfig?.controlPlaneUrl,
    enforcement: normalizeHopEnforcementOptions(entry.enforcement),
    options: entry.automation,
    agentRef: generateRunRef(),
  }
}

function buildOrchestratorOptionsFromConfig(entry: RegisteredHopOf<'orchestrator'>): OrchestratorAuditOptions {
  const profile = currentAppProfile
  if (!entry.nodeId) {
    throw new Error(`[sec0] Orchestrator hop "${entry.key}" requires a non-empty nodeId.`)
  }
  const orchestratorName = entry.orchestratorName?.trim()
  const orchestratorVersion = entry.orchestratorVersion?.trim()
  if (!orchestratorName || !orchestratorVersion) {
    throw new Error(
      `[sec0] Orchestrator hop "${entry.key}" requires 'orchestratorName' and 'orchestratorVersion' in app.hops.`
    )
  }
  return {
    orchestratorName,
    orchestratorVersion,
    nodeId: entry.nodeId,
    tenant: profile?.tenant ?? globalConfig?.tenant,
    apiKey: profile?.apiKey ?? globalConfig?.apiKey,
    controlPlaneUrl: profile?.controlPlaneUrl ?? globalConfig?.controlPlaneUrl,
    enforcement: normalizeHopEnforcementOptions(entry.enforcement),
    agentRef: generateRunRef(),
  }
}

function applyHopAutomation(params: any, automation: HopAutomationOptions, context: { tenant: string; identity: NodeIdentity }) {
  if (!automation || !params || typeof params !== 'object') return
  const headers = ensureHeaders(params)

  if (automation.auth && typeof params.authHeader === 'string' && params.authHeader.trim()) {
    if (!headers['Authorization']) headers['Authorization'] = params.authHeader
  }

  if (automation.ap2 && params.ap2) {
    const ap2 = params.ap2 || {}
    if (ap2.intent && !headers['x-ap2-intent-mandate']) {
      headers['x-ap2-intent-mandate'] = stringifyHeaderValue(ap2.intent)
    }
    if (ap2.cart && !headers['x-ap2-cart-mandate']) {
      headers['x-ap2-cart-mandate'] = stringifyHeaderValue(ap2.cart)
    }
    if (ap2.bundle && !headers['x-ap2-bundle']) {
      headers['x-ap2-bundle'] = stringifyHeaderValue(ap2.bundle)
    }
  }

  if (automation.identityContext) {
    const header = resolveIdentityHeader(params.identity, context.tenant)
    if (header && !headers[header.name]) {
      headers[header.name] = header.value
    }
  }

  if (automation.idempotency) {
    const key = params.idKey || params.idempotencyKey || deriveIdempotencyKey(params)
    if (key && !headers['x-idempotency-key']) {
      headers['x-idempotency-key'] = key
      params.idKey = key
    }
  }

  if (automation.cause && params.cause) {
    if (params.cause.traceId && !headers['x-cause-trace']) {
      headers['x-cause-trace'] = String(params.cause.traceId)
    }
    if (params.cause.spanId && !headers['x-cause-span']) {
      headers['x-cause-span'] = String(params.cause.spanId)
    }
  }
}

function ensureHeaders(params: any): Record<string, string> {
  const existing = params.headers
  if (existing && typeof existing === 'object' && !Array.isArray(existing)) {
    return existing as Record<string, string>
  }
  const next: Record<string, string> = {}
  params.headers = next
  return next
}

function stringifyHeaderValue(value: any): string {
  if (typeof value === 'string') return value
  try {
    return JSON.stringify(value)
  } catch {
    return String(value)
  }
}

function resolveIdentityHeader(input: any, tenant: string): { name: string; value: string } | undefined {
  if (!input) return undefined
  if (typeof input === 'string') {
    return { name: 'x-auth-context', value: input }
  }
  if (typeof input === 'object') {
    if (typeof input.name === 'string' && typeof input.value === 'string') {
      return { name: input.name, value: input.value }
    }
    let userHash: string | undefined = typeof input.userHash === 'string' ? input.userHash : undefined
    if (!userHash && input.userId) {
      try {
        const raw = typeof input.userId === 'string' ? input.userId : JSON.stringify(input.userId)
        userHash = sha256Hex(Buffer.from(raw))
      } catch {
        userHash = undefined
      }
    }
    if (!userHash) return undefined
    const payload: any = {
      scheme: 'prehashed',
      user_hash: userHash,
      tenant: input.tenant ?? tenant,
    }
    if (Array.isArray(input.roles)) {
      const roles = input.roles.map((r: any) => String(r)).filter(Boolean)
      if (roles.length) payload.roles = roles
    }
    const headerName =
      typeof input.headerName === 'string' && input.headerName.trim()
        ? input.headerName.trim().toLowerCase()
        : 'x-auth-context'
    return { name: headerName, value: JSON.stringify(payload) }
  }
  return undefined
}

function deriveIdempotencyKey(params: any): string | undefined {
  try {
    const data = {
      runId: params?.runId ?? generateRunRef(),
      nodeId: params?.nodeId,
      server: params?.server,
      tool: params?.toolAtVersion ?? params?.tool,
      args: params?.args ?? null,
    }
    return sha256Hex(Buffer.from(JSON.stringify(data)))
  } catch {
    return undefined
  }
}

/**
 * Decorate a gateway hop (router/forwarder).
 */
function wrapGatewayFunction<T extends (opts: any, helper?: AgentStateHelper) => Promise<any>>(
  call: T,
  opts: GatewayAuditOptions,
  hop?: RegisteredHopOf<'gateway'>
): T {
  // Ingest-friendly identity: include stable server/tool fields so EnvelopeIndex can index gateway hops.
  const identity: NodeIdentity = {
    node_type: 'gateway',
    gateway: opts.gateway,
    server: 'sec0-gateway',
    tool: opts.gateway,
    tool_ref: `sec0-gateway ${opts.gateway}`,
  }
  const callWithInjection = async (params: any, helper?: AgentStateHelper) => {
    if (!params || typeof params !== 'object') {
      throw new Error('[sec0-node] Gateway hops expect a params object as the first argument.')
    }
    if (hop?.gatewayBaseUrl) {
      params.gatewayBaseUrl ??= hop.gatewayBaseUrl
    }
    if (hop?.tenant) {
      params.tenant ??= hop.tenant
    }
    if (hop && hop.authHeader !== undefined) {
      params.authHeader ??= hop.authHeader
    }
    return call(params, helper)
  }
  return wrapNodeFunction(callWithInjection as any, {
    identity,
    tenant: opts.tenant,
    apiKey: opts.apiKey,
    controlPlaneUrl: opts.controlPlaneUrl,
    nodeId: opts.nodeId,
    agentRef: opts.agentRef,
    agentState: opts.agentState,
    enforcement: opts.enforcement,
    automation: opts.options,
    nodeLabel: 'sec0-gateway',
  })
}

/**
 * Decorate an MCP server hop.
 */
function wrapServerFunction<T extends (opts: any, helper?: AgentStateHelper) => Promise<any>>(
  call: T,
  opts: ServerAuditOptions
): T {
  // Ingest-friendly identity: include a stable placeholder tool so EnvelopeIndex can index server hops.
  const identity: NodeIdentity = { node_type: 'server', server: opts.server, tool: 'server', tool_ref: `${opts.server} server` }
  return wrapNodeFunction(call, {
    identity,
    tenant: opts.tenant,
    apiKey: opts.apiKey,
    controlPlaneUrl: opts.controlPlaneUrl,
    nodeId: opts.nodeId,
    agentRef: opts.agentRef,
    agentState: opts.agentState,
    enforcement: opts.enforcement,
    automation: opts.options,
    nodeLabel: 'sec0-server',
  })
}

/**
 * Decorate a middleware enforcement hop.
 */
function wrapMiddlewareFunction<T extends (opts: any, helper?: AgentStateHelper) => Promise<any>>(
  call: T,
  opts: MiddlewareAuditOptions
): T {
  // Ingest-friendly identity: node_type='middleware' with server/tool fields populated.
  const identity: NodeIdentity = {
    node_type: 'middleware',
    middleware: opts.middleware,
    server: opts.middleware,
    tool: opts.op,
    tool_ref: `${opts.middleware} ${opts.op}`,
  }
  return wrapNodeFunction(call, {
    identity,
    tenant: opts.tenant,
    apiKey: opts.apiKey,
    controlPlaneUrl: opts.controlPlaneUrl,
    nodeId: opts.nodeId,
    agentRef: opts.agentRef,
    agentState: opts.agentState,
    enforcement: opts.enforcement,
    automation: opts.options,
    nodeLabel: 'sec0-middleware',
  })
}

/**
 * Decorate a tool invocation hop.
 */
function wrapToolFunction<T extends (opts: any, helper?: AgentStateHelper) => Promise<any>>(
  call: T,
  opts: ToolAuditOptions
): T {
  const identity: NodeIdentity = {
    node_type: 'tool',
    server: opts.server,
    tool: opts.tool,
    ...(opts.toolRef ? { tool_ref: opts.toolRef } : {}),
  }
  return wrapNodeFunction(call, {
    identity,
    tenant: opts.tenant,
    apiKey: opts.apiKey,
    controlPlaneUrl: opts.controlPlaneUrl,
    nodeId: opts.nodeId,
    agentRef: opts.agentRef,
    agentState: opts.agentState,
    enforcement: opts.enforcement,
    automation: opts.options,
    nodeLabel: 'sec0-tool',
  })
}

/**
 * Decorate a skill hop.
 */
function wrapSkillFunction<T extends (opts: any, helper?: AgentStateHelper) => Promise<any>>(
  call: T,
  opts: SkillAuditOptions
): T {
  const source = opts.source?.trim() || undefined
  const skillRef = opts.skillRef?.trim() || (source ? `${source} ${opts.skill}` : opts.skill)
  const identity: NodeIdentity = {
    node_type: 'skill',
    ...(source ? { server: source } : {}),
    tool: opts.skill,
    ...(skillRef ? { tool_ref: skillRef } : {}),
    skill: opts.skill,
    skill_ref: skillRef,
  }
  return wrapNodeFunction(call, {
    identity,
    tenant: opts.tenant,
    apiKey: opts.apiKey,
    controlPlaneUrl: opts.controlPlaneUrl,
    nodeId: opts.nodeId,
    agentRef: opts.agentRef,
    agentState: opts.agentState,
    enforcement: opts.enforcement,
    automation: opts.options,
    nodeLabel: source || 'skill',
  })
}

type AnyMethod = (...args: any[]) => any

/**
 * Internal helper to turn a wrapping function into a method decorator.
 */
function createMethodDecorator<T extends AnyMethod>(name: string, wrap: (fn: T) => T): MethodDecorator {
  return (target: any, propertyKey: string | symbol, descriptor: PropertyDescriptor) => {
    const original = descriptor?.value
    if (typeof original !== 'function') {
      throw new Error(`[sec0-node] @${name} can only be applied to class methods.`)
    }
    descriptor.value = wrap(original as T)
  }
}

/**
 * Decorator for agent hops (inference/worker).
 */
export function sec0Agent(hopKey?: string): MethodDecorator {
  if (hopKey && typeof hopKey !== 'string') {
    throw new Error('[sec0] @sec0.agent expects a hop key string when provided.')
  }
  return (target: any, propertyKey: string | symbol, descriptor: PropertyDescriptor) => {
    if (!descriptor || typeof descriptor.value !== 'function') {
      throw new Error('[sec0] @sec0.agent can only be applied to class methods.')
    }
    const key = (hopKey && hopKey.trim()) || inferHopKey(target, propertyKey)
    const entry = getRegisteredHop(key, 'agent')
    const options = buildAgentOptionsFromConfig(entry)
    descriptor.value = wrapAgentFunction(descriptor.value as any, options)
    return descriptor
  }
}

/**
 * Decorator for orchestrator hops.
 */
export function sec0Orchestrator(hopKey?: string): MethodDecorator {
  if (hopKey && typeof hopKey !== 'string') {
    throw new Error('[sec0] @sec0.orchestrator no longer accepts inline options. Define app.hops entries instead.')
  }
  return (target: any, propertyKey: string | symbol, descriptor: PropertyDescriptor) => {
    if (!descriptor || typeof descriptor.value !== 'function') {
      throw new Error('[sec0] @sec0.orchestrator can only be applied to class methods.')
    }
    const key = (hopKey && hopKey.trim()) || inferHopKey(target, propertyKey)
    const entry = getRegisteredHop(key, 'orchestrator')
    const options = buildOrchestratorOptionsFromConfig(entry)
    descriptor.value = wrapOrchestratorFunction(descriptor.value as any, options)
    return descriptor
  }
}

/**
 * Decorator for gateway hops.
 */
export function sec0Gateway(hopKey?: string): MethodDecorator {
  if (hopKey && typeof hopKey !== 'string') {
    throw new Error('[sec0] @sec0.gateway no longer accepts inline options. Define app.hops entries instead.')
  }
  return (target: any, propertyKey: string | symbol, descriptor: PropertyDescriptor) => {
    if (!descriptor || typeof descriptor.value !== 'function') {
      throw new Error('[sec0] @sec0.gateway can only be applied to class methods.')
    }
    const key = (hopKey && hopKey.trim()) || inferHopKey(target, propertyKey)
    const entry = getRegisteredHop(key, 'gateway')
    const options = buildGatewayOptionsFromConfig(entry)
    descriptor.value = wrapGatewayFunction(descriptor.value as any, options, entry)
    return descriptor
  }
}

/**
 * Decorator for MCP server hops.
 */
export function sec0Server(hopKey?: string): MethodDecorator {
  if (hopKey && typeof hopKey !== 'string') {
    throw new Error('[sec0] @sec0.server expects a hop key string when provided.')
  }
  return (target: any, propertyKey: string | symbol, descriptor: PropertyDescriptor) => {
    if (!descriptor || typeof descriptor.value !== 'function') {
      throw new Error('[sec0] @sec0.server can only be applied to class methods.')
    }
    const key = (hopKey && hopKey.trim()) || inferHopKey(target, propertyKey)
    const entry = getRegisteredHop(key, 'server')
    const options = buildServerOptionsFromConfig(entry)
    descriptor.value = wrapServerFunction(descriptor.value as any, options)
    return descriptor
  }
}

/**
 * Decorator for middleware enforcement hops.
 */
export function sec0Middleware(hopKey?: string): MethodDecorator {
  if (hopKey && typeof hopKey !== 'string') {
    throw new Error('[sec0] @sec0.middleware expects a hop key string when provided.')
  }
  return (target: any, propertyKey: string | symbol, descriptor: PropertyDescriptor) => {
    if (!descriptor || typeof descriptor.value !== 'function') {
      throw new Error('[sec0] @sec0.middleware can only be applied to class methods.')
    }
    const key = (hopKey && hopKey.trim()) || inferHopKey(target, propertyKey)
    const entry = getRegisteredHop(key, 'middleware')
    const options = buildMiddlewareOptionsFromConfig(entry)
    descriptor.value = wrapMiddlewareFunction(descriptor.value as any, options)
    return descriptor
  }
}

/**
 * Decorator for tool invocation hops.
 */
export function sec0Tool(hopKey?: string): MethodDecorator {
  if (hopKey && typeof hopKey !== 'string') {
    throw new Error('[sec0] @sec0.tool expects a hop key string when provided.')
  }
  return (target: any, propertyKey: string | symbol, descriptor: PropertyDescriptor) => {
    if (!descriptor || typeof descriptor.value !== 'function') {
      throw new Error('[sec0] @sec0.tool can only be applied to class methods.')
    }
    const key = (hopKey && hopKey.trim()) || inferHopKey(target, propertyKey)
    const entry = getRegisteredHop(key, 'tool')
    const options = buildToolOptionsFromConfig(entry)
    descriptor.value = wrapToolFunction(descriptor.value as any, options)
    return descriptor
  }
}

/**
 * Decorator for skill invocation hops.
 */
export function sec0Skill(hopKey?: string): MethodDecorator {
  if (hopKey && typeof hopKey !== 'string') {
    throw new Error('[sec0] @sec0.skill expects a hop key string when provided.')
  }
  return (target: any, propertyKey: string | symbol, descriptor: PropertyDescriptor) => {
    if (!descriptor || typeof descriptor.value !== 'function') {
      throw new Error('[sec0] @sec0.skill can only be applied to class methods.')
    }
    const key = (hopKey && hopKey.trim()) || inferHopKey(target, propertyKey)
    const entry = getRegisteredHop(key, 'skill')
    const options = buildSkillOptionsFromConfig(entry)
    descriptor.value = wrapSkillFunction(descriptor.value as any, options)
    return descriptor
  }
}

export type Sec0DecoratorNamespace = Readonly<{
  agent: typeof sec0Agent
  orchestrator: typeof sec0Orchestrator
  gateway: typeof sec0Gateway
  server: typeof sec0Server
  middleware: typeof sec0Middleware
  tool: typeof sec0Tool
  skill: typeof sec0Skill
}>

export const sec0: Sec0DecoratorNamespace = Object.freeze({
  agent: sec0Agent,
  orchestrator: sec0Orchestrator,
  gateway: sec0Gateway,
  server: sec0Server,
  middleware: sec0Middleware,
  tool: sec0Tool,
  skill: sec0Skill,
})

export const sec0Decorators = {
  'sec0-agent': sec0Agent,
  'sec0-orchestrator': sec0Orchestrator,
  'sec0-gateway': sec0Gateway,
  'sec0-server': sec0Server,
  'sec0-middleware': sec0Middleware,
  'sec0-tool': sec0Tool,
  'sec0-skill': sec0Skill,
} as const
