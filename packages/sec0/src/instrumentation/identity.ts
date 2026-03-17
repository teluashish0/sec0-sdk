export type NodeType = 'agent'|'agent_orchestrator'|'gateway'|'server'|'tool'|'middleware'|'skill'

export type NodeIdentity = {
  node_type?: NodeType
  agent?: string
  agent_orchestrator?: string
  gateway?: string
  middleware?: string
  server?: string
  tool?: string
  tool_ref?: string
  skill?: string
  skill_ref?: string
}

export type AgentIdentityInput = { agent?: string; agentName?: string; agentVersion?: string }
export type OrchestratorIdentityInput = { agent_orchestrator?: string; orchestratorName?: string; orchestratorVersion?: string }

/**
 * Resolve agent identity as `name@version`, enforcing required fields.
 */
export function normalizeAgent({ agent, agentName, agentVersion }: AgentIdentityInput): string {
  if (agent) return agent
  if (agentName) {
    if (!agentVersion) {
      throw new Error("[sec0-node] Missing agentVersion when agentName is provided.")
    }
    return `${agentName}@${agentVersion}`
  }
  throw new Error("[sec0-node] Missing agent identity. Provide 'agent' or both 'agentName' and 'agentVersion'.")
}

/**
 * Resolve orchestrator identity as `name@version`, enforcing required fields.
 */
export function normalizeOrchestrator({ agent_orchestrator, orchestratorName, orchestratorVersion }: OrchestratorIdentityInput): string {
  if (agent_orchestrator) return agent_orchestrator
  if (orchestratorName) {
    if (!orchestratorVersion) {
      throw new Error("[sec0-node] Missing orchestratorVersion when orchestratorName is provided.")
    }
    return `${orchestratorName}@${orchestratorVersion}`
  }
  throw new Error("[sec0-node] Missing orchestrator identity. Provide 'agent_orchestrator' or both 'orchestratorName' and 'orchestratorVersion'.")
}

/**
 * Merge a primary node identity with fallback data, validating required fields per node type.
 */
export function resolveNodeIdentity(primary: NodeIdentity, fallback: NodeIdentity & { server?: string; tool?: string; tool_ref?: string }): NodeIdentity {
  const merged: NodeIdentity = {
    node_type: primary.node_type ?? fallback.node_type,
    agent: primary.agent ?? fallback.agent,
    agent_orchestrator: primary.agent_orchestrator ?? fallback.agent_orchestrator,
    gateway: primary.gateway ?? fallback.gateway,
    middleware: primary.middleware ?? fallback.middleware,
    server: primary.server ?? fallback.server,
    tool: primary.tool ?? fallback.tool,
    tool_ref: primary.tool_ref ?? fallback.tool_ref,
    skill: primary.skill ?? fallback.skill,
    skill_ref: primary.skill_ref ?? fallback.skill_ref,
  }

  if (!merged.node_type) {
    throw new Error("[sec0-node] Unable to resolve node identity. Provide a 'node_type'.")
  }

  switch (merged.node_type) {
    case 'agent': {
      if (!merged.agent) {
        throw new Error("[sec0-node] Agent identity requires the 'agent' field.")
      }
      return { node_type: 'agent', agent: merged.agent }
    }
    case 'agent_orchestrator': {
      if (!merged.agent_orchestrator) {
        throw new Error("[sec0-node] Orchestrator identity requires the 'agent_orchestrator' field.")
      }
      return { node_type: 'agent_orchestrator', agent_orchestrator: merged.agent_orchestrator }
    }
    case 'gateway': {
      if (!merged.gateway) {
        throw new Error("[sec0-node] Gateway identity requires the 'gateway' field.")
      }
      return { node_type: 'gateway', gateway: merged.gateway }
    }
    case 'middleware': {
      if (!merged.middleware) {
        throw new Error("[sec0-node] Middleware identity requires the 'middleware' field.")
      }
      return { node_type: 'middleware', middleware: merged.middleware }
    }
    case 'server': {
      if (!merged.server) {
        throw new Error("[sec0-node] Server identity requires the 'server' field.")
      }
      return { node_type: 'server', server: merged.server }
    }
    case 'tool':
      return normalizeToolIdentity(merged)
    case 'skill':
      return normalizeSkillIdentity(merged)
    default:
      throw new Error(`[sec0-node] Unsupported node_type '${merged.node_type}'.`)
  }
}

/**
 * Build the base envelope payload (node_type plus optional identity fields).
 */
export function baseEnvelope(identity?: NodeIdentity) {
  const { node_type, agent, agent_orchestrator, gateway, middleware, server, tool, tool_ref, skill, skill_ref } = identity || {}
  return {
    node_type,
    ...(agent ? { agent } : {}),
    ...(agent_orchestrator ? { agent_orchestrator } : {}),
    ...(gateway ? { gateway } : {}),
    ...(middleware ? { middleware } : {}),
    ...(server ? { server } : {}),
    ...(tool ? { tool } : {}),
    ...(tool_ref ? { tool_ref } : {}),
    ...(skill ? { skill } : {}),
    ...(skill_ref ? { skill_ref } : {}),
  }
}

/**
 * Construct a tool reference string, validating required components.
 */
export function buildToolRef(server?: string, tool?: string) {
  if (!server) {
    throw new Error("[sec0-node] Tool identity requires a 'server'.")
  }
  if (!tool) {
    throw new Error("[sec0-node] Tool identity requires a 'tool'.")
  }
  return `${server} ${tool}`
}

/**
 * Construct a skill reference string, validating required components.
 */
export function buildSkillRef(server?: string, skill?: string) {
  if (!skill) {
    throw new Error("[sec0-node] Skill identity requires a 'skill'.")
  }
  return server ? `${server} ${skill}` : skill
}

/**
 * Normalize tool identity to ensure server/tool/tool_ref are properly populated.
 */
export function normalizeToolIdentity(identity: NodeIdentity): NodeIdentity {
  if (identity.node_type !== 'tool') return identity
  const server = identity.server
  const tool = identity.tool
  if (!server) {
    throw new Error("[sec0-node] Tool identity requires the 'server' field.")
  }
  if (!tool) {
    throw new Error("[sec0-node] Tool identity requires the 'tool' field.")
  }
  const tool_ref = identity.tool_ref ?? buildToolRef(server, tool)
  return {
    node_type: 'tool',
    server,
    tool,
    tool_ref,
  }
}

/**
 * Normalize skill identity to ensure skill/skill_ref are populated.
 */
export function normalizeSkillIdentity(identity: NodeIdentity): NodeIdentity {
  if (identity.node_type !== 'skill') return identity
  const skill = identity.skill ?? identity.tool
  if (!skill) {
    throw new Error("[sec0-node] Skill identity requires the 'skill' field.")
  }
  const skill_ref = identity.skill_ref ?? identity.tool_ref ?? buildSkillRef(identity.server, skill)
  return {
    node_type: 'skill',
    ...(identity.server ? { server: identity.server } : {}),
    ...(identity.tool ?? skill ? { tool: identity.tool ?? skill } : {}),
    ...(identity.tool_ref ?? skill_ref ? { tool_ref: identity.tool_ref ?? skill_ref } : {}),
    skill,
    skill_ref,
  }
}

/**
 * Final validation step to ensure the node identity is complete before use.
 */
export function finalizeIdentity(identity: NodeIdentity): NodeIdentity {
  if (!identity.node_type) {
    throw new Error("[sec0-node] finalizeIdentity requires a 'node_type'.")
  }
  if (identity.node_type === 'tool') {
    return normalizeToolIdentity(identity)
  }
  if (identity.node_type === 'skill') {
    return normalizeSkillIdentity(identity)
  }
  if (identity.node_type === 'agent' && !identity.agent) {
    throw new Error("[sec0-node] Agent identity requires the 'agent' field.")
  }
  if (identity.node_type === 'agent_orchestrator' && !identity.agent_orchestrator) {
    throw new Error("[sec0-node] Orchestrator identity requires the 'agent_orchestrator' field.")
  }
  if (identity.node_type === 'gateway' && !identity.gateway) {
    throw new Error("[sec0-node] Gateway identity requires the 'gateway' field.")
  }
  if (identity.node_type === 'middleware' && !identity.middleware) {
    throw new Error("[sec0-node] Middleware identity requires the 'middleware' field.")
  }
  if (identity.node_type === 'server' && !identity.server) {
    throw new Error("[sec0-node] Server identity requires the 'server' field.")
  }
  return identity
}
