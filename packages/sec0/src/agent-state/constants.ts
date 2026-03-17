import type { AgentVariableScope } from "./types";

export const NODE_ID_HEADER = "x-node-id";
export const AGENT_REF_HEADER = "x-agent-ref";
export const AGENT_PARENT_REF_HEADER = "x-agent-parent-ref";
export const AGENT_STATE_HEADER = "x-agent-state";
export const AGENT_STATE_VERSION = 1;

export const LOG_PREFIX = "[sec0-agent-state]";

export const SCOPE_ALIASES: Record<string, AgentVariableScope> = {
  AGENT: "AGENT",
  GATEWAY: "GATEWAY",
  SERVER: "SERVER",
  TOOL: "TOOL",
  ORCHESTRATOR: "ORCHESTRATOR",
  LLM: "ORCHESTRATOR",
};
