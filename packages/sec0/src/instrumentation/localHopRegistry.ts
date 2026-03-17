import type { AgentStatePayload } from '../agent-state'

type LocalHopHandler = (params: Record<string, any>, agentState: AgentStatePayload) => Promise<any> | any

const localHopHandlers = new Map<string, LocalHopHandler>()

export function registerLocalHopHandler(hopKey: string, handler: LocalHopHandler) {
  if (!hopKey?.trim()) {
    throw new Error('[sec0] registerLocalHopHandler requires a hopKey.')
  }
  localHopHandlers.set(hopKey.trim(), handler)
}

export function unregisterLocalHopHandler(hopKey: string) {
  localHopHandlers.delete(hopKey.trim())
}

export function getLocalHopHandler(hopKey: string): LocalHopHandler | undefined {
  return localHopHandlers.get(hopKey.trim())
}

