import type { ManagedGenericHop } from './agentManager'
import type { AgentStatePayload } from '../agent-state'

export class HopTransporter {
  async invokeRemote(hop: ManagedGenericHop, params: Record<string, any>, agentState: AgentStatePayload) {
    const url = hop.config.remoteUrl?.trim()
    if (!url) {
      throw new Error(`[sec0] Hop "${hop.key}" is missing remoteUrl for remote invocation.`)
    }
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        hopKey: hop.key,
        hopType: hop.type,
        params,
        agentState,
      }),
    }).catch((err: any) => {
      throw new Error(`[sec0] Remote hop "${hop.key}" failed: ${err?.message || err}`)
    })
    if (!res.ok) {
      throw new Error(`[sec0] Remote hop "${hop.key}" returned status ${res.status}`)
    }
    const text = await res.text()
    if (!text) return undefined
    try {
      return JSON.parse(text)
    } catch {
      return text
    }
  }
}

