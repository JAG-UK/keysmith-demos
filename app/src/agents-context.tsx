import { createContext, type ReactNode, useCallback, useContext, useMemo, useState } from 'react'
import type { Address } from 'viem'
import { loadAgents, type SessionKeyRecord, saveAgents } from './agents.ts'
import type { Network } from './networks.ts'

interface Agents {
  agents: SessionKeyRecord[]
  upsert: (record: SessionKeyRecord) => void
  remove: (sessionKeyPublic: Address) => void
  /** Bumped whenever a piece is written, so the access matrix re-checks. */
  version: number
  bump: () => void
}

const AgentsContext = createContext<Agents | null>(null)

/** One list per network and wallet, as the console keeps it. Remount to switch. */
export function AgentsProvider(props: { network: Network | undefined; account: Address | undefined; children: ReactNode }) {
  const { network, account } = props
  const [agents, setAgents] = useState<SessionKeyRecord[]>(() => (network && account ? loadAgents(network, account) : []))
  const [version, setVersion] = useState(0)
  const persist = useCallback(
    (next: SessionKeyRecord[]) => {
      setAgents(next)
      if (network && account) saveAgents(network, account, next)
    },
    [network, account]
  )
  const value = useMemo<Agents>(
    () => ({
      agents,
      upsert: (record) =>
        persist([...agents.filter((each) => each.sessionKeyPublic !== record.sessionKeyPublic), record].sort((a, b) => a.createdAt - b.createdAt)),
      remove: (address) => persist(agents.filter((each) => each.sessionKeyPublic !== address)),
      version,
      bump: () => setVersion((n) => n + 1),
    }),
    [agents, persist, version]
  )
  return <AgentsContext.Provider value={value}>{props.children}</AgentsContext.Provider>
}

export function useAgents(): Agents {
  const agents = useContext(AgentsContext)
  if (!agents) throw new Error('useAgents outside AgentsProvider')
  return agents
}
