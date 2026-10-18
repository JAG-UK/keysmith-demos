import { useState } from 'react'
import { useConnection } from 'wagmi'
import { ActivityLog, ActivityProvider } from './activity.tsx'
import { Header } from './components/Header.tsx'
import { OwnerPanel } from './components/OwnerPanel.tsx'
import { Notice, Panel } from './components/Panel.tsx'
import type { Network } from './networks.ts'
import { AgentsProvider } from './agents-context.tsx'
import { AccessMatrix } from './components/AccessMatrix.tsx'
import { Inspector } from './components/Inspector.tsx'
import { SessionKeysPanel } from './components/SessionKeysPanel.tsx'
import { OwnerProvider } from './owner-context.tsx'

export function App(props: { networks: Network[] }) {
  const { address, chainId, isConnected } = useConnection()
  const [preferred, setPreferred] = useState(props.networks[0])
  // Connected, the wallet's chain decides; otherwise the visitor's pick.
  const network = isConnected ? props.networks.find((each) => each.chain.id === chainId) : preferred

  return (
    <ActivityProvider>
    <OwnerProvider key={`${chainId}:${address}`} network={network}>
    <AgentsProvider key={`${network?.id}:${address}`} network={network} account={address}>
    <div className="page">
      <Header networks={props.networks} network={network} onPick={setPreferred} />
      {isConnected && !network ? (
        <Notice tone="warn">Your wallet is on a chain this demo doesn't know (id {chainId}). Pick a network above.</Notice>
      ) : null}
      {network ? <p className="network-note">{network.note}</p> : null}

      <main className="grid">
        <Panel step={1} area="owner" title="Owner" lede="Start a keyspace with your wallet, store a first piece through Synapse, and get your keys back from the chain alone.">
          <OwnerPanel />
        </Panel>
        <Panel step={2} area="agents" title="Session keys" lede="Agents that write for you without your wallet, each with only the keys its job needs.">
          <SessionKeysPanel />
        </Panel>
        <Panel area="activity" title="Activity" lede="Every wallet prompt is announced here before it appears.">
          <ActivityLog />
        </Panel>
        <Panel step={3} area="matrix" title="Who can read what" lede="Each reader against each piece, using the real ciphertext, fetched by Synapse.">
          <AccessMatrix />
        </Panel>
        <Panel step={4} area="inspector" title="Inspector" lede="Drop in a piece or a grant and see exactly what it says, byte by byte.">
          <Inspector />
        </Panel>
      </main>

      <footer className="foot muted">
        Keys exist only in this tab. Agents' session keys are kept in this browser's local storage: fine for a demo, not for
        anything of value.
      </footer>
    </div>
    </AgentsProvider>
    </OwnerProvider>
    </ActivityProvider>
  )
}
