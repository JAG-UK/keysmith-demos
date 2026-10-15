import { useState } from 'react'
import { useConnection } from 'wagmi'
import { ActivityLog, ActivityProvider } from './activity.tsx'
import { Header } from './components/Header.tsx'
import { OwnerPanel } from './components/OwnerPanel.tsx'
import { Notice, Panel, Placeholder } from './components/Panel.tsx'
import type { Network } from './networks.ts'
import { OwnerProvider } from './owner-context.tsx'

export function App(props: { networks: Network[] }) {
  const { address, chainId, isConnected } = useConnection()
  const [preferred, setPreferred] = useState(props.networks[0])
  // Connected, the wallet's chain decides; otherwise the visitor's pick.
  const network = isConnected ? props.networks.find((each) => each.chain.id === chainId) : preferred

  return (
    <ActivityProvider>
    <OwnerProvider key={`${chainId}:${address}`} network={network}>
    <div className="page">
      <Header networks={props.networks} network={network} onPick={setPreferred} />
      {isConnected && !network ? (
        <Notice tone="warn">Your wallet is on a chain this demo doesn't know (id {chainId}). Pick a network above.</Notice>
      ) : null}
      {network ? <p className="network-note">{network.note}</p> : null}

      <main className="grid">
        <Panel step={1} area="owner" title="Owner" lede="Start a keyspace with your wallet, create a dataset, and get your keys back from the chain alone.">
          <OwnerPanel />
        </Panel>
        <Panel step={2} area="agents" title="Session keys" lede="Agents that write for you without your wallet, each with only the keys its job needs.">
          <Placeholder phase={3}>
            Authorise agents in SessionKeyRegistry, the way the Filecoin Pay console does, then share grants: everyone gets the{' '}
            <code>shared</code> scope, and each agent a private <code>agents/&lt;name&gt;</code> scope of its own.
          </Placeholder>
        </Panel>
        <Panel area="activity" title="Activity" lede="Every wallet prompt is announced here before it appears.">
          <ActivityLog />
        </Panel>
        <Panel step={3} area="matrix" title="Who can read what" lede="Every cell is a real decryption attempt, on the real ciphertext.">
          <Placeholder phase={3}>
            For each agent and each piece, fetch the ciphertext from the provider and try to open it with that agent's keys.
          </Placeholder>
        </Panel>
        <Panel step={4} area="inspector" title="Inspector" lede="Drop in a piece or a grant and see exactly what it says, byte by byte.">
          <Placeholder phase={4}>
            Decoded CBOR beside a hex view: the FEE envelope's labels (owner, keyspace, scope, salt) and how the piece is
            encrypted, or a grant's descriptor and wrap. Then: which of your keys opens it, and the derivation path it took.
          </Placeholder>
        </Panel>
      </main>

      <footer className="foot muted">
        Keys exist only in this tab. Agents' session keys are kept in this browser's local storage: fine for a demo, not for
        anything of value.
      </footer>
    </div>
    </OwnerProvider>
    </ActivityProvider>
  )
}
