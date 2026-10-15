import { formatEther } from 'viem'
import { useBalance, useConnect, useConnection, useConnectors, useDisconnect, useSwitchChain } from 'wagmi'
import type { Network } from '../networks.ts'

export const short = (address: string) => `${address.slice(0, 6)}…${address.slice(-4)}`

export function Header(props: { networks: Network[]; network: Network | undefined; onPick: (network: Network) => void }) {
  return (
    <header className="topbar">
      <div className="brand">
        <span className="mark" aria-hidden>
          ◆
        </span>
        <div>
          <h1>Keysmith on FOC</h1>
          <p>One wallet signature roots a key hierarchy for encrypted storage on Filecoin.</p>
        </div>
      </div>
      <div className="topbar-controls">
        <NetworkSelect {...props} />
        <Wallet network={props.network} />
      </div>
    </header>
  )
}

function NetworkSelect(props: { networks: Network[]; network: Network | undefined; onPick: (network: Network) => void }) {
  const { isConnected } = useConnection()
  const switchChain = useSwitchChain()
  return (
    <label className="field">
      <span>Network</span>
      <select
        value={props.network?.id ?? ''}
        disabled={switchChain.isPending}
        onChange={(event) => {
          const picked = props.networks.find((network) => network.id === event.target.value)
          if (!picked) return
          // Connected, the wallet's chain is the source of truth: ask it to switch (adding the chain if needed).
          if (isConnected) switchChain.mutate({ chainId: picked.chain.id })
          else props.onPick(picked)
        }}
      >
        {props.network ? null : <option value="">Unknown network</option>}
        {props.networks.map((network) => (
          <option key={network.id} value={network.id}>
            {network.label}
          </option>
        ))}
      </select>
    </label>
  )
}

function Wallet(props: { network: Network | undefined }) {
  const { address, connector, isConnected } = useConnection()
  const connectors = useConnectors()
  const connect = useConnect()
  const disconnect = useDisconnect()
  const balance = useBalance({ address, query: { enabled: isConnected && props.network != null } })

  if (!isConnected || !address) {
    // Wallets that announce themselves (EIP-6963) by name; the generic fallback only if none do.
    const announced = connectors.filter((each) => each.id !== 'injected')
    const shown = announced.length > 0 ? announced : connectors
    if (announced.length === 0 && !('ethereum' in window)) {
      return <span className="muted">No browser wallet found. Install MetaMask, or another wallet, to continue.</span>
    }
    return (
      <div className="wallet">
        {shown.map((each) => (
          <button
            key={each.uid}
            type="button"
            className="button primary"
            disabled={connect.isPending}
            onClick={() => connect.mutate({ connector: each, chainId: props.network?.chain.id })}
          >
            {each.icon ? <img src={each.icon} alt="" width={16} height={16} /> : null}
            Connect {each.id === 'injected' ? 'browser wallet' : each.name}
          </button>
        ))}
        {connect.error ? <span className="error-text">{connect.error.message.split('\n')[0]}</span> : null}
      </div>
    )
  }
  return (
    <div className="wallet connected">
      <div className="account">
        <span className="mono">{short(address)}</span>
        <span className="muted">
          {connector?.name}
          {balance.data ? ` · ${Number(formatEther(balance.data.value)).toFixed(3)} ${balance.data.symbol}` : ''}
        </span>
      </div>
      <button type="button" className="button ghost" onClick={() => disconnect.mutate()}>
        Disconnect
      </button>
    </div>
  )
}
