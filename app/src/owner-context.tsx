import type { Hex } from 'viem'
import { createClient, custom, type EIP1193Provider, walletActions } from 'viem'
import { createContext, type ReactNode, useContext, useEffect, useMemo, useState } from 'react'
import { useConnection } from 'wagmi'
import { useActivity } from './activity.tsx'
import { Keyring } from './keyring.ts'
import type { Network } from './networks.ts'
import type { OwnerEnv } from './owner.ts'

interface Owner {
  /** Everything the owner flows need, once a wallet is connected on a known network. */
  env: OwnerEnv | null
  /** Keyspace signatures the wallet has given Keysmith in this tab (not Warm Storage's). */
  signatures: number
  /** The keyspace being worked on. */
  current: { keyspace: Hex; commitment: string } | null
  /** Whether it has storage yet: Synapse has made its datasets, so agents can add to them. */
  stored: boolean
  setCurrent: (current: { keyspace: Hex; commitment: string } | null) => void
  setStored: (stored: boolean) => void
}

const OwnerContext = createContext<Owner | null>(null)

/** Remount (key it on wallet and network) to start over: keys never leak between accounts. */
export function OwnerProvider(props: { network: Network | undefined; children: ReactNode }) {
  const { address, connector, isConnected } = useConnection()
  const activity = useActivity()
  const [provider, setProvider] = useState<EIP1193Provider | null>(null)
  const [signatures, setSignatures] = useState(0)
  const [current, setCurrent] = useState<Owner['current']>(null)
  const [stored, setStored] = useState(false)

  useEffect(() => {
    let live = true
    setProvider(null)
    // While wagmi is still restoring a connection after a reload, `connector` is stored data, not a connector.
    if (isConnected && typeof connector?.getProvider === 'function') {
      connector
        .getProvider()
        .then((p) => live && setProvider(p as EIP1193Provider))
        .catch((err: unknown) => live && activity.fail(err))
    }
    return () => {
      live = false
    }
    // activity.fail only appends to the log
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [connector, isConnected])

  const { network } = props
  const keyring = useMemo(() => {
    if (!network || !address || !provider) return null
    const wallet = createClient({ chain: network.readChain, transport: custom(provider), account: address }).extend(walletActions)
    // Keysmith calls this; counting here shows what the key hierarchy costs in prompts.
    const signer = {
      signTypedData: async (args: Parameters<typeof wallet.signTypedData>[0]) => {
        const signature = await wallet.signTypedData(args)
        setSignatures((n) => n + 1) // given, not merely asked for: a rejection doesn't count
        return signature
      },
    }
    return new Keyring(address, signer as never, activity.prompt)
    // activity.prompt is stable for the purpose here: it only appends to the log
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [network, address, provider])

  const env = keyring && network && address && provider ? { network, owner: address, provider, keyring, activity } : null
  const value = useMemo<Owner>(
    () => ({ env, signatures, current, stored, setCurrent, setStored }),
    [env, signatures, current, stored]
  )
  return <OwnerContext.Provider value={value}>{props.children}</OwnerContext.Provider>
}

export function useOwner(): Owner {
  const owner = useContext(OwnerContext)
  if (!owner) throw new Error('useOwner outside OwnerProvider')
  return owner
}
