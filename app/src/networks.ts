import { calibration, type FilecoinChain, mainnet } from '@filoz/synapse-core/chains'
import { toChain } from '@filoz/synapse-core/devnet'

export type NetworkId = 'devnet' | 'calibration' | 'mainnet'

export interface Network {
  id: NetworkId
  label: string
  /** What the wallet is given: its RPC is the node's real address. */
  chain: FilecoinChain
  /**
   * What the page reads with, and hands to library code that builds its own
   * read clients. On devnet its RPC is the dev server's proxy, because Lotus
   * sends no CORS headers.
   */
  readChain: FilecoinChain
  note: string
}

/** The public networks always; devnet too when the dev server has one running. */
export async function loadNetworks(): Promise<Network[]> {
  const networks: Network[] = []
  const response = await fetch('/devnet.json').catch(() => null)
  if (response?.ok) {
    const devnet = await response.json()
    const chain = toChain(devnet)
    const proxied = { http: [`${location.origin}/rpc/v1`] }
    networks.push({
      id: 'devnet',
      label: 'Devnet',
      chain,
      readChain: { ...chain, rpcUrls: { default: proxied, public: proxied } },
      note: `foc-devnet run ${devnet.info.run_id}. Import a devnet user's key into your wallet to fund it.`,
    })
  }
  networks.push(
    {
      id: 'calibration',
      label: 'Calibration',
      chain: calibration,
      readChain: calibration,
      note: 'Filecoin testnet. Needs tFIL for gas and USDFC for storage, both from faucets.',
    },
    {
      id: 'mainnet',
      label: 'Mainnet',
      chain: mainnet,
      readChain: mainnet,
      note: 'Real FIL and USDFC. Everything here costs money.',
    }
  )
  return networks
}
