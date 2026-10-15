import { calibration, type FilecoinChain, mainnet } from '@filoz/synapse-core/chains'
import { toChain } from '@filoz/synapse-core/devnet'

export type NetworkId = 'devnet' | 'calibration' | 'mainnet'

export interface Network {
  id: NetworkId
  label: string
  chain: FilecoinChain
  /** Where the page reads from. Devnet goes through the dev server, because Lotus sends no CORS headers. */
  rpc: string
  note: string
}

/** The public networks always; devnet too when the dev server has one running. */
export async function loadNetworks(): Promise<Network[]> {
  const networks: Network[] = []
  const response = await fetch('/devnet.json').catch(() => null)
  if (response?.ok) {
    const devnet = await response.json()
    networks.push({
      id: 'devnet',
      label: 'Devnet',
      chain: toChain(devnet),
      rpc: `${location.origin}/rpc/v1`,
      note: `foc-devnet run ${devnet.info.run_id}. Import a devnet user's key into your wallet to fund it.`,
    })
  }
  networks.push(
    {
      id: 'calibration',
      label: 'Calibration',
      chain: calibration,
      rpc: calibration.rpcUrls.default.http[0],
      note: 'Filecoin testnet. Needs tFIL for gas and USDFC for storage, both from faucets.',
    },
    {
      id: 'mainnet',
      label: 'Mainnet',
      chain: mainnet,
      rpc: mainnet.rpcUrls.default.http[0],
      note: 'Real FIL and USDFC. Everything here costs money.',
    }
  )
  return networks
}
