import { http, createConfig } from 'wagmi'
import { injected } from 'wagmi/connectors'
import type { Network } from './networks.ts'

/**
 * Wallets announce themselves (EIP-6963), so MetaMask, Rabby, Coinbase Wallet and
 * friends each appear by name; `injected()` catches any that don't.
 */
export function makeConfig(networks: Network[]) {
  const [first, ...rest] = networks.map((network) => network.chain)
  return createConfig({
    chains: [first, ...rest],
    connectors: [injected()],
    transports: Object.fromEntries(networks.map((network) => [network.chain.id, http(network.readChain.rpcUrls.default.http[0])])),
  })
}
