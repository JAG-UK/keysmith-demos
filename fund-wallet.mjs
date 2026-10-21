#!/usr/bin/env node
/**
 * Fund your own wallet on the current foc-devnet run, so you can keep one
 * MetaMask account across devnet restarts instead of importing a devnet key.
 *
 *   pnpm fund 0xYourAddress [--fil 100] [--usdfc 1000]
 *
 * USER_1 pays: tFIL as a plain transfer, USDFC as a MockUSDFC transfer. Its
 * key is read from devnet-info.json and never printed. Run it again after each
 * `foc-devnet start`: a new run is a new chain, so balances start from zero.
 */
import { readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { toChain } from '@filoz/synapse-core/devnet'
import { createWalletClient, erc20Abi, formatEther, http, isAddress, parseEther, publicActions } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'

const args = process.argv.slice(2)
const option = (name, fallback) => {
  const i = args.indexOf(`--${name}`)
  return i === -1 ? fallback : args[i + 1]
}
const to = args.find((arg, i) => !arg.startsWith('--') && !args[i - 1]?.startsWith('--'))
if (!to || !isAddress(to)) {
  console.error('Usage: pnpm fund 0xYourAddress [--fil 100] [--usdfc 1000]')
  process.exit(1)
}
const fil = option('fil', '100')
const usdfcAmount = option('usdfc', '1000')

const base = process.env.FOC_DEVNET_BASEDIR || join(homedir(), '.foc-devnet')
const devnet = JSON.parse(readFileSync(join(base, 'state/latest/devnet-info.json'), 'utf8'))
const chain = toChain(devnet)
const rpc = devnet.info.lotus.host_rpc_url
const funder = createWalletClient({
  chain,
  transport: http(rpc),
  account: privateKeyToAccount(devnet.info.users[0].private_key_hex),
}).extend(publicActions)
const usdfc = chain.contracts.usdfc.address
// No replacement check: it fetches blocks by number, and Filecoin's null rounds have none.
const confirm = (hash) => funder.waitForTransactionReceipt({ hash, checkReplacement: false })

console.log(`Devnet run ${devnet.info.run_id}: funding ${to} from USER_1`)
await confirm(await funder.sendTransaction({ to, value: parseEther(fil) }))
console.log(`  ✓ ${fil} ${chain.nativeCurrency.symbol}`)
await confirm(
  await funder.writeContract({ address: usdfc, abi: erc20Abi, functionName: 'transfer', args: [to, parseEther(usdfcAmount)] })
)
console.log(`  ✓ ${usdfcAmount} USDFC`)

const [filBalance, usdfcBalance] = await Promise.all([
  funder.getBalance({ address: to }),
  funder.readContract({ address: usdfc, abi: erc20Abi, functionName: 'balanceOf', args: [to] }),
])
console.log(`  Balance now: ${formatEther(filBalance)} ${chain.nativeCurrency.symbol}, ${formatEther(usdfcBalance)} USDFC`)
console.log(`
MetaMask network: RPC ${rpc}, chain id ${chain.id}, currency ${chain.nativeCurrency.symbol}
USDFC token to import in MetaMask: ${usdfc}
If MetaMask used this account on an earlier run, clear its cached nonces first:
  Settings → Advanced → Clear activity tab data`)
