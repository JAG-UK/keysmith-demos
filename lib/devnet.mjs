/** Devnet wiring and demo bookkeeping. Nothing here is part of the design. */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { toChain, validateDevnetInfo } from '@filoz/synapse-core/devnet'
import { createClient, http, publicActions } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'

const HERE = dirname(fileURLToPath(import.meta.url))
const OUT = join(HERE, '..', 'out')
const STATE = join(OUT, 'state.json')

export function devnet() {
  const path =
    process.env.DEVNET_INFO_PATH ?? join(homedir(), '.foc-devnet', 'state', 'latest', 'devnet-info.json')
  const parsed = validateDevnetInfo(JSON.parse(readFileSync(path, 'utf8')))
  const { info } = parsed
  const sp = info.pdp_sps[0]
  return {
    chain: toChain(parsed),
    runId: info.run_id,
    users: info.users,
    sp: { serviceURL: sp.pdp_service_url, payee: sp.eth_addr },
  }
}

/** A viem client that can both read and write, for a given private key. */
export function clientFor(privateKeyHex, chain) {
  return createClient({
    chain,
    transport: http(),
    account: privateKeyToAccount(privateKeyHex),
  }).extend(publicActions)
}

export function save(patch) {
  const next = { ...load(), ...patch }
  if (!existsSync(OUT)) mkdirSync(OUT, { recursive: true })
  writeFileSync(STATE, `${JSON.stringify(next, bigints, 2)}\n`)
  return next
}

export function load() {
  return existsSync(STATE) ? JSON.parse(readFileSync(STATE, 'utf8')) : {}
}

export function writeJson(name, value) {
  if (!existsSync(OUT)) mkdirSync(OUT, { recursive: true })
  const path = join(OUT, name)
  writeFileSync(path, `${JSON.stringify(value, bigints, 2)}\n`)
  return path
}

export const readJson = (name) => JSON.parse(readFileSync(join(OUT, name), 'utf8'))

const bigints = (_k, v) => (typeof v === 'bigint' ? v.toString() : v)

/**
 * Devnet tipsets sometimes have no blocks, and Lotus answers
 * "requested epoch was a null round". Nothing to do with the design: retry.
 */
export async function onDevnet(fn, tries = 8) {
  for (let i = 0; ; i++) {
    try {
      return await fn()
    } catch (err) {
      const text = `${err?.message ?? ''}${err?.cause?.message ?? ''}${err?.details ?? ''}`
      if (i >= tries || !/null round/i.test(text)) throw err
      await new Promise((r) => setTimeout(r, 3000))
    }
  }
}

let n = 0
export const step = (text) => console.log(`\n[${++n}] ${text}`)
export const note = (text) => console.log(`    ${text}`)
export const need = (state, key, demo) => {
  if (state[key] == null) throw new Error(`missing "${key}" — run ${demo} first`)
  return state[key]
}
