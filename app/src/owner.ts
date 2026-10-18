/**
 * The owner's side, as plain functions: start a keyspace, store a first piece,
 * recover every key from the chain. Ported from web/app.mjs.
 *
 * Layers: @filoz/keysmith derives · FEE encrypts · Synapse stores · FWSS records.
 */
import * as Keysmith from '@filoz/keysmith'
import { getAllDataSetMetadata, getClientDataSets } from '@filoz/synapse-core/warm-storage'
import { Synapse } from '@filoz/synapse-sdk'
import { type Address, custom, type EIP1193Provider, formatUnits, type Hex, parseUnits } from 'viem'
import { decryptBytes, encryptBytes, readEnvelope } from '../../lib/fee.mjs'
import { listPiecesOnChain } from '../../lib/store.mjs'
import type { Activity } from './activity.tsx'
import type { Keyring } from './keyring.ts'
import type { Network } from './networks.ts'
import { dataSetMetadata, readerFor, readerSynapse, store } from './storage.ts'

export interface OwnerEnv {
  network: Network
  owner: Address
  provider: EIP1193Provider
  keyring: Keyring
  activity: Activity
}

/** Synapse acting as the owner, signing through the wallet. */
const ownerSynapse = (env: OwnerEnv) =>
  Synapse.create({ chain: env.network.readChain, transport: custom(env.provider), account: env.owner, source: 'keysmith-demo' })

const utf8 = (text: string) => new TextEncoder().encode(text)

export type StepId = 'encrypt' | 'fund' | 'upload' | 'commit'
export type StepState = { status: 'active' | 'done' | 'error'; detail?: string }
export type OnStep = (id: StepId, state: StepState) => void

/**
 * Encrypt a first piece and hand it to Synapse with the keyspace and its
 * commitment as dataset metadata. Synapse picks the providers and creates the
 * datasets; later writes with the same metadata land in the same ones.
 */
export async function storeFirstPiece(env: OwnerEnv, keyspace: Hex, text: string, step: OnStep): Promise<{ pieceCid: string }> {
  const { kk, commitment, descriptor } = await env.keyring.keysFor(keyspace)

  step('encrypt', { status: 'active' })
  // The owner writes the way a delegate does: the keyspace comes from what was signed.
  const target = Keysmith.writeTarget(descriptor, kk)
  const salt = Keysmith.newSalt()
  const ciphertext = await encryptBytes(utf8(text), Keysmith.pieceKey(target.key, salt), Keysmith.pieceMetadata(target.ref, { salt, scope: target.scope }))
  step('encrypt', { status: 'done', detail: `${ciphertext.length} B envelope, no prompt` })

  step('fund', { status: 'active' })
  step('fund', { status: 'done', detail: await fund(env) })

  step('upload', { status: 'active', detail: 'Synapse picks the providers' })
  env.activity.prompt('sign the Warm Storage messages for each copy: "create dataset" and "add pieces" the first time, "add pieces" after. The providers submit them and pay the gas')
  const { pieceCid, copies } = await store(ownerSynapse(env), env.network, ciphertext, dataSetMetadata(keyspace, commitment), (event) => {
    if (event.kind === 'submitted') {
      step('upload', { status: 'done', detail: 'stored, and copied' })
      step('commit', { status: 'active', detail: 'waiting for the chain' })
    }
    if (event.kind !== 'confirmed') env.activity.log(`Synapse: ${event.kind}, ${event.detail}`)
  })
  step('commit', { status: 'done', detail: `${pieceCid}, ${copies} cop${copies === 1 ? 'y' : 'ies'}` })
  return { pieceCid }
}

/** Ordinary Synapse payment setup. Nothing to do with keys. */
async function fund(env: OwnerEnv): Promise<string> {
  const reader = readerFor(env.network)
  // Lotus refuses even a read "from" an address it has never seen, so say why rather than fail obscurely.
  if ((await reader.getBalance({ address: env.owner })) === 0n) {
    throw new Error(`This account has no ${env.network.chain.nativeCurrency.symbol}, so the chain does not know it yet.`)
  }
  const synapse = ownerSynapse(env)
  const notes: string[] = []
  // Each half is checked on its own, so an interrupted run resumes where it stopped.
  const { availableFunds } = await synapse.payments.accountInfo()
  if (availableFunds < parseUnits('2', 18)) {
    env.activity.prompt('allow Filecoin Pay to take 10 USDFC (if not already allowed), then deposit it')
    await reader.waitForTransactionReceipt({ hash: await synapse.payments.deposit({ amount: parseUnits('10', 18) }) })
    notes.push('deposited 10 USDFC')
  } else {
    notes.push(`${formatUnits(availableFunds, 18)} USDFC available`)
  }
  if (!(await synapse.payments.serviceApproval()).isApproved) {
    env.activity.prompt('approve Warm Storage as an operator, so it can charge for storage')
    await reader.waitForTransactionReceipt({ hash: await synapse.payments.approveService({}) })
    notes.push('approved Warm Storage')
  }
  return notes.join(', ')
}

export interface RecoveredPiece {
  cid: string
  scope?: string
  text?: string
  note?: string
}
export interface RecoveredKeyspace {
  keyspace?: Hex
  /** Where the chain lists its pieces today. Informational: repair can move them. */
  dataSetIds: bigint[]
  check: 'commitment matches' | 'no commitment recorded' | 'no keyspace recorded' | 'pre-release format' | 'commitment mismatch'
  pieces: RecoveredPiece[]
}

/** Every keyspace this wallet pays to store, every piece in it, opened from the wallet alone. */
export async function recover(env: OwnerEnv, onKeyspace: (found: RecoveredKeyspace) => void): Promise<void> {
  const reader = readerFor(env.network)
  const { items } = await getClientDataSets(reader, { address: env.owner })
  env.activity.log(`The chain lists ${items.length} dataset(s) paid for by this wallet.`)
  // Synapse keeps copies in several datasets, so group by what they record, not by dataset.
  const groups = new Map<string, { keyspace?: Hex; recorded?: string; ids: bigint[] }>()
  for (const { dataSetId } of items) {
    const id = BigInt(dataSetId)
    const metadata = await getAllDataSetMetadata(reader, { dataSetId: id })
    const keyspace = metadata[Keysmith.KEYSPACE_ID_KEY] as Hex | undefined
    const recorded = metadata[Keysmith.COMMITMENT_KEY]
    const key = `${keyspace}|${recorded}`
    const group = groups.get(key) ?? { keyspace, recorded, ids: [] }
    group.ids.push(id)
    groups.set(key, group)
  }
  const synapse = readerSynapse(env.network, env.owner)
  for (const { keyspace, recorded, ids } of groups.values()) {
    const found: RecoveredKeyspace = {
      keyspace,
      dataSetIds: ids,
      check: !keyspace ? 'no keyspace recorded' : recorded ? 'commitment matches' : 'no commitment recorded',
      pieces: [],
    }
    // On a public network a wallet may pay for other apps' datasets: don't download those.
    if (!keyspace && env.network.id !== 'devnet') {
      onKeyspace(found)
      continue
    }
    if (keyspace && recorded) {
      // Checked before signing, so a dataset from a pre-release format costs no prompt.
      if (!/^v1\.[0-9a-f]{32}$/.test(recorded)) {
        onKeyspace({ ...found, check: 'pre-release format' })
        continue
      }
      try {
        await env.keyring.keysFor(keyspace, recorded)
      } catch (err) {
        env.activity.fail(err)
        onKeyspace({ ...found, check: 'commitment mismatch' })
        continue
      }
    }
    const seen = new Set<string>()
    for (const id of ids) {
      for (const { pieceCid } of await listPiecesOnChain(reader, id)) {
        const cid = pieceCid.toString()
        if (seen.has(cid)) continue
        seen.add(cid)
        found.pieces.push(await openPiece(env, synapse, cid))
      }
    }
    onKeyspace(found)
  }
}

/** Fetch a piece by CID, wherever it is now, and open it by the keyspace its own envelope names. */
async function openPiece(env: OwnerEnv, synapse: Synapse, cid: string): Promise<RecoveredPiece> {
  let blob: Uint8Array
  try {
    blob = await synapse.storage.download({ pieceCid: cid })
  } catch (err) {
    return { cid, note: `could not download: ${(err as Error).message}` }
  }
  let appMetadata: Record<string, unknown> | undefined
  try {
    ;({ appMetadata } = await readEnvelope(blob))
  } catch {
    return { cid, note: 'not a FEE 0.1 piece: plaintext, or an older envelope format' }
  }
  if (!appMetadata) return { cid, note: 'encrypted, but not by Keysmith' }
  const metadata = appMetadata as unknown as Keysmith.PieceMetadata
  if (metadata['foc/v'] !== 1 || !metadata['foc/ks']) return { cid, note: 'pre-release envelope' }
  const { kk } = await env.keyring.keysFor(metadata['foc/ks'])
  // FEE reads the envelope, then asks Keysmith for the key.
  const text = new TextDecoder().decode(await decryptBytes(blob, Keysmith.keyResolver(kk)))
  return { cid, scope: metadata['foc/scope'], text }
}
