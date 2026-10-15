/**
 * The owner's side, as plain functions: start a keyspace, create a dataset,
 * recover every key from the chain. Ported from web/app.mjs.
 *
 * Layers: @filoz/keysmith derives · FEE encrypts · Curio stores · FWSS records.
 */
import * as Keysmith from '@filoz/keysmith'
import { getAllDataSetMetadata, getClientDataSets, getDataSet } from '@filoz/synapse-core/warm-storage'
import { Synapse } from '@filoz/synapse-sdk'
import { CoseAlgorithm, decrypt, encrypt, parseEnvelope } from 'foc-encryption'
import {
  type Address,
  createClient,
  custom,
  type EIP1193Provider,
  formatUnits,
  type Hex,
  http,
  parseUnits,
  publicActions,
  walletActions,
} from 'viem'
import { createDataSetWithPiece, getPiece, listPiecesOnChain, pieceUrl, putPiece } from '../../lib/store.mjs'
import type { Activity } from './activity.tsx'
import type { Keyring } from './keyring.ts'
import type { Network } from './networks.ts'

export const ALGORITHM = CoseAlgorithm.CHUNKED_AES_256_GCM_STREAM

export interface OwnerEnv {
  network: Network
  owner: Address
  provider: EIP1193Provider
  keyring: Keyring
  activity: Activity
}

export interface DataSet {
  id: bigint
  clientDataSetId: bigint
  keyspace: Hex
}

export const readerFor = (network: Network) => createClient({ chain: network.readChain, transport: http() }).extend(publicActions)

/** The owner's wallet, reading through the page's RPC and signing through the wallet. */
const walletFor = (env: OwnerEnv) =>
  createClient({ chain: env.network.readChain, transport: custom(env.provider), account: env.owner })
    .extend(publicActions)
    .extend(walletActions)

const utf8 = (text: string) => new TextEncoder().encode(text)

function needSp(network: Network) {
  if (!network.sp) throw new Error(`Storing on ${network.label} arrives in phase 5: this phase stores on devnet only.`)
  return network.sp
}

async function dataSetInfo(network: Network, dataSetId: bigint) {
  const info = await getDataSet(readerFor(network), { dataSetId })
  if (!info) throw new Error(`Warm Storage has no dataset ${dataSetId}`)
  return info
}

export type StepId = 'encrypt' | 'fund' | 'upload' | 'create'
export type StepState = { status: 'active' | 'done' | 'error'; detail?: string }
export type OnStep = (id: StepId, state: StepState) => void

/** Encrypt a first piece, store it, and create a dataset that records the keyspace and its commitment. */
export async function createDataset(env: OwnerEnv, keyspace: Hex, text: string, step: OnStep): Promise<DataSet & { pieceCid: string }> {
  const sp = needSp(env.network)
  const { kk, commitment, descriptor } = await env.keyring.keysFor(keyspace)

  step('encrypt', { status: 'active' })
  // The owner writes the way a delegate does: the keyspace comes from what was signed.
  const target = Keysmith.writeTarget(descriptor, kk)
  const salt = Keysmith.newSalt()
  const ciphertext = await encrypt(utf8(text), Keysmith.pieceKey(target.key, salt), {
    algorithm: ALGORITHM,
    appMetadata: { ...Keysmith.pieceMetadata(target.ref, { salt, scope: target.scope }) },
  })
  step('encrypt', { status: 'done', detail: `${ciphertext.length} B envelope, no prompt` })

  step('fund', { status: 'active' })
  step('fund', { status: 'done', detail: await fund(env) })

  step('upload', { status: 'active', detail: 'the SP stores the piece; this can take a minute' })
  const pieceCid = await putPiece(sp.serviceURL, ciphertext)
  step('upload', { status: 'done', detail: pieceCid.toString() })

  step('create', { status: 'active', detail: 'the SP submits it and pays the gas' })
  env.activity.prompt('sign two Warm Storage messages, "create dataset" and "add pieces". The SP submits them and pays the gas')
  const created = await createDataSetWithPiece(walletFor(env), {
    serviceURL: sp.serviceURL,
    payee: sp.payee,
    metadata: { [Keysmith.KEYSPACE_ID_KEY]: keyspace, [Keysmith.COMMITMENT_KEY]: commitment },
    pieceCid,
  })
  // Only addPieces needs this, and only because FWSS signs over it. No key depends on it.
  const { clientDataSetId } = await dataSetInfo(env.network, created.dataSetId)
  step('create', { status: 'done', detail: `dataset ${created.dataSetId}` })
  return { id: created.dataSetId, clientDataSetId, keyspace, pieceCid: pieceCid.toString() }
}

/** Ordinary Synapse payment setup. Nothing to do with keys. */
async function fund(env: OwnerEnv): Promise<string> {
  const reader = readerFor(env.network)
  // Lotus refuses even a read "from" an address it has never seen, so say why rather than fail obscurely.
  if ((await reader.getBalance({ address: env.owner })) === 0n) {
    throw new Error(`This account has no ${env.network.chain.nativeCurrency.symbol}, so the chain does not know it yet.`)
  }
  const synapse = Synapse.create({
    chain: env.network.readChain,
    transport: custom(env.provider),
    account: env.owner,
    source: 'keysmith-demo',
  })
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
  id: bigint
  cid: string
  url: string
  scope?: string
  text?: string
  note?: string
}
export interface RecoveredDataSet {
  id: bigint
  clientDataSetId: bigint
  keyspace?: Hex
  check: 'commitment matches' | 'no commitment recorded' | 'no keyspace recorded' | 'pre-release format' | 'commitment mismatch'
  pieces: RecoveredPiece[]
}

/** Every dataset this wallet pays for, every piece in it, opened from the wallet alone. */
export async function recover(env: OwnerEnv, onDataSet: (dataSet: RecoveredDataSet) => void): Promise<void> {
  const sp = needSp(env.network)
  const reader = readerFor(env.network)
  const { items } = await getClientDataSets(reader, { address: env.owner })
  env.activity.log(`The chain lists ${items.length} dataset(s) paid for by this wallet.`)
  for (const { dataSetId } of items) {
    const id = BigInt(dataSetId)
    const metadata = await getAllDataSetMetadata(reader, { dataSetId: id })
    const keyspace = metadata[Keysmith.KEYSPACE_ID_KEY] as Hex | undefined
    const recorded = metadata[Keysmith.COMMITMENT_KEY]
    const { clientDataSetId } = await dataSetInfo(env.network, id)
    const dataSet: RecoveredDataSet = {
      id,
      clientDataSetId,
      keyspace,
      check: !keyspace ? 'no keyspace recorded' : recorded ? 'commitment matches' : 'no commitment recorded',
      pieces: [],
    }
    if (keyspace && recorded) {
      // Checked before signing, so a dataset from a pre-release format costs no prompt.
      if (!/^v1\.[0-9a-f]{32}$/.test(recorded)) {
        onDataSet({ ...dataSet, check: 'pre-release format' })
        continue
      }
      try {
        await env.keyring.keysFor(keyspace, recorded)
      } catch (err) {
        env.activity.fail(err)
        onDataSet({ ...dataSet, check: 'commitment mismatch' })
        continue
      }
    }
    for (const piece of await listPiecesOnChain(reader, id)) {
      dataSet.pieces.push(await openPiece(env, sp.serviceURL, piece.pieceId, piece.pieceCid))
    }
    onDataSet(dataSet)
  }
}

/** Open one piece by the keyspace its own envelope names, whichever dataset it was found in. */
async function openPiece(env: OwnerEnv, serviceURL: string, id: bigint, cid: string): Promise<RecoveredPiece> {
  const url = pieceUrl(serviceURL, cid)
  const blob = await getPiece(serviceURL, cid)
  let appMetadata: Record<string, unknown> | undefined
  try {
    ;({ appMetadata } = parseEnvelope(blob))
  } catch {
    return { id, cid, url, note: 'not encrypted' }
  }
  if (!appMetadata) return { id, cid, url, note: 'encrypted, but not by Keysmith' }
  const metadata = appMetadata as unknown as Keysmith.PieceMetadata
  if (metadata['foc/v'] !== 1 || !metadata['foc/ks']) return { id, cid, url, note: 'pre-release envelope' }
  const { kk } = await env.keyring.keysFor(metadata['foc/ks'])
  const text = new TextDecoder().decode(await decrypt(blob, Keysmith.keyForEnvelope(kk, metadata)))
  return { id, cid, url, scope: metadata['foc/scope'], text }
}
