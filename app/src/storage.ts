/**
 * Storage, through Synapse alone. Synapse picks the providers, makes the copies,
 * and reuses whichever datasets match the metadata; the page never names an SP.
 * Pieces are found by keyspace on the chain and fetched by piece CID.
 */
import * as Keysmith from '@filoz/keysmith'
import { getAllDataSetMetadata, getClientDataSets } from '@filoz/synapse-core/warm-storage'
import { Synapse } from '@filoz/synapse-sdk'
import { type Address, createClient, type Hex, http, publicActions } from 'viem'
import { listPiecesOnChain } from '../../lib/store.mjs'
import type { Network } from './networks.ts'

export const readerFor = (network: Network) => createClient({ chain: network.readChain, transport: http() }).extend(publicActions)

/** A Synapse that only reads, for the account whose datasets hold the pieces. */
export const readerSynapse = (network: Network, account: Address) =>
  Synapse.create({ chain: network.readChain, transport: http(), account, source: 'keysmith-demo' })

/** What every dataset of a keyspace records, so Synapse reuses them instead of making new ones. */
export const dataSetMetadata = (keyspace: Hex, commitment: string) => ({
  [Keysmith.KEYSPACE_ID_KEY]: keyspace,
  [Keysmith.COMMITMENT_KEY]: commitment,
})

export type StoreEvent = { kind: 'stored' | 'copied' | 'submitted' | 'confirmed'; detail: string }

/**
 * `synapse.storage.upload()`, confirmed by the chain.
 *
 * Synapse waits on each provider's add-pieces status endpoint. Curio batches
 * piece additions, and the endpoint can answer 404, or nothing, for minutes
 * after the transaction has landed. So once Synapse has submitted the add
 * transactions, their receipts decide: the upload is done when the chain says
 * so, whether or not Synapse's own wait has finished.
 */
export async function store(
  synapse: Synapse,
  network: Network,
  bytes: Uint8Array,
  metadata: Record<string, string>,
  on: (event: StoreEvent) => void = () => {}
): Promise<{ pieceCid: string; copies: number }> {
  const reader = readerFor(network)
  let pieceCid = ''
  let copies = 1
  const submitted: Hex[] = []
  return new Promise((resolve, reject) => {
    let confirming: Promise<void> | undefined
    // Every copy has been pulled before any commit starts, so the first submission knows how many follow.
    const onSubmitted = (txHash: Hex, providerId: bigint) => {
      submitted.push(txHash)
      on({ kind: 'submitted', detail: `provider ${providerId}: ${txHash}` })
      if (submitted.length < copies || confirming) return
      // No replacement check: it fetches blocks by number, and Filecoin's null rounds have none.
      confirming = Promise.all(submitted.map((hash) => reader.waitForTransactionReceipt({ hash, checkReplacement: false })))
        .then((receipts) => {
          const reverted = receipts.find((receipt) => receipt.status !== 'success')
          if (reverted) throw new Error(`Add-pieces transaction ${reverted.transactionHash} reverted`)
          on({ kind: 'confirmed', detail: `${receipts.length} add-pieces transaction(s) on chain` })
          resolve({ pieceCid, copies })
        })
        .catch(reject)
    }
    synapse.storage
      .upload(bytes, {
        metadata,
        callbacks: {
          onStored: (providerId, cid) => {
            pieceCid = cid.toString()
            on({ kind: 'stored', detail: `provider ${providerId} holds ${pieceCid}` })
          },
          onCopyComplete: (providerId) => {
            copies++
            on({ kind: 'copied', detail: `provider ${providerId} pulled a copy` })
          },
          onPiecesAdded: (txHash, providerId) => onSubmitted(txHash, providerId),
        },
      })
      .then((result) => resolve({ pieceCid: result.pieceCid.toString(), copies: result.copies.length }))
      // Once submitted, the receipts decide; Synapse failing only its status wait is not a failure.
      .catch((err) => submitted.length === 0 && reject(err))
  })
}

export interface StoredPiece {
  cid: string
  /** Where the chain lists it now. Informational: repair can move it. */
  dataSetIds: bigint[]
}

/** Every piece in any dataset this account pays for that records the keyspace, once per piece CID. */
export async function keyspacePieces(network: Network, account: Address, keyspace: Hex): Promise<StoredPiece[]> {
  const pieces = new Map<string, StoredPiece>()
  for (const id of await keyspaceDataSets(network, account, keyspace)) {
    for (const { pieceCid } of await listPiecesOnChain(readerFor(network), id)) {
      const cid = pieceCid.toString()
      const piece = pieces.get(cid) ?? { cid, dataSetIds: [] }
      piece.dataSetIds.push(id)
      pieces.set(cid, piece)
    }
  }
  return [...pieces.values()]
}

export async function keyspaceDataSets(network: Network, account: Address, keyspace: Hex): Promise<bigint[]> {
  const reader = readerFor(network)
  const { items } = await getClientDataSets(reader, { address: account })
  const ids: bigint[] = []
  for (const { dataSetId } of items) {
    const metadata = await getAllDataSetMetadata(reader, { dataSetId: BigInt(dataSetId) })
    if (metadata[Keysmith.KEYSPACE_ID_KEY] === keyspace) ids.push(BigInt(dataSetId))
  }
  return ids
}
