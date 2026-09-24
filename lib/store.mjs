/**
 * The storage layer, unchanged by encryption: it moves opaque bytes.
 * Thin wrappers over @filoz/synapse-core so the demos read as steps.
 *
 * Note on waiting: we confirm piece additions against PDPVerifier rather than
 * the SP's status endpoint. synapse-core 0.9.1 polls
 * /pdp/data-sets/{id}/pieces/added/{hash}, which this devnet's Curio build does
 * not serve ("Piece addition not found for given transaction") — the SDK's own
 * storage.upload() fails the same way here. The chain is the source of truth,
 * and it shows the pieces landing correctly.
 */
import * as Piece from '@filoz/synapse-core/piece'
import * as SP from '@filoz/synapse-core/sp'
import { CID } from 'multiformats/cid'
import { createClient, http, publicActions } from 'viem'
import * as Trace from './trace.mjs'

const PDP_ABI = [
  {
    name: 'getNextPieceId',
    type: 'function',
    stateMutability: 'view',
    inputs: [{ name: 'setId', type: 'uint256' }],
    outputs: [{ type: 'uint256' }],
  },
  {
    name: 'getPieceCid',
    type: 'function',
    stateMutability: 'view',
    inputs: [
      { name: 'setId', type: 'uint256' },
      { name: 'pieceId', type: 'uint256' },
    ],
    outputs: [{ components: [{ name: 'data', type: 'bytes' }], type: 'tuple' }],
  },
  {
    name: 'pieceLive',
    type: 'function',
    stateMutability: 'view',
    inputs: [
      { name: 'setId', type: 'uint256' },
      { name: 'pieceId', type: 'uint256' },
    ],
    outputs: [{ type: 'bool' }],
  },
]

/**
 * PUT the bytes to Curio, then wait until the SP has parked them.
 * No chain interaction, no key, no metadata — Curio only ever sees ciphertext.
 */
export async function putPiece(serviceURL, bytes) {
  const pieceCid = await Piece.calculate(bytes)
  Trace.title('piece CID — computed over ciphertext, not plaintext')
  Trace.say(
    `${bytes.length} B → ${pieceCid}`,
    'fr32-padded merkle root (multicodec fil-commitment-unsealed, multihash sha2-256-trunc254-padded)'
  )
  Trace.http('POST', `${serviceURL}/pdp/piece`, `{"pieceCid":"${pieceCid}"}`)
  await SP.uploadPiece({ serviceURL, data: bytes, pieceCid })
  Trace.http('PUT', `${serviceURL}/pdp/piece/upload/<uuid>`, `${bytes.length} B octet-stream`)
  await SP.findPiece({ serviceURL, pieceCid, poll: true })
  Trace.http('GET', `${serviceURL}/pdp/piece?pieceCid=${pieceCid}`, '→ parked')
  return pieceCid
}

/** The URL any HTTP client can GET, unauthenticated. */
export const pieceUrl = (serviceURL, pieceCid) =>
  Piece.createPieceUrlPDP({ cid: pieceCid.toString(), serviceURL })

export async function getPiece(serviceURL, pieceCid) {
  const url = pieceUrl(serviceURL, pieceCid)
  Trace.http('GET', url, '(no auth header, no chain call)')
  const res = await fetch(url)
  if (!res.ok) throw new Error(`GET piece failed: ${res.status} ${res.statusText}`)
  const blob = new Uint8Array(await res.arrayBuffer())
  Trace.say(`${res.status} ${res.statusText} · ${blob.length} B · ${res.headers.get('content-type')}`)
  return blob
}

/** createDataSet + addPieces in one signed call. */
export async function createDataSetWithPiece(client, opts) {
  const { statusUrl } = await SP.createDataSetAndAddPieces(client, {
    serviceURL: opts.serviceURL,
    payee: opts.payee,
    clientDataSetId: opts.clientDataSetId,
    metadata: opts.metadata,
    pieces: [{ pieceCid: opts.pieceCid }],
  })
  const created = await SP.waitForCreateDataSet({ statusUrl })
  await waitForPieceCount(client, created.dataSetId, 1n)
  return created
}

export async function addPiece(client, opts) {
  const dataSetId = BigInt(opts.dataSetId)
  const before = await pieceCount(client, dataSetId)
  const { txHash } = await SP.addPieces(client, {
    serviceURL: opts.serviceURL,
    dataSetId,
    clientDataSetId: BigInt(opts.clientDataSetId),
    pieces: [{ pieceCid: opts.pieceCid }],
  })
  await waitForPieceCount(client, dataSetId, before + 1n)
  return { txHash }
}

const pdp = (client) => ({ address: client.chain.contracts.pdp.address, abi: PDP_ABI })

/**
 * Reads go through an account-less client. A session key holds no FIL, and
 * Lotus rejects an eth_call whose `from` is an actor that does not exist yet.
 */
const readers = new WeakMap()
function reader(client) {
  if (!readers.has(client.chain)) {
    readers.set(client.chain, createClient({ chain: client.chain, transport: http() }).extend(publicActions))
  }
  return readers.get(client.chain)
}

export async function pieceCount(client, dataSetId) {
  const n = await reader(client).readContract({
    ...pdp(client),
    functionName: 'getNextPieceId',
    args: [BigInt(dataSetId)],
  })
  Trace.chain('PDPVerifier.getNextPieceId', [dataSetId], n)
  return n
}

async function waitForPieceCount(client, dataSetId, want, timeoutMs = 300_000) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    try {
      if ((await pieceCount(client, dataSetId)) >= want) return
    } catch {
      // devnet null rounds and RPC hiccups: keep polling
    }
    await new Promise((r) => setTimeout(r, 2000))
  }
  throw new Error(`timed out waiting for data set ${dataSetId} to reach ${want} piece(s)`)
}

/** Every live piece of a data set, straight from PDPVerifier — no SP, no local records. */
export async function listPiecesOnChain(client, dataSetId) {
  const next = await pieceCount(client, dataSetId)
  const read = reader(client)
  const out = []
  for (let id = 0n; id < next; id++) {
    const live = await read.readContract({ ...pdp(client), functionName: 'pieceLive', args: [BigInt(dataSetId), id] })
    if (!live) continue
    const raw = await read.readContract({ ...pdp(client), functionName: 'getPieceCid', args: [BigInt(dataSetId), id] })
    const cid = CID.decode(Buffer.from(raw.data.slice(2), 'hex'))
    Trace.chain('PDPVerifier.getPieceCid', [dataSetId, id], `${raw.data.slice(0, 20)}… → ${cid}`)
    out.push({ pieceId: id, pieceCid: cid.toString() })
  }
  return out
}
