/**
 * 4. Sharing read access by scope, and by single piece.
 *
 * A scope is an access label — `agent-memory`, `super-secret` — one HKDF step
 * below the keyspace key: RK = HKDF(KK, "scope" ‖ name). Labelling a piece with
 * a scope costs nothing extra, and sharing the scope hands over one key that
 * opens everything carrying that label, and the scopes beneath it.
 *
 * These two are siblings, so neither opens the other: a scope reaches down its
 * own branch of the tree, never across or up. Each piece carries at most one
 * scope. The label travels in the envelope in clear, which for access labels
 * leaks classification — prefer opaque scope ids.
 *
 * A piece grant is narrower still: one piece's key, named by the piece's salt.
 * It opens that piece and nothing else, and it can never be used to write.
 */
import { decryptBytes, encryptBytes, readEnvelope } from './lib/fee.mjs'
import { clientFor, devnet, load, need, note, readBytes, save, step, writeBytes } from './lib/devnet.mjs'
import * as Keys from './lib/keys.mjs'
import * as Trace from './lib/trace.mjs'
import { addPiece, getPiece, putPiece } from './lib/store.mjs'

const { chain, sp, users } = devnet()
const state = load()
const dataSetId = need(state, 'dataSetId', '01-create-dataset.mjs')
const clientDataSetId = BigInt(state.clientDataSetId)
const keyspace = need(state, 'keyspace', '01-create-dataset.mjs')
const payer = users[0]
const agent = users[2]
const auditor = users[1]
const payerClient = clientFor(payer.private_key_hex, chain)

step('Payer derives KK, then two scope keys')
const { kk: KK } = await Keys.keyspaceKeys(payerClient.account, { owner: payer.evm_addr, keyspace })
const scopes = { 'agent-memory': Keys.scopeKey(KK, 'agent-memory'), 'super-secret': Keys.scopeKey(KK, 'super-secret') }
note(`RK(agent-memory) = ${Keys.hex(scopes['agent-memory']).slice(0, 18)}…`)
note(`RK(super-secret) = ${Keys.hex(scopes['super-secret']).slice(0, 18)}…  (unrelated: siblings, neither opens the other)`)

step('Write one piece labelled with each scope')
const written = {}
const envelopes = {}
for (const [scope, node] of Object.entries(scopes)) {
  const salt = Keys.newSalt()
  const meta = Keys.appMetadata({ owner: payer.evm_addr, keyspace, scope, salt })
  envelopes[scope] = meta
  const body = new TextEncoder().encode(`${scope}: notes for 2026-09. ${'#'.repeat(200)}`)
  const ciphertext = await encryptBytes(body, Keys.pieceKey(node, salt), meta)
  const pieceCid = await putPiece(sp.serviceURL, ciphertext)
  const added = await addPiece(payerClient, {
    serviceURL: sp.serviceURL,
    dataSetId,
    clientDataSetId,
    pieceCid,
  })
  written[scope] = pieceCid.toString()
  note(`${scope}: ${pieceCid} · tx ${added.txHash}`)
}

step('Share the agent-memory scope only, with an agent')
// dataSetId rides alongside the grant: informational, outside the authenticated descriptor.
const grant = {
  ...(await Keys.wrapTo(Keys.publicKeyOf(agent.private_key_hex), scopes['agent-memory'], Keys.grantDescriptor({ owner: payer.evm_addr, keyspace }, 'scope:agent-memory'))),
  dataSetId: String(dataSetId),
}
note(`grant → ${writeBytes('grant-scope-agent-memory.cbor', Keys.encodeGrant(grant))}`)

// ── agent side ────────────────────────────────────────────────────────────
step('Agent unwraps the scope key and reads what carries that scope')
const RK = await Keys.unwrapWith(agent.private_key_hex, readBytes('grant-scope-agent-memory.cbor'))
for (const [scope, cid] of Object.entries(written)) {
  const blob = await getPiece(sp.serviceURL, cid)
  Trace.envelope(blob, `piece labelled ${scope}`)
  const { appMetadata } = await readEnvelope(blob)
  try {
    const key = Keys.keyForEnvelope(RK, appMetadata, Keys.holdingOf(grant))
    const text = new TextDecoder().decode(await decryptBytes(blob, key))
    note(`${scope}: readable → "${text.slice(0, 40)}…"`)
  } catch (err) {
    note(`${scope}: NOT readable → ${err.constructor.name} (${appMetadata['foc/scope']} needs its own scope key)`)
  }
}

// ── payer again: one piece, nothing more ───────────────────────────────────
step('Share one super-secret piece, and nothing else, with an auditor')
const secret = envelopes['super-secret']
const PK = Keys.keyForEnvelope(KK, secret)
// Bound to the salt; the CID rides alongside as a locator, outside the authenticated descriptor.
const pieceGrant = {
  ...(await Keys.wrapTo(
    Keys.publicKeyOf(auditor.private_key_hex),
    PK,
    Keys.grantDescriptor({ owner: payer.evm_addr, keyspace }, Keys.pieceNode(secret))
  )),
  pieceCid: written['super-secret'],
}
note(`node ${pieceGrant.node}  (bound to the piece's salt: its key is HKDF(RK, "piece" ‖ salt))`)
note(`pieceCid ${pieceGrant.pieceCid}  (where to fetch it; a wrong CID just leads to a salt that doesn't match)`)
note(`grant → ${writeBytes('grant-piece-super-secret.cbor', Keys.encodeGrant(pieceGrant))}`)

// ── auditor side ──────────────────────────────────────────────────────────
step('Auditor fetches the piece the grant points to, then tries the other one too')
const delivered = Keys.decodeGrant(readBytes('grant-piece-super-secret.cbor')) // pieceCid survives, unauthenticated
const auditorKey = await Keys.unwrapWith(auditor.private_key_hex, delivered)
const tryOrder = [delivered.pieceCid, ...Object.values(written).filter((cid) => cid !== delivered.pieceCid)]
for (const cid of tryOrder) {
  const scope = Object.keys(written).find((r) => written[r] === cid)
  const blob = await getPiece(sp.serviceURL, cid)
  const { appMetadata } = await readEnvelope(blob)
  try {
    const key = Keys.keyForEnvelope(auditorKey, appMetadata, Keys.holdingOf(delivered))
    const text = new TextDecoder().decode(await decryptBytes(blob, key))
    note(`${scope} piece: readable → "${text.slice(0, 40)}…"`)
  } catch (err) {
    note(`${scope} piece: NOT readable → ${err.message}`)
  }
}
try {
  Keys.writeTarget(pieceGrant, auditorKey)
  note('write: allowed (this would be a bug)')
} catch (err) {
  note(`write: refused → ${err.message}`)
}

save({ pieces: { ...state.pieces, ...written } })
console.log('\nThe agent holds one key for one scope; the auditor, one key for one piece.')
console.log('The payer still reads everything, because every key derives from the KK the wallet reproduces on demand.')
