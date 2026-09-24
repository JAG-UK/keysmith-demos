/**
 * 4. Sharing read access to a subset of a dataset.
 *
 * A scope is one HKDF step below DK: SK = HKDF(DK, "scope" ‖ name). Writing a
 * piece into a scope costs nothing extra, and sharing that scope hands over
 * one key that opens that section and nothing else.
 *
 * Note the honest limit: the scope NAME travels in the envelope's app_metadata
 * in clear, because the reader needs it to derive. The bytes stay secret; the
 * label does not. Sealing labels is possible (see ../../keysmith), and costs
 * an ECDH per level.
 */
import { CoseAlgorithm, decrypt, encrypt, parseEnvelope } from 'foc-encryption'
import { clientFor, devnet, load, need, note, save, step, writeJson } from './lib/devnet.mjs'
import * as Keys from './lib/keys.mjs'
import * as Trace from './lib/trace.mjs'
import { addPiece, getPiece, putPiece } from './lib/store.mjs'

const { chain, sp, users } = devnet()
const state = load()
const dataSetId = need(state, 'dataSetId', '01-create-dataset.mjs')
const clientDataSetId = BigInt(state.clientDataSetId)
const payer = users[0]
const auditor = users[2]
const payerClient = clientFor(payer.private_key_hex, chain)

step('Payer derives DK, then two scope keys')
const secret = await Keys.datasetSecret(
  payerClient.account,
  Keys.datasetKeyMessage({
    chainId: chain.id,
    service: chain.contracts.fwss.address,
    payer: payer.evm_addr,
    clientDataSetId,
  })
)
const DK = Keys.datasetKey(secret)
const scopes = { invoices: Keys.scopeKey(DK, 'invoices'), payroll: Keys.scopeKey(DK, 'payroll') }
note(`SK(invoices) = ${Keys.hex(scopes.invoices).slice(0, 18)}…`)
note(`SK(payroll)  = ${Keys.hex(scopes.payroll).slice(0, 18)}…  (unrelated)`)

step('Write one piece into each scope')
const written = {}
for (const [scope, node] of Object.entries(scopes)) {
  const salt = Keys.newSalt()
  const meta = Keys.appMetadata({ clientDataSetId, scope, salt })
  const body = new TextEncoder().encode(`${scope} for 2026-09 — confidential. ${'#'.repeat(200)}`)
  const ciphertext = await encrypt(body, Keys.pieceKey(node, salt), {
    algorithm: CoseAlgorithm.CHUNKED_AES_256_GCM_STREAM,
    appMetadata: meta,
  })
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

step('Share the invoices scope only')
const grant = await Keys.wrapTo(Keys.publicKeyOf(auditor.private_key_hex), scopes.invoices, {
  v: 1,
  node: 'scope:invoices',
  chainId: chain.id,
  service: chain.contracts.fwss.address,
  payer: payer.evm_addr,
  clientDataSetId: clientDataSetId.toString(),
  dataSetId: String(dataSetId),
})
note(`grant → ${writeJson('grant-scope-invoices.json', grant)}`)

// ── auditor side ────────────────────────────────────────────────────────────
step('Auditor unwraps the scope key and reads what it covers')
const SK = await Keys.unwrapWith(auditor.private_key_hex, grant)
for (const [scope, cid] of Object.entries(written)) {
  const blob = await getPiece(sp.serviceURL, cid)
  Trace.envelope(blob, `piece in scope ${scope}`)
  const { appMetadata } = parseEnvelope(blob)
  try {
    const key = Keys.keyForEnvelope(SK, appMetadata, 'scope')
    const text = new TextDecoder().decode(await decrypt(blob, key))
    note(`${scope}: readable → "${text.slice(0, 40)}…"`)
  } catch (err) {
    note(`${scope}: NOT readable → ${err.constructor.name} (${appMetadata['foc/scope']} needs its own key)`)
  }
}

save({ pieces: { ...state.pieces, ...written } })
console.log('\nThe auditor holds one key for one section. The payer still reads everything,')
console.log('because both scopes hang below the DK the wallet reproduces on demand.')
