/**
 * 2. Delegating writes to a session key.
 *
 * The agent never touches the payer's wallet, so it can never derive KK. It is
 * given a copy of KK wrapped to the session key it already holds (D2), which
 * travels with the session key itself (O1 default: no new state anywhere).
 *
 * Two authorities, deliberately separate:
 *   chain   — SessionKeyRegistry says this signer may call AddPieces
 *   crypto  — the wrapped KK says this signer may read and write this dataset
 */
import * as SessionKey from '@filoz/synapse-core/session-key'
import { encryptBytes } from './lib/fee.mjs'
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import { clientFor, devnet, load, need, note, onDevnet, save, step, writeJson } from './lib/devnet.mjs'
import * as Keys from './lib/keys.mjs'
import * as Trace from './lib/trace.mjs'
import { addPiece, putPiece } from './lib/store.mjs'

const { chain, sp, users } = devnet()
const state = load()
const dataSetId = need(state, 'dataSetId', '01-create-dataset.mjs')
const clientDataSetId = BigInt(state.clientDataSetId)
const keyspace = need(state, 'keyspace', '01-create-dataset.mjs')
const payer = users[0]
const payerClient = clientFor(payer.private_key_hex, chain)

// ── payer side ──────────────────────────────────────────────────────────────
step('Payer re-derives KK for this dataset (one signature, same as demo 1)')
const { kk: KK } = await Keys.keyspaceKeys(payerClient.account, { owner: payer.evm_addr, keyspace })
note(`KK = ${Keys.hex(KK).slice(0, 18)}…`)

step('Mint a session key and authorise it on chain for AddPieces only')
const sessionPrivateKey = generatePrivateKey()
const session = privateKeyToAccount(sessionPrivateKey)
const expiresAt = BigInt(Math.floor(Date.now() / 1000) + 3600)
const { event } = await onDevnet(() =>
  SessionKey.loginSync(payerClient, {
    address: session.address,
    permissions: [SessionKey.AddPiecesPermission],
    expiresAt,
    onHash: (h) => note(`login tx ${h}`),
  })
)
note(`registry now authorises ${event.args.identity} → ${session.address}`)

step('Wrap KK to the session key, and ship it with the key (D2 / O1)')
// dataSetId rides alongside the grant: informational, outside the authenticated descriptor.
const grant = {
  ...(await Keys.wrapTo(Keys.publicKeyOf(sessionPrivateKey), KK, Keys.grantDescriptor({ owner: payer.evm_addr, keyspace }, 'keyspace'))),
  dataSetId: String(dataSetId),
}
const path = writeJson('agent-credentials.json', { sessionPrivateKey, grant: Keys.hex(Keys.encodeGrant(grant)) })
note(`agent credentials → ${path}`)
note('the wrapped key is useless without the session private key, so it needs no protection of its own')

// ── agent side: a different process, with no access to the payer wallet ─────
step('Agent unwraps KK with the key it already had')
const agentClient = clientFor(sessionPrivateKey, chain)
const agentKK = await Keys.unwrapWith(sessionPrivateKey, grant)
note(`agent KK matches payer KK: ${Keys.hex(agentKK) === Keys.hex(KK)}`)

step('Agent derives a fresh piece key and encrypts')
const salt = Keys.newSalt()
const target = Keys.writeTarget(grant, agentKK) // keyspace and scope, from the grant alone
const meta = Keys.appMetadata({ ...target.ref, scope: target.scope, salt })
const plaintext = new TextEncoder().encode(
  `agent report, written by ${session.address}. ${'='.repeat(200)}`
)
const ciphertext = await encryptBytes(plaintext, Keys.pieceKey(target.key, salt), meta)
Trace.envelope(ciphertext, 'agent-written piece')
note(`envelope ${ciphertext.length} B`)

step('Agent PUTs to Curio and calls addPieces, signing as the session key')
const pieceCid = await putPiece(sp.serviceURL, ciphertext)
const added = await addPiece(agentClient, {
  serviceURL: sp.serviceURL,
  dataSetId,
  clientDataSetId,
  pieceCid,
})
note(`pieceCid ${pieceCid}`)
note(`added by session key · tx ${added.txHash}`)

save({ pieces: { ...state.pieces, report: pieceCid.toString() }, sessionAddress: session.address })
console.log('\nThe payer signed nothing for this write. revoke() ends the chain half at once;')
console.log('the key half is permanent, which is why an agent that only writes should hold no key at all.')
