/**
 * 2. Delegating writes to a session key.
 *
 * The agent never touches the payer's wallet, so it can never derive DK. It is
 * given a copy of DK wrapped to the session key it already holds (D2), which
 * travels with the session key itself (O1 default: no new state anywhere).
 *
 * Two authorities, deliberately separate:
 *   chain   — SessionKeyRegistry says this signer may call AddPieces
 *   crypto  — the wrapped DK says this signer may read and write this dataset
 */
import * as SessionKey from '@filoz/synapse-core/session-key'
import { CoseAlgorithm, encrypt } from 'foc-encryption'
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import { clientFor, devnet, load, need, note, onDevnet, save, step, writeJson } from './lib/devnet.mjs'
import * as Keys from './lib/keys.mjs'
import * as Trace from './lib/trace.mjs'
import { addPiece, putPiece } from './lib/store.mjs'

const { chain, sp, users } = devnet()
const state = load()
const dataSetId = need(state, 'dataSetId', '01-create-dataset.mjs')
const clientDataSetId = BigInt(state.clientDataSetId)
const payer = users[0]
const payerClient = clientFor(payer.private_key_hex, chain)

// ── payer side ──────────────────────────────────────────────────────────────
step('Payer re-derives DK for this dataset (one signature, same as demo 1)')
const { dk: DK } = await Keys.datasetKeys(payerClient.account, {
  chainId: chain.id,
  service: chain.contracts.fwss.address,
  payer: payer.evm_addr,
  clientDataSetId,
})
note(`DK = ${Keys.hex(DK).slice(0, 18)}…`)

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

step('Wrap DK to the session key, and ship it with the key (D2 / O1)')
const grant = await Keys.wrapTo(Keys.publicKeyOf(sessionPrivateKey), DK, {
  ...Keys.grantDescriptor(
    { chainId: chain.id, service: chain.contracts.fwss.address, payer: payer.evm_addr, clientDataSetId },
    'dataset'
  ),
  dataSetId: String(dataSetId),
})
const path = writeJson('agent-credentials.json', { sessionPrivateKey, grant })
note(`agent credentials → ${path}`)
note('the wrapped key is useless without the session private key, so it needs no protection of its own')

// ── agent side: a different process, with no access to the payer wallet ─────
step('Agent unwraps DK with the key it already had')
const agentClient = clientFor(sessionPrivateKey, chain)
const agentDK = await Keys.unwrapWith(sessionPrivateKey, grant)
note(`agent DK matches payer DK: ${Keys.hex(agentDK) === Keys.hex(DK)}`)

step('Agent derives a fresh piece key and encrypts')
const salt = Keys.newSalt()
const meta = Keys.appMetadata({ clientDataSetId, salt })
const plaintext = new TextEncoder().encode(
  `agent report, written by ${session.address}. ${'='.repeat(200)}`
)
const ciphertext = await encrypt(plaintext, Keys.pieceKey(agentDK, salt), {
  algorithm: CoseAlgorithm.CHUNKED_AES_256_GCM_STREAM,
  appMetadata: meta,
})
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
