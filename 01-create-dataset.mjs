/**
 * 1. Where a dataset's encryption key comes from.
 *
 * The payer signs one EIP-712 message, and that signature is the only secret
 * in the system. Everything else is derived. The dataset does not exist yet
 * when the key is made: the key is bound to clientDataSetId, which the client
 * chooses, so the first piece can be encrypted before any chain call.
 *
 * Layers: keys.mjs derives · FEE encrypts · Curio stores · FWSS records.
 */
import { Synapse } from '@filoz/synapse-sdk'
import { CoseAlgorithm, encrypt } from 'foc-encryption'
import { formatUnits, http, parseUnits } from 'viem'
import { clientFor, devnet, note, save, step } from './lib/devnet.mjs'
import * as Keys from './lib/keys.mjs'
import * as Trace from './lib/trace.mjs'
import { createDataSetWithPiece, putPiece } from './lib/store.mjs'

const { chain, sp, users, runId } = devnet()
const payer = users[0]
const client = clientFor(payer.private_key_hex, chain)
const plaintext = new TextEncoder().encode(
  `invoice 2026-09: 42 FIL. devnet run ${runId}. ${'-'.repeat(200)}`
)

console.log(`devnet ${runId} · payer ${payer.evm_addr} · SP ${sp.serviceURL}`)

step('Pick clientDataSetId (client-chosen, before the dataset exists)')
const clientDataSetId = Keys.newClientDataSetId()
note(`clientDataSetId = ${clientDataSetId}`)

step('Sign DatasetKey once — twice, and compare (D3a)')
const message = Keys.datasetKeyMessage({
  chainId: chain.id,
  service: chain.contracts.fwss.address,
  payer: payer.evm_addr,
  clientDataSetId,
})
const secret = await Keys.datasetSecret(client.account, message)
const DK = Keys.datasetKey(secret)
const kc = Keys.commitment(secret)
note(`signature is deterministic; DK = ${Keys.hex(DK).slice(0, 18)}…`)
note(`foc/kc = ${kc}   (non-secret commitment, D3b)`)

step('Derive a key for this piece, and encrypt with FEE')
const salt = Keys.newSalt()
const meta = Keys.appMetadata({ clientDataSetId, salt })
const ciphertext = await encrypt(plaintext, Keys.pieceKey(DK, salt), {
  algorithm: CoseAlgorithm.CHUNKED_AES_256_GCM_STREAM,
  appMetadata: meta,
})
Trace.envelope(ciphertext, 'the piece as it will be stored')
note(`plaintext ${plaintext.length} B → envelope ${ciphertext.length} B`)
note(`app_metadata: ${JSON.stringify(meta)}`)

step('Fund the rails (ordinary Synapse payment setup, nothing to do with keys)')
const synapse = Synapse.create({ chain, transport: http(), account: client.account })
const account = await synapse.payments.accountInfo()
note(`available ${formatUnits(account.availableFunds, 18)} USDFC`)
// Each new data set opens its own PDP rail and needs its own lockup, so top up
// when the balance is thin rather than relying on an estimate for existing rails.
if (account.availableFunds < parseUnits('2', 18)) {
  // deposit(), not fundSync(): fundSync takes the EIP-2612 permit path and
  // devnet's MockUSDFC has no nonces().
  const deposit = await synapse.payments.deposit({ amount: parseUnits('10', 18) })
  const approval = await synapse.payments.approveService({})
  note(`deposited 10 USDFC · tx ${deposit}`)
  note(`approved FWSS as operator · tx ${approval}`)
  await client.waitForTransactionReceipt({ hash: approval })
} else {
  note('already funded')
}

step('PUT the ciphertext to Curio')
const pieceCid = await putPiece(sp.serviceURL, ciphertext)
note(`pieceCid ${pieceCid} — Curio never saw a key`)

step('createDataSet + addPieces, carrying foc/kc in metadata')
const result = await createDataSetWithPiece(client, {
  serviceURL: sp.serviceURL,
  payee: sp.payee,
  clientDataSetId,
  metadata: { 'foc/kc': kc },
  pieceCid,
})
note(`dataSetId ${result.dataSetId} · tx ${result.confirmedTxHash ?? result.createMessageHash}`)
note('piece confirmed live on PDPVerifier')

save({
  clientDataSetId: clientDataSetId.toString(),
  dataSetId: result.dataSetId.toString(),
  payer: payer.evm_addr,
  kc,
  pieces: { invoice: pieceCid.toString() },
})
console.log('\nStored. The only secret is a signature the payer can reproduce at will.')
