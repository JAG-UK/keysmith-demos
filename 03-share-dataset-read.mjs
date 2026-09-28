/**
 * 3. Sharing read access to a whole dataset.
 *
 * One wrap of DK to the recipient's public key. Nothing is written on chain,
 * no piece is rewritten, and the recipient reads every piece in the dataset —
 * including the one the agent wrote in demo 2, and any piece written later.
 */
import { decrypt, parseEnvelope } from 'foc-encryption'
import { clientFor, devnet, load, need, note, readJson, save, step, writeJson } from './lib/devnet.mjs'
import * as Keys from './lib/keys.mjs'
import * as Trace from './lib/trace.mjs'
import { getPiece } from './lib/store.mjs'

const { chain, sp, users } = devnet()
const state = load()
const dataSetId = need(state, 'dataSetId', '01-create-dataset.mjs')
const clientDataSetId = BigInt(state.clientDataSetId)
const payer = users[0]
const recipient = users[1]
const payerClient = clientFor(payer.private_key_hex, chain)

step('Payer derives DK and wraps it to the recipient')
const { dk: DK } = await Keys.datasetKeys(payerClient.account, {
  chainId: chain.id,
  service: chain.contracts.fwss.address,
  payer: payer.evm_addr,
  clientDataSetId,
})
const grant = await Keys.wrapTo(Keys.publicKeyOf(recipient.private_key_hex), DK, {
  ...Keys.grantDescriptor(
    { chainId: chain.id, service: chain.contracts.fwss.address, payer: payer.evm_addr, clientDataSetId },
    'dataset'
  ),
  dataSetId: String(dataSetId),
})
const path = writeJson('grant-dataset.json', grant)
note(`grant → ${path} (${JSON.stringify(grant).length} B, deliver however you like)`)
note('nothing written on chain, no piece rewritten')

// ── recipient side ──────────────────────────────────────────────────────────
step('Recipient unwraps the grant with their own wallet key')
const recipientDK = await Keys.unwrapWith(recipient.private_key_hex, readJson('grant-dataset.json'))
note(`recipient ${recipient.evm_addr} now holds the dataset key`)

step('Recipient reads every piece, deriving each piece key from the envelope')
for (const [name, cid] of Object.entries(state.pieces)) {
  const blob = await getPiece(sp.serviceURL, cid)
  Trace.envelope(blob, `piece: ${name}`)
  const { appMetadata } = parseEnvelope(blob)
  const key = Keys.keyForEnvelope(recipientDK, appMetadata)
  const plaintext = new TextDecoder().decode(await decrypt(blob, key))
  note(`${name} (${cid.slice(0, 20)}…) → "${plaintext.slice(0, 48)}…"`)
}

step('A different wallet gets nothing')
try {
  await Keys.unwrapWith(users[2].private_key_hex, grant)
  console.error('    UNEXPECTED: unwrap succeeded')
} catch {
  note(`${users[2].evm_addr} cannot unwrap the grant — AES-GCM rejects it`)
}

save({ sharedWith: recipient.evm_addr })
console.log('\nOne key, every piece, forever. That is the whole cost of a dataset-wide share —')
console.log('and it cannot be taken back, which is why demo 4 exists.')
