/** Offline checks for lib/keys.mjs — no devnet, no framework: `node lib/keys.test.mjs`. */
import assert from 'node:assert/strict'
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import * as Keys from './keys.mjs'

const account = privateKeyToAccount(generatePrivateKey())
const message = Keys.datasetKeyMessage({
  chainId: 31415926,
  service: '0xfcDDd1E5BC2658fB7483B8e2fa72d8368756F5A3',
  payer: account.address,
  clientDataSetId: 42n,
})

// Same wallet + same dataset → same key, every time. This is the whole recovery story.
const secret = await Keys.datasetSecret(account, message)
assert.equal(
  Keys.hex(Keys.datasetKey(secret)),
  Keys.hex(Keys.datasetKey(await Keys.datasetSecret(account, message)))
)

// A different dataset under the same wallet is a different key.
const other = await Keys.datasetSecret(account, { ...message, clientDataSetId: 43n })
assert.notEqual(Keys.hex(Keys.datasetKey(secret)), Keys.hex(Keys.datasetKey(other)))

// The commitment is derived from the signature, not the key, and is stable.
assert.equal(Keys.commitment(secret), Keys.commitment(secret))
assert.notEqual(Keys.commitment(secret), Keys.commitment(other))
assert.match(Keys.commitment(secret), /^v1\.[0-9a-f]{32}$/)

// Derivation is one-way and domain-separated: siblings never collide.
const DK = Keys.datasetKey(secret)
const invoices = Keys.scopeKey(DK, 'invoices')
const payroll = Keys.scopeKey(DK, 'payroll')
assert.notEqual(Keys.hex(invoices), Keys.hex(payroll))
const salt = Keys.newSalt()
assert.notEqual(Keys.hex(Keys.pieceKey(invoices, salt)), Keys.hex(Keys.pieceKey(payroll, salt)))
assert.notEqual(Keys.hex(Keys.pieceKey(DK, salt)), Keys.hex(Keys.pieceKey(DK, Keys.newSalt())))

// A dataset-key holder walks down to a scoped piece; a scope-key holder is already there.
const meta = Keys.appMetadata({ clientDataSetId: 42n, scope: 'invoices', salt })
assert.equal(
  Keys.hex(Keys.keyForEnvelope(DK, meta)),
  Keys.hex(Keys.keyForEnvelope(invoices, meta, 'scope'))
)

// Wrapping: only the named recipient opens it.
const recipient = generatePrivateKey()
const stranger = generatePrivateKey()
const descriptor = { v: 1, node: 'dataset', clientDataSetId: '42' }
const grant = await Keys.wrapTo(Keys.publicKeyOf(recipient), DK, descriptor)
assert.equal(Keys.hex(await Keys.unwrapWith(recipient, grant)), Keys.hex(DK))
await assert.rejects(() => Keys.unwrapWith(stranger, grant))

// The descriptor is authenticated: relabelling a grant breaks it.
await assert.rejects(() => Keys.unwrapWith(recipient, { ...grant, node: 'scope:payroll' }))

// A randomising signer is refused before any data depends on the key.
let calls = 0
const flaky = { signTypedData: async () => `0x${String(++calls).padStart(130, '0')}` }
await assert.rejects(() => Keys.datasetSecret(flaky, message), /not deterministic/)

console.log('ok — 13 checks passed')
