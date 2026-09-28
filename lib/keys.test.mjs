/** Offline checks for lib/keys.mjs — no devnet, no framework: `node lib/keys.test.mjs`. */
import assert from 'node:assert/strict'
import { createECDH } from 'node:crypto'
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import * as Keys from './keys.mjs'

const account = privateKeyToAccount(generatePrivateKey())
const ref = {
  chainId: 31415926,
  service: '0xfcDDd1E5BC2658fB7483B8e2fa72d8368756F5A3',
  payer: account.address,
  clientDataSetId: 42n,
}
let checks = 0
const ok = (fn) => {
  fn()
  checks++
}
const rejects = async (fn, re) => {
  await assert.rejects(fn, re)
  checks++
}

// Same wallet + same dataset → same key, every time. This is the whole recovery story.
const a = await Keys.datasetKeys(account, ref)
const b = await Keys.datasetKeys(account, ref)
ok(() => assert.deepEqual(a.dk, b.dk))
ok(() => assert.equal(a.commitment, b.commitment))
ok(() => assert.match(a.commitment, /^v1\.[0-9a-f]{32}$/))

// A different dataset under the same wallet is a different key and a different commitment.
const other = await Keys.datasetKeys(account, { ...ref, clientDataSetId: 43n })
ok(() => assert.notDeepEqual(a.dk, other.dk))
ok(() => assert.notEqual(a.commitment, other.commitment))

// First use signs twice; after that, once.
let calls = 0
const counted = { signTypedData: (args) => (calls++, account.signTypedData(args)) }
await Keys.datasetKeys(counted, ref)
ok(() => assert.equal(calls, 2))
await Keys.datasetKeys(counted, ref)
ok(() => assert.equal(calls, 3))

// A randomising signer is refused before any data depends on the key …
let n = 0
const r = `0x${'01'.repeat(32)}`
const flaky = { signTypedData: async () => `${r}${(++n).toString(16).padStart(64, '0')}1b` }
await rejects(() => Keys.datasetKeys(flaky, ref), /not deterministic/)

// … and so is anything that is not a plain ECDSA signature: an ABI-encoded blob has no secret in its first 64 bytes.
const abiLike = { signTypedData: async () => `0x${'20'.padStart(64, '0')}${'41'.padStart(64, '0')}${'ab'.repeat(65)}` }
await rejects(() => Keys.datasetKeys(abiLike, ref), /64- or 65-byte/)
ok(() => assert.throws(() => Keys.lowSrs(`${r}${'00'.repeat(32)}1b`), /\[1, n−1\]/))

// Derivation is one-way and domain-separated: siblings never collide.
const DK = a.dk
const invoices = Keys.scopeKey(DK, 'invoices')
const payroll = Keys.scopeKey(DK, 'payroll')
ok(() => assert.notDeepEqual(invoices, payroll))
const salt = Keys.newSalt()
ok(() => assert.notDeepEqual(Keys.pieceKey(invoices, salt), Keys.pieceKey(payroll, salt)))
ok(() => assert.notDeepEqual(Keys.pieceKey(DK, salt), Keys.pieceKey(DK, Keys.newSalt())))

// A dataset-key holder walks down to a scoped piece; a scope-key holder is already there.
const meta = Keys.appMetadata({ clientDataSetId: 42n, scope: 'invoices', salt })
ok(() => assert.deepEqual(Keys.keyForEnvelope(DK, meta), Keys.keyForEnvelope(invoices, meta, 'scope')))
ok(() =>
  assert.throws(() => Keys.keyForEnvelope(invoices, Keys.appMetadata({ clientDataSetId: 42n, salt }), 'scope'), /not in a scope/)
)

// The key-agreement key is derived from the signing key, not the signing key itself.
const recipient = generatePrivateKey()
const signing = createECDH('secp256k1')
signing.setPrivateKey(Keys.unhex(recipient))
ok(() => assert.notEqual(Keys.publicKeyOf(recipient), Keys.hex(signing.getPublicKey())))
ok(() => assert.equal(Keys.publicKeyOf(recipient), Keys.publicKeyOf(recipient)))

// Wrapping: only the named recipient opens it.
const descriptor = Keys.grantDescriptor(ref, 'dataset')
const grant = await Keys.wrapTo(Keys.publicKeyOf(recipient), DK, descriptor)
assert.deepEqual(await Keys.unwrapWith(recipient, grant), DK)
checks++
await rejects(() => Keys.unwrapWith(generatePrivateKey(), grant))

// The descriptor is authenticated: relabelling a grant breaks it.
await rejects(() => Keys.unwrapWith(recipient, { ...grant, node: 'scope:payroll' }))
await rejects(() => Keys.unwrapWith(recipient, { ...grant, clientDataSetId: '0x2b' }))
await rejects(() => Keys.unwrapWith(recipient, { ...grant, v: 2 }), /version/)

// But spelling is not: checksummed and lowercase addresses are one grant, and extras are ignored.
const byHand = { ...descriptor, service: ref.service, payer: account.address, clientDataSetId: '0x2A' }
assert.deepEqual(await Keys.unwrapWith(recipient, await Keys.wrapTo(Keys.publicKeyOf(recipient), DK, byHand)), DK)
checks++
assert.deepEqual(await Keys.unwrapWith(recipient, { ...grant, dataSetId: '7' }), DK)
checks++
ok(() => assert.equal(descriptor.payer, account.address.toLowerCase()))

// Canonical forms: one spelling per value, produced by the library, re-derived on the way in.
ok(() => assert.deepEqual(Keys.scopeKey(DK, 'caf\u00e9'), Keys.scopeKey(DK, 'cafe\u0301')))
ok(() => assert.notDeepEqual(Keys.scopeKey(DK, 'Invoices'), Keys.scopeKey(DK, 'invoices')))
ok(() => assert.throws(() => Keys.scopeKey(DK, ' invoices'), /whitespace/))
ok(() => assert.deepEqual(Keys.pieceKey(DK, '0x00ABCD'), Keys.pieceKey(DK, '0x00abcd')))
ok(() => assert.equal(Keys.grantDescriptor({ ...ref, epoch: 3 }, 'scope:cafe\u0301').node, 'scope:caf\u00e9'))
ok(() => assert.equal(Keys.grantDescriptor(ref, 'dataset').epoch, 0))
const scoped = await Keys.wrapTo(Keys.publicKeyOf(recipient), invoices, Keys.grantDescriptor(ref, 'scope:invoices'))
const mangled = { ...scoped, chainId: '31415926', epoch: '0', clientDataSetId: '0x002A' }
assert.deepEqual(await Keys.unwrapWith(recipient, mangled), invoices)
checks++
await rejects(() => Keys.unwrapWith(recipient, { ...scoped, epoch: 1 }))

console.log(`ok — ${checks} checks passed`)
