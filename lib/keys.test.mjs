/** Offline checks for lib/keys.mjs — no devnet, no framework: `node lib/keys.test.mjs`. */
import assert from 'node:assert/strict'
import { createECDH } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import * as Keys from './keys.mjs'

const account = privateKeyToAccount(generatePrivateKey())
const ref = { owner: account.address, keyspace: '0x00112233445566778899aabbccddeeff' }
let checks = 0
const ok = (fn) => {
  fn()
  checks++
}
const rejects = async (fn, re) => {
  await assert.rejects(fn, re)
  checks++
}

// Same wallet + same keyspace → same key, every time. This is the whole recovery story.
const a = await Keys.keyspaceKeys(account, ref)
const b = await Keys.keyspaceKeys(account, ref)
ok(() => assert.deepEqual(a.kk, b.kk))
ok(() => assert.equal(a.commitment, Keys.commitment(a.kk)))
ok(() => assert.match(a.commitment, /^v1\.[0-9a-f]{32}$/))
const other = await Keys.keyspaceKeys(account, { ...ref, keyspace: Keys.newKeyspace() })
ok(() => assert.notDeepEqual(a.kk, other.kk))

// Nothing about chains, contracts or datasets is signed.
ok(() => assert.deepEqual(Object.keys(Keys.keyspaceKeyMessage(ref)).sort(), ['keyspace', 'owner']))

// A new keyspace signs twice; an existing one, checked against its commitment, once.
let calls = 0
const counted = { signTypedData: (args) => (calls++, account.signTypedData(args)) }
await Keys.keyspaceKeys(counted, ref)
ok(() => assert.equal(calls, 2))
await Keys.keyspaceKeys(counted, ref, { commitment: a.commitment })
ok(() => assert.equal(calls, 3))
await rejects(() => Keys.keyspaceKeys(account, ref, { commitment: other.commitment }), /does not match the recorded commitment/)

// Randomising signers and non-ECDSA blobs are refused.
let n = 0
const r = `0x${'01'.repeat(32)}`
const flaky = { signTypedData: async () => `${r}${(++n).toString(16).padStart(64, '0')}1b` }
await rejects(() => Keys.keyspaceKeys(flaky, ref), /not deterministic/)
const abiLike = { signTypedData: async () => `0x${'20'.padStart(64, '0')}${'41'.padStart(64, '0')}${'ab'.repeat(65)}` }
await rejects(() => Keys.keyspaceKeys(abiLike, ref), /64- or 65-byte/)

// Sibling scopes are unrelated; a keyspace holder and a scope holder reach the same piece key.
const KK = a.kk
const salt = Keys.newSalt()
ok(() => assert.notDeepEqual(Keys.scopeKey(KK, 'super-secret'), Keys.scopeKey(KK, 'secret')))
const labelled = Keys.appMetadata({ ...ref, scope: 'agent-memory', salt })
ok(() =>
  assert.deepEqual(Keys.keyForEnvelope(KK, labelled), Keys.keyForEnvelope(Keys.scopeKey(KK, 'agent-memory'), labelled, { scope: 'agent-memory' }))
)
const unlabelled = Keys.appMetadata({ ...ref, salt })
ok(() => assert.equal(unlabelled['foc/own'], ref.owner.toLowerCase()))
ok(() => assert.deepEqual(Keys.keyForEnvelope(KK, { ...unlabelled, 'foc/own': '0x' + '00'.repeat(20) }), Keys.keyForEnvelope(KK, unlabelled)))
ok(() => assert.throws(() => Keys.keyForEnvelope(Keys.scopeKey(KK, 'agent-memory'), unlabelled, { scope: 'agent-memory' }), /does not contain/))

// Location independence: the envelope alone names the key, wherever the copy is found.
ok(() => assert.deepEqual(Keys.keyForEnvelope(KK, JSON.parse(JSON.stringify(unlabelled))), Keys.pieceKey(KK, salt)))
ok(() => assert.throws(() => Keys.keyForEnvelope(KK, { 'foc/v': 1, 'foc/cds': '0x2a', 'foc/salt': salt }), /format 1 with a keyspace/))

// Canonical forms.
ok(() => assert.deepEqual(Keys.scopeKey(KK, 'café'), Keys.scopeKey(KK, 'café')))
ok(() => assert.throws(() => Keys.scopeKey(KK, ' secret'), /whitespace/))
ok(() => assert.deepEqual(Keys.pieceKey(KK, '0x00ABCD'), Keys.pieceKey(KK, '0x00abcd')))
ok(() => assert.throws(() => Keys.keyspaceId('0x2a'), /16 bytes/))

// The key-agreement key is derived from the signing key, not the signing key itself.
const recipient = generatePrivateKey()
const signing = createECDH('secp256k1')
signing.setPrivateKey(Keys.unhex(recipient))
ok(() => assert.notEqual(Keys.publicKeyOf(recipient), Keys.hex(signing.getPublicKey())))

// Grants: only the named recipient opens; relabelling breaks it; spelling and extras don't.
const grant = await Keys.wrapTo(Keys.publicKeyOf(recipient), KK, Keys.grantDescriptor(ref, 'keyspace'))
assert.deepEqual(await Keys.unwrapWith(recipient, grant), KK)
checks++
await rejects(() => Keys.unwrapWith(generatePrivateKey(), grant))
await rejects(() => Keys.unwrapWith(recipient, { ...grant, node: 'scope:super-secret' }))
await rejects(() => Keys.unwrapWith(recipient, { ...grant, v: 2 }), /version/)
const rk = Keys.scopeKey(KK, 'agent-memory')
const scopeGrant = await Keys.wrapTo(Keys.publicKeyOf(recipient), rk, Keys.grantDescriptor(ref, 'scope:agent-memory'))
const up = (h) => h.toUpperCase().replace('0X', '0x')
const mangled = { ...scopeGrant, owner: up(scopeGrant.owner), keyspace: up(scopeGrant.keyspace), dataSetId: '7' }
assert.deepEqual(await Keys.unwrapWith(recipient, mangled), rk)
checks++
ok(() => assert.deepEqual(Keys.holdingOf(scopeGrant), { scope: 'agent-memory' }))

// The scope tree: a scope opens itself and everything beneath it, nothing above or beside it.
const deep = Keys.appMetadata({ ...ref, scope: 'super-secret/secret', salt })
ok(() => assert.deepEqual(Keys.keyForEnvelope(Keys.scopeKey(KK, 'super-secret'), deep, { scope: 'super-secret' }), Keys.keyForEnvelope(KK, deep)))
const top = Keys.appMetadata({ ...ref, scope: 'super-secret', salt })
ok(() => assert.throws(() => Keys.keyForEnvelope(Keys.scopeKey(KK, 'super-secret/secret'), top, { scope: 'super-secret/secret' }), /does not contain/))
ok(() => assert.notDeepEqual(Keys.scopeKey(KK, 'secret'), Keys.scopeKey(KK, 'super-secret/secret')))

// writeTarget: a delegate writes only inside its grant's subtree, and the owner can read it.
const finance = Keys.grantDescriptor(ref, 'scope:admin/finance')
const fk = Keys.scopeKey(KK, 'admin/finance')
const t = Keys.writeTarget(finance, fk, 'admin/finance/clerks')
const ws = Keys.newSalt()
ok(() => assert.deepEqual(Keys.pieceKey(t.key, ws), Keys.keyForEnvelope(KK, Keys.appMetadata({ ...t.ref, scope: t.scope, salt: ws }))))
ok(() => assert.throws(() => Keys.writeTarget(finance, fk, 'admin'), /cannot write under/))

// Only the owner's wallet roots its keyspace; the result says what was signed.
await rejects(() => Keys.keyspaceKeys(privateKeyToAccount(generatePrivateKey()), ref), /not from the keyspace owner/)
const signed = await Keys.keyspaceKeys(account, ref)
ok(() => assert.deepEqual(signed.descriptor, Keys.grantDescriptor(ref, 'keyspace')))
ok(() => assert.equal(Keys.writeTarget(signed.descriptor, signed.kk).ref.keyspace, ref.keyspace))

// Commitments: right wallet, right keyspace; the earlier v1.<epoch>.<hex> form is refused.
ok(() => assert.ok(Keys.matchesCommitment(signed.kk, signed.commitment)))
ok(() => assert.ok(!Keys.matchesCommitment(other.kk, signed.commitment), 'another keyspace'))
ok(() => assert.throws(() => Keys.matchesCommitment(KK, `v1.0.${signed.commitment.slice(3)}`), /format v1/))

// Grants carry exactly the canonical descriptor; private keys are checked.
const handBuilt = { v: 1, node: 'scope:agent-memory', owner: ref.owner, keyspace: ref.keyspace.toUpperCase().replace('0X', '0x'), extra: 1 }
const { alg: _a, epk: _e, iv: _i, ct: _c, ...carried } = await Keys.wrapTo(Keys.publicKeyOf(recipient), rk, handBuilt)
ok(() => assert.deepEqual(carried, Keys.grantDescriptor(ref, 'scope:agent-memory')))
await rejects(() => Keys.wrapTo(Keys.publicKeyOf(recipient), rk, { ...handBuilt, v: 2 }), /version/)
ok(() => assert.throws(() => Keys.publicKeyOf(account.address), /32-byte secp256k1 private key/))

// Piece grants: one piece's key, opening that piece only, and never writing.
const pieceMeta = Keys.appMetadata({ ...ref, scope: 'super-secret', salt: Keys.newSalt() })
const piecePK = Keys.keyForEnvelope(KK, pieceMeta)
const pieceGrant = await Keys.wrapTo(Keys.publicKeyOf(recipient), piecePK, Keys.grantDescriptor(ref, `piece:${pieceMeta['foc/salt'].toUpperCase().replace('0X', '0x')}`))
ok(() => assert.equal(pieceGrant.node, `piece:${pieceMeta['foc/salt']}`))
ok(() => assert.equal(Keys.pieceNode({ 'foc/salt': pieceMeta['foc/salt'].toUpperCase().replace('0X', '0x') }), pieceGrant.node))
const openedPiece = await Keys.unwrapWith(recipient, pieceGrant)
ok(() => assert.deepEqual(Keys.keyForEnvelope(openedPiece, pieceMeta, Keys.holdingOf(pieceGrant)), piecePK))
ok(() => assert.throws(() => Keys.keyForEnvelope(openedPiece, { ...pieceMeta, 'foc/salt': Keys.newSalt() }, Keys.holdingOf(pieceGrant)), /another piece/))
ok(() => assert.throws(() => Keys.writeTarget(pieceGrant, openedPiece), /cannot write/))
await rejects(() => Keys.unwrapWith(recipient, { ...pieceGrant, node: `piece:${Keys.newSalt()}` }))

// The package's pinned test vectors: the same fixed inputs must give the same bytes here.
const keysmithDir = process.env.KEYSMITH_DIR ?? fileURLToPath(new URL('../../../synapse-sdk/packages/keysmith', import.meta.url))
const vectorsPath = join(keysmithDir, 'test', 'vectors.json')
if (existsSync(vectorsPath)) {
  const v = JSON.parse(readFileSync(vectorsPath, 'utf8'))
  const vOwner = privateKeyToAccount(v.owner.privateKey)
  const vKeys = await Keys.keyspaceKeys(vOwner, { owner: vOwner.address, keyspace: v.keyspace })
  ok(() => assert.equal(Keys.hex(vKeys.kk), v.keyspaceKey.kk))
  ok(() => assert.equal(vKeys.commitment, v.keyspaceKey.commitment))
  const vKK = Keys.unhex(v.keyspaceKey.kk)
  ok(() => assert.equal(Keys.hex(Keys.scopeKey(vKK, v.scope.path)), v.scope.key))
  ok(() => assert.equal(Keys.hex(Keys.keyForEnvelope(vKK, v.piece.metadata)), v.piece.key))
  ok(() => assert.equal(Keys.publicKeyOf(v.recipient.privateKey), v.recipient.publicKey))
  assert.equal(Keys.hex(await Keys.unwrapWith(v.recipient.privateKey, Keys.unhex(v.grant.cbor))), v.scope.key)
  checks++
  const vPieceGrant = Keys.decodeGrant(Keys.unhex(v.pieceGrant.cbor))
  const vPiece = await Keys.unwrapWith(v.recipient.privateKey, vPieceGrant)
  ok(() => assert.equal(Keys.hex(Keys.keyForEnvelope(vPiece, v.piece.metadata, Keys.holdingOf(vPieceGrant))), v.piece.key))
} else {
  console.log(`(package test vectors not found at ${vectorsPath}; set KEYSMITH_DIR to check them)`)
}

console.log(`ok — ${checks} checks passed`)
