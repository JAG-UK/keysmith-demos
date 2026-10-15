/**
 * The key-source layer this track proposes. node:crypto, plus viem to recover a signer's address.
 *
 * Everything below is OURS to build. FEE (the envelope) and Synapse (storage)
 * are separate layers and never see a wallet or derive a key.
 *
 *   D1  one EIP-712 signature per keyspace — Keysmith's own namespace, not an FWSS dataset
 *   D2  a delegate unwraps a copy of a key with the key it already holds
 *   D3  determinism checked twice: sign-twice at issuance, foc/kc commitment on chain
 *
 * Kept byte-compatible with @filoz/keysmith (FilOzone/synapse-sdk#983): a grant
 * made here opens there, and the other way round.
 */
import { decode, encode } from 'cborg'
import { createECDH, ECDH, hkdfSync, randomBytes, webcrypto } from 'node:crypto'
import { hashTypedData, recoverAddress } from 'viem'
import * as Trace from './trace.mjs'

const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n
const HALF_N = N / 2n
const ALG = 'ECDH-ES+A256GCM/secp256k1'
const KEY_LENGTH = 32

/**
 * Fixed forever. No chainId, no verifyingContract, and never zero-fill them —
 * absent and zero are different domains, and different keys. Nothing about
 * chains, contracts or datasets is signed at all: a keyspace is 128 random
 * bits, and a piece must open wherever replication or repair puts its copies.
 */
export const DOMAIN = { name: 'FOC Encryption', version: '1' }
export const TYPES = {
  KeyspaceKey: [
    { name: 'owner', type: 'address' },
    { name: 'keyspace', type: 'bytes16' },
  ],
}

export const hex = (b) => `0x${Buffer.from(b).toString('hex')}`
export const unhex = (s) => Buffer.from(String(s).replace(/^0x/, ''), 'hex')
const hkdf = (ikm, info, len = 32, label) => {
  const out = new Uint8Array(hkdfSync('sha256', ikm, Buffer.alloc(0), Buffer.from(info), len))
  if (label) Trace.hkdf(label, { ikm, info, out })
  return out
}

export const newSalt = () => hex(randomBytes(16))
/** A fresh keyspace id: 16 random bytes, unique without reference to any chain or dataset. */
export const newKeyspace = () => hex(randomBytes(16))

/** A keyspace id in canonical form: exactly 16 bytes, lowercase hex. */
export function keyspaceId(keyspace) {
  const lower = String(keyspace).toLowerCase()
  if (!/^0x[0-9a-f]{32}$/.test(lower)) throw new Error(`A keyspace id is 16 bytes of hex, got ${JSON.stringify(keyspace)}`)
  return lower
}

export function keyspaceKeyMessage({ owner, keyspace }) {
  return { owner, keyspace: keyspaceId(keyspace) }
}

/**
 * D1 + D3(a). Sign for one keyspace and derive its key.
 *
 * The signature is the root secret and never leaves this function: the caller
 * gets { kk, commitment, descriptor } and has nothing else to guard. For a new
 * keyspace this signs twice and compares, catching a randomising signer before
 * any data depends on it; for an existing one, pass the dataset's `foc/kc` as
 * `commitment` and it signs once, the commitment catching the same faults.
 * Only the owner's own wallet may sign: a delegate receives a grant instead.
 */
export async function keyspaceKeys(signer, ref, { commitment: recorded, verifySigner } = {}) {
  const message = keyspaceKeyMessage(ref)
  const args = { domain: DOMAIN, types: TYPES, primaryType: 'KeyspaceKey', message }
  const first = await signer.signTypedData(args)
  if (verifySigner ?? recorded == null) {
    const second = await signer.signTypedData(args)
    if (first !== second) {
      throw new Error('signer is not deterministic (RFC 6979 expected); this wallet cannot root a keyspace')
    }
  }
  const secret = lowSrs(first)
  await assertSignedBy(message.owner, hashTypedData(args), secret)
  Trace.eip712(DOMAIN, TYPES, message, first, secret)
  const kk = hkdf(secret, 'foc/acl/keyspace/v1', 32, 'KK (keyspace key)')
  if (recorded != null && !matchesCommitment(kk, recorded)) {
    throw new Error('this key does not match the recorded commitment: the signer is not deterministic, or the commitment belongs to another keyspace')
  }
  return { kk, commitment: commitment(kk), descriptor: grantDescriptor(ref, 'keyspace') }
}

/** v is dropped and s normalised before anything is derived, so try both parities: one must recover to the owner. */
async function assertSignedBy(owner, hash, rs) {
  const r = hex(rs.subarray(0, 32))
  const s = hex(rs.subarray(32, 64))
  for (const yParity of [0, 1]) {
    if ((await recoverAddress({ hash, signature: { r, s, yParity } })).toLowerCase() === owner.toLowerCase()) return
  }
  throw new Error(`This signature is not from the keyspace owner ${owner}; a delegate receives a grant instead`)
}

/** D3(b). Non-secret, derived from KK so any keyspace-key holder can write it into a new dataset: `v1.<hex>`. */
export const commitment = (kk) => `v1.${Buffer.from(hkdf(kk, 'foc/kc/v1', 16, 'foc/kc (public commitment)')).toString('hex')}`

/** Right wallet, right keyspace. */
export function matchesCommitment(kk, recorded) {
  if (!/^v1\.[0-9a-f]{32}$/.test(recorded)) throw new Error(`Not a keyspace commitment in format v1: ${JSON.stringify(recorded)}`)
  return commitment(kk) === recorded
}

/**
 * r‖s with s normalised to the low half; never the v byte. Only a plain ECDSA
 * signature is accepted: a contract account answers with an ABI-encoded blob
 * whose leading bytes are structure, not secret, and a key derived from that
 * would be guessable.
 */
export function lowSrs(sigHex) {
  const raw = unhex(sigHex)
  if (raw.length !== 64 && raw.length !== 65) {
    throw new Error(`Expected a 64- or 65-byte ECDSA signature, got ${raw.length} bytes`)
  }
  const r = BigInt(hex(raw.subarray(0, 32)))
  const s = BigInt(hex(raw.subarray(32, 64)))
  if (r < 1n || r >= N || s < 1n || s >= N) {
    throw new Error('Signature r and s must lie in [1, n−1]; this is not a secp256k1 ECDSA signature')
  }
  const lowS = s > HALF_N ? N - s : s
  return Buffer.concat([raw.subarray(0, 32), Buffer.from(lowS.toString(16).padStart(64, '0'), 'hex')])
}

/** One scope name: NFC, non-empty, unpadded, no "/". Case is significant. */
export function scopeName(name) {
  const normalised = name.normalize('NFC')
  if (normalised.length === 0 || normalised.trim() !== normalised || normalised.includes('/')) {
    throw new Error(`A scope name must be non-empty, with no leading or trailing whitespace and no "/", got ${JSON.stringify(name)}`)
  }
  return normalised
}

/** A scope path, top scope first: `super-secret/secret`. */
export const scopePath = (path) => path.split('/').map(scopeName).join('/')

/** A grant node in canonical form: 'keyspace', 'scope:' plus a canonical scope path, or 'piece:' plus a lowercase salt. */
export function canonicalNode(node) {
  if (node === 'keyspace') return 'keyspace'
  if (node.startsWith('scope:')) return `scope:${scopePath(node.slice('scope:'.length))}`
  if (node.startsWith('piece:')) return `piece:${saltOf(node.slice('piece:'.length))}`
  throw new Error(`Unrecognised grant node: ${node}`)
}

/**
 * The grant node for one piece: `piece:<salt>`. Bound to the salt (canonical, checked
 * against the envelope for free); carry the piece CID beside the grant as a locator.
 */
export const pieceNode = (meta) => `piece:${saltOf(meta['foc/salt'])}`

/** A salt as it is derived from and compared: hex bytes, lowercase. */
function saltOf(salt) {
  const lower = String(salt).toLowerCase()
  if (!/^0x([0-9a-f]{2})+$/.test(lower)) throw new Error(`A piece salt is hex bytes, got ${JSON.stringify(salt)}`)
  return lower
}

const walk = (key, names) => names.reduce((parent, name) => hkdf(parent, `foc/acl/role/v1${name}`, 32, `RK (scope "${name}")`), key)

/** A scope's key, derived from its parent's: holding a scope opens every scope beneath it, nothing above. */
export const scopeKey = (kk, scope) => walk(kk, scopePath(scope).split('/'))
/** One key per piece: FEE forbids key reuse across objects. Salts are bytes: case folded, zeros kept. */
export const pieceKey = (node, salt) => hkdf(node, `foc/acl/piece/v1${salt.toLowerCase()}`, 32, 'PK (piece key) → FEE')

/**
 * The descriptor naming what a grant unlocks. Build it here, never by hand:
 * it is the AAD of the wrap, compared byte for byte, so the owner is
 * lowercased and the keyspace is spelled exactly as the envelope spells it.
 */
export function grantDescriptor({ owner, keyspace }, node) {
  return { v: 1, node: canonicalNode(node), owner: owner.toLowerCase(), keyspace: keyspaceId(keyspace) }
}

/**
 * Rides in the FEE envelope: everything a reader needs, wherever the copy ends up.
 * `foc/own` names the owner, so a provider can gate retrieval on it.
 */
export function appMetadata({ owner, keyspace, scope, salt }) {
  return {
    'foc/v': 1,
    'foc/own': owner.toLowerCase(),
    'foc/ks': keyspaceId(keyspace),
    ...(scope ? { 'foc/scope': scopePath(scope) } : {}),
    'foc/salt': salt.toLowerCase(),
  }
}

/**
 * Derive a piece key from whichever node the caller holds. A keyspace holder
 * walks the piece's whole scope path; a scope holder walks the rest of it below
 * its own scope — only if its scope is the piece's scope or an ancestor of it. A
 * piece holder already has the key, and gets it back only for its own piece.
 */
export function keyForEnvelope(node, meta, holding = 'keyspace') {
  // Pre-release prototypes also wrote foc/v 1, but named no keyspace.
  if (meta['foc/v'] !== 1 || typeof meta['foc/ks'] !== 'string') {
    throw new Error(`This piece's envelope is not format 1 with a keyspace (foc/v ${meta['foc/v']}, foc/ks ${meta['foc/ks']})`)
  }
  if (holding !== 'keyspace' && 'piece' in holding) {
    if (saltOf(holding.piece) !== saltOf(meta['foc/salt'])) throw new Error('This piece key belongs to another piece: the envelope names a different salt')
    Trace.title('key identification from app_metadata')
    Trace.say(`holding: PK for the piece with salt ${holding.piece} — nothing to derive`)
    return node.slice()
  }
  const scope = meta['foc/scope']
  const target = scope ? scopePath(scope).split('/') : []
  const held = holding === 'keyspace' ? [] : scopePath(holding.scope).split('/')
  if (held.length > target.length || held.some((n, i) => n !== target[i])) {
    throw new Error(`Scope "${held.join('/')}" does not contain this piece's scope "${scope ?? '(none)'}"`)
  }
  const rest = target.slice(held.length)
  Trace.title('key identification from app_metadata')
  Trace.say(
    `holding: ${holding === 'keyspace' ? 'KK — the whole keyspace' : `RK for "${held.join('/')}"`}`,
    `envelope says: keyspace ${meta['foc/ks']} · scope ${scope ?? '(none)'} · salt ${meta['foc/salt']}`,
    `walk: ${holding === 'keyspace' ? 'KK' : 'RK'}${rest.map((n) => ` ──"${n}"──▶ RK`).join('')} ──salt──▶ PK`
  )
  return pieceKey(walk(node, rest), meta['foc/salt'])
}

/**
 * For a delegate: the ref, scope and key to write a piece, from its grant. A scope
 * grant writes under its own scope (the default) or beneath it; a keyspace grant
 * anywhere; a piece grant nowhere, since FEE needs a fresh key for every object.
 * Anything else is refused before a byte is encrypted.
 */
export function writeTarget(grant, nodeKey, scope) {
  if (nodeKey.length !== 32) throw new Error(`Expected a 32-byte node key, got ${nodeKey.length} bytes`)
  const holding = holdingOf(grant)
  if (holding !== 'keyspace' && 'piece' in holding) {
    throw new Error('A piece grant opens one existing piece and cannot write: FEE needs a fresh key for every object.')
  }
  const held = holding === 'keyspace' ? [] : holding.scope.split('/')
  const path = scope == null ? held : scopePath(scope).split('/')
  if (held.length > path.length || held.some((n, i) => n !== path[i])) {
    const covers = held.length === 0 ? 'the whole keyspace' : `scope "${held.join('/')}" and the scopes beneath it`
    throw new Error(`This grant covers ${covers}; it cannot write under "${scope}".`)
  }
  return {
    ref: { owner: grant.owner, keyspace: keyspaceId(grant.keyspace) },
    ...(path.length === 0 ? {} : { scope: path.join('/') }),
    key: walk(nodeKey, path.slice(held.length)),
  }
}

/** Which node a grant carries — keys are indistinguishable bytes, but the grant knows. */
export function holdingOf(grant) {
  const node = canonicalNode(grant.node)
  if (node === 'keyspace') return 'keyspace'
  return node.startsWith('piece:') ? { piece: node.slice('piece:'.length) } : { scope: node.slice('scope:'.length) }
}

/**
 * The key-agreement key derived from a signing key, so one credential never
 * serves two algorithms. HKDF stretches the key to 48 bytes; hash-to-scalar
 * (FIPS 186-5 §A.2.1: reduce mod n−1, add 1) makes a uniform scalar. The same
 * arithmetic as noble's mapHashToField, which @filoz/keysmith uses.
 */
function ecdhSecretKey(privateKeyHex) {
  const raw = unhex(privateKeyHex)
  // An address or public key passed by mistake would otherwise hash to a key nobody holds.
  const k = raw.length === 32 ? BigInt(hex(raw)) : 0n
  if (k < 1n || k >= N) throw new Error(`Expected a 32-byte secp256k1 private key, got ${raw.length} bytes that are not one`)
  const seed = hkdf(raw, 'foc/acl/ecdh/v1', 48)
  const scalar = (BigInt(hex(seed)) % (N - 1n)) + 1n
  return Buffer.from(scalar.toString(16).padStart(64, '0'), 'hex')
}

const ecdhFor = (privateKeyHex) => {
  const ecdh = createECDH('secp256k1')
  ecdh.setPrivateKey(ecdhSecretKey(privateKeyHex))
  return ecdh
}

/** The public key a sender wraps to: the derived key-agreement key, not the signing key. */
export const publicKeyOf = (privateKeyHex) => hex(ecdhFor(privateKeyHex).getPublicKey())

/**
 * D2. Wrap a node key to a recipient's key-agreement key: ECDH-ES + AES-256-GCM.
 * The descriptor is authenticated (AAD), so a grant cannot be relabelled as
 * one naming another keyspace or scope. A grant proves nothing about who made
 * it — before writing with a key you were handed, open a known piece with it.
 */
export async function wrapTo(recipientPub, keyBytes, input) {
  const descriptor = canonical(input)
  if (keyBytes.length !== KEY_LENGTH) throw new Error(`Expected a ${KEY_LENGTH}-byte node key, got ${keyBytes.length}`)
  const pkR = ECDH.convertKey(unhex(recipientPub), 'secp256k1', null, null, 'uncompressed')
  const ecdh = createECDH('secp256k1')
  ecdh.generateKeys()
  const epk = ecdh.getPublicKey()
  const shared = ecdh.computeSecret(pkR)
  const kek = wrapKek(shared, epk, pkR)
  const iv = randomBytes(12)
  const key = await webcrypto.subtle.importKey('raw', kek, 'AES-GCM', false, ['encrypt'])
  const ct = new Uint8Array(
    await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad(descriptor) }, key, keyBytes)
  )
  Trace.ecdh(`wrap to ${recipientPub.slice(0, 14)}…`, { epk, pkR, shared, kek, aad: hex(aad(descriptor)), iv, ct })
  return { ...descriptor, alg: ALG, epk: hex(epk), iv: hex(iv), ct: hex(ct) }
}

export async function unwrapWith(privateKeyHex, input) {
  const grant = input instanceof Uint8Array ? decodeGrant(input) : input
  const { alg, epk, iv, ct, ...rest } = grant
  const descriptor = canonical(rest)
  if (alg !== ALG) throw new Error(`Unsupported grant algorithm: ${alg}`)
  const ecdh = ecdhFor(privateKeyHex)
  const pkR = ecdh.getPublicKey()
  const shared = ecdh.computeSecret(unhex(epk))
  const kek = wrapKek(shared, unhex(epk), pkR)
  Trace.ecdh(`unwrap grant for ${descriptor.node ?? 'node'}`, {
    epk: unhex(epk),
    pkR,
    shared,
    kek,
    aad: hex(aad(descriptor)),
    iv: unhex(iv),
    ct: unhex(ct),
  })
  const key = await webcrypto.subtle.importKey('raw', kek, 'AES-GCM', false, ['decrypt'])
  const out = new Uint8Array(
    await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv: unhex(iv), additionalData: aad(descriptor) }, key, unhex(ct))
  )
  if (out.length !== KEY_LENGTH) throw new Error(`Grant carried a ${out.length}-byte key; a node key is ${KEY_LENGTH} bytes`)
  Trace.bytes('unwrapped node key', out)
  return out
}

/** KEK = HKDF(shared ‖ epk ‖ pkR): both public keys bound in, as HPKE does. */
const wrapKek = (shared, epk, pkR) => hkdf(Buffer.concat([shared, epk, pkR]), 'foc/acl/wrap/v1')

/**
 * The descriptor's five fields in canonical form, and nothing else: spelling
 * cannot split a grant, and a grant carries exactly these, whoever built it.
 */
function canonical(d) {
  if (d.v !== 1) throw new Error(`Unsupported grant version: ${d.v}`)
  return { v: 1, node: canonicalNode(d.node), owner: d.owner.toLowerCase(), keyspace: keyspaceId(d.keyspace) }
}

/**
 * The authenticated fields of a canonical descriptor, in a fixed order, as
 * deterministic CBOR: [v, node, owner bytes, keyspace bytes].
 */
const aad = (d) => encode([d.v, d.node, new Uint8Array(unhex(d.owner)), new Uint8Array(unhex(d.keyspace))])

/**
 * A grant on the wire: a CBOR map with numbered fields, and text keys for
 * anything informational. Version 1 implies the algorithm, so it is not written.
 *   { 0 v, 1 node, 2 owner(20), 3 keyspace(16), 4 epk(65), 5 iv(12), 6 ct(48), * text: info }
 */
const WIRE = ['v', 'node', 'owner', 'keyspace', 'epk', 'iv', 'ct']
const BYTES = { owner: 20, keyspace: 16, epk: 65, iv: 12, ct: 48 }

export function encodeGrant(grant) {
  const { alg, ...fields } = grant
  if (alg !== ALG) throw new Error(`Unsupported grant algorithm: ${alg}`)
  const d = canonical(fields)
  const wire = { ...fields, ...d }
  const map = new Map(WIRE.map((name, i) => [i, name in BYTES ? new Uint8Array(unhex(wire[name])) : wire[name]]))
  for (const [k, v] of Object.entries(fields)) if (!WIRE.includes(k)) map.set(k, v)
  return encode(map)
}

export function decodeGrant(bytes) {
  const map = decode(bytes, { strict: true, useMaps: true, rejectDuplicateMapKeys: true, allowIndefinite: false, allowUndefined: false })
  if (!(map instanceof Map)) throw new Error('Not a grant: expected a CBOR map')
  const grant = { alg: ALG }
  for (const [k, v] of map) {
    if (typeof k === 'string') grant[k] = v
    else if (WIRE[k] === undefined) throw new Error(`Not a grant this version understands: unknown field ${k}`)
  }
  WIRE.forEach((name, i) => {
    const v = map.get(i)
    if (name in BYTES && !(v instanceof Uint8Array && v.length === BYTES[name])) throw new Error(`A grant's ${name} must be ${BYTES[name]} bytes`)
    grant[name] = name in BYTES ? hex(v) : v
  })
  if (grant.v !== 1) throw new Error(`Unsupported grant version: ${grant.v}`)
  return grant
}
