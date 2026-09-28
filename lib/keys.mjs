/**
 * The key-source layer this track proposes. No dependencies beyond node:crypto.
 *
 * Everything below is OURS to build. FEE (the envelope) and Synapse (storage)
 * are separate layers and never see a wallet or derive a key.
 *
 *   D1  one EIP-712 signature per dataset, keyed by clientDataSetId
 *   D2  a delegate unwraps a copy of the dataset key with the key it already holds
 *   D3  determinism checked twice: sign-twice at issuance, foc/kc commitment on chain
 *
 * Kept byte-compatible with @filoz/keysmith (FilOzone/synapse-sdk#983): a grant
 * made here opens there, and the other way round. lib/keys.test.mjs checks it.
 */
import { createECDH, ECDH, hkdfSync, randomBytes, webcrypto } from 'node:crypto'
import * as Trace from './trace.mjs'

const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n
const HALF_N = N / 2n
const ALG = 'ECDH-ES+A256GCM/secp256k1'
const KEY_LENGTH = 32

/**
 * Fixed forever: a redeployed contract must not orphan a dataset's key. No
 * chainId, no verifyingContract, and never zero-fill them — absent and zero
 * are different domains, and different keys.
 */
export const DOMAIN = { name: 'FOC Encryption', version: '1' }
export const TYPES = {
  DatasetKey: [
    { name: 'purpose', type: 'string' },
    { name: 'chainId', type: 'uint256' },
    { name: 'service', type: 'address' },
    { name: 'payer', type: 'address' },
    { name: 'clientDataSetId', type: 'uint256' },
    { name: 'epoch', type: 'uint32' },
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
/** FWSS requires clientDataSetId to be unused by this payer; it is chosen before the dataset exists. */
export const newClientDataSetId = () => BigInt(hex(randomBytes(8)))

export function datasetKeyMessage({ chainId, service, payer, clientDataSetId, epoch = 0 }) {
  return {
    purpose: 'foc/enc/v1 dataset key',
    chainId: BigInt(chainId),
    service,
    payer,
    clientDataSetId,
    epoch,
  }
}

/** Signers already shown to sign deterministically, so later calls cost one prompt. */
const verifiedSigners = new WeakSet()

/**
 * D1 + D3(a). Sign for one dataset and derive its key.
 *
 * The signature is the root secret and never leaves this function: the caller
 * gets { dk, commitment } and has nothing else to guard. On a signer's first
 * use this signs twice and compares, catching a randomising signer before any
 * data depends on it; later calls sign once.
 */
export async function datasetKeys(signer, ref, { verifySigner } = {}) {
  const message = datasetKeyMessage(ref)
  const args = { domain: DOMAIN, types: TYPES, primaryType: 'DatasetKey', message }
  const first = await signer.signTypedData(args)
  if (verifySigner ?? !verifiedSigners.has(signer)) {
    const second = await signer.signTypedData(args)
    if (first !== second) {
      throw new Error('signer is not deterministic (RFC 6979 expected); this wallet cannot root a dataset')
    }
    verifiedSigners.add(signer)
  }
  const secret = lowSrs(first)
  Trace.eip712(DOMAIN, TYPES, message, first, secret)
  return {
    dk: hkdf(secret, 'foc/acl/dataset/v1', 32, 'DK (dataset key)'),
    commitment: `v1.${Buffer.from(hkdf(secret, 'foc/kc/v1', 16, 'foc/kc (public commitment)')).toString('hex')}`,
  }
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

/**
 * A scope name in the one form it is derived from: Unicode NFC, non-empty, no
 * leading or trailing whitespace. Case is significant, so it is not folded.
 */
export function scopeName(name) {
  const normalised = name.normalize('NFC')
  if (normalised.length === 0 || normalised.trim() !== normalised) {
    throw new Error(`A scope name must be non-empty with no leading or trailing whitespace, got ${JSON.stringify(name)}`)
  }
  return normalised
}

/** A grant node in canonical form: 'dataset', or 'scope:' plus a canonical scope name. */
export function canonicalNode(node) {
  if (node === 'dataset') return 'dataset'
  if (node.startsWith('scope:')) return `scope:${scopeName(node.slice('scope:'.length))}`
  throw new Error(`Unrecognised grant node: ${node}`)
}

/** A subset of one dataset. The name is an HKDF input, never a key itself. */
export const scopeKey = (dk, scope) => hkdf(dk, `foc/acl/scope/v1${scopeName(scope)}`, 32, `SK (scope "${scope}")`)
/** One key per piece: FEE forbids key reuse across objects. Salts are bytes: case folded, zeros kept. */
export const pieceKey = (node, salt) => hkdf(node, `foc/acl/piece/v1${salt.toLowerCase()}`, 32, 'PK (piece key) → FEE')

/**
 * The one spelling of a clientDataSetId on the wire: minimal lowercase hex.
 * It appears in a piece's foc/cds and in a grant descriptor, and a descriptor is
 * authenticated bytewise, so the two must not drift.
 */
const cdsHex = (id) => `0x${id.toString(16)}`

/**
 * The descriptor naming what a grant unlocks. Build it here, never by hand:
 * it is the AAD of the wrap, compared byte for byte, so addresses are
 * lowercased and the id is spelled exactly as the envelope spells it.
 */
export function grantDescriptor({ chainId, service, payer, clientDataSetId, epoch = 0 }, node) {
  return {
    v: 1,
    node: canonicalNode(node),
    chainId,
    epoch,
    service: service.toLowerCase(),
    payer: payer.toLowerCase(),
    clientDataSetId: cdsHex(clientDataSetId),
  }
}

/** Rides in the FEE envelope, so a reader needs nothing but the piece and a key. */
export function appMetadata({ clientDataSetId, epoch = 0, scope, salt }) {
  return {
    'foc/v': 1,
    'foc/cds': cdsHex(clientDataSetId),
    'foc/epoch': epoch,
    ...(scope ? { 'foc/scope': scopeName(scope) } : {}),
    'foc/salt': salt.toLowerCase(),
  }
}

/**
 * Derive a piece key from whichever node the caller holds.
 * holding: 'dataset' walks down through the scope; 'scope' is already at it.
 */
export function keyForEnvelope(node, meta, holding = 'dataset') {
  const scope = meta['foc/scope']
  if (holding === 'scope' && !scope) {
    throw new Error('This piece is not in a scope, so no scope key opens it; it needs the dataset key')
  }
  Trace.title('key identification from app_metadata')
  Trace.say(
    `holding: ${holding === 'dataset' ? 'DK — the whole dataset' : 'SK — one scope'}`,
    `envelope says: cds ${meta['foc/cds']} · epoch ${meta['foc/epoch']} · scope ${scope ?? '(none)'} · salt ${meta['foc/salt']}`,
    holding === 'dataset' && scope
      ? `walk: DK ──scope "${scope}"──▶ SK ──salt──▶ PK`
      : `walk: ${holding === 'scope' ? 'SK' : 'DK'} ──salt──▶ PK`
  )
  const at = holding === 'dataset' && scope ? scopeKey(node, scope) : node
  return pieceKey(at, meta['foc/salt'])
}

/**
 * The key-agreement key derived from a signing key, so one credential never
 * serves two algorithms. HKDF stretches the key to 48 bytes; hash-to-scalar
 * (FIPS 186-5 §A.2.1: reduce mod n−1, add 1) makes a uniform scalar. The same
 * arithmetic as noble's mapHashToField, which @filoz/keysmith uses.
 */
function ecdhSecretKey(privateKeyHex) {
  const seed = hkdf(unhex(privateKeyHex), 'foc/acl/ecdh/v1', 48)
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
 * one naming another dataset or scope. A grant proves nothing about who made
 * it — before writing with a key you were handed, open a known piece with it.
 */
export async function wrapTo(recipientPub, keyBytes, descriptor) {
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
  Trace.ecdh(`wrap to ${recipientPub.slice(0, 14)}…`, { epk, pkR, shared, kek, aad: aad(descriptor).toString(), iv, ct })
  return { ...descriptor, alg: ALG, epk: hex(epk), iv: hex(iv), ct: hex(ct) }
}

export async function unwrapWith(privateKeyHex, grant) {
  const { alg, epk, iv, ct, ...descriptor } = grant
  if (descriptor.v !== 1) throw new Error(`Unsupported grant version: ${descriptor.v}`)
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
    aad: aad(descriptor).toString(),
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
 * The authenticated fields, in a fixed order, as a JSON array of primitives.
 * Addresses and the id are lowercased so spelling cannot split a grant. Only
 * these six fields are covered; anything else in a grant is informational.
 */
const aad = (d) =>
  Buffer.from(
    JSON.stringify([
      d.v,
      canonicalNode(d.node),
      integer(d.chainId, 'chainId'),
      integer(d.epoch, 'epoch'),
      d.service.toLowerCase(),
      d.payer.toLowerCase(),
      `0x${BigInt(d.clientDataSetId).toString(16)}`,
    ])
  )

/** A relay may have rendered a number as a string; accept that, but nothing that is not an integer. */
function integer(value, name) {
  const n = Number(value)
  if (!Number.isSafeInteger(n) || n < 0) throw new Error(`Grant ${name} must be a non-negative integer, got ${value}`)
  return n
}
