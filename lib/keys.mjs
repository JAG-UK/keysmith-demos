/**
 * The key-source layer this track proposes. No dependencies beyond node:crypto.
 *
 * Everything below is OURS to build. FEE (the envelope) and Synapse (storage)
 * are separate layers and never see a wallet or derive a key.
 *
 *   D1  one EIP-712 signature per dataset, keyed by clientDataSetId
 *   D2  a delegate unwraps a copy of the dataset key with the key it already holds
 *   D3  determinism checked twice: sign-twice at issuance, foc/kc commitment on chain
 */
import { createECDH, hkdfSync, randomBytes, webcrypto } from 'node:crypto'
import * as Trace from './trace.mjs'

const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n

/** Fixed forever: a redeployed contract must not orphan a dataset's key. */
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

/**
 * D1 + D3(a). Signs the same message twice and refuses to continue if a
 * randomising signer returns two different signatures — caught before any
 * data depends on the key.
 */
export async function datasetSecret(account, message) {
  const args = { domain: DOMAIN, types: TYPES, primaryType: 'DatasetKey', message }
  const first = await account.signTypedData(args)
  const second = await account.signTypedData(args)
  if (first !== second) {
    throw new Error('signer is not deterministic (RFC 6979 expected); this wallet cannot root a dataset')
  }
  const rs = lowSrs(first)
  Trace.eip712(DOMAIN, TYPES, message, first, rs)
  return rs
}

/** Take r‖s only, with s normalised to the low half; never the v byte. */
function lowSrs(sigHex) {
  const raw = unhex(sigHex)
  const r = raw.subarray(0, 32)
  let s = BigInt(hex(raw.subarray(32, 64)))
  if (s > SECP256K1_N / 2n) s = SECP256K1_N - s
  const sBuf = Buffer.from(s.toString(16).padStart(64, '0'), 'hex')
  return Buffer.concat([r, sBuf])
}

export const datasetKey = (secret) => hkdf(secret, 'foc/acl/dataset/v1', 32, 'DK (dataset key)')
/** D3(b). Non-secret, 16 bytes, rides in the createDataSet metadata that happens anyway. */
export const commitment = (secret) =>
  `v1.${Buffer.from(hkdf(secret, 'foc/kc/v1', 16, 'foc/kc (public commitment)')).toString('hex')}`
/** A subset of one dataset. The name is an HKDF input, never a key itself. */
export const scopeKey = (dk, scope) => hkdf(dk, `foc/acl/scope/v1${scope}`, 32, `SK (scope "${scope}")`)
/** One key per piece: FEE forbids key reuse across objects. */
export const pieceKey = (node, salt) => hkdf(node, `foc/acl/piece/v1${salt}`, 32, 'PK (piece key) → FEE')

/** Rides in the FEE envelope, so a reader needs nothing but the piece and a key. */
export function appMetadata({ clientDataSetId, epoch = 0, scope, salt }) {
  return {
    'foc/v': 1,
    'foc/cds': `0x${clientDataSetId.toString(16)}`,
    'foc/epoch': epoch,
    ...(scope ? { 'foc/scope': scope } : {}),
    'foc/salt': salt,
  }
}

/**
 * Derive a piece key from whichever node the caller holds.
 * holding: 'dataset' walks down through the scope; 'scope' is already at it.
 */
export function keyForEnvelope(node, meta, holding = 'dataset') {
  const scope = meta['foc/scope']
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

/** The public half of a secp256k1 key — a session key, or an agent's own wallet. */
export function publicKeyOf(privateKeyHex) {
  const ecdh = createECDH('secp256k1')
  ecdh.setPrivateKey(unhex(privateKeyHex))
  return hex(ecdh.getPublicKey())
}

/**
 * D2. Wrap a node key to a secp256k1 public key: ECDH-ES + AES-256-GCM.
 * The descriptor is authenticated (AAD), so a grant cannot be relabelled as
 * one naming another dataset or scope.
 */
export async function wrapTo(recipientPub, keyBytes, descriptor) {
  const ecdh = createECDH('secp256k1')
  ecdh.generateKeys()
  const shared = ecdh.computeSecret(unhex(recipientPub))
  const kek = wrapKek(shared, ecdh.getPublicKey())
  const iv = randomBytes(12)
  const key = await webcrypto.subtle.importKey('raw', kek, 'AES-GCM', false, ['encrypt'])
  const ct = await webcrypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aad(descriptor) },
    key,
    keyBytes
  )
  Trace.ecdh(`wrap to ${recipientPub.slice(0, 14)}…`, {
    epk: ecdh.getPublicKey(),
    shared,
    kek,
    aad: aad(descriptor).toString(),
    iv,
    ct: new Uint8Array(ct),
  })
  return {
    ...descriptor,
    alg: 'ECDH-ES+A256GCM/secp256k1',
    epk: hex(ecdh.getPublicKey()),
    iv: hex(iv),
    ct: hex(new Uint8Array(ct)),
  }
}

export async function unwrapWith(privateKeyHex, grant) {
  const { alg, epk, iv, ct, ...descriptor } = grant
  const ecdh = createECDH('secp256k1')
  ecdh.setPrivateKey(unhex(privateKeyHex))
  const shared = ecdh.computeSecret(unhex(epk))
  const kek = wrapKek(shared, unhex(epk))
  Trace.ecdh(`unwrap grant for ${descriptor.node ?? 'node'}`, {
    epk: unhex(epk),
    shared,
    kek,
    aad: aad(descriptor).toString(),
    iv: unhex(iv),
    ct: unhex(ct),
  })
  const key = await webcrypto.subtle.importKey('raw', kek, 'AES-GCM', false, ['decrypt'])
  const out = await webcrypto.subtle.decrypt(
    { name: 'AES-GCM', iv: unhex(iv), additionalData: aad(descriptor) },
    key,
    unhex(ct)
  )
  Trace.bytes('unwrapped node key', new Uint8Array(out))
  return new Uint8Array(out)
}

const wrapKek = (shared, epk) => hkdf(Buffer.concat([shared, Buffer.from(epk)]), 'foc/acl/wrap/v1')
const aad = (descriptor) => Buffer.from(JSON.stringify(descriptor))
