/**
 * Turn piece or grant bytes into labelled byte ranges: what each part is, where
 * it sits, and what it says. Display only.
 */
import * as Keysmith from '@filoz/keysmith'
import { encode } from 'cborg'
import { constants } from 'filecoin-encryption-envelope'
import { bytesToHex, type Hex, hexToBytes } from 'viem'
import { type CborNode, parseCbor } from './cbor.ts'

export type Group = 'structure' | 'protected' | 'header' | 'labels' | 'nonce' | 'ciphertext' | 'tag' | 'descriptor' | 'wrap' | 'info'

export interface Field {
  label: string
  start: number
  end: number
  depth: number
  group: Group
  value?: string
  note?: string
}

export interface PieceView {
  kind: 'piece'
  fields: Field[]
  metadata?: Keysmith.PieceMetadata
  envelopeSize: number
  chunkCount: number
  algorithm: string
}
export interface GrantView {
  kind: 'grant'
  fields: Field[]
  grant?: Keysmith.Grant & Record<string, unknown>
  strictError?: string
  aad?: Hex
}
export interface UnknownView {
  kind: 'unknown'
  fields: Field[]
  reason: string
}
export type View = PieceView | GrantView | UnknownView

/** FEE 0.1's wire labels and algorithm ids. The package doesn't export these, so they are spelled out here. */
const HEADER = { alg: 1, iv: 5, typ: 16, chunkSize: -1, plaintextLength: -65789, appMetadata: -65792 } as const
const ALGORITHMS: Record<number, string> = {
  3: 'AES-256-GCM, whole object',
  [-65793]: 'Chunked AES-256-GCM stream',
}
const TAG_LENGTH = 16

export function show(value: CborNode['value']): string {
  if (value instanceof Uint8Array) return value.length > 20 ? `${bytesToHex(value.subarray(0, 16))}… (${value.length} B)` : bytesToHex(value)
  if (typeof value === 'string') return JSON.stringify(value)
  return String(value)
}

export function inspectBytes(bytes: Uint8Array): View {
  if (bytes.length === 0) return { kind: 'unknown', fields: [], reason: 'No bytes.' }
  let root: CborNode
  try {
    root = parseCbor(bytes)
  } catch (err) {
    return { kind: 'unknown', fields: [], reason: `Not CBOR that this inspector reads: ${(err as Error).message}.` }
  }
  if (root.major === 6 && (root.tag === 16 || root.tag === 96)) return describePiece(bytes, root)
  if (root.major === 5) return describeGrant(bytes, root)
  return { kind: 'unknown', fields: [field('CBOR item', root, 0, 'structure')], reason: 'Neither a FEE envelope (CBOR tag 16 or 96) nor a Keysmith grant (a CBOR map).' }
}

const field = (label: string, node: { start: number; end: number }, depth: number, group: Group, value?: string, note?: string): Field => ({
  label,
  start: node.start,
  end: node.end,
  depth,
  group,
  value,
  note,
})

function describePiece(bytes: Uint8Array, root: CborNode): PieceView | UnknownView {
  const fields: Field[] = []
  const array = root.items?.[0]
  if (!array?.items || array.items.length < 3) return { kind: 'unknown', fields: [], reason: 'A COSE tag, but not a COSE_Encrypt structure.' }
  const [protectedNode, unprotected, slot] = array.items
  fields.push(field(`CBOR tag ${root.tag}`, { start: root.start, end: root.head }, 0, 'structure', root.tag === 16 ? 'COSE_Encrypt0' : 'COSE_Encrypt', 'a COSE encrypted object (RFC 9052)'))
  fields.push(field(`array of ${array.items.length}`, { start: array.start, end: array.head }, 0, 'structure', undefined, '[protected, unprotected, ciphertext]'))

  let algorithm = 'unknown'
  let chunkSize = 0
  let metadata: Keysmith.PieceMetadata | undefined
  // FEE 0.1 puts every header in the protected map: all of it, Keysmith's labels too, is authenticated.
  fields.push(field('protected header', protectedNode, 1, 'protected', `${protectedNode.end - protectedNode.head} B`, 'authenticated by every chunk tag'))
  try {
    const inner = parseCbor(bytes, protectedNode.head)
    for (const [key, value] of inner.entries ?? []) {
      const range = { start: key.start, end: value.end }
      if (key.value === HEADER.alg) {
        algorithm = ALGORITHMS[Number(value.value)] ?? `algorithm ${value.value}`
        fields.push(field('alg (1)', range, 2, 'protected', String(value.value), algorithm))
      } else if (key.value === HEADER.iv) {
        fields.push(field('base nonce (5)', range, 2, 'nonce', show(value.value), 'each chunk adds its index and a last-chunk flag'))
      } else if (key.value === HEADER.typ) {
        fields.push(field('typ (16)', range, 2, 'protected', show(value.value), value.value === constants.ENVELOPE_TYPE ? 'a Filecoin encryption envelope' : 'an unexpected type'))
      } else if (key.value === HEADER.chunkSize) {
        chunkSize = Number(value.value)
        fields.push(field('chunk_size (−1)', range, 2, 'header', `${chunkSize} B`, 'plaintext per chunk'))
      } else if (key.value === HEADER.plaintextLength) {
        fields.push(field('plaintext_length (−65789)', range, 2, 'header', `${value.value} B`, 'committed: a different length fails'))
      } else if (key.value === HEADER.appMetadata) {
        fields.push(field('app_metadata (−65792)', { start: key.start, end: value.head }, 2, 'labels', `${value.entries?.length ?? 0} labels`, "Keysmith's labels: readable by anyone, authenticated by the tags"))
        const labels: Record<string, unknown> = {}
        for (const [name, entry] of value.entries ?? []) {
          labels[String(name.value)] = entry.value
          fields.push(field(String(name.value), { start: name.start, end: entry.end }, 3, 'labels', show(entry.value), LABEL_NOTES[String(name.value)]))
        }
        if (labels['foc/ks']) metadata = labels as unknown as Keysmith.PieceMetadata
      } else fields.push(field(`label ${key.value}`, range, 2, 'protected', show(value.value)))
    }
  } catch {
    // an empty or odd protected header: the bytes still show
  }
  const unprotectedCount = unprotected.entries?.length ?? 0
  fields.push(field('unprotected header', unprotected, 1, 'header', `${unprotectedCount} entries`, unprotectedCount === 0 ? 'empty: nothing here goes unauthenticated' : 'not authenticated by the tags'))
  fields.push(field('ciphertext slot', slot, 1, 'structure', show(slot.value), 'null: the ciphertext is detached and follows the envelope'))

  // The ciphertext: one run per chunk, each ending in its 16-byte tag. No header counts them: the size does.
  const envelopeSize = root.end
  const chunkCount = chunkSize > 0 ? Math.max(1, Math.ceil((bytes.length - envelopeSize) / (chunkSize + TAG_LENGTH))) : 1
  let at = envelopeSize
  for (let i = 0; i < chunkCount && at < bytes.length; i++) {
    const length = chunkSize > 0 && i < chunkCount - 1 ? chunkSize : bytes.length - at - TAG_LENGTH
    const name = chunkCount > 1 ? `chunk ${i}` : 'ciphertext'
    fields.push(field(name, { start: at, end: at + length }, 0, 'ciphertext', `${length} B`, 'AES-256-GCM output'))
    fields.push(field(`${name} tag`, { start: at + length, end: at + length + TAG_LENGTH }, 0, 'tag', `${TAG_LENGTH} B`, 'proves this chunk and the whole protected header are unaltered'))
    at += length + TAG_LENGTH
  }
  return { kind: 'piece', fields, metadata, envelopeSize, chunkCount, algorithm }
}

const LABEL_NOTES: Record<string, string> = {
  'foc/v': 'Keysmith envelope format',
  'foc/own': 'the keyspace owner; a gating provider serves the piece only to their grant chains',
  'foc/ks': 'the keyspace this piece belongs to',
  'foc/scope': 'the scope path; that scope and its ancestors can read it',
  'foc/salt': "16 random bytes; the piece's key is derived from it",
}

const GRANT_FIELDS: Record<number, { label: string; group: Group; note: string }> = {
  0: { label: 'v (0)', group: 'descriptor', note: 'version 1, which implies ECDH-ES + AES-256-GCM over secp256k1' },
  1: { label: 'node (1)', group: 'descriptor', note: 'what this grant unlocks' },
  2: { label: 'owner (2)', group: 'descriptor', note: 'the wallet that roots the keyspace' },
  3: { label: 'keyspace (3)', group: 'descriptor', note: 'the keyspace id' },
  4: { label: 'epk (4)', group: 'wrap', note: 'a one-time public key; with the recipient key it gives the wrapping key' },
  5: { label: 'iv (5)', group: 'nonce', note: 'AES-GCM nonce' },
  6: { label: 'ct (6)', group: 'wrap', note: 'the wrapped node key, then its tag' },
}

function describeGrant(bytes: Uint8Array, root: CborNode): GrantView {
  const fields: Field[] = [field(`map of ${root.entries?.length ?? 0}`, { start: root.start, end: root.head }, 0, 'structure', 'Keysmith grant')]
  for (const [key, value] of root.entries ?? []) {
    const range = { start: key.start, end: value.end }
    const known = typeof key.value === 'number' ? GRANT_FIELDS[key.value] : undefined
    if (key.value === 6 && value.value instanceof Uint8Array && value.value.length === 48) {
      fields.push(field(known?.label ?? 'ct', { start: key.start, end: value.head }, 1, 'wrap', '48 B', known?.note))
      fields.push(field('wrapped node key', { start: value.head, end: value.head + 32 }, 2, 'wrap', '32 B', 'only the recipient can unwrap it'))
      fields.push(field('tag', { start: value.head + 32, end: value.end }, 2, 'tag', '16 B', 'proves the key and the descriptor are unaltered'))
    } else if (known) fields.push(field(known.label, range, 1, known.group, show(value.value), known.note))
    else fields.push(field(String(key.value), range, 1, 'info', show(value.value), 'informational, not authenticated'))
  }
  if (root.end < bytes.length) fields.push(field('trailing bytes', { start: root.end, end: bytes.length }, 0, 'info', `${bytes.length - root.end} B`, 'not part of a grant'))
  try {
    const grant = Keysmith.decodeGrant(bytes)
    const aad = bytesToHex(encode([grant.v, grant.node, hexToBytes(grant.owner), hexToBytes(grant.keyspace)]))
    return { kind: 'grant', fields, grant, aad }
  } catch (err) {
    return { kind: 'grant', fields, strictError: (err as Error).message }
  }
}
