/**
 * Session keys, in the Filecoin Pay console's shape, plus the one thing Keysmith
 * adds: encryption grants. The console's SessionKeyRecord, scopes, expiry
 * presets and `login`/`revoke` calls are mirrored as-is, so this is the code the
 * console would grow, not a parallel design.
 *
 * Demo-only difference: the console never stores a session key's private key.
 * This page does (in local storage), because it also plays the agents.
 */
import * as Keysmith from '@filoz/keysmith'
import {
  AddPiecesPermission,
  authorizationExpiry,
  CreateDataSetPermission,
  fromSecp256k1,
  SchedulePieceRemovalsPermission,
  TerminateServicePermission,
} from '@filoz/synapse-core/session-key'
import { Synapse } from '@filoz/synapse-sdk'
import { type Address, bytesToHex, type Hex, hexToBytes, http } from 'viem'
import { decryptBytes, encryptBytes } from '../../lib/fee.mjs'
import type { Network } from './networks.ts'
import { readerFor, store } from './storage.ts'

// ── the console's model ────────────────────────────────────────────────────

export type ScopeId = 'createDataSet' | 'addPieces' | 'schedulePieceRemovals' | 'terminateService'
export interface SessionKeyScope {
  id: ScopeId
  label: string
  description: string
  typehash: Hex
  destructive?: boolean
}
export const SESSION_KEY_SCOPES: SessionKeyScope[] = [
  { id: 'createDataSet', label: 'Create data set', description: 'Key may create new Warm Storage data sets billed to your account.', typehash: CreateDataSetPermission },
  { id: 'addPieces', label: 'Add pieces', description: 'Key may add pieces to your existing data sets.', typehash: AddPiecesPermission },
  { id: 'schedulePieceRemovals', label: 'Schedule piece removals', description: 'Key may schedule pieces for removal from your data sets.', typehash: SchedulePieceRemovalsPermission, destructive: true },
  { id: 'terminateService', label: 'Terminate service', description: 'Key may end storage service for whole data sets.', typehash: TerminateServicePermission, destructive: true },
]
export const SCOPE_BY_ID = Object.fromEntries(SESSION_KEY_SCOPES.map((scope) => [scope.id, scope])) as Record<ScopeId, SessionKeyScope>

export const EXPIRY_PRESETS = [
  { label: '7 days', days: 7 },
  { label: '30 days', days: 30 },
  { label: '90 days', days: 90 },
]

/** The console's record, plus Keysmith's grants and (demo only) the private key. */
export interface SessionKeyRecord {
  name: string
  sessionKeyPublic: Address
  scopes: ScopeId[]
  createdAt: number
  txHash?: string
  /** Keysmith: grants for this key, as delivered (CBOR, hex). */
  grants: Hex[]
  /** Demo only: the console never stores this. */
  privateKey: Hex
}

const storageKey = (network: Network, account: Address) => `keysmith-demo-agents:${network.id}:${account.toLowerCase()}`

export function loadAgents(network: Network, account: Address): SessionKeyRecord[] {
  try {
    const parsed = JSON.parse(localStorage.getItem(storageKey(network, account)) ?? '[]')
    return Array.isArray(parsed) ? parsed : []
  } catch {
    return []
  }
}
export function saveAgents(network: Network, account: Address, agents: SessionKeyRecord[]): void {
  try {
    localStorage.setItem(storageKey(network, account), JSON.stringify(agents))
  } catch {
    // a private window: agents last as long as the tab
  }
}

/** The console's name rule: no control or bidi characters, trimmed, at most 64. Public and onchain, as `origin`. */
export const normalizeKeyName = (name: string) =>
  name.replace(/[\u0000-\u001f\u007f‎‏‪-‮⁦-⁩]/g, '').trim().slice(0, 64)

export const loginArgs = (record: SessionKeyRecord, expiry: bigint) =>
  [record.sessionKeyPublic, expiry, record.scopes.map((id) => SCOPE_BY_ID[id].typehash), record.name] as const
export const revokeArgs = (record: SessionKeyRecord) =>
  [record.sessionKeyPublic, record.scopes.map((id) => SCOPE_BY_ID[id].typehash), record.name] as const

// ── what Keysmith adds ─────────────────────────────────────────────────────

export const SHARED_SCOPE = 'shared'
/** An agent's private scope, from its name: a scope name has no "/" and no padding. */
export const privateScopeOf = (name: string) =>
  `agents/${name.normalize('NFC').toLowerCase().replace(/[\s/]+/g, '-').replace(/^-+|-+$/g, '') || 'unnamed'}`

/** The grants a key holds, decoded: what each one names. */
export const decodedGrants = (record: SessionKeyRecord) => record.grants.map((hex) => Keysmith.decodeGrant(hexToBytes(hex)))

/**
 * Wrap one scope key to the agent's key-agreement key. No wallet prompt: the
 * owner already holds the keyspace key. In a real deployment the agent would
 * publish `publicKeyOf(its key)`; here the page knows it because it plays the agent.
 */
export async function shareScope(record: SessionKeyRecord, kk: Uint8Array, keyspace: Hex, owner: Address, scope: string): Promise<Hex> {
  const descriptor = Keysmith.grantDescriptor({ owner, keyspace }, `scope:${scope}`)
  const grant = await Keysmith.wrapTo(Keysmith.publicKeyOf(record.privateKey), Keysmith.scopeKey(kk, scope), descriptor)
  return bytesToHex(Keysmith.encodeGrant(grant))
}

/**
 * The agent's side: open its grant, write one piece under that scope, and hand
 * it to Synapse as the owner's session key. No wallet involved. The dataset
 * metadata is the owner's (keyspace and commitment, both public on chain), so
 * Synapse adds to the owner's datasets rather than making new ones.
 */
export async function agentWrite(
  network: Network,
  owner: Address,
  record: SessionKeyRecord,
  grantHex: Hex,
  dataSetMetadata: Record<string, string>,
  text: string
): Promise<string> {
  const grant = Keysmith.decodeGrant(hexToBytes(grantHex))
  const target = Keysmith.writeTarget(grant, await Keysmith.unwrapWith(record.privateKey, grant))
  const salt = Keysmith.newSalt()
  const ciphertext = await encryptBytes(
    new TextEncoder().encode(text),
    Keysmith.pieceKey(target.key, salt),
    Keysmith.pieceMetadata(target.ref, { salt, scope: target.scope })
  )
  // sessionKey.syncExpirations() reads as the session key, and Lotus refuses calls from an address it
  // has never seen, so a fresh key reads as unauthorized. Read the registry without an account instead.
  const expiry = await authorizationExpiry(readerFor(network), { address: owner, sessionKeyAddress: record.sessionKeyPublic, permission: AddPiecesPermission })
  if (expiry <= BigInt(Math.floor(Date.now() / 1000))) {
    throw new Error(`"${record.name}" may not add pieces: its session key is ${expiry === 0n ? 'not authorized, or was revoked' : 'expired'}.`)
  }
  const sessionKey = fromSecp256k1({ privateKey: record.privateKey, root: owner, chain: network.readChain, transport: http() })
  // Checked above; the chain checks it again when the piece is added.
  const synapse = Synapse.create({ chain: network.readChain, transport: http(), account: owner, sessionKey, requiredPermissions: [], source: 'keysmith-demo' })
  const { pieceCid } = await store(synapse, network, ciphertext, dataSetMetadata)
  return pieceCid
}

/** A node key someone holds, and what it is. */
export interface HeldKey {
  key: Uint8Array
  holding: Keysmith.Holding
  keyspace: Hex
  label: string
}

export async function heldKeysOf(record: SessionKeyRecord): Promise<HeldKey[]> {
  return Promise.all(
    decodedGrants(record).map(async (grant) => ({
      key: await Keysmith.unwrapWith(record.privateKey, grant),
      holding: Keysmith.holdingOf(grant),
      keyspace: grant.keyspace,
      label: grant.node,
    }))
  )
}

/**
 * Can these keys open this piece? A real decryption when a key reaches it;
 * otherwise Keysmith's own refusal says why none does.
 */
export async function tryOpen(
  keys: HeldKey[],
  blob: Uint8Array,
  metadata: Keysmith.PieceMetadata
): Promise<{ ok: true; text: string; via: string } | { ok: false; why: string }> {
  const reasons: string[] = []
  for (const held of keys) {
    if (held.keyspace !== metadata['foc/ks']) {
      reasons.push(`${held.label}: another keyspace`)
      continue
    }
    let pieceKey: Uint8Array
    try {
      pieceKey = Keysmith.keyForEnvelope(held.key, metadata, held.holding)
    } catch (err) {
      reasons.push(`${held.label}: ${(err as Error).message.split(';')[0]}`)
      continue
    }
    try {
      return { ok: true, text: new TextDecoder().decode(await decryptBytes(blob, pieceKey)), via: held.label }
    } catch {
      reasons.push(`${held.label}: derived a key, but it did not decrypt`)
    }
  }
  return { ok: false, why: reasons.length > 0 ? reasons.join(' · ') : 'holds no keys for this keyspace' }
}
