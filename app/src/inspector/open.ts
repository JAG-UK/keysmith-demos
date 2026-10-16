/** Who in this page can open a piece or a grant, and exactly how. */
import * as Keysmith from '@filoz/keysmith'
import { decryptBytes } from '../../../lib/fee.mjs'
import { bytesToHex } from 'viem'
import type { HeldKey, SessionKeyRecord } from '../agents.ts'

export interface Reader {
  label: string
  keys: HeldKey[]
}

export type PieceOpening =
  | { reader: string; ok: true; via: string; path: string[]; preview: string }
  | { reader: string; ok: false; why: string }

const short = (hex: string) => `${hex.slice(0, 10)}…`

/** The derivation from what the reader holds down to this piece's key, one HKDF step per line. */
export function derivationPath(held: HeldKey, metadata: Keysmith.PieceMetadata): string[] {
  if (held.holding !== 'keyspace' && 'piece' in held.holding) return ['holds the piece key itself: a piece grant', 'FEE decrypts with it']
  const target = metadata['foc/scope'] ? Keysmith.scopePath(metadata['foc/scope']).split('/') : []
  const from = held.holding === 'keyspace' ? [] : Keysmith.scopePath(held.holding.scope).split('/')
  const lines = [held.holding === 'keyspace' ? `KK, the keyspace key (${short(held.keyspace)})` : `RK for scope ${from.join('/')}, from its grant`]
  const walked = [...from]
  for (const name of target.slice(from.length)) {
    walked.push(name)
    lines.push(`HKDF(·, "foc/acl/role/v1" ‖ "${name}") → RK for ${walked.join('/')}`)
  }
  lines.push(`HKDF(·, "foc/acl/piece/v1" ‖ ${short(metadata['foc/salt'])}) → PK, this piece's key`)
  lines.push('FEE decrypts with PK, and every chunk tag checks out')
  return lines
}

export async function openPiece(readers: Reader[], blob: Uint8Array, metadata: Keysmith.PieceMetadata): Promise<PieceOpening[]> {
  const results: PieceOpening[] = []
  for (const reader of readers) {
    const reasons: string[] = []
    let opened: PieceOpening | null = null
    for (const held of reader.keys) {
      if (held.keyspace !== metadata['foc/ks']) {
        reasons.push(`${held.label}: another keyspace`)
        continue
      }
      try {
        const plaintext = await decryptBytes(blob, Keysmith.keyForEnvelope(held.key, metadata, held.holding))
        opened = { reader: reader.label, ok: true, via: held.label, path: derivationPath(held, metadata), preview: preview(plaintext) }
        break
      } catch (err) {
        reasons.push(`${held.label}: ${(err as Error).message.split(';')[0]}`)
      }
    }
    results.push(opened ?? { reader: reader.label, ok: false, why: reasons.join(' · ') || 'holds no keys' })
  }
  return results
}

/** Text if it reads as text, otherwise the first bytes in hex. */
function preview(bytes: Uint8Array): string {
  const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes.subarray(0, 400))
  const printable = [...text].filter((c) => c >= ' ' || c === '\n' || c === '\t').length / Math.max(text.length, 1)
  return printable > 0.95 ? `“${text}${bytes.length > 400 ? '…' : ''}”` : `${bytes.length} B: ${bytesToHex(bytes.subarray(0, 24))}…`
}

export type GrantOpening = { agent: string; ok: true; note: string } | { agent: string; ok: false }

/** Which agent this grant is addressed to: only that agent's private key opens it. */
export async function openGrant(
  agents: SessionKeyRecord[],
  grant: Keysmith.Grant,
  commitment?: { keyspace: string; value: string }
): Promise<GrantOpening[]> {
  return Promise.all(
    agents.map(async (agent): Promise<GrantOpening> => {
      try {
        const key = await Keysmith.unwrapWith(agent.privateKey, grant)
        let note = `unwraps to a 32-byte ${grant.node === 'keyspace' ? 'keyspace' : grant.node.startsWith('piece:') ? 'piece' : 'scope'} key`
        if (grant.node === 'keyspace' && commitment?.keyspace === grant.keyspace) {
          note += Keysmith.matchesCommitment(key, commitment.value) ? ", matching the dataset's commitment" : ", which does NOT match the dataset's commitment"
        }
        return { agent: agent.name, ok: true, note }
      } catch {
        return { agent: agent.name, ok: false }
      }
    })
  )
}
