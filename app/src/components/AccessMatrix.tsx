import type * as Keysmith from '@filoz/keysmith'
import { useCallback, useEffect, useRef, useState } from 'react'
import { readEnvelope } from '../../../lib/fee.mjs'
import { useActivity } from '../activity.tsx'
import { type HeldKey, heldKeysOf, tryOpen } from '../agents.ts'
import { useAgents } from '../agents-context.tsx'
import { useOwner } from '../owner-context.tsx'
import { keyspacePieces, readerSynapse } from '../storage.ts'

interface Column {
  cid: string
  metadata?: Keysmith.PieceMetadata
}
type Cell = { ok: true; text: string; via: string } | { ok: false; why: string } | null
interface Row {
  label: string
  cells: Cell[]
}

/** Every reader against every piece of the current keyspace: real decryptions, or Keysmith's reason why not. */
export function AccessMatrix() {
  const { env, current, stored } = useOwner()
  const { agents, version } = useAgents()
  const activity = useActivity()
  const blobs = useRef(new Map<string, Uint8Array>())
  const [table, setTable] = useState<{ columns: Column[]; rows: Row[] } | null>(null)
  const [busy, setBusy] = useState(false)
  const [picked, setPicked] = useState<{ row: number; column: number } | null>(null)

  const check = useCallback(async () => {
    if (!env || !current || !stored) return
    setBusy(true)
    try {
      const pieces = await keyspacePieces(env.network, env.owner, current.keyspace)
      const synapse = readerSynapse(env.network, env.owner)
      const columns: Column[] = []
      for (const { cid } of pieces) {
        let blob = blobs.current.get(cid)
        if (!blob) {
          blob = await synapse.storage.download({ pieceCid: cid })
          blobs.current.set(cid, blob)
        }
        let metadata: Keysmith.PieceMetadata | undefined
        try {
          metadata = (await readEnvelope(blob)).appMetadata as Keysmith.PieceMetadata | undefined
        } catch {
          metadata = undefined
        }
        columns.push({ cid, metadata: metadata?.['foc/ks'] ? metadata : undefined })
      }
      const ownerKeys = env.keyring.keyspaces.get(current.keyspace)
      const readers: { label: string; keys: HeldKey[] }[] = [
        { label: 'You (owner)', keys: ownerKeys ? [{ key: ownerKeys.kk, holding: 'keyspace', keyspace: current.keyspace, label: 'keyspace' }] : [] },
        ...(await Promise.all(agents.map(async (agent) => ({ label: agent.name, keys: await heldKeysOf(agent) })))),
      ]
      const rows: Row[] = []
      for (const reader of readers) {
        const cells: Cell[] = []
        for (const column of columns) {
          const blob = blobs.current.get(column.cid) as Uint8Array
          cells.push(column.metadata ? await tryOpen(reader.keys, blob, column.metadata) : null)
        }
        rows.push({ label: reader.label, cells })
      }
      setTable({ columns, rows })
    } catch (err) {
      activity.fail(err)
    } finally {
      setBusy(false)
    }
    // activity.fail only appends to the log
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [env?.network, env?.owner, env?.keyring, current, stored, agents])

  useEffect(() => {
    void check()
  }, [check, version])

  if (!env) return <p className="muted">Connect a wallet to start.</p>
  if (!current || !stored) return <p className="muted">Store a first piece, or recover, in the Owner panel, then add agents: this fills in as they write.</p>
  const detail = picked && table ? { row: table.rows[picked.row], column: table.columns[picked.column], cell: table.rows[picked.row].cells[picked.column] } : null

  return (
    <div className="stack">
      <div className="row">
        <span className="muted small">
          Every piece in this keyspace. Green: a real decryption of the ciphertext Synapse fetched. Red: no key this reader holds
          reaches the piece, and Keysmith says why.
        </span>
        <button type="button" className="button ghost compact" disabled={busy} onClick={() => void check()}>
          {busy ? 'Checking…' : 'Check again'}
        </button>
      </div>
      {table ? (
        <div className="table-wrap">
          <table className="matrix">
            <thead>
              <tr>
                <th>Reader</th>
                {table.columns.map((column) => (
                  <th key={column.cid}>
                    <div className="mono" title={column.cid}>…{column.cid.slice(-8)}</div>
                    <span className="pill mono">{column.metadata ? (column.metadata['foc/scope'] ?? 'no scope') : 'other format'}</span>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {table.rows.map((row, r) => (
                <tr key={row.label}>
                  <th>{row.label}</th>
                  {row.cells.map((cell, c) => (
                    <td key={table.columns[c].cid}>
                      {cell ? (
                        <button
                          type="button"
                          className={`cell ${cell.ok ? 'cell-ok' : 'cell-no'}${picked?.row === r && picked.column === c ? ' picked' : ''}`}
                          aria-label={`${row.label}, piece …${table.columns[c].cid.slice(-8)}: ${cell.ok ? 'opens' : 'cannot open'}`}
                          onClick={() => setPicked({ row: r, column: c })}
                        >
                          {cell.ok ? '✓' : '✗'}
                        </button>
                      ) : (
                        <span className="muted">—</span>
                      )}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="muted small">{busy ? 'Fetching every piece and trying every key…' : 'Nothing checked yet.'}</p>
      )}
      {detail?.cell ? (
        <div className={`notice ${detail.cell.ok ? 'notice-ok' : 'notice-error'}`}>
          <strong>{detail.row.label}</strong>, piece <span className="mono">…{detail.column.cid.slice(-8)}</span>:{' '}
          {detail.cell.ok ? (
            <>
              opened with <span className="mono">{detail.cell.via}</span>: “{detail.cell.text}”
            </>
          ) : (
            <>cannot open it. {detail.cell.why}</>
          )}
        </div>
      ) : null}
    </div>
  )
}
