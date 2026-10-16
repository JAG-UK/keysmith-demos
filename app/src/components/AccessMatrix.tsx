import type * as Keysmith from '@filoz/keysmith'
import { useCallback, useEffect, useRef, useState } from 'react'
import { readEnvelope } from '../../../lib/fee.mjs'
import { getPiece, listPiecesOnChain } from '../../../lib/store.mjs'
import { useActivity } from '../activity.tsx'
import { type HeldKey, heldKeysOf, tryOpen } from '../agents.ts'
import { useAgents } from '../agents-context.tsx'
import { useOwner } from '../owner-context.tsx'
import { readerFor } from '../owner.ts'

interface Column {
  id: bigint
  cid: string
  metadata?: Keysmith.PieceMetadata
}
type Cell = { ok: true; text: string; via: string } | { ok: false; why: string } | null
interface Row {
  label: string
  cells: Cell[]
}

/** Every reader against every piece of the current dataset: real decryptions, or Keysmith's reason why not. */
export function AccessMatrix() {
  const { env, dataSet } = useOwner()
  const { agents, version } = useAgents()
  const activity = useActivity()
  const blobs = useRef(new Map<string, Uint8Array>())
  const [table, setTable] = useState<{ columns: Column[]; rows: Row[] } | null>(null)
  const [busy, setBusy] = useState(false)
  const [picked, setPicked] = useState<{ row: number; column: number } | null>(null)

  const check = useCallback(async () => {
    if (!env || !dataSet || !env.network.sp) return
    const sp = env.network.sp
    setBusy(true)
    try {
      const pieces = await listPiecesOnChain(readerFor(env.network), dataSet.id)
      const columns: Column[] = []
      for (const piece of pieces) {
        let blob = blobs.current.get(piece.pieceCid)
        if (!blob) {
          blob = await getPiece(sp.serviceURL, piece.pieceCid)
          blobs.current.set(piece.pieceCid, blob)
        }
        let metadata: Keysmith.PieceMetadata | undefined
        try {
          metadata = (await readEnvelope(blob)).appMetadata as Keysmith.PieceMetadata | undefined
        } catch {
          metadata = undefined
        }
        columns.push({ id: piece.pieceId, cid: piece.pieceCid, metadata: metadata?.['foc/ks'] ? metadata : undefined })
      }
      const ownerKeys = env.keyring.keyspaces.get(dataSet.keyspace)
      const readers: { label: string; keys: HeldKey[] }[] = [
        { label: 'You (owner)', keys: ownerKeys ? [{ key: ownerKeys.kk, holding: 'keyspace', keyspace: dataSet.keyspace, label: 'keyspace' }] : [] },
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
  }, [env?.network, env?.keyring, dataSet, agents])

  useEffect(() => {
    void check()
  }, [check, version])

  if (!env) return <p className="muted">Connect a wallet to start.</p>
  if (!dataSet) return <p className="muted">Create or recover a dataset in the Owner panel, then add agents: this fills in as they write.</p>
  const detail = picked && table ? { row: table.rows[picked.row], column: table.columns[picked.column], cell: table.rows[picked.row].cells[picked.column] } : null

  return (
    <div className="stack">
      <div className="row">
        <span className="muted small">
          Dataset {dataSet.id.toString()}. Green: a real decryption of the ciphertext fetched from the SP. Red: no key this reader holds
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
                    <div>piece {column.id.toString()}</div>
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
                          aria-label={`${row.label}, piece ${table.columns[c].id}: ${cell.ok ? 'opens' : 'cannot open'}`}
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
          <strong>{detail.row.label}</strong>, piece {detail.column.id.toString()}:{' '}
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
