import { useEffect, useMemo, useState } from 'react'
import { type Hex, hexToBytes } from 'viem'
import { describeError, useActivity } from '../activity.tsx'
import { decodedGrants, heldKeysOf } from '../agents.ts'
import { useAgents } from '../agents-context.tsx'
import { inspectBytes, type View } from '../inspector/describe.ts'
import { type GrantOpening, openGrant, openPiece, type PieceOpening, type Reader } from '../inspector/open.ts'
import { useOwner } from '../owner-context.tsx'
import { keyspacePieces, readerSynapse } from '../storage.ts'
import { Notice } from './Panel.tsx'

const SHOWN = 1536 // bytes of hex before the view trims; the fields still cover everything

/** Hex, base64 or base64url text, as bytes. */
function bytesFromText(text: string): Uint8Array {
  const clean = text.trim().replace(/\s+/g, '')
  if (/^(0x)?[0-9a-fA-F]+$/.test(clean) && clean.replace(/^0x/, '').length % 2 === 0) return hexToBytes(`0x${clean.replace(/^0x/, '')}` as Hex)
  const base64 = clean.replace(/-/g, '+').replace(/_/g, '/')
  const binary = atob(base64 + '='.repeat((4 - (base64.length % 4)) % 4))
  return Uint8Array.from(binary, (c) => c.charCodeAt(0))
}

const toBase64Url = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')

/** Reading bytes needs no wallet; only "who can open it" uses the keys this page holds. */
export function Inspector() {
  const { env, stored, current } = useOwner()
  const { agents } = useAgents()
  const activity = useActivity()
  const [input, setInput] = useState<{ bytes: Uint8Array; source: string } | null>(null)
  const [pasted, setPasted] = useState('')
  const [cid, setCid] = useState('')
  const [pieces, setPieces] = useState<string[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [active, setActive] = useState<number | null>(null)
  const [openings, setOpenings] = useState<PieceOpening[] | GrantOpening[] | null>(null)

  const view: View | null = useMemo(() => (input ? inspectBytes(input.bytes) : null), [input])
  const load = (bytes: Uint8Array, source: string) => {
    setError(null)
    setActive(null)
    setOpenings(null)
    setInput({ bytes, source })
  }
  const fail = (err: unknown) => setError(describeError(err))

  // Who can open it: every key this page holds.
  useEffect(() => {
    let live = true
    if (!view || !input || !env) return
    ;(async () => {
      if (view.kind === 'piece' && view.metadata) {
        const readers: Reader[] = [
          {
            label: 'You (owner)',
            keys: [...env.keyring.keyspaces].map(([keyspace, keys]) => ({ key: keys.kk, holding: 'keyspace' as const, keyspace, label: 'keyspace' })),
          },
          ...(await Promise.all(agents.map(async (agent) => ({ label: agent.name, keys: await heldKeysOf(agent) })))),
        ]
        const result = await openPiece(readers, input.bytes, view.metadata)
        if (live) setOpenings(result)
      } else if (view.kind === 'grant' && view.grant) {
        const result = await openGrant(agents, view.grant, current ? { keyspace: current.keyspace, value: current.commitment } : undefined)
        if (live) setOpenings(result)
      }
    })().catch((err) => live && fail(err))
    return () => {
      live = false
    }
  }, [view, input, env, agents, current])

  const fetchPiece = async (pieceCid: string) => {
    // Synapse finds a provider holding it among the datasets this wallet pays for.
    if (!env) throw new Error('Connect a wallet first: pieces are found among the datasets it pays for.')
    load(await readerSynapse(env.network, env.owner).storage.download({ pieceCid }), `piece ${pieceCid}`)
  }

  const owners = useMemo(() => {
    const byte: number[] = []
    for (const [i, f] of (view?.fields ?? []).entries()) for (let b = f.start; b < Math.min(f.end, SHOWN); b++) byte[b] = i
    return byte
  }, [view])
  const activeField = active != null ? view?.fields[active] : undefined

  return (
    <div className="stack">
      <div className="inspector-inputs">
        <label
          className="dropzone"
          onDragOver={(event) => event.preventDefault()}
          onDrop={(event) => {
            event.preventDefault()
            const file = event.dataTransfer.files[0]
            if (file) file.arrayBuffer().then((buffer) => load(new Uint8Array(buffer), file.name), fail)
          }}
        >
          <input
            type="file"
            onChange={(event) => {
              const file = event.target.files?.[0]
              if (file) file.arrayBuffer().then((buffer) => load(new Uint8Array(buffer), file.name), fail)
            }}
          />
          <span>Drop a piece or a grant here, or choose a file</span>
        </label>
        <div className="stack">
          <label className="field">
            <span>Or paste bytes (hex, base64 or base64url)</span>
            <textarea rows={2} value={pasted} onChange={(event) => setPasted(event.target.value)} placeholder="0xa7000101…" />
          </label>
          <div className="row">
            <button type="button" className="button ghost compact" disabled={!pasted.trim()} onClick={() => {
              try {
                load(bytesFromText(pasted), 'pasted bytes')
              } catch (err) {
                fail(err)
              }
            }}>
              Inspect pasted bytes
            </button>
          </div>
        </div>
        <div className="stack">
          <label className="field">
            <span>Or fetch a piece by CID</span>
            <input value={cid} onChange={(event) => setCid(event.target.value)} placeholder="bafkzcib…" />
          </label>
          <div className="row">
            <button type="button" className="button ghost compact" disabled={!cid.trim() || !env} onClick={() => fetchPiece(cid.trim()).catch(fail)}>
              Fetch with Synapse
            </button>
            {stored && current && env ? (
              <button
                type="button"
                className="button ghost compact"
                onClick={() =>
                  keyspacePieces(env.network, env.owner, current.keyspace)
                    .then((list) => setPieces(list.map((piece) => piece.cid)))
                    .catch(fail)
                }
              >
                List this keyspace's pieces
              </button>
            ) : null}
          </div>
        </div>
      </div>
      {pieces || agents.some((agent) => agent.grants.length > 0) ? (
        <div className="row">
          <span className="muted small">Quick picks:</span>
          {pieces?.map((pieceCid, i) => (
            <button key={pieceCid} type="button" className="pill pick" onClick={() => fetchPiece(pieceCid).catch(fail)}>
              piece {i}
            </button>
          ))}
          {agents.flatMap((agent) =>
            decodedGrants(agent).map((grant, i) => (
              <button key={`${agent.sessionKeyPublic}:${i}`} type="button" className="pill pick" onClick={() => load(hexToBytes(agent.grants[i]), `${agent.name}'s ${grant.node} grant`)}>
                {agent.name} · {grant.node}
              </button>
            ))
          )}
        </div>
      ) : null}
      {error ? <Notice tone="error">{error}</Notice> : null}

      {input && view ? (
        <>
          <div className="row">
            <strong>{view.kind === 'piece' ? 'A FEE-encrypted piece' : view.kind === 'grant' ? 'A Keysmith grant' : 'Unrecognised bytes'}</strong>
            <span className="muted small">
              {input.source} · {input.bytes.length} B
              {view.kind === 'piece' ? ` · ${view.algorithm} · ${view.envelopeSize} B envelope + ${input.bytes.length - view.envelopeSize} B ciphertext, ${view.chunkCount} chunk(s)` : ''}
            </span>
            {view.kind === 'grant' ? (
              <button type="button" className="button ghost compact" onClick={() => navigator.clipboard.writeText(toBase64Url(input.bytes)).then(() => activity.log('Copied the grant as base64url.', 'dim'))}>
                Copy as base64url
              </button>
            ) : null}
          </div>
          {view.kind === 'unknown' ? <Notice tone="warn">{view.reason}</Notice> : null}
          {view.kind === 'grant' && view.strictError ? <Notice tone="error">Keysmith refuses this grant: {view.strictError}</Notice> : null}
          <div className="bytes-view">
            <div className="hex" onMouseLeave={() => setActive(null)}>
              {Array.from({ length: Math.ceil(Math.min(input.bytes.length, SHOWN) / 16) }, (_, row) => (
                <div key={row} className="hex-row">
                  <span className="offset">{(row * 16).toString(16).padStart(4, '0')}</span>
                  {Array.from(input.bytes.subarray(row * 16, Math.min(row * 16 + 16, SHOWN)), (byte, i) => {
                    const at = row * 16 + i
                    const owner = owners[at]
                    const group = owner != null ? view.fields[owner].group : 'none'
                    const lit = activeField && at >= activeField.start && at < activeField.end
                    return (
                      <span key={at} className={`byte g-${group}${lit ? ' lit' : ''}`} onMouseEnter={() => setActive(owner ?? null)}>
                        {byte.toString(16).padStart(2, '0')}
                      </span>
                    )
                  })}
                </div>
              ))}
              {input.bytes.length > SHOWN ? <div className="muted small">… {input.bytes.length - SHOWN} more bytes</div> : null}
            </div>
            <ol className="fields" onMouseLeave={() => setActive(null)}>
              {view.fields.map((f, i) => (
                <li key={`${f.start}:${f.label}`} className={`g-${f.group}${active === i ? ' lit' : ''}`} style={{ paddingLeft: `${f.depth * 14 + 6}px` }} onMouseEnter={() => setActive(i)}>
                  <span className="field-name">{f.label}</span>
                  {f.value ? <span className="mono field-value">{f.value}</span> : null}
                  <span className="muted small">
                    @{f.start}–{f.end} ({f.end - f.start} B){f.note ? ` · ${f.note}` : ''}
                  </span>
                </li>
              ))}
            </ol>
          </div>
          {view.kind === 'grant' && view.aad ? (
            <p className="small">
              <span className="muted">Authenticated bytes, deterministic CBOR [v, node, owner, keyspace]: </span>
              <span className="mono-wrap">{view.aad}</span>
            </p>
          ) : null}
          {openings ? <Openings view={view} openings={openings} /> : null}
          {view.kind === 'piece' && view.metadata && env ? (
            <p className="muted small">
              Owner {view.metadata['foc/own']?.toLowerCase() === env.owner.toLowerCase() ? 'is you' : `${view.metadata['foc/own'] ?? 'not recorded'}`} ·
              keyspace {view.metadata['foc/ks'] === current?.keyspace ? 'is the one you are working in' : env.keyring.keyspaces.has(view.metadata['foc/ks']) ? 'is one you hold' : 'is not one you hold yet'}
            </p>
          ) : null}
        </>
      ) : (
        <p className="muted small">
          Try a quick pick: your agents' grants appear above once they exist, and "List this keyspace's pieces" shows what is stored.
        </p>
      )}
    </div>
  )
}

function Openings(props: { view: View; openings: PieceOpening[] | GrantOpening[] }) {
  if (props.view.kind === 'piece') {
    return (
      <div className="stack">
        <strong className="small">Who can open it</strong>
        <ul className="openings">
          {(props.openings as PieceOpening[]).map((each) => (
            <li key={each.reader} className={each.ok ? 'ok' : 'no'}>
              <strong>{each.reader}</strong>{' '}
              {each.ok ? (
                <>
                  opens it with <span className="mono">{each.via}</span>: {each.preview}
                  <ol className="path">
                    {each.path.map((step) => (
                      <li key={step} className="mono small">
                        {step}
                      </li>
                    ))}
                  </ol>
                </>
              ) : (
                <span className="muted">cannot: {each.why}</span>
              )}
            </li>
          ))}
        </ul>
      </div>
    )
  }
  const grantOpenings = props.openings as GrantOpening[]
  return (
    <div className="stack">
      <strong className="small">Who it is addressed to</strong>
      {grantOpenings.length === 0 ? <p className="muted small">No agents in this page to try it on.</p> : null}
      <ul className="openings">
        {grantOpenings.map((each) => (
          <li key={each.agent} className={each.ok ? 'ok' : 'no'}>
            <strong>{each.agent}</strong> {each.ok ? <>can open it: it {each.note}.</> : <span className="muted">cannot: it was wrapped to another key.</span>}
          </li>
        ))}
      </ul>
    </div>
  )
}

