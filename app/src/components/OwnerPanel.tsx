import * as Keysmith from '@filoz/keysmith'
import { useState } from 'react'
import { useActivity } from '../activity.tsx'
import { keyspaceRequest } from '../keyring.ts'
import { useOwner } from '../owner-context.tsx'
import { type RecoveredKeyspace, recover, type StepId, type StepState, storeFirstPiece } from '../owner.ts'
import { Notice } from './Panel.tsx'

const STEPS: { id: StepId; label: string }[] = [
  { id: 'encrypt', label: 'Encrypt in this tab' },
  { id: 'fund', label: 'Payment setup' },
  { id: 'upload', label: 'Synapse stores it, with copies' },
  { id: 'commit', label: 'Recorded on chain' },
]

export function OwnerPanel() {
  const { env, signatures, current, stored, setCurrent, setStored } = useOwner()
  const activity = useActivity()
  const [busy, setBusy] = useState<string | null>(null)
  const [text, setText] = useState(() => `First piece, written ${new Date().toLocaleString()}.`)
  const [steps, setSteps] = useState<Partial<Record<StepId, StepState>>>({})
  const [recovered, setRecovered] = useState<RecoveredKeyspace[] | null>(null)
  // Minted up front, so the preview shows exactly what the wallet will be asked to sign.
  const [draft, setDraft] = useState(() => Keysmith.newKeyspace())

  if (!env) return <p className="muted">Connect a wallet to start.</p>

  /** One action at a time; errors land in the activity log. */
  const run = (name: string, action: () => Promise<void>) => async () => {
    setBusy(name)
    try {
      await action()
    } catch (err) {
      activity.fail(err)
    } finally {
      setBusy(null)
    }
  }

  const startKeyspace = run('keyspace', async () => {
    const keyspace = draft
    activity.log(`New keyspace ${keyspace}: random, and with your wallet the only input to every key.`)
    const { commitment } = await env.keyring.keysFor(keyspace)
    setCurrent({ keyspace, commitment })
    setDraft(Keysmith.newKeyspace())
    setStored(false)
    setSteps({})
    activity.log(`Keyspace key derived, in this tab only. Its commitment ${commitment} is the one trace that goes on chain.`, 'ok')
  })

  const store = run('store', async () => {
    if (!current) return
    setSteps({})
    const onStep = (id: StepId, state: StepState) => setSteps((all) => ({ ...all, [id]: state }))
    try {
      const { pieceCid } = await storeFirstPiece(env, current.keyspace, text, onStep)
      setStored(true)
      activity.log(`First piece ${pieceCid} is on chain; Synapse chose the providers and the datasets.`, 'ok')
    } catch (err) {
      setSteps((all) => {
        const active = STEPS.find((step) => all[step.id]?.status === 'active')
        return active ? { ...all, [active.id]: { status: 'error' } } : all
      })
      throw err
    }
  })

  const forget = () => {
    env.keyring.forget()
    setCurrent(null)
    setStored(false)
    setRecovered(null)
    activity.log('Forgot every key in this tab, the same as a reload.')
  }

  const doRecover = run('recover', async () => {
    const found: RecoveredKeyspace[] = []
    setRecovered(found)
    await recover(env, (each) => {
      found.push(each)
      setRecovered([...found])
      // Pick up the newest keyspace, so the agents can carry on after a reload.
      if (each.keyspace && each.check === 'commitment matches') {
        const keys = env.keyring.keyspaces.get(each.keyspace)
        if (keys) setCurrent({ keyspace: each.keyspace, commitment: keys.commitment })
        setStored(true)
      }
    })
    activity.log(`Recovered ${found.length} keyspace(s). Each one not already in this tab cost one signature.`, 'ok')
  })

  return (
    <div className="stack">
      <div className="counters">
        <span>
          <strong>{signatures}</strong> Keysmith signature{signatures === 1 ? '' : 's'} this session
        </span>
        <span>
          <strong>{env.keyring.keyspaces.size}</strong> keyspace{env.keyring.keyspaces.size === 1 ? '' : 's'} held in this tab
        </span>
      </div>

      <section className="section">
        <h3>Keyspace</h3>
        {current ? (
          <dl className="kv">
            <dt>Keyspace</dt>
            <dd className="mono">{current.keyspace}</dd>
            <dt>Commitment</dt>
            <dd className="mono">{current.commitment}</dd>
          </dl>
        ) : (
          <p className="muted">
            A keyspace is 16 random bytes. Your wallet signs one message naming it, and every key is derived from that
            signature. The first time, it signs twice, so Keysmith can check your wallet always gives the same signature.
          </p>
        )}
        <div className="row">
          <button type="button" className="button primary" disabled={busy != null} onClick={startKeyspace}>
            {busy === 'keyspace' ? 'Waiting for your wallet…' : current ? 'Start another keyspace' : 'Start a keyspace'}
          </button>
        </div>
        <details>
          <summary>What your wallet will sign{current ? ' for the next keyspace' : ''}</summary>
          <pre className="code">{JSON.stringify(keyspaceRequest(env.owner, draft), null, 2)}</pre>
          <p className="muted small">
            No chain id and no contract address: the key must not depend on which network or deployment you use.
          </p>
        </details>
      </section>

      <section className="section">
        <h3>First piece</h3>
        <p className="muted small">
          Synapse picks the providers and keeps copies. The datasets it makes record the keyspace and its commitment, so
          every later write in this keyspace lands in them too. Which provider holds what can change: nothing here depends on it.
        </p>
        <label className="field">
          <span>Its first piece</span>
          <textarea rows={2} value={text} onChange={(event) => setText(event.target.value)} disabled={stored} />
        </label>
        <div className="row">
          <button
            type="button"
            className="button primary"
            disabled={busy != null || !current || stored}
            onClick={store}
          >
            {busy === 'store' ? 'Working…' : 'Encrypt and store'}
          </button>
          {!current ? <span className="muted small">Start a keyspace first.</span> : null}
        </div>
        {Object.keys(steps).length > 0 ? (
          <ol className="steps">
            {STEPS.map((step) => {
              const state = steps[step.id]
              return (
                <li key={step.id} className={`step-${state?.status ?? 'todo'}`}>
                  <span className="step-mark" aria-hidden />
                  <span>{step.label}</span>
                  {state?.detail ? <span className="muted small mono-wrap">{state.detail}</span> : null}
                </li>
              )
            })}
          </ol>
        ) : null}
        {stored ? <Notice tone="ok">Stored. The chain records the keyspace and its commitment, and nothing secret.</Notice> : null}
      </section>

      <section className="section">
        <h3>Recover from the chain</h3>
        <p className="muted">
          Forget every key, or reload the page. Then rebuild them from your wallet and the chain alone: one signature per
          keyspace, checked against its commitment before anything is decrypted.
        </p>
        <div className="row">
          <button type="button" className="button ghost" disabled={busy != null || env.keyring.keyspaces.size === 0} onClick={forget}>
            Forget keys
          </button>
          <button type="button" className="button primary" disabled={busy != null} onClick={doRecover}>
            {busy === 'recover' ? 'Recovering…' : 'Recover'}
          </button>
        </div>
        {recovered ? <Recovered keyspaces={recovered} reading={busy === 'recover'} network={env.network.label} /> : null}
      </section>
    </div>
  )
}

function Recovered(props: { keyspaces: RecoveredKeyspace[]; reading: boolean; network: string }) {
  if (props.keyspaces.length === 0) {
    return <p className="muted small">{props.reading ? 'Reading the chain…' : `This wallet pays for no datasets on ${props.network}.`}</p>
  }
  return (
    <ul className="recovered">
      {props.keyspaces.map((found) => (
        <li key={`${found.keyspace}:${found.dataSetIds.join(',')}`}>
          <div className="recovered-head">
            <strong className="mono small">{found.keyspace ?? 'No keyspace'}</strong>
            <span className={`pill ${found.check === 'commitment matches' ? 'pill-ok' : found.check === 'commitment mismatch' ? 'pill-error' : ''}`}>
              {found.check}
            </span>
            <span className="muted small">
              {found.pieces.length} piece{found.pieces.length === 1 ? '' : 's'}, listed in dataset{found.dataSetIds.length === 1 ? '' : 's'}{' '}
              {found.dataSetIds.join(', ')}
            </span>
          </div>
          <ul className="pieces">
            {found.pieces.map((piece) => (
              <li key={piece.cid}>
                <span className="mono small" title={piece.cid}>
                  …{piece.cid.slice(-10)}
                </span>
                <span className="pill">{piece.scope ?? (piece.note ? '—' : 'no scope')}</span>
                <span className={piece.text ? '' : 'muted'}>{piece.text ?? piece.note}</span>
              </li>
            ))}
          </ul>
        </li>
      ))}
    </ul>
  )
}
