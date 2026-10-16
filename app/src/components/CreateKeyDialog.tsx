import { useState } from 'react'
import type { Hex } from 'viem'
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import { useWriteContract } from 'wagmi'
import { describeError, useActivity } from '../activity.tsx'
import {
  EXPIRY_PRESETS,
  loginArgs,
  normalizeKeyName,
  privateScopeOf,
  SESSION_KEY_SCOPES,
  type ScopeId,
  type SessionKeyRecord,
  SHARED_SCOPE,
  shareScope,
} from '../agents.ts'
import { useAgents } from '../agents-context.tsx'
import { useOwner } from '../owner-context.tsx'
import { readerFor } from '../owner.ts'
import { Notice } from './Panel.tsx'

/**
 * The console's "New session key" flow, with Keysmith's grants added at the end.
 * One transaction (SessionKeyRegistry.login); the grants cost no prompt.
 */
export function CreateKeyDialog(props: { onClose: () => void }) {
  const { env, current } = useOwner()
  const { upsert, remove } = useAgents()
  const activity = useActivity()
  const write = useWriteContract()
  const [name, setName] = useState('')
  // These agents write pieces, so "Add pieces" starts checked (the console starts with none).
  const [scopes, setScopes] = useState<ScopeId[]>(['addPieces'])
  const [preset, setPreset] = useState(1)
  const [grantShared, setGrantShared] = useState(true)
  const [grantPrivate, setGrantPrivate] = useState(true)
  const [phase, setPhase] = useState<'form' | 'wallet' | 'pending' | 'grants' | 'done' | 'error'>('form')
  const [error, setError] = useState<string | null>(null)
  const [done, setDone] = useState<{ record: SessionKeyRecord; until: Date } | null>(null)

  if (!env) return null
  const cleanName = normalizeKeyName(name)
  const privateScope = privateScopeOf(cleanName || 'unnamed')
  const canGrant = current != null
  const canCreate = cleanName.length > 0 && scopes.length > 0 && phase === 'form'
  const registry = env.network.chain.contracts.sessionKeyRegistry

  const create = async () => {
    const privateKey: Hex = generatePrivateKey()
    const record: SessionKeyRecord = {
      name: cleanName,
      sessionKeyPublic: privateKeyToAccount(privateKey).address,
      scopes: SESSION_KEY_SCOPES.map((scope) => scope.id).filter((id) => scopes.includes(id)),
      createdAt: Date.now(),
      grants: [],
      privateKey,
    }
    const expiry = BigInt(Math.floor(Date.now() / 1000) + EXPIRY_PRESETS[preset].days * 86400)
    let listed = false
    try {
      setPhase('wallet')
      activity.prompt(`send SessionKeyRegistry.login: lets "${record.name}" (${record.sessionKeyPublic.slice(0, 10)}…) ${record.scopes.join(', ')} for ${EXPIRY_PRESETS[preset].label}`)
      const txHash = await write.mutateAsync({
        address: registry.address,
        abi: registry.abi,
        functionName: 'login',
        args: loginArgs(record, expiry),
        chainId: env.network.chain.id,
      })
      setPhase('pending')
      upsert({ ...record, txHash }) // shown at once, as the console does; removed again if it reverts
      listed = true
      const receipt = await readerFor(env.network).waitForTransactionReceipt({ hash: txHash })
      if (receipt.status !== 'success') throw new Error('The login transaction reverted.')
      listed = false // authorised on chain now: keep the record whatever happens next
      upsert({ ...record, txHash })
      activity.log(`"${record.name}" is authorised on chain for ${record.scopes.join(', ')}.`, 'ok')

      const grants: Hex[] = []
      if (canGrant && (grantShared || grantPrivate)) {
        setPhase('grants')
        const { kk } = await env.keyring.keysFor(current.keyspace)
        if (grantShared) grants.push(await shareScope(record, kk, current.keyspace, env.owner, SHARED_SCOPE))
        if (grantPrivate) grants.push(await shareScope(record, kk, current.keyspace, env.owner, privateScope))
        activity.log(`Wrapped ${grants.length} scope key(s) to "${record.name}": no prompt, the keyspace key was already in this tab.`, 'ok')
      }
      const saved = { ...record, txHash, grants }
      upsert(saved)
      setDone({ record: saved, until: new Date(Number(expiry) * 1000) })
      setPhase('done')
    } catch (err) {
      if (listed) remove(record.sessionKeyPublic)
      setError(describeError(err))
      setPhase('error')
      activity.fail(err)
    }
  }

  return (
    <dialog open className="dialog" aria-labelledby="create-key-title">
      <div className="dialog-card">
        <h3 id="create-key-title">{phase === 'done' ? 'Session key created' : 'New session key'}</h3>
        {phase === 'done' && done ? (
          <>
            <Notice tone="ok">
              ✓ <strong>{done.record.name}</strong> is now authorized with{' '}
              <strong>{done.record.scopes.join(', ')}</strong> · active until {done.until.toLocaleDateString()}
              {done.record.grants.length > 0 ? `, and holds ${done.record.grants.length} encryption grant(s)` : ''}.
            </Notice>
            <details>
              <summary>The session key, as the console shows it once</summary>
              <pre className="code">{`# Session key for Filecoin Warm Storage.\n# session address: ${done.record.sessionKeyPublic}\nSESSION_KEY=${done.record.privateKey}\nWALLET_ADDRESS=${env.owner}`}</pre>
              <p className="muted small">The console never stores this. The demo keeps it, because it also plays the agent.</p>
            </details>
            <div className="row end">
              <button type="button" className="button primary" onClick={props.onClose}>
                Done
              </button>
            </div>
          </>
        ) : (
          <>
            <p className="muted small">All selected scopes share the same expiry.</p>
            <label className="field">
              <span>Name (what is this key for?)</span>
              <input value={name} onChange={(event) => setName(event.target.value)} placeholder="e.g. alice" disabled={phase !== 'form'} />
              <span className="small">Saved on chain, so public and permanent.</span>
            </label>
            <fieldset className="field">
              <legend>Scopes</legend>
              {SESSION_KEY_SCOPES.map((scope) => (
                <label key={scope.id} className={`choice${scope.destructive ? ' destructive' : ''}`}>
                  <input
                    type="checkbox"
                    checked={scopes.includes(scope.id)}
                    disabled={phase !== 'form'}
                    onChange={(event) => setScopes((all) => (event.target.checked ? [...all, scope.id] : all.filter((id) => id !== scope.id)))}
                  />
                  <span>
                    <strong>{scope.label}</strong>
                    {scope.destructive ? <span className="pill pill-error">Destructive</span> : null}
                    <span className="muted small">{scope.description}</span>
                  </span>
                </label>
              ))}
            </fieldset>
            <label className="field">
              <span>Expiration</span>
              <select value={preset} onChange={(event) => setPreset(Number(event.target.value))} disabled={phase !== 'form'}>
                {EXPIRY_PRESETS.map((each, i) => (
                  <option key={each.label} value={i}>
                    {each.label}
                  </option>
                ))}
              </select>
              <span className="small">The key stops working on this date. Every key has to expire.</span>
            </label>
            <fieldset className="field keysmith">
              <legend>Encryption grants · Keysmith</legend>
              {canGrant ? (
                <>
                  <label className="choice">
                    <input type="checkbox" checked={grantShared} onChange={(e) => setGrantShared(e.target.checked)} disabled={phase !== 'form'} />
                    <span>
                      <strong className="mono">scope:{SHARED_SCOPE}</strong>
                      <span className="muted small">The common space every agent reads and writes.</span>
                    </span>
                  </label>
                  <label className="choice">
                    <input type="checkbox" checked={grantPrivate} onChange={(e) => setGrantPrivate(e.target.checked)} disabled={phase !== 'form'} />
                    <span>
                      <strong className="mono">scope:{privateScope}</strong>
                      <span className="muted small">This agent's own space. No other agent can open it.</span>
                    </span>
                  </label>
                  <span className="small">Wrapped to the key in this tab, about 190 bytes each. No extra wallet prompt.</span>
                </>
              ) : (
                <span className="muted small">Start or recover a keyspace in the Owner panel to grant encryption keys.</span>
              )}
            </fieldset>
            {phase === 'wallet' ? <Notice tone="info">Finish in your wallet…</Notice> : null}
            {phase === 'pending' ? <Notice tone="info">Waiting for confirmation… keep this window open.</Notice> : null}
            {phase === 'grants' ? <Notice tone="info">Wrapping encryption keys to the session key…</Notice> : null}
            {phase === 'error' ? <Notice tone="error">Authorization failed: {error}</Notice> : null}
            <div className="row end">
              <button type="button" className="button ghost" onClick={props.onClose} disabled={phase === 'wallet' || phase === 'pending' || phase === 'grants'}>
                Cancel
              </button>
              <button type="button" className="button primary" disabled={!canCreate} onClick={create}>
                Create session key
              </button>
            </div>
          </>
        )}
      </div>
    </dialog>
  )
}
