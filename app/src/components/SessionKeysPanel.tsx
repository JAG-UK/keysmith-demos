import * as Keysmith from '@filoz/keysmith'
import { useState } from 'react'
import type { Address, Hex } from 'viem'
import { useReadContracts, useWriteContract } from 'wagmi'
import { useActivity } from '../activity.tsx'
import {
  agentWrite,
  decodedGrants,
  privateScopeOf,
  revokeArgs,
  SCOPE_BY_ID,
  type SessionKeyRecord,
  SHARED_SCOPE,
  shareScope,
} from '../agents.ts'
import { useAgents } from '../agents-context.tsx'
import { useOwner } from '../owner-context.tsx'
import { dataSetMetadata, readerFor } from '../storage.ts'
import { CreateKeyDialog } from './CreateKeyDialog.tsx'
import { short } from './Header.tsx'
import { Notice } from './Panel.tsx'

type Status = 'active' | 'expired' | 'revoked' | 'unknown'

export function SessionKeysPanel() {
  const { env, current, stored } = useOwner()
  const { agents } = useAgents()
  const [creating, setCreating] = useState(false)
  const [managing, setManaging] = useState<Address | null>(null)
  const registry = env?.network.chain.contracts.sessionKeyRegistry

  // Status is always read live from the chain, one read per key and scope, as the console does.
  const pairs = agents.flatMap((agent) => agent.scopes.map((scope) => ({ agent, scope })))
  const reads = useReadContracts({
    contracts: pairs.map(({ agent, scope }) => ({
      address: registry?.address,
      abi: registry?.abi,
      functionName: 'authorizationExpiry',
      args: [env?.owner, agent.sessionKeyPublic, SCOPE_BY_ID[scope].typehash],
      chainId: env?.network.chain.id,
    })) as never[],
    query: { enabled: env != null && pairs.length > 0, refetchInterval: 30_000 },
  })

  if (!env) return <p className="muted">Connect a wallet to manage session keys.</p>

  const now = BigInt(Math.floor(Date.now() / 1000))
  const statusOf = (agent: SessionKeyRecord): { status: Status; until?: Date } => {
    const expiries = pairs
      .map((pair, i) => (pair.agent === agent ? (reads.data?.[i]?.result as bigint | undefined) : null))
      .filter((each) => each !== null)
    if (expiries.some((each) => each === undefined)) return { status: 'unknown' }
    const live = (expiries as bigint[]).filter((each) => each >= now)
    if (live.length > 0) return { status: 'active', until: new Date(Number(live.reduce((a, b) => (a > b ? a : b))) * 1000) }
    return { status: (expiries as bigint[]).every((each) => each === 0n) ? 'revoked' : 'expired' }
  }

  return (
    <div className="stack">
      <p className="muted">
        Scoped, expiring signing keys for apps and agents, like API tokens that live on chain. They can never move your funds.
        Keysmith adds the other half: <strong>encryption grants</strong> that say which of your data each key can read and write.
      </p>
      {!current ? <Notice tone="info">Start or recover a keyspace in the Owner panel to give keys encryption grants.</Notice> : null}
      {current && !stored ? <Notice tone="info">Store a first piece, or recover, in the Owner panel: agents add to the same storage.</Notice> : null}
      <div className="row">
        <button type="button" className="button primary" onClick={() => setCreating(true)}>
          + New session key
        </button>
      </div>
      {agents.length === 0 ? (
        <div className="placeholder">
          <strong>No session keys yet</strong>
          <p>Create one to let an agent upload to your datasets without holding your wallet key.</p>
        </div>
      ) : (
        <div className="table-wrap">
          <table className="keys">
            <thead>
              <tr>
                <th>Name</th>
                <th>Session key</th>
                <th>Scopes</th>
                <th>Encryption grants</th>
                <th>Status</th>
                <th aria-label="Actions" />
              </tr>
            </thead>
            <tbody>
              {agents.map((agent) => {
                const { status, until } = statusOf(agent)
                const open = managing === agent.sessionKeyPublic
                return (
                  <tr key={agent.sessionKeyPublic} className={open ? 'open' : ''}>
                    <td>
                      <strong>{agent.name}</strong>
                      <div className="muted small">created {new Date(agent.createdAt).toLocaleDateString()}</div>
                    </td>
                    <td className="mono small">{short(agent.sessionKeyPublic)}</td>
                    <td className="small">
                      {agent.scopes.map((id) => SCOPE_BY_ID[id].label).join(', ')}
                      {until ? <div className="muted">until {until.toLocaleDateString()}</div> : null}
                    </td>
                    <td>
                      <div className="pills">
                        {decodedGrants(agent).map((grant) => (
                          <span key={grant.node} className="pill mono">
                            {grant.node.replace(/^scope:/, '')}
                          </span>
                        ))}
                        {agent.grants.length === 0 ? <span className="muted small">none</span> : null}
                      </div>
                    </td>
                    <td>
                      <span className={`pill status-${status}`}>{status === 'unknown' ? '…' : status}</span>
                    </td>
                    <td>
                      <button type="button" className="button ghost compact" onClick={() => setManaging(open ? null : agent.sessionKeyPublic)}>
                        {open ? 'Close' : 'Use'}
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
      {managing ? <Workbench key={managing} address={managing} active={statusOf(agents.find((a) => a.sessionKeyPublic === managing) as SessionKeyRecord).status === 'active'} onRevoked={() => reads.refetch()} /> : null}
      {creating ? <CreateKeyDialog onClose={() => setCreating(false)} /> : null}
    </div>
  )
}

/** One agent at work: write as it, share it more keys, or revoke it. */
function Workbench(props: { address: Address; active: boolean; onRevoked: () => void }) {
  const { env, current, stored } = useOwner()
  const { agents, upsert, bump } = useAgents()
  const activity = useActivity()
  const write = useWriteContract()
  const agent = agents.find((each) => each.sessionKeyPublic === props.address)
  const grants = agent ? decodedGrants(agent) : []
  const [choice, setChoice] = useState(0)
  const [text, setText] = useState(() => `${agent?.name ?? 'Agent'}'s note, ${new Date().toLocaleTimeString()}.`)
  const [busy, setBusy] = useState<string | null>(null)
  if (!env || !agent) return null

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

  const writeAs = run('write', async () => {
    if (!current || !stored) throw new Error('Nothing stored in this keyspace yet: store a first piece, or recover, in the Owner panel.')
    const grant = agent.grants[choice] as Hex
    const scope = grants[choice].node.replace(/^scope:/, '')
    activity.log(`"${agent.name}" opens its ${scope} grant, encrypts, and hands the piece to Synapse, signing as its session key. No wallet prompt.`, 'dim')
    const cid = await agentWrite(env.network, env.owner, agent, grant, dataSetMetadata(current.keyspace, current.commitment), text)
    activity.log(`"${agent.name}" wrote a piece under ${scope}: ${cid}`, 'ok')
    bump()
  })

  const missing = [SHARED_SCOPE, privateScopeOf(agent.name)].filter((scope) => !grants.some((grant) => grant.node === `scope:${scope}`))
  const share = (scope: string) =>
    run(`share:${scope}`, async () => {
      if (!current) throw new Error('No keyspace yet: start or recover one in the Owner panel.')
      const { kk } = await env.keyring.keysFor(current.keyspace)
      const grant = await shareScope(agent, kk, current.keyspace, env.owner, scope)
      upsert({ ...agent, grants: [...agent.grants, grant] })
      activity.log(`Wrapped scope:${scope} to "${agent.name}". No prompt.`, 'ok')
      bump()
    })

  const revoke = run('revoke', async () => {
    const registry = env.network.chain.contracts.sessionKeyRegistry
    activity.prompt(`send SessionKeyRegistry.revoke for "${agent.name}": it stops at once, for every scope`)
    const hash = await write.mutateAsync({
      address: registry.address,
      abi: registry.abi,
      functionName: 'revoke',
      args: revokeArgs(agent),
      chainId: env.network.chain.id,
    })
    await readerFor(env.network).waitForTransactionReceipt({ hash })
    activity.log(`"${agent.name}" is revoked on chain. It can no longer add pieces. Keys it was already given still open what they opened.`, 'ok')
    props.onRevoked()
  })

  return (
    <section className="workbench">
      <h3>
        Working as <span className="mono">{agent.name}</span>
      </h3>
      <div className="workbench-grid">
        <div className="stack">
          <strong className="small">Write a piece, as this agent</strong>
          {grants.length === 0 ? (
            <p className="muted small">It holds no grants yet.</p>
          ) : (
            <>
              <label className="field">
                <span>Under scope</span>
                <select value={choice} onChange={(event) => setChoice(Number(event.target.value))}>
                  {grants.map((grant, i) => (
                    <option key={grant.node} value={i}>
                      {grant.node}
                    </option>
                  ))}
                </select>
              </label>
              <textarea rows={2} value={text} onChange={(event) => setText(event.target.value)} />
              <div className="row">
                <button type="button" className="button primary" disabled={busy != null || !stored || !props.active} onClick={writeAs}>
                  {busy === 'write' ? 'Writing… (about a minute)' : `Write as ${agent.name}`}
                </button>
                {!props.active ? <span className="muted small">Not authorised on chain.</span> : null}
              </div>
            </>
          )}
        </div>
        <div className="stack">
          <strong className="small">Share more keys</strong>
          {missing.length === 0 ? <p className="muted small">It holds both the shared and its own scope.</p> : null}
          {missing.map((scope) => (
            <button key={scope} type="button" className="button ghost" disabled={busy != null || !current} onClick={share(scope)}>
              Grant scope:{scope}
            </button>
          ))}
          <p className="muted small">
            Its key-agreement key, which grants are wrapped to: <span className="mono">{Keysmith.publicKeyOf(agent.privateKey).slice(0, 18)}…</span>. A real
            agent would publish this.
          </p>
        </div>
        <div className="stack">
          <strong className="small">Revoke</strong>
          <p className="muted small">Immediately disables every scope of this key on chain. Encryption keys already handed over cannot be taken back.</p>
          <button type="button" className="button danger" disabled={busy != null || !props.active} onClick={revoke}>
            {busy === 'revoke' ? 'Revoking…' : 'Revoke key'}
          </button>
        </div>
      </div>
    </section>
  )
}
