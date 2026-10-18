import { createContext, type ReactNode, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'

export type Tone = 'info' | 'ok' | 'warn' | 'error' | 'prompt' | 'dim'
interface Entry {
  id: number
  at: Date
  text: string
  tone: Tone
  href?: string
}

export interface Activity {
  entries: Entry[]
  log: (text: string, tone?: Tone, href?: string) => void
  /** Say what the wallet is about to ask for, before it asks. */
  prompt: (text: string) => void
  fail: (err: unknown) => void
}

const ActivityContext = createContext<Activity | null>(null)

export function ActivityProvider(props: { children: ReactNode }) {
  const [entries, setEntries] = useState<Entry[]>([])
  const next = useRef(0)
  const log = useCallback((text: string, tone: Tone = 'info', href?: string) => {
    const entry = { id: next.current++, at: new Date(), text, tone, href }
    setEntries((all) => [...all.slice(-199), entry])
  }, [])
  const value = useMemo<Activity>(
    () => ({
      entries,
      log,
      prompt: (text) => log(`Your wallet will ask you to ${text}`, 'prompt'),
      fail: (err) => {
        console.error(err)
        log(describeError(err), 'error')
      },
    }),
    [entries, log]
  )
  return <ActivityContext.Provider value={value}>{props.children}</ActivityContext.Provider>
}

export function useActivity(): Activity {
  const activity = useContext(ActivityContext)
  if (!activity) throw new Error('useActivity outside ActivityProvider')
  return activity
}

/** A wallet rejection reads as one plain sentence; anything else as its shortest message. */
export function describeError(err: unknown): string {
  for (let e = err as { code?: number; cause?: unknown } | undefined; e; e = e.cause as typeof e) {
    if (e.code === 4001) return 'Rejected in your wallet. Nothing was signed or sent.'
  }
  const e = err as { shortMessage?: string; message?: string; details?: string }
  const detail = e?.details ? ` (${e.details})` : ''
  const message = `${e?.shortMessage ?? e?.message ?? String(err)}${detail}`
  return `${message}${walletAdvice(message)}`
}

/** The two ways a wallet can't root a keyspace, said in terms of the wallet. */
function walletAdvice(message: string): string {
  if (/64- or 65-byte/.test(message)) {
    return ' This looks like a smart-contract or passkey wallet (Safe, a smart account): Keysmith needs a plain ECDSA account, such as MetaMask, a Ledger, or Rabby.'
  }
  if (/not deterministic/.test(message)) {
    return ' This wallet adds randomness to its signatures, so the same message never gives the same key twice. Use a wallet that signs deterministically (RFC 6979), such as MetaMask or a Ledger.'
  }
  return ''
}

export function ActivityLog() {
  const { entries } = useActivity()
  const end = useRef<HTMLLIElement>(null)
  useEffect(() => {
    end.current?.scrollIntoView({ block: 'nearest' })
  }, [entries.length])
  if (entries.length === 0) return <p className="muted">Nothing yet. Every wallet prompt is announced here before it appears.</p>
  return (
    <ol className="activity">
      {entries.map((entry) => (
        <li key={entry.id} className={`tone-${entry.tone}`}>
          <time>{entry.at.toLocaleTimeString()}</time>
          <span>
            {entry.text}
            {entry.href ? (
              <>
                {' '}
                <a href={entry.href} target="_blank" rel="noreferrer">
                  {entry.href}
                </a>
              </>
            ) : null}
          </span>
        </li>
      ))}
      <li ref={end} aria-hidden className="activity-end" />
    </ol>
  )
}
