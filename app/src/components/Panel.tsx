import type { ReactNode } from 'react'

/** A numbered step of the demo: what it shows, and its content. */
export function Panel(props: { step: number; title: string; lede: string; area: string; children?: ReactNode }) {
  return (
    <section className="panel" style={{ gridArea: props.area }}>
      <header className="panel-head">
        <span className="step">{props.step}</span>
        <div>
          <h2>{props.title}</h2>
          <p className="lede">{props.lede}</p>
        </div>
      </header>
      <div className="panel-body">{props.children}</div>
    </section>
  )
}

/** Where a later phase of the build will put real content. */
export function Placeholder(props: { phase: number; children: ReactNode }) {
  return (
    <div className="placeholder">
      <span className="pill">Phase {props.phase}</span>
      <p>{props.children}</p>
    </div>
  )
}

export function Notice(props: { tone: 'info' | 'warn' | 'error' | 'ok'; children: ReactNode }) {
  return <div className={`notice notice-${props.tone}`}>{props.children}</div>
}
