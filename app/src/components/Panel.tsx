import { Component, type ReactNode } from 'react'

/** A numbered step of the demo: what it shows, and its content. */
export function Panel(props: { step?: number; title: string; lede: string; area: string; children?: ReactNode }) {
  return (
    <section className="panel" style={{ gridArea: props.area }}>
      <header className="panel-head">
        {props.step ? <span className="step">{props.step}</span> : null}
        <div>
          <h2>{props.title}</h2>
          <p className="lede">{props.lede}</p>
        </div>
      </header>
      <div className="panel-body">
        <Contained>{props.children}</Contained>
      </div>
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

/** A crash in one panel shows here, instead of blanking the page. */
export class Contained extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null }
  static getDerivedStateFromError(error: Error) {
    return { error }
  }
  render() {
    if (!this.state.error) return this.props.children
    return (
      <Notice tone="error">
        This panel hit an error: {this.state.error.message}{' '}
        <button type="button" className="button ghost" onClick={() => this.setState({ error: null })}>
          Try again
        </button>
      </Notice>
    )
  }
}
