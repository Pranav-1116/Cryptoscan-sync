/* ErrorBoundary — keeps one page's render error from blanking the console.
 *
 * Without this, any exception thrown while rendering a lazy page unmounts the
 * whole React tree and the operator is left with a white screen and no way
 * back short of reloading. A console whose job is incident response should not
 * fail that way, so the error is caught here, shown with enough detail to
 * report it, and the rest of the shell (nav, other routes) stays usable.
 *
 * Only render errors are caught: React error boundaries do not see errors from
 * event handlers, async callbacks or the realtime stream. Those paths surface
 * their own errors through the page-level hooks (useLive / usePollingApi).
 */
import React from "react";

type Props = {
  children: React.ReactNode;
  /** Changing this resets the boundary — pass the route path so navigating away clears a stuck error. */
  resetKey?: string;
};

type State = { error: Error | null };

export default class ErrorBoundary extends React.Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    // Keep the component stack: the message alone rarely identifies the page.
    console.error("page render failed", error, info.componentStack);
  }

  componentDidUpdate(prev: Props) {
    if (prev.resetKey !== this.props.resetKey && this.state.error) {
      this.setState({ error: null });
    }
  }

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;
    return (
      <div style={{ padding: 24, maxWidth: 720 }}>
        <h2 style={{ margin: "0 0 8px" }}>This page failed to render</h2>
        <p style={{ margin: "0 0 16px", opacity: 0.8 }}>
          The rest of the console is still usable — pick another page from the
          navigation, or retry this one.
        </p>
        <pre
          style={{
            whiteSpace: "pre-wrap",
            wordBreak: "break-word",
            padding: 12,
            borderRadius: "var(--r)",
            background: "color-mix(in srgb, var(--violet) 12%, transparent)",
            fontSize: 12,
          }}
        >
          {error.message || String(error)}
        </pre>
        <button style={{ marginTop: 12 }} onClick={() => this.setState({ error: null })}>
          Retry
        </button>
      </div>
    );
  }
}


/**
 * PanelErrorBoundary — one panel's render failure must not blank the page.
 *
 * Charts, tables and graph views are independent panels; a bug in one is a
 * bug in ONE. The fallback says which panel failed, keeps the rest of the
 * page live, and offers a retry (render errors are often transient data
 * shapes). Mounted inside ui.tsx `Panel`, so every panel on every page is
 * isolated without per-page wiring.
 */
export class PanelErrorBoundary extends React.Component<
  { children: React.ReactNode; label?: string },
  { error: Error | null }
> {
  state: { error: Error | null } = { error: null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error("panel render failed", error, info.componentStack);
  }

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;
    return (
      <div role="alert" style={{ padding: 14, fontSize: 12.5, color: "var(--dim)" }}>
        <strong style={{ color: "var(--text)" }}>
          {this.props.label ? `“${this.props.label}”` : "This panel"} failed to render.
        </strong>{" "}
        The rest of the page is still live.
        <button
          type="button"
          className="btn outline"
          style={{ marginLeft: 10, padding: "3px 10px", fontSize: 12 }}
          onClick={() => this.setState({ error: null })}
        >
          Retry
        </button>
      </div>
    );
  }
}
