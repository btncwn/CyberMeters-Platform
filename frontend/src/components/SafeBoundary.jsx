import { Component } from 'react'

/**
 * SafeBoundary — isolates a non-critical widget so its render errors can never
 * take down the whole app shell. If children throw, it renders `fallback`
 * (nothing by default) and logs once for diagnostics. Used to wrap the
 * persistent workspace sidebar: a sidebar failure must degrade to "no sidebar",
 * never to a blank screen.
 */
export default class SafeBoundary extends Component {
  state = { failed: false }

  static getDerivedStateFromError() {
    return { failed: true }
  }

  componentDidCatch(error, info) {
    // Customer-safe: no raw error shown to the user; a single console line for us.
    const where = info?.componentStack?.split('\n')[1]?.trim() || ''
    console.error('[SafeBoundary] contained a render error:', error?.message, where)
  }

  render() {
    if (this.state.failed) return this.props.fallback ?? null
    return this.props.children
  }
}
