import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

// Founder, 21 Oct 2026 (signed-in keyboard pass): every action must work
// without a mouse. These rows act on click; each now carries a real link or
// button for the same action, and each modal/drawer is a dialog that traps
// focus, closes on Escape and returns focus (lib/useDialog.js).

const src = resolve(__dirname, '..')
const read = (p) => readFileSync(resolve(src, p), 'utf8')

const ROW_CONTROLS = [
  ['pages/Dashboard.jsx', /<Link to=\{`\/scans\/\$\{scan\.id\}`\}[\s\S]{0,240}?>\{scan\.domain\}<\/Link>/],
  ['pages/DomainHistory.jsx', /<Link to=\{`\/scans\/\$\{scan\.id\}`\}[\s\S]{0,240}?aria-label=\{`Open the scan from/],
  ['pages/ScansPage.jsx', /<Link to=\{`\/scans\/\$\{scan\.id\}`\}[\s\S]{0,240}?>\{scan\.domain\}<\/Link>/],
  ['pages/AssetsPage.jsx', /<button type="button" onClick=\{\(e\) => \{ e\.stopPropagation\(\); setSelectedId\(asset\.id\) \}\}/],
  ['pages/PortfolioPage.jsx', /<button type="button" onClick=\{\(e\) => \{ e\.stopPropagation\(\); openWorkspace\(ws\) \}\}/],
  ['pages/ws/WorkspaceEmailProtectionPage.jsx', /aria-pressed=\{r\.domain === selectedDomain\}/],
  ['pages/ws/WorkspaceEmailProtectionPage.jsx', /aria-expanded=\{open\} className="mono/],
  ['pages/NotificationsPage.jsx', /<button type="button" onClick=\{\(e\) => \{ e\.stopPropagation\(\); handleClick\(\) \}\}/],
  ['components/NotificationBell.jsx', /<button type="button" onClick=\{\(e\) => \{ e\.stopPropagation\(\); handleNotifClick\(\) \}\}/],
]

const DIALOGS = [
  ['pages/AssetsPage.jsx', 'Asset detail'],
  ['pages/WorkspacesPage.jsx', 'New workspace'],
  ['pages/WorkspaceDetailPage.jsx', 'Add domain'],
  ['pages/WorkspaceDetailPage.jsx', 'Delete workspace'],
  ['pages/ws/WorkspaceAlertsPage.jsx', 'Your signing secret'],
]

describe('signed-in keyboard reachability', () => {
  it.each(ROW_CONTROLS)('%s: the row action has a keyboard-reachable control', (file, pattern) => {
    expect(read(file)).toMatch(pattern)
  })

  it.each(DIALOGS)('%s: "%s" is a keyboard dialog', (file, name) => {
    const s = read(file)
    expect(s).toMatch(new RegExp(`ref=\\{dialogRef\\} role="dialog" aria-modal="true" aria-label="${name}" tabIndex=\\{-1\\}`))
    expect(s).toMatch(/const dialogRef = useDialog\(/)
  })
})
