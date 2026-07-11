// ── Glacier service palette — SINGLE SOURCE OF TRUTH ──────────────────────────
// The four CyberMeters services each own one cool "glacier" identity colour,
// drawn from the ice/water reference palette. Every surface that shows the four
// services — the public landing, the dashboard KPI cards, the service pages and
// the workspace sidebar — reads its colours from HERE, so the four services can
// never drift apart again (a duplicated copy in the sidebar once broke CI).
//
// Fields per service:
//   icon  — strong accent for icons, active left-borders and top accents
//   text  — darker shade for eyebrows / question labels / active nav text
//   chip  — light background behind an icon (and the active nav-item background)
//   card  — soft tinted card background (landing service cards)
//   ring  — border colour that pairs with `card`
//   tint  — very light hover background (sidebar) — same as `card`
export const SERVICE_COLORS = {
  email:   { icon: '#1E5FDB', text: '#1A4FB8', chip: '#DCE8FC', card: '#EEF3FD', ring: '#D6E2FB' }, // Glacier blue
  brand:   { icon: '#0797BC', text: '#0A7592', chip: '#D5F1F8', card: '#E5F7FB', ring: '#C7EDF5' }, // Turquoise
  surface: { icon: '#12938C', text: '#0E736D', chip: '#D6F0EC', card: '#E6F5F3', ring: '#CBEBE6' }, // Glacier teal
  certs:   { icon: '#1685C9', text: '#0F689F', chip: '#DBEDFB', card: '#E8F3FC', ring: '#CFE6F8' }, // Azure
}

// `tint` is an alias of `card` — the sidebar hover state uses the same value.
for (const c of Object.values(SERVICE_COLORS)) c.tint = c.card

export const SERVICE_KEYS = Object.keys(SERVICE_COLORS)
