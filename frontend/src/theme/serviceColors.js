// ── Glacier domain palette — SINGLE SOURCE OF TRUTH ───────────────────────────
// The canonical Cyber MOT domains each own one cool "glacier" identity colour.
// Every surface that shows domain navigation, dashboard cards or workspace
// sections reads its colours from here so customer-facing domain presentation
// cannot drift between frontend surfaces.
//
// Fields per service:
//   icon  — strong accent for icons, active left-borders and top accents
//   text  — darker shade for eyebrows / question labels / active nav text
//   chip  — light background behind an icon (and the active nav-item background)
//   card  — soft tinted card background (landing service cards)
//   ring  — border colour that pairs with `card`
//   tint  — very light hover background (sidebar) — same as `card`
export const SERVICE_COLORS = {
  email:            { icon: '#1E5FDB', text: '#1A4FB8', chip: '#DCE8FC', card: '#EEF3FD', ring: '#D6E2FB' }, // Glacier blue
  brand:            { icon: '#0797BC', text: '#0A7592', chip: '#D5F1F8', card: '#E5F7FB', ring: '#C7EDF5' }, // Turquoise
  surface:          { icon: '#12938C', text: '#0E736D', chip: '#D6F0EC', card: '#E6F5F3', ring: '#CBEBE6' }, // Glacier teal
  certs:            { icon: '#1685C9', text: '#0F689F', chip: '#DBEDFB', card: '#E8F3FC', ring: '#CFE6F8' }, // Azure
  cyber_essentials: { icon: '#0F9F6E', text: '#0B7D56', chip: '#D9F3E8', card: '#E9F8F1', ring: '#CBEFDB' }, // Mint
  website:          { icon: '#C77C16', text: '#98600F', chip: '#F8E9CF', card: '#FCF3E4', ring: '#F4DDB7' }, // Gold
  identity:         { icon: '#5B6EE1', text: '#4656B7', chip: '#E3E7FC', card: '#F0F2FE', ring: '#D8DDFB' }, // Periwinkle
  shadow_it:        { icon: '#8A5CCB', text: '#6E46A5', chip: '#ECE3F8', card: '#F5F0FB', ring: '#E4D6F4' }, // Violet
}

// `tint` is an alias of `card` — the sidebar hover state uses the same value.
for (const c of Object.values(SERVICE_COLORS)) c.tint = c.card

export const SERVICE_KEYS = Object.keys(SERVICE_COLORS)
