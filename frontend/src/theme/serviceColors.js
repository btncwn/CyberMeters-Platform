// ── Sea-glass domain palette — SINGLE SOURCE OF TRUTH ───────────────────────────
// The canonical Cyber MOT domains each own one soft sea-glass colour: a pastel
// fill (chip/card) and a deep ink (text) that reads at 4.5:1 on the fill and on white.
// Every surface that shows domain navigation, dashboard cards or workspace
// sections reads its colours from here so customer-facing domain presentation
// cannot drift between frontend surfaces.
//
// Fields per service:
//   icon    — strong accent for icons, active left-borders and top accents
//   text    — darker shade for eyebrows / question labels / active nav text
//   chip    — light background behind an icon (and the active nav-item background)
//   card    — soft tinted card background (landing service cards)
//   ring    — border colour that pairs with `card`
//   tint    — very light hover background (sidebar) — same as `card`
//   surface — faintest wash for LARGE areas: the routed content column behind a
//             domain's pages. Deliberately lighter than `card` so white cards
//             still pop and severity colours stay unambiguous on top of it.
export const SERVICE_COLORS = {
  email:            { icon: '#517894', text: '#2C5878', chip: '#BFD7EA', card: '#DCE9F3', ring: '#C9DDED', surface: '#F1F6FA' }, // Powder blue
  brand:            { icon: '#8C5F7C', text: '#6E3C5C', chip: '#E4C7DA', card: '#F0E0EB', ring: '#E8CFE0', surface: '#F9F3F7' }, // Lilac rose
  surface:          { icon: '#4A8476', text: '#246656', chip: '#BDE0D8', card: '#DBEEEA', ring: '#C7E5DE', surface: '#F0F8F6' }, // Sea glass
  certs:            { icon: '#557E90', text: '#2F5E72', chip: '#C7DDE8', card: '#E0ECF2', ring: '#CFE2EB', surface: '#F3F8FA' }, // Harbour
  cyber_essentials: { icon: '#608358', text: '#3B6232', chip: '#CFE5C9', card: '#E5F1E1', ring: '#D6E9D1', surface: '#F4F9F3' }, // Mint
  website:          { icon: '#7D7256', text: '#5E5232', chip: '#D9D2C0', card: '#EAE6DC', ring: '#DFD9C9', surface: '#F7F5F1' }, // Sand
  identity:         { icon: '#696699', text: '#48447E', chip: '#CDCBEA', card: '#E4E2F3', ring: '#D4D3ED', surface: '#F4F4FA' }, // Lavender
  shadow_it:        { icon: '#6E7786', text: '#4B5566', chip: '#D9DEE6', card: '#EAEDF1', ring: '#DFE3EA', surface: '#F7F8FA' }, // Slate mist
}

// `tint` is an alias of `card` — the sidebar hover state uses the same value.
for (const c of Object.values(SERVICE_COLORS)) c.tint = c.card

export const SERVICE_KEYS = Object.keys(SERVICE_COLORS)
