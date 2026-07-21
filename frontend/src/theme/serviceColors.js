// ── Glacier domain palette — SINGLE SOURCE OF TRUTH ───────────────────────────
// The canonical Cyber MOT domains each own one cool "glacier" identity colour.
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
  email:            { icon: '#1E5FDB', text: '#1A4FB8', chip: '#DCE8FC', card: '#EEF3FD', ring: '#D6E2FB', surface: '#F5F8FE' }, // Glacier blue
  brand:            { icon: '#D6488E', text: '#AE3670', chip: '#FADFEC', card: '#FCEFF6', ring: '#F6D2E4', surface: '#FEF6FA' }, // Rose (founder re-theme 21 Jul — completes the 8-swatch scale; also breaks up the blue-family crowding next to certs/surface)
  surface:          { icon: '#12938C', text: '#0E736D', chip: '#D6F0EC', card: '#E6F5F3', ring: '#CBEBE6', surface: '#F1F9F8' }, // Glacier teal
  certs:            { icon: '#1685C9', text: '#0F689F', chip: '#DBEDFB', card: '#E8F3FC', ring: '#CFE6F8', surface: '#F3F8FD' }, // Azure
  cyber_essentials: { icon: '#0F9F6E', text: '#0B7D56', chip: '#D9F3E8', card: '#E9F8F1', ring: '#CBEFDB', surface: '#F3FBF7' }, // Mint
  website:          { icon: '#C77C16', text: '#98600F', chip: '#F8E9CF', card: '#FCF3E4', ring: '#F4DDB7', surface: '#FDF9F0' }, // Gold
  identity:         { icon: '#5B6EE1', text: '#4656B7', chip: '#E3E7FC', card: '#F0F2FE', ring: '#D8DDFB', surface: '#F6F7FE' }, // Periwinkle
  shadow_it:        { icon: '#8A5CCB', text: '#6E46A5', chip: '#ECE3F8', card: '#F5F0FB', ring: '#E4D6F4', surface: '#F9F6FD' }, // Violet
}

// `tint` is an alias of `card` — the sidebar hover state uses the same value.
for (const c of Object.values(SERVICE_COLORS)) c.tint = c.card

export const SERVICE_KEYS = Object.keys(SERVICE_COLORS)
