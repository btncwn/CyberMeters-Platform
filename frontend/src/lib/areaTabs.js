// The five tabs of every area page, in order. One list: the area template
// (ModuleContract) renders them, and the app shell's second top-bar row links
// to them on an area's sub-pages (S1-SHELL-V2).
export const MODULE_TABS = Object.freeze([
  // "Summary", not "Overview": the top navigation already has an Overview,
  // and one word names one place (design standard §2).
  { id: 'overview', label: 'Summary' },
  { id: 'findings', label: 'Findings' },
  { id: 'cases',    label: 'Cases' },
  { id: 'settings', label: 'Settings' },
  { id: 'guide',    label: 'Field Guide' },
])
