// One icon per module colour key, for the 72px rail and the module tiles.
// Presentation only: the module list itself is lib/moduleRegistry.js.
import { Mail, Radar, Globe, KeyRound, Boxes, ShieldCheck, Tag, ClipboardCheck } from 'lucide-react'

export const MODULE_ICONS = Object.freeze({
  email: Mail,
  surface: Radar,
  website: Globe,
  identity: KeyRound,
  shadow_it: Boxes,
  certs: ShieldCheck,
  brand: Tag,
  cyber_essentials: ClipboardCheck,
})

export function moduleIcon(colourKey) {
  return MODULE_ICONS[colourKey] || ShieldCheck
}
