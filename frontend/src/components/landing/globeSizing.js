// Globe sizes shared by the hero layout and the globe itself. Kept apart from
// IrisGlobe.jsx so the homepage can lay out its hero without loading the
// globe's drawing code, which arrives after the heading has painted.

// Share of the eye's radius the globe fills. A larger share gives a bigger
// world in the same eye; the pupil and its tick ring grow with it.
export const GLOBE = 0.29
export const HERO_GLOBE_MAX = 0.4

// The desktop hero has more room beside its heading as the screen widens. The
// world keeps the standard size up to 1200px and grows to its largest by
// 1300px, staying clear of the heading at every width in between.
export function heroGlobe(width) {
  const t = Math.min(1, Math.max(0, (width - 1200) / 100))
  return Math.round((GLOBE + t * (HERO_GLOBE_MAX - GLOBE)) * 100) / 100
}
