// The eight customer-facing areas in founder order (17 Oct 2026). ONE constant:
// the area sheet (AreaMenu), the Overview posture list (moduleRegistry →
// PostureCard) and the Field Guide (fieldGuide) all order themselves by it, so
// the three can never disagree. Keys are the backend's canonical domain keys.
export const AREA_ORDER = Object.freeze([
  'email_protection',
  'attack_surface',
  'website_security',
  'identity_exposure',
  'shadow_it_unmanaged_technology',
  'certificates_trust',
  'brand_protection',
  'cyber_essentials_readiness',
]);

/** Sort a list of records carrying `domainKey` into founder order; unknown keys last, stable. */
export function sortByAreaOrder(items, keyOf = (item) => item?.domainKey) {
  const rank = new Map(AREA_ORDER.map((key, index) => [key, index]));
  return [...items]
    .map((item, index) => ({ item, index }))
    .sort((a, b) => (rank.get(keyOf(a.item)) ?? AREA_ORDER.length) - (rank.get(keyOf(b.item)) ?? AREA_ORDER.length) || a.index - b.index)
    .map(({ item }) => item);
}
