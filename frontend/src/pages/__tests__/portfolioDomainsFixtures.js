// The canonical eight, in the backend's fixed order. Duplicated here deliberately:
// the frontend test must fail if the API stops sending one of them, so it cannot import
// the list from the code under test.
export const CYBER_MOT_KEYS = [
  'email_protection',
  'brand_protection',
  'attack_surface',
  'certificates_trust',
  'cyber_essentials_readiness',
  'website_security',
  'identity_exposure',
  'shadow_it_unmanaged_technology',
]
