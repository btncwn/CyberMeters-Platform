/**
 * CyberMeters Field Guide — the customer guide to the eight areas.
 *
 * One entry per canonical customer-facing area, in the order the product shows
 * them (founder order, 14 Oct 2026: strongest evidence first, readiness last).
 * Every entry has the same four sections so a reader always knows where to
 * look:
 *   covers   — what the area is about, in a business owner's words
 *   checks   — what CyberMeters observes from outside, why, and what it cannot see
 *   reading  — the states and findings as the product shows them, and what they mean
 *   next     — who usually makes the change, and how a fix is verified
 *
 * The guide describes the product as it is. It never claims an observation the
 * scanner does not make, and it never calls a customer's own word "verified":
 * that wording is reserved for what CyberMeters re-observed itself
 * (docs/verification-vocabulary.md).
 *
 * In-depth articles live in ./academy.js and hang off an area as deeper reading
 * through ARTICLE_AREAS below.
 */
import { ARTICLES } from './academy'

// Shared vocabulary: the coverage states every area can show, as the product
// labels them, with what each means for the reader. Areas add their own rows.
const COMMON_STATES = [
  ['Healthy', 'CyberMeters observed the evidence it needs for this area and found nothing that needs action. Healthy is only ever shown from evidence, never from the absence of evidence.'],
  ['Issue detected', 'Something observed from outside needs action. The findings below the state say what, why it matters and who usually fixes it.'],
  ['Provisional', 'A result exists but rests on partial or first-time evidence. Treat it as a first reading, not a settled one.'],
  ['Evidence insufficient', 'A check could not run or did not finish, so CyberMeters will not say whether you are protected. This is never shown as Healthy.'],
  ['Input required', 'CyberMeters needs something only you know, such as a classification or a questionnaire answer, before it can go further.'],
  ['Monitoring', 'CyberMeters is watching for change but has nothing that needs action right now.'],
  ['Not assessed', 'No completed check exists for this area yet. Run a scan, or wait for the scheduled one.'],
  ['Unavailable', 'The result could not be loaded. Refresh; if it persists, the scan did not complete.'],
]

export const GUIDE_AREAS = []

// Article slug → area key, so each article appears as deeper reading under the
// one area it belongs to. Articles not listed here are reachable by search
// only.
export const ARTICLE_AREAS = {}

export function getGuideArea(slug) {
  if (!slug) return null
  return GUIDE_AREAS.find(a => a.key === slug) || null
}

export function getGuideAreaArticles(areaKey) {
  return ARTICLES.filter(a => ARTICLE_AREAS[a.slug] === areaKey)
}

export function getGuideAreaForArticle(slug) {
  const key = ARTICLE_AREAS[slug]
  return key ? getGuideArea(key) : null
}

// The sidebar and area pages address an area by its service colour key.
export function guideSlugForColourKey(colourKey) {
  const area = GUIDE_AREAS.find(a => a.colourKey === colourKey)
  return area ? area.key : ''
}

export function guideAreaForDomainKey(domainKey) {
  return GUIDE_AREAS.find(a => a.domainKey === domainKey) || null
}

export { COMMON_STATES }
