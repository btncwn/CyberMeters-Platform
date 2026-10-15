import { useState, useMemo } from 'react'
import { Link } from 'react-router-dom'
import { searchArticles } from '../data/academy'
import { GUIDE_AREAS, getGuideAreaForArticle } from '../data/fieldGuide'
import { SERVICE_COLORS } from '../theme/serviceColors'

// The Field Guide home: the eight areas in the order the product shows them,
// each opening a guide with the same four sections. The in-depth articles are
// reachable by search here and as deeper reading inside each area.

function AreaCard({ area, index }) {
  const colours = SERVICE_COLORS[area.colourKey]
  return (
    <Link
      to={`/guide/${area.key}`}
      className="group flex flex-col rounded-2xl border border-gray-200 bg-white hover:shadow-md transition-all overflow-hidden"
    >
      <div className="h-2" style={{ backgroundColor: colours.icon }} aria-hidden="true" />
      <div className="p-5 flex flex-col gap-2 flex-1">
        <p className="text-xs font-semibold uppercase tracking-wider" style={{ color: colours.text }}>Area {index + 1}</p>
        <h2 className="text-[19px] font-bold text-black leading-snug group-hover:text-brand-700 transition-colors">{area.title}</h2>
        <p className="text-[16px] text-black leading-relaxed">{area.summary}</p>
        <span className="mt-auto pt-2 text-[15px] font-semibold text-brand-700">Open guide →</span>
      </div>
    </Link>
  )
}

function ArticleResult({ article }) {
  const area = getGuideAreaForArticle(article.slug)
  return (
    <Link
      to={`/guide/${article.slug}`}
      className="group flex flex-col bg-white rounded-xl border border-gray-200 hover:border-brand-200 hover:shadow-sm transition-all p-4 gap-1.5"
    >
      {area && <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: SERVICE_COLORS[area.colourKey].text }}>{area.title}</span>}
      <p className="text-[16px] font-bold text-black group-hover:text-brand-700 leading-snug">{article.title}</p>
      <p className="text-xs text-black leading-relaxed line-clamp-2">{article.summary}</p>
      <span className="text-xs text-gray-600 mt-auto pt-1">{article.readTime} min read</span>
    </Link>
  )
}

export default function AcademyPage() {
  const [query, setQuery] = useState('')
  const searching = query.trim().length >= 2
  const results = useMemo(() => (searching ? searchArticles(query) : []), [query, searching])

  return (
    <div className="max-w-screen-xl mx-auto px-6 py-8">
      <div className="mb-8">
        <h1 className="text-[28px] font-bold text-black">CyberMeters Field Guide</h1>
        <p className="mt-2 text-[17px] text-black max-w-[70ch] leading-relaxed">
          One guide for each of the eight areas: what it covers, what CyberMeters checks and why, how to read your results, and what to do next. Every area follows the same four steps.
        </p>
        <div className="relative max-w-md mt-5">
          <label htmlFor="guide-search" className="sr-only">Search the Field Guide</label>
          <input
            id="guide-search"
            type="search"
            placeholder="Search articles, e.g. DMARC, HSTS, takeover…"
            value={query}
            onChange={e => setQuery(e.target.value)}
            className="w-full pl-4 pr-4 py-2.5 rounded-xl border border-gray-300 bg-white text-[16px] text-black placeholder:text-gray-500 focus:outline-none focus:ring-2 focus:ring-brand-500 focus:border-transparent"
          />
        </div>
      </div>

      {searching ? (
        <section aria-live="polite">
          <p className="text-[16px] text-black mb-4">
            {results.length === 0 ? `No articles match "${query}".` : `${results.length} article${results.length === 1 ? '' : 's'} for "${query}"`}
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {results.map(a => <ArticleResult key={a.slug} article={a} />)}
          </div>
        </section>
      ) : (
        <section>
          <h2 className="sr-only">The eight areas</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {GUIDE_AREAS.map((area, i) => <AreaCard key={area.key} area={area} index={i} />)}
          </div>
        </section>
      )}
    </div>
  )
}
