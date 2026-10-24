import { useMemo } from 'react'
import { useParams, Link, Navigate } from 'react-router-dom'
import { getArticle, getCategoryMeta, getRelatedArticles } from '../data/academy'
import { getGuideAreaForArticle } from '../data/fieldGuide'

// ── Colour helpers ─────────────────────────────────────────────────────────────
const COLOR_CLASSES = {
  brand:  { badge: 'bg-brand-50 text-brand-700' },
  blue:   { badge: 'bg-blue-50 text-blue-700' },
  indigo: { badge: 'bg-indigo-50 text-indigo-700' },
  green:  { badge: 'bg-brand-200 text-brand-900' },
  purple: { badge: 'bg-purple-50 text-purple-700' },
  red:    { badge: 'bg-red-50 text-red-700' },
  cyan:   { badge: 'bg-cyan-50 text-cyan-700' },
  amber:  { badge: 'bg-transparent text-brand-700' },
  pink:   { badge: 'bg-pink-50 text-pink-700' },
  orange: { badge: 'bg-red-50 text-red-700' },
  rose:   { badge: 'bg-rose-50 text-rose-700' },
}

// ── Block renderer ─────────────────────────────────────────────────────────────

function Block({ block }) {
  switch (block.type) {
    case 'list':
      return (
        <ul className="mt-3 space-y-1.5 pl-1">
          {block.items.map((item, i) => (
            <li key={i} className="flex items-start gap-2.5 text-[15px] text-gray-700 leading-relaxed">
              <span className="mt-[7px] w-1.5 h-1.5 rounded-full bg-brand-500 shrink-0" />
              {item}
            </li>
          ))}
        </ul>
      )

    case 'code':
      return (
        <div className="mt-4 rounded-xl overflow-hidden border border-gray-200">
          {block.lang && (
            <div className="px-4 py-2 bg-gray-100 border-b border-gray-200 flex items-center gap-2">
              <div className="flex gap-1.5">
                <div className="w-2.5 h-2.5 rounded-full bg-red-400" />
                <div className="w-2.5 h-2.5 rounded-full bg-brand-700" />
                <div className="w-2.5 h-2.5 rounded-full bg-brand-700" />
              </div>
              <span className="text-xs font-medium text-gray-400 ml-1 uppercase tracking-wide">{block.lang}</span>
            </div>
          )}
          <pre className="px-5 py-4 bg-gray-950 overflow-x-auto">
            <code className="text-[14px] font-mono text-white/80 leading-relaxed whitespace-pre">
              {block.text}
            </code>
          </pre>
        </div>
      )

    case 'callout': {
      const variants = {
        info:    { bg: 'bg-blue-50 border-blue-100',   text: 'text-blue-900' },
        warning: { bg: 'bg-transparent border-[1.5px] border-brand-700', text: 'text-brand-700' },
        success: { bg: 'bg-brand-200 border-brand-200', text: 'text-brand-900' },
      }
      const v = variants[block.variant] || variants.info
      return (
        <div className={`mt-4 flex gap-3 p-4 rounded-xl border ${v.bg}`}>
          <p className={`text-[14px] leading-relaxed ${v.text}`}>{block.text}</p>
        </div>
      )
    }

    case 'para':
    default:
      return <p className="mt-3 text-[15px] text-gray-700 leading-relaxed">{block.text}</p>
  }
}

// ── Section renderer ───────────────────────────────────────────────────────────
function Section({ section, index }) {
  return (
    <div className="mb-8">
      <div className="flex items-center gap-3 mb-2">
        <span className="w-6 h-6 rounded-full bg-brand-200 text-brand-900 text-xs font-bold flex items-center justify-center shrink-0">
          {index + 1}
        </span>
        <h2 className="text-base font-bold text-gray-900">{section.heading}</h2>
      </div>
      <div className="pl-9">
        {section.blocks.map((block, i) => (
          <Block key={i} block={block} />
        ))}
      </div>
    </div>
  )
}

// ── Related article mini-card ──────────────────────────────────────────────────
function RelatedCard({ article }) {
  return (
    <Link
      to={`/guide/${article.slug}`}
      className="group flex items-start gap-3 p-3.5 bg-white rounded-xl border border-gray-100 hover:border-brand-200 hover:shadow-xs transition-all"
    >
      <div className="min-w-0">
        <p className="text-sm font-semibold text-gray-800 group-hover:text-brand-800 transition-colors leading-snug line-clamp-2">
          {article.title}
        </p>
        <div className="flex items-center gap-1 mt-1">
          <span className="text-xs text-gray-400">{article.readTime} min</span>
        </div>
      </div>
    </Link>
  )
}

// ── Table of Contents ──────────────────────────────────────────────────────────
function TableOfContents({ sections }) {
  return (
    <nav className="space-y-1">
      {sections.map((s, i) => (
        <a
          key={i}
          href={`#section-${i}`}
          className="flex items-center gap-2 text-[14px] text-gray-500 hover:text-brand-800 transition-colors py-0.5"
        >
          <span className="w-4 h-4 rounded-full bg-gray-100 text-gray-400 text-xs font-bold flex items-center justify-center shrink-0">
            {i + 1}
          </span>
          {s.heading}
        </a>
      ))}
    </nav>
  )
}

// ── Main page ──────────────────────────────────────────────────────────────────
export default function AcademyArticlePage() {
  const { slug } = useParams()

  const article  = useMemo(() => getArticle(slug), [slug])
  const catMeta  = useMemo(() => article ? getCategoryMeta(article.category) : null, [article])
  const related  = useMemo(() => article ? getRelatedArticles(slug) : [], [slug, article])
  const area     = useMemo(() => article ? getGuideAreaForArticle(article.slug) : null, [article])
  const c        = COLOR_CLASSES[catMeta?.color] || COLOR_CLASSES.brand

  // An earlier slug still opens the article, at its current address.
  if (article && article.slug !== slug) return <Navigate to={`/guide/${article.slug}`} replace />

  if (!article) {
    return (
      <div className="max-w-(--breakpoint-xl) mx-auto px-6 py-16 text-center">
        <h1 className="text-lg font-bold text-gray-900 mb-2">Article not found</h1>
        <p className="text-sm text-gray-500 mb-6">The article you're looking for doesn't exist or may have been moved.</p>
        <Link to="/guide" className="btn-primary inline-flex items-center gap-2">
          Back to Field Guide
        </Link>
      </div>
    )
  }

  return (
    <div className="max-w-(--breakpoint-xl) mx-auto px-6 py-8">

      {/* Breadcrumb */}
      <nav className="flex items-center gap-1.5 text-xs text-gray-400 mb-6">
        <Link to="/guide" className="hover:text-brand-800 flex items-center gap-1 transition-colors">
          Field Guide
        </Link>
        <span aria-hidden="true">/</span>
        {/* A product article (e.g. AI assistant access) has no area: no empty step. */}
        {area && (
          <>
            <Link to={`/guide/${area.key}`} className="hover:text-brand-800 transition-colors">
              {area.title}
            </Link>
            <span aria-hidden="true">/</span>
          </>
        )}
        <span className="text-gray-600 font-medium truncate max-w-xs">{article.title}</span>
      </nav>

      <div className="flex gap-8 items-start">

        {/* ── Main content ──────────────────────────────────────────────────── */}
        <article className="flex-1 min-w-0">

          {/* Article header */}
          <div className="mb-8">
            <div className="flex items-center gap-2 mb-3 flex-wrap">
              <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold ${c.badge}`}>
                {catMeta?.label}
              </span>
              {article.featured && (
                <span className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-semibold bg-transparent text-brand-700">
                  Featured
                </span>
              )}
              <span className="flex items-center gap-1 text-xs text-gray-400 ml-auto">
                {article.readTime} min read
              </span>
            </div>

            <h1 className="text-2xl font-bold text-gray-900 leading-snug mb-4">{article.title}</h1>

            {/* Executive summary */}
            <div className="bg-gray-50 rounded-xl border border-gray-100 p-5">
              <p className="text-[15px] text-gray-700 leading-relaxed">{article.summary}</p>
            </div>
          </div>

          {/* Sections */}
          <div>
            {article.sections.map((section, i) => (
              <div key={i} id={`section-${i}`}>
                <Section section={section} index={i} />
                {i < article.sections.length - 1 && (
                  <hr className="border-gray-100 my-6" />
                )}
              </div>
            ))}
          </div>

          {/* Back link */}
          <div className="mt-10 pt-6 border-t border-gray-100">
            <Link
              to={area ? `/guide/${area.key}` : '/guide'}
              className="cm-backlink inline-flex items-center gap-2 text-sm"
            >
              {area ? `Back to ${area.title}` : 'Back to Field Guide'}
            </Link>
          </div>
        </article>

        {/* ── Sidebar ───────────────────────────────────────────────────────── */}
        <aside className="w-72 shrink-0 hidden lg:flex flex-col gap-6 sticky top-24">

          {/* Table of contents */}
          <div className="bg-white rounded-xl border border-gray-100 p-5">
            <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">In this article</h3>
            <TableOfContents sections={article.sections} />
          </div>

          {/* Related articles */}
          {related.length > 0 && (
            <div className="bg-white rounded-xl border border-gray-100 p-5">
              <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">Related articles</h3>
              <div className="space-y-2">
                {related.map(a => <RelatedCard key={a.slug} article={a} />)}
              </div>
            </div>
          )}

          {/* Back to Field Guide */}
          <Link
            to="/guide"
            className="flex items-center gap-2.5 px-4 py-3 bg-brand-50 hover:bg-brand-100 rounded-xl text-sm font-semibold text-brand-700 transition-colors"
          >
            Field Guide home
          </Link>
        </aside>
      </div>
    </div>
  )
}
