import { useState, useMemo } from 'react'
import { Link } from 'react-router-dom'
import {
  GraduationCap, Search, Clock, ArrowRight, BookOpen,
  Radar, Mail, Globe, Lock, Shield, AlertTriangle, Cloud,
  Users, Layers, Briefcase, Link as LinkIcon,
} from 'lucide-react'
import { CATEGORIES, ARTICLES, getFeaturedArticles, searchArticles, getArticlesByCategory } from '../data/academy'

// ── Icon resolver ──────────────────────────────────────────────────────────────
const ICON_MAP = {
  Radar, Mail, Globe, Lock, Shield, AlertTriangle,
  Cloud, Users, Layers, Briefcase, Link: LinkIcon,
}

function CategoryIcon({ name, className = 'w-5 h-5' }) {
  const Icon = ICON_MAP[name] || BookOpen
  return <Icon className={className} />
}

// ── Colour helpers ─────────────────────────────────────────────────────────────
const COLOR_CLASSES = {
  brand:  { bg: 'bg-brand-50',  icon: 'text-brand-600',  badge: 'bg-brand-50 text-brand-700'  },
  blue:   { bg: 'bg-blue-50',   icon: 'text-blue-600',   badge: 'bg-blue-50 text-blue-700'    },
  indigo: { bg: 'bg-indigo-50', icon: 'text-indigo-600', badge: 'bg-indigo-50 text-indigo-700'},
  green:  { bg: 'bg-emerald-50',icon: 'text-emerald-600',badge: 'bg-emerald-50 text-emerald-700'},
  purple: { bg: 'bg-purple-50', icon: 'text-purple-600', badge: 'bg-purple-50 text-purple-700'},
  red:    { bg: 'bg-red-50',    icon: 'text-red-600',    badge: 'bg-red-50 text-red-700'      },
  cyan:   { bg: 'bg-cyan-50',   icon: 'text-cyan-600',   badge: 'bg-cyan-50 text-cyan-700'    },
  amber:  { bg: 'bg-amber-50',  icon: 'text-amber-600',  badge: 'bg-amber-50 text-amber-700'  },
  pink:   { bg: 'bg-pink-50',   icon: 'text-pink-600',   badge: 'bg-pink-50 text-pink-700'    },
  orange: { bg: 'bg-orange-50', icon: 'text-orange-600', badge: 'bg-orange-50 text-orange-700'},
  rose:   { bg: 'bg-rose-50',   icon: 'text-rose-600',   badge: 'bg-rose-50 text-rose-700'    },
}

function colorFor(slug) {
  const cat = CATEGORIES.find(c => c.slug === slug)
  return COLOR_CLASSES[cat?.color] || COLOR_CLASSES.brand
}

// ── Article card ───────────────────────────────────────────────────────────────
function ArticleCard({ article }) {
  const c = colorFor(article.category)
  const cat = CATEGORIES.find(cat => cat.slug === article.category)

  return (
    <Link
      to={`/academy/${article.slug}`}
      className="group flex flex-col bg-white rounded-xl border border-gray-100 hover:border-brand-200 hover:shadow-sm transition-all p-5 gap-3"
    >
      <div className="flex items-start justify-between gap-2">
        <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-semibold ${c.badge}`}>
          <CategoryIcon name={cat?.icon} className="w-3 h-3" />
          {cat?.label || article.category}
        </span>
        {article.featured && (
          <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-semibold bg-amber-50 text-amber-700">
            Featured
          </span>
        )}
      </div>

      <div>
        <h3 className="text-sm font-bold text-gray-900 group-hover:text-brand-600 transition-colors leading-snug">
          {article.title}
        </h3>
        <p className="text-[13px] text-gray-500 mt-1.5 leading-relaxed line-clamp-2">
          {article.summary}
        </p>
      </div>

      <div className="flex items-center gap-3 mt-auto pt-1">
        <span className="flex items-center gap-1 text-[11px] text-gray-400">
          <Clock className="w-3 h-3" />
          {article.readTime} min read
        </span>
        <span className="ml-auto flex items-center gap-1 text-[11px] font-semibold text-brand-600 opacity-0 group-hover:opacity-100 transition-opacity">
          Read <ArrowRight className="w-3 h-3" />
        </span>
      </div>
    </Link>
  )
}

// ── Featured hero card ─────────────────────────────────────────────────────────
function FeaturedCard({ article }) {
  const c = colorFor(article.category)
  const cat = CATEGORIES.find(cat => cat.slug === article.category)

  return (
    <Link
      to={`/academy/${article.slug}`}
      className="group relative flex flex-col bg-white rounded-xl border border-gray-100 hover:border-brand-200 hover:shadow-md transition-all p-6 gap-4"
    >
      <div className={`w-10 h-10 rounded-xl ${c.bg} flex items-center justify-center flex-shrink-0`}>
        <CategoryIcon name={cat?.icon} className={`w-5 h-5 ${c.icon}`} />
      </div>

      <div>
        <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase tracking-wider ${c.badge} mb-2`}>
          {cat?.label}
        </span>
        <h3 className="text-base font-bold text-gray-900 group-hover:text-brand-600 transition-colors leading-snug">
          {article.title}
        </h3>
        <p className="text-sm text-gray-500 mt-2 leading-relaxed line-clamp-3">
          {article.summary}
        </p>
      </div>

      <div className="flex items-center gap-2 mt-auto">
        <Clock className="w-3.5 h-3.5 text-gray-400" />
        <span className="text-xs text-gray-400">{article.readTime} min read</span>
        <span className="ml-auto flex items-center gap-1.5 text-xs font-semibold text-brand-600">
          Read article <ArrowRight className="w-3.5 h-3.5" />
        </span>
      </div>
    </Link>
  )
}

// ── Category pill ──────────────────────────────────────────────────────────────
function CategoryPill({ cat, active, onClick }) {
  const c = COLOR_CLASSES[cat.color] || COLOR_CLASSES.brand
  return (
    <button
      onClick={onClick}
      className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[12px] font-semibold transition-all whitespace-nowrap
        ${active
          ? `${c.badge} ring-1 ring-inset ring-current`
          : 'text-gray-500 hover:text-gray-700 hover:bg-gray-100 bg-white border border-gray-200'
        }`}
    >
      <CategoryIcon name={cat.icon} className="w-3.5 h-3.5" />
      {cat.label}
    </button>
  )
}

// ── Main page ──────────────────────────────────────────────────────────────────
export default function AcademyPage() {
  const [query, setQuery]           = useState('')
  const [activeCategory, setActive] = useState(null) // null = all

  const featured = useMemo(() => getFeaturedArticles(), [])

  const displayArticles = useMemo(() => {
    let articles = query.trim().length >= 2 ? searchArticles(query) : ARTICLES
    if (activeCategory && !query.trim()) {
      articles = articles.filter(a => a.category === activeCategory)
    }
    return articles
  }, [query, activeCategory])

  const isSearching = query.trim().length >= 2

  return (
    <div className="max-w-screen-xl mx-auto px-6 py-8">

      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-3">
          <div className="w-10 h-10 rounded-xl bg-brand-600 flex items-center justify-center">
            <GraduationCap className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-gray-900">CyberMeters Academy</h1>
            <p className="text-sm text-gray-500">Security knowledge base — findings, remediation, and detection explained.</p>
          </div>
        </div>

        {/* Search */}
        <div className="relative max-w-md mt-5">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
          <input
            type="text"
            placeholder="Search articles…"
            value={query}
            onChange={e => setQuery(e.target.value)}
            className="w-full pl-9 pr-4 py-2.5 rounded-xl border border-gray-200 bg-white text-sm text-gray-900 placeholder:text-gray-400 focus:outline-none focus:ring-2 focus:ring-brand-500 focus:border-transparent"
          />
          {query && (
            <button
              onClick={() => setQuery('')}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
            >
              ×
            </button>
          )}
        </div>
      </div>

      {/* Featured — only when not searching or filtering */}
      {!isSearching && !activeCategory && (
        <section className="mb-10">
          <h2 className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider mb-4">Featured Articles</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {featured.map(a => <FeaturedCard key={a.slug} article={a} />)}
          </div>
        </section>
      )}

      {/* Category filter */}
      {!isSearching && (
        <section className="mb-6">
          <div className="flex items-center gap-2 flex-wrap">
            <button
              onClick={() => setActive(null)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[12px] font-semibold transition-all whitespace-nowrap
                ${!activeCategory
                  ? 'bg-gray-900 text-white'
                  : 'text-gray-500 hover:text-gray-700 hover:bg-gray-100 bg-white border border-gray-200'
                }`}
            >
              All topics
            </button>
            {CATEGORIES.map(cat => (
              <CategoryPill
                key={cat.slug}
                cat={cat}
                active={activeCategory === cat.slug}
                onClick={() => setActive(activeCategory === cat.slug ? null : cat.slug)}
              />
            ))}
          </div>
        </section>
      )}

      {/* Articles grid */}
      <section>
        {isSearching && (
          <p className="text-sm text-gray-500 mb-4">
            {displayArticles.length === 0
              ? `No articles found for "${query}"`
              : `${displayArticles.length} article${displayArticles.length === 1 ? '' : 's'} for "${query}"`
            }
          </p>
        )}

        {activeCategory && !isSearching && (
          <h2 className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider mb-4">
            {CATEGORIES.find(c => c.slug === activeCategory)?.label}
            <span className="ml-2 normal-case font-normal">— {displayArticles.length} article{displayArticles.length !== 1 ? 's' : ''}</span>
          </h2>
        )}

        {!isSearching && !activeCategory && (
          <h2 className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider mb-4">All Articles</h2>
        )}

        {displayArticles.length === 0 ? (
          <div className="text-center py-16 text-gray-400">
            <BookOpen className="w-10 h-10 mx-auto mb-3 opacity-30" />
            <p className="text-sm">No articles found.</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {displayArticles.map(a => <ArticleCard key={a.slug} article={a} />)}
          </div>
        )}
      </section>
    </div>
  )
}
