import { useMemo } from 'react'
import { useParams, Link, useNavigate } from 'react-router-dom'
import {
  GraduationCap, ArrowLeft, Clock, ChevronRight,
  BookOpen, ArrowRight, Info, AlertTriangle, CheckCircle,
  Radar, Mail, Globe, Lock, Shield, Cloud,
  Users, Layers, Briefcase, Link as LinkIcon,
} from 'lucide-react'
import { getArticle, getCategoryMeta, getRelatedArticles } from '../data/academy'

// ── Icon resolver ──────────────────────────────────────────────────────────────
const ICON_MAP = {
  Radar, Mail, Globe, Lock, Shield, AlertTriangle,
  Cloud, Users, Layers, Briefcase, Link: LinkIcon,
}
function CategoryIcon({ name, className = 'w-4 h-4' }) {
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

// ── Block renderer ─────────────────────────────────────────────────────────────

function Block({ block }) {
  switch (block.type) {
    case 'list':
      return (
        <ul className="mt-3 space-y-1.5 pl-1">
          {block.items.map((item, i) => (
            <li key={i} className="flex items-start gap-2.5 text-[15px] text-gray-700 leading-relaxed">
              <span className="mt-[7px] w-1.5 h-1.5 rounded-full bg-brand-500 flex-shrink-0" />
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
                <div className="w-2.5 h-2.5 rounded-full bg-amber-400" />
                <div className="w-2.5 h-2.5 rounded-full bg-emerald-400" />
              </div>
              <span className="text-[11px] font-medium text-gray-400 ml-1 uppercase tracking-wide">{block.lang}</span>
            </div>
          )}
          <pre className="px-5 py-4 bg-gray-950 overflow-x-auto">
            <code className="text-[13px] font-mono text-gray-100 leading-relaxed whitespace-pre">
              {block.text}
            </code>
          </pre>
        </div>
      )

    case 'callout': {
      const variants = {
        info:    { bg: 'bg-blue-50 border-blue-100',   icon: <Info className="w-4 h-4 text-blue-600 flex-shrink-0 mt-0.5" />,           text: 'text-blue-900' },
        warning: { bg: 'bg-amber-50 border-amber-100', icon: <AlertTriangle className="w-4 h-4 text-amber-600 flex-shrink-0 mt-0.5" />, text: 'text-amber-900' },
        success: { bg: 'bg-emerald-50 border-emerald-100', icon: <CheckCircle className="w-4 h-4 text-emerald-600 flex-shrink-0 mt-0.5" />, text: 'text-emerald-900' },
      }
      const v = variants[block.variant] || variants.info
      return (
        <div className={`mt-4 flex gap-3 p-4 rounded-xl border ${v.bg}`}>
          {v.icon}
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
        <span className="w-6 h-6 rounded-full bg-brand-600 text-white text-[11px] font-bold flex items-center justify-center flex-shrink-0">
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
  const cat = getCategoryMeta(article.category)
  const c = COLOR_CLASSES[cat?.color] || COLOR_CLASSES.brand
  return (
    <Link
      to={`/academy/${article.slug}`}
      className="group flex items-start gap-3 p-3.5 bg-white rounded-xl border border-gray-100 hover:border-brand-200 hover:shadow-sm transition-all"
    >
      <div className={`w-8 h-8 rounded-lg ${c.bg} flex items-center justify-center flex-shrink-0`}>
        <CategoryIcon name={cat?.icon} className={`w-4 h-4 ${c.icon}`} />
      </div>
      <div className="min-w-0">
        <p className="text-sm font-semibold text-gray-800 group-hover:text-brand-600 transition-colors leading-snug line-clamp-2">
          {article.title}
        </p>
        <div className="flex items-center gap-1 mt-1">
          <Clock className="w-3 h-3 text-gray-400" />
          <span className="text-[11px] text-gray-400">{article.readTime} min</span>
        </div>
      </div>
      <ArrowRight className="w-3.5 h-3.5 text-gray-300 group-hover:text-brand-500 flex-shrink-0 mt-1 transition-colors" />
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
          className="flex items-center gap-2 text-[13px] text-gray-500 hover:text-brand-600 transition-colors py-0.5"
        >
          <span className="w-4 h-4 rounded-full bg-gray-100 text-gray-400 text-[10px] font-bold flex items-center justify-center flex-shrink-0">
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
  const navigate  = useNavigate()

  const article  = useMemo(() => getArticle(slug), [slug])
  const catMeta  = useMemo(() => article ? getCategoryMeta(article.category) : null, [article])
  const related  = useMemo(() => article ? getRelatedArticles(slug) : [], [slug, article])
  const c        = COLOR_CLASSES[catMeta?.color] || COLOR_CLASSES.brand

  if (!article) {
    return (
      <div className="max-w-screen-xl mx-auto px-6 py-16 text-center">
        <GraduationCap className="w-12 h-12 text-gray-300 mx-auto mb-4" />
        <h1 className="text-lg font-bold text-gray-900 mb-2">Article not found</h1>
        <p className="text-sm text-gray-500 mb-6">The article you're looking for doesn't exist or may have been moved.</p>
        <Link to="/academy" className="btn-primary inline-flex items-center gap-2">
          <ArrowLeft className="w-4 h-4" />
          Back to Academy
        </Link>
      </div>
    )
  }

  return (
    <div className="max-w-screen-xl mx-auto px-6 py-8">

      {/* Breadcrumb */}
      <nav className="flex items-center gap-1.5 text-[12px] text-gray-400 mb-6">
        <Link to="/academy" className="hover:text-brand-600 flex items-center gap-1 transition-colors">
          <GraduationCap className="w-3.5 h-3.5" />
          Academy
        </Link>
        <ChevronRight className="w-3.5 h-3.5" />
        <Link
          to={`/academy`}
          onClick={e => { e.preventDefault(); navigate('/academy') }}
          className="hover:text-brand-600 transition-colors"
        >
          {catMeta?.label}
        </Link>
        <ChevronRight className="w-3.5 h-3.5" />
        <span className="text-gray-600 font-medium truncate max-w-xs">{article.title}</span>
      </nav>

      <div className="flex gap-8 items-start">

        {/* ── Main content ──────────────────────────────────────────────────── */}
        <article className="flex-1 min-w-0">

          {/* Article header */}
          <div className="mb-8">
            <div className="flex items-center gap-2 mb-3 flex-wrap">
              <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-semibold ${c.badge}`}>
                <CategoryIcon name={catMeta?.icon} className="w-3 h-3" />
                {catMeta?.label}
              </span>
              {article.featured && (
                <span className="inline-flex items-center px-2.5 py-1 rounded-full text-[11px] font-semibold bg-amber-50 text-amber-700">
                  Featured
                </span>
              )}
              <span className="flex items-center gap-1 text-[12px] text-gray-400 ml-auto">
                <Clock className="w-3.5 h-3.5" />
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
              to="/academy"
              className="inline-flex items-center gap-2 text-sm text-gray-500 hover:text-brand-600 transition-colors"
            >
              <ArrowLeft className="w-4 h-4" />
              Back to Academy
            </Link>
          </div>
        </article>

        {/* ── Sidebar ───────────────────────────────────────────────────────── */}
        <aside className="w-72 flex-shrink-0 hidden lg:flex flex-col gap-6 sticky top-24">

          {/* Table of contents */}
          <div className="bg-white rounded-xl border border-gray-100 p-5">
            <h3 className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider mb-3">In this article</h3>
            <TableOfContents sections={article.sections} />
          </div>

          {/* Related articles */}
          {related.length > 0 && (
            <div className="bg-white rounded-xl border border-gray-100 p-5">
              <h3 className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider mb-3">Related articles</h3>
              <div className="space-y-2">
                {related.map(a => <RelatedCard key={a.slug} article={a} />)}
              </div>
            </div>
          )}

          {/* Back to Academy */}
          <Link
            to="/academy"
            className="flex items-center gap-2.5 px-4 py-3 bg-brand-50 hover:bg-brand-100 rounded-xl text-sm font-semibold text-brand-700 transition-colors"
          >
            <GraduationCap className="w-4 h-4" />
            Academy home
            <ArrowRight className="w-3.5 h-3.5 ml-auto" />
          </Link>
        </aside>
      </div>
    </div>
  )
}
