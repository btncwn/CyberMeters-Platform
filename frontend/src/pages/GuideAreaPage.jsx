import { useMemo } from 'react'
import { useParams, Link, Navigate } from 'react-router-dom'
import { GUIDE_AREAS, getGuideArea, getGuideAreaArticles } from '../data/fieldGuide'
import { SERVICE_COLORS } from '../theme/serviceColors'

// One area of the Field Guide. Every area follows the same four sections, in
// the same order, so a customer who has read one knows where to look in the
// next: what the area covers, what CyberMeters checks and why, how to read the
// results, and what to do next. Existing in-depth articles hang off the area
// as deeper reading.

const SECTIONS = [
  { id: 'covers',  heading: 'What this area covers' },
  { id: 'checks',  heading: 'What CyberMeters checks, and why' },
  { id: 'reading', heading: 'Reading your results' },
  { id: 'next',    heading: 'What to do next' },
]

function Paragraphs({ items }) {
  return items.map((text, i) => (
    <p key={i} className="mt-3 text-[16px] text-black leading-relaxed">{text}</p>
  ))
}

function Bullets({ items, colour }) {
  return (
    <ul className="mt-3 space-y-2 pl-1">
      {items.map((item, i) => (
        <li key={i} className="flex items-start gap-2.5 text-[16px] text-black leading-relaxed">
          <span className="mt-[9px] w-1.5 h-1.5 rounded-full shrink-0" style={{ backgroundColor: colour }} aria-hidden="true" />
          <span>{item}</span>
        </li>
      ))}
    </ul>
  )
}

function Labelled({ label, children }) {
  return (
    <div className="mt-5">
      <h3 className="text-[17px] font-bold text-black">{label}</h3>
      {children}
    </div>
  )
}

// Status words as the product shows them, each with what it means for you.
function StateTable({ rows, colours }) {
  return (
    <div className="mt-3 overflow-x-auto rounded-xl border border-gray-200">
      <table className="w-full border-collapse text-[16px] min-w-[520px]">
        <thead>
          <tr className="text-left text-xs uppercase tracking-wider" style={{ backgroundColor: colours.surface }}>
            <th className="px-4 py-2.5 font-semibold">You see</th>
            <th className="px-4 py-2.5 font-semibold">It means</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(([state, meaning]) => (
            <tr key={state}>
              <td className="px-4 py-3 border-t border-gray-200 font-semibold whitespace-nowrap align-top">{state}</td>
              <td className="px-4 py-3 border-t border-gray-200 align-top">{meaning}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function ArticleCard({ article }) {
  return (
    <Link
      to={`/guide/${article.slug}`}
      className="group flex flex-col bg-white rounded-xl border border-gray-200 hover:border-brand-200 hover:shadow-xs transition-all p-4 gap-1.5"
    >
      <p className="text-[16px] font-bold text-black group-hover:text-brand-700 leading-snug">{article.title}</p>
      <p className="text-xs text-black leading-relaxed line-clamp-2">{article.summary}</p>
      <span className="text-xs text-gray-600 mt-auto pt-1">{article.readTime} min read</span>
    </Link>
  )
}

export default function GuideAreaPage() {
  const { slug } = useParams()
  const area = useMemo(() => getGuideArea(slug), [slug])
  const articles = useMemo(() => (area ? getGuideAreaArticles(area.key) : []), [area])
  if (!area) return <Navigate to="/guide" replace />
  const colours = SERVICE_COLORS[area.colourKey]
  const index = GUIDE_AREAS.findIndex(a => a.key === area.key)
  const previous = GUIDE_AREAS[index - 1]
  const next = GUIDE_AREAS[index + 1]

  return (
    <div className="max-w-(--breakpoint-xl) mx-auto px-6 py-8">
      <nav className="flex items-center gap-1.5 text-xs text-black mb-6" aria-label="Breadcrumb">
        <Link to="/guide" className="hover:text-brand-700 transition-colors">Field Guide</Link>
        <span aria-hidden="true">/</span>
        <span className="font-semibold">{area.title}</span>
      </nav>

      <div className="flex gap-8 items-start">
        <article className="flex-1 min-w-0">
          <header className="mb-8 rounded-2xl p-6" style={{ backgroundColor: colours.card, borderLeft: `4px solid ${colours.icon}` }}>
            <p className="text-xs font-semibold uppercase tracking-wider" style={{ color: colours.text }}>
              Area {index + 1} of {GUIDE_AREAS.length}
            </p>
            <h1 className="mt-1 text-[28px] font-bold text-black leading-tight">{area.title}</h1>
            <p className="mt-3 text-[17px] text-black leading-relaxed max-w-[70ch]">{area.intro}</p>
            <div className="mt-4 flex flex-wrap gap-3">
              <Link to={area.route} className="btn-primary">Open {area.shortTitle} in your workspace</Link>
            </div>
          </header>

          {/* 1. Covers */}
          <section id="covers" className="mb-10">
            <h2 className="text-[21px] font-bold text-black">1. {SECTIONS[0].heading}</h2>
            <Paragraphs items={area.covers} />
          </section>

          {/* 2. Checks */}
          <section id="checks" className="mb-10">
            <h2 className="text-[21px] font-bold text-black">2. {SECTIONS[1].heading}</h2>
            <Paragraphs items={area.checks.why} />
            <Labelled label="What CyberMeters observes from outside">
              <Bullets items={area.checks.observed} colour={colours.icon} />
            </Labelled>
            <Labelled label="What CyberMeters cannot see">
              <Bullets items={area.checks.notObserved} colour="#6B7280" />
            </Labelled>
          </section>

          {/* 3. Reading */}
          <section id="reading" className="mb-10">
            <h2 className="text-[21px] font-bold text-black">3. {SECTIONS[2].heading}</h2>
            <Paragraphs items={area.reading.intro} />
            <StateTable rows={area.reading.states} colours={colours} />
            {area.reading.findings?.length > 0 && (
              <Labelled label="Findings you are most likely to see">
                <Bullets items={area.reading.findings} colour={colours.icon} />
              </Labelled>
            )}
          </section>

          {/* 4. Next */}
          <section id="next" className="mb-10">
            <h2 className="text-[21px] font-bold text-black">4. {SECTIONS[3].heading}</h2>
            <Paragraphs items={area.next.intro} />
            <Labelled label="Who usually makes the change">
              <Bullets items={area.next.owners} colour={colours.icon} />
            </Labelled>
            <Labelled label="How a fix is verified">
              <Paragraphs items={area.next.verification} />
            </Labelled>
          </section>

          {articles.length > 0 && (
            <section id="deeper" className="mb-10">
              <h2 className="text-[21px] font-bold text-black">Deeper reading</h2>
              <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-4">
                {articles.map(a => <ArticleCard key={a.slug} article={a} />)}
              </div>
            </section>
          )}

          <nav className="mt-10 pt-6 border-t border-gray-200 flex flex-wrap justify-between gap-4 text-[16px]" aria-label="Other areas">
            {previous ? <Link to={`/guide/${previous.key}`} className="font-semibold text-brand-700 hover:underline">← {previous.title}</Link> : <span />}
            {next ? <Link to={`/guide/${next.key}`} className="font-semibold text-brand-700 hover:underline">{next.title} →</Link> : <span />}
          </nav>
        </article>

        <aside className="w-72 shrink-0 hidden lg:flex flex-col gap-6 sticky top-[160px]">
          <div className="bg-white rounded-xl border border-gray-200 p-5">
            <h3 className="text-xs font-semibold uppercase tracking-wider mb-3">On this page</h3>
            <nav className="space-y-1.5">
              {SECTIONS.map((s, i) => (
                <a key={s.id} href={`#${s.id}`} className="flex items-center gap-2 text-[15px] text-black hover:text-brand-700 transition-colors">
                  <span className="w-5 h-5 rounded-full text-xs font-bold flex items-center justify-center shrink-0" style={{ backgroundColor: colours.chip, color: colours.text }}>{i + 1}</span>
                  {s.heading}
                </a>
              ))}
              {articles.length > 0 && (
                <a href="#deeper" className="flex items-center gap-2 text-[15px] text-black hover:text-brand-700 transition-colors">
                  <span className="w-5 h-5 rounded-full bg-gray-100 text-xs font-bold flex items-center justify-center shrink-0">+</span>
                  Deeper reading
                </a>
              )}
            </nav>
          </div>
          <div className="bg-white rounded-xl border border-gray-200 p-5">
            <h3 className="text-xs font-semibold uppercase tracking-wider mb-3">All eight areas</h3>
            <ol className="space-y-1.5">
              {GUIDE_AREAS.map((a, i) => (
                <li key={a.key}>
                  <Link to={`/guide/${a.key}`} className={`flex items-center gap-2 text-[15px] hover:text-brand-700 transition-colors ${a.key === area.key ? 'font-bold' : ''}`}>
                    <span className="w-5 text-xs text-gray-600">{i + 1}</span>{a.title}
                  </Link>
                </li>
              ))}
            </ol>
          </div>
        </aside>
      </div>
    </div>
  )
}
