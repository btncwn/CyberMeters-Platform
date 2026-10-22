import { describe, it, expect } from 'vitest'
import { ARTICLES, getArticle } from '../../data/academy'

describe('Academy content', () => {
  it('never narrows the audience to small businesses', () => {
    const text = JSON.stringify(ARTICLES.map(({ aliases, ...article }) => article))
    expect(text).not.toMatch(/small business|small compan|small teams|startups|digital agencies|UK SMB/i)
  })

  it('opens the DMARC impersonation article by its current and earlier address', () => {
    const article = getArticle('dmarc-stop-email-impersonation')
    expect(article?.title).toBe('DMARC: stop criminals sending email as your business')
    expect(getArticle('dmarc-explained-for-uk-small-businesses')).toBe(article)
    expect(getArticle('no-such-article')).toBeNull()
  })

  it('keeps every slug unique, including earlier addresses', () => {
    const all = ARTICLES.flatMap(a => [a.slug, ...(a.aliases ?? [])])
    expect(new Set(all).size).toBe(all.length)
  })

  it('explains AI assistant access honestly, names no assistant product and points to the setup steps', () => {
    const article = getArticle('connect-your-ai-assistant')
    const text = JSON.stringify(article)
    for (const fact of ['read-only', 'cannot start scans', 'change DNS', '15-minute access token', 'up to 7 days', 'up to 50 customer workspaces', 'has not verified it', 'cannot delete data the app has already received', 'Remove access', 'cybermeters.com/support#mcp']) {
      expect(text, fact).toContain(fact)
    }
    expect(text).not.toMatch(/ChatGPT|OpenAI|Claude|Anthropic|Gemini|Google|Copilot|Microsoft/)
  })
})
