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
})
