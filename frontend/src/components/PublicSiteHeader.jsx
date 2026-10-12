import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import CyberMetersLogo from './CyberMetersLogo'
import { marketingHomeHref } from '../utils/siteLinks'

export const CONTACT = 'mailto:hello@cybermeters.com'
export const SITE_CONTAINER = 'mx-auto w-full max-w-[1280px] px-6 sm:px-10 lg:px-16'

// The public site's navigation, shared by the landing page (dark, over the
// hero) and every other public page (light). Section links point back to the
// landing page sections from wherever the visitor is.
export function siteNav(sectionBase) {
  const section = id => `${sectionBase}#${id}`
  return [
    { label: 'Product', href: section('product') },
    { label: 'Areas', href: section('areas') },
    { label: 'How it works', href: section('how') },
    { label: 'Pricing', to: '/pricing' },
    { label: 'Trust & Security', to: '/trust' },
    { label: 'About', to: '/about' },
  ]
}

function NavItem({ item, className, onClick }) {
  return item.to
    ? <Link to={item.to} className={className} onClick={onClick}>{item.label}</Link>
    : <a href={item.href} className={className} onClick={onClick}>{item.label}</a>
}

export default function PublicSiteHeader({ tone = 'light', signedIn = false }) {
  const dark = tone === 'dark'
  const [solid, setSolid] = useState(!dark)
  const [menuOpen, setMenuOpen] = useState(false)
  const home = marketingHomeHref()
  // On the landing page the section links stay on the page.
  const nav = siteNav(dark ? '' : home)

  useEffect(() => {
    if (!dark) return undefined
    const on = () => setSolid(window.scrollY > 24)
    on()
    window.addEventListener('scroll', on, { passive: true })
    return () => window.removeEventListener('scroll', on)
  }, [dark])

  const shell = dark
    ? `fixed inset-x-0 top-0 z-50 transition-[background-color,box-shadow] duration-300 ${solid || menuOpen ? 'bg-[#183A86]/95 shadow-[0_8px_30px_-12px_rgba(6,16,48,.6)] backdrop-blur' : 'bg-transparent'}`
    : 'sticky top-0 z-50 bg-white/95 backdrop-blur border-b border-[#E6EAF3]'
  const utility = dark ? 'text-white/80 hover:text-white' : 'text-[#5A6378] hover:text-[#121A2E]'
  const link = dark ? 'hover:text-[#BFE6FF]' : 'hover:text-[#1D46A8]'
  const navText = dark ? 'text-white' : 'text-[#121A2E]'
  const account = signedIn
    ? { label: 'Dashboard', href: '/dashboard' }
    : { label: 'Sign in', href: dark ? 'https://app.cybermeters.com/login' : '/login' }

  return (
    <header className={shell}>
      <div className={`${SITE_CONTAINER} hidden lg:flex justify-end gap-7 pt-3 text-[14px]`}>
        <a href={CONTACT} className={utility}>Contact</a>
        <a href={account.href} className={utility}>{account.label}</a>
      </div>
      <div className={`${SITE_CONTAINER} flex items-center justify-between h-[68px]`}>
        {dark
          ? <Link to="/" aria-label="CyberMeters home"><CyberMetersLogo size={30} showWordmark darkMode /></Link>
          : <a href={home} aria-label="CyberMeters home"><CyberMetersLogo size={30} showWordmark /></a>}
        <nav aria-label="Main" className={`hidden lg:flex items-center gap-7 xl:gap-9 text-[16px] font-semibold ${navText}`}>
          {nav.map(item => <NavItem key={item.label} item={item} className={link} />)}
        </nav>
        <div className="flex items-center gap-3">
          <Link
            to="/free-scan"
            className={`h-11 px-5 rounded-[8px] text-[15px] font-semibold inline-flex items-center transition-colors ${dark ? 'bg-white text-[#183A86] hover:bg-[#EEF3FF]' : 'bg-[#FFB81C] text-[#1B2333] hover:bg-[#FFC640]'}`}
          >
            Run a free check
          </Link>
          <button
            type="button"
            className={`lg:hidden h-11 px-4 rounded-[8px] border text-[15px] font-semibold ${dark ? 'border-white/40 text-white' : 'border-[#C9D1E4] text-[#121A2E]'}`}
            aria-expanded={menuOpen}
            aria-controls="site-menu"
            onClick={() => setMenuOpen(v => !v)}
          >
            {menuOpen ? 'Close' : 'Menu'}
          </button>
        </div>
      </div>
      {menuOpen && (
        <nav id="site-menu" aria-label="Main" className={`lg:hidden border-t ${dark ? 'border-white/15' : 'border-[#E6EAF3] bg-white'}`}>
          <ul className={`${SITE_CONTAINER} py-4 grid gap-1 text-[16px] font-semibold ${navText}`}>
            {nav.map(item => (
              <li key={item.label}><NavItem item={item} className="block py-2.5" onClick={() => setMenuOpen(false)} /></li>
            ))}
            <li><a href={CONTACT} className="block py-2.5">Contact</a></li>
            <li><a href={account.href} className="block py-2.5">{account.label}</a></li>
          </ul>
        </nav>
      )}
    </header>
  )
}
