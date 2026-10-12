import { Link } from 'react-router-dom'
import CyberMetersLogo from './CyberMetersLogo'
import { CONTACT, SITE_CONTAINER } from './PublicSiteHeader'
import { marketingHomeHref } from '../utils/siteLinks'

// One footer for every public page. `sectionBase` is '' on the landing page
// (section links stay on the page) and the public home everywhere else.
export default function PublicSiteFooter({ sectionBase }) {
  const base = sectionBase ?? marketingHomeHref()
  const year = new Date().getFullYear()
  const columns = [
    { title: 'Product', links: [
      { label: 'Free check', to: '/free-scan' },
      { label: 'Areas', href: `${base}#areas` },
      { label: 'How it works', href: `${base}#how` },
      { label: 'Pricing', to: '/pricing' },
    ] },
    { title: 'Company', links: [
      { label: 'About', to: '/about' },
      { label: 'Trust & Security', to: '/trust' },
      { label: 'Status', to: '/status' },
      { label: 'Support', to: '/support' },
    ] },
    { title: 'Legal', links: [
      { label: 'Privacy', to: '/privacy' },
      { label: 'Terms', to: '/terms' },
      { label: 'DPA', to: '/dpa' },
      { label: 'Cookies', to: '/cookies' },
      { label: 'Sign in', href: sectionBase === '' ? 'https://app.cybermeters.com/login' : '/login' },
    ] },
  ]
  return (
    <footer className="bg-white border-t border-[#E6EAF3]">
      <div className={`${SITE_CONTAINER} py-14 grid grid-cols-2 md:grid-cols-[1.4fr_1fr_1fr_1fr] gap-x-10 gap-y-10`}>
        <div className="col-span-2 md:col-span-1">
          <CyberMetersLogo size={28} showWordmark />
          <p className="mt-4 text-[15px] text-[#5A6378] max-w-[30ch]">External security checks for your business.</p>
          <p className="mt-1 text-[15px] text-[#5A6378]">
            <a href={CONTACT} className="hover:text-[#121A2E]">hello@cybermeters.com</a>
          </p>
        </div>
        {columns.map(col => (
          <nav key={col.title} aria-label={col.title}>
            <p className="text-[15px] font-semibold text-[#121A2E]">{col.title}</p>
            <ul className="mt-4 space-y-3 text-[15px] text-[#46506A]">
              {col.links.map(l => (
                <li key={l.label}>
                  {l.to ? <Link to={l.to} className="hover:text-[#121A2E]">{l.label}</Link> : <a href={l.href} className="hover:text-[#121A2E]">{l.label}</a>}
                </li>
              ))}
            </ul>
          </nav>
        ))}
      </div>
      <div className="border-t border-[#EEF1F7]">
        <div className={`${SITE_CONTAINER} py-5 text-[14px] text-[#5A6378]`}>© {year} CyberMeters. All rights reserved.</div>
      </div>
    </footer>
  )
}
