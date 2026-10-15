import CyberMetersLogo from './CyberMetersLogo'
import { marketingHomeHref } from '../utils/siteLinks'

// The frame shared by sign-in, sign-up, password and email-verification
// screens: the same top bar as the public site (brand mark left, a way back
// right), then the screen's own card, optionally beside a short "what happens
// next" panel.
export default function AuthShell({ children, aside = null }) {
  const home = marketingHomeHref()
  return (
    <div className="min-h-screen auth-bg flex flex-col">
      <header className="w-full">
        <div className="mx-auto w-full max-w-[1280px] px-6 sm:px-10 h-[68px] flex items-center justify-between">
          <a href={home} aria-label="CyberMeters home"><CyberMetersLogo size={30} showWordmark /></a>
          <a href={home} className="text-sm font-semibold text-gray-600 hover:text-gray-900">Back to the website</a>
        </div>
      </header>
      <main className="flex-1 flex items-center justify-center px-4 py-10">
        {aside ? (
          <div className="w-full max-w-[1100px] grid grid-cols-1 lg:grid-cols-[minmax(0,1fr)_minmax(0,380px)] gap-10 lg:gap-14 items-center justify-items-center">
            <div className="w-full flex flex-col items-center">{children}</div>
            <aside className="w-full max-w-136 lg:max-w-none">{aside}</aside>
          </div>
        ) : (
          <div className="w-full flex flex-col items-center">{children}</div>
        )}
      </main>
    </div>
  )
}
