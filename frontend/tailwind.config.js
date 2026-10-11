/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        brand: {
          50:  '#E6F4F1',
          100: '#C1E4DA',
          200: '#97D3C2',
          300: '#6DC2AA',
          400: '#4DB596',
          500: '#2EA989',
          600: '#00876A',   // PRIMARY
          700: '#006A53',
          800: '#004D3C',
          900: '#003328',
        },
      },
      // Readable type scale (founder, 11 Oct): product text never reads below
      // the market average. Every step sits above Tailwind's default.
      fontSize: {
        xs: ['0.875rem', { lineHeight: '1.25rem' }],     // 14px (default 12)
        sm: ['1rem', { lineHeight: '1.5rem' }],          // 16px (default 14)
        base: ['1.0625rem', { lineHeight: '1.65rem' }],  // 17px (default 16)
        lg: ['1.1875rem', { lineHeight: '1.75rem' }],    // 19px (default 18)
        xl: ['1.3125rem', { lineHeight: '1.875rem' }],   // 21px (default 20)
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        // Public website display face (Computer Modern, self-hosted, SIL OFL).
        cm: ['"Computer Modern Serif"', 'Georgia', 'Cambria', 'serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
      },
      boxShadow: {
        // Refined, slightly cooler shadows (navy-tinted) read more premium than flat black.
        card: '0 1px 2px 0 rgba(16,24,40,.05), 0 1px 3px 0 rgba(16,24,40,.04)',
        'card-md': '0 4px 14px -3px rgba(16,24,40,.10), 0 2px 6px -2px rgba(16,24,40,.05)',
        'card-lg': '0 12px 30px -6px rgba(16,24,40,.14), 0 4px 10px -3px rgba(16,24,40,.07)',
        // Confident primary-CTA shadow — a subtle green lift so buttons feel deliberate.
        btn: '0 1px 2px 0 rgba(16,24,40,.08)',
        'btn-brand': '0 2px 5px -1px rgba(0,135,106,.35), 0 1px 2px 0 rgba(0,135,106,.20)',
        header: '0 1px 0 0 rgba(16,24,40,.06), 0 4px 16px -8px rgba(16,24,40,.10)',
      },
      borderRadius: {
        '2xl': '1rem',
        '3xl': '1.5rem',
      },
    },
  },
  plugins: [],
}
