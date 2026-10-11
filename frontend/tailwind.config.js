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
        ink:       '#15241F',   // primary text
        graphite:  '#4A5A54',   // secondary text
        bay:       '#F2F5F3',   // app / section canvas
        rule:      '#DCE3DF',   // hairlines and borders
        evergreen: { DEFAULT: '#0C3D34', 600: '#0F4A40', 400: '#3E7A6E', 200: '#B9D6CF', 100: '#DCEBE7' },
        result: {
          pass:     '#127A4E',
          advisory: '#9A5B00',
          fail:     '#B42318',
          unknown:  '#5E6B66',
        },
      },
      // Design system (Oct 2026): one family, Archivo, used at two widths.
      // Text runs at its normal width; display type is set expanded
      // (font-stretch via the .stretch-* utilities in index.css) — the
      // technical, number-plate feel of a test certificate.
      fontFamily: {
        sans: ['Archivo', 'system-ui', 'sans-serif'],
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
