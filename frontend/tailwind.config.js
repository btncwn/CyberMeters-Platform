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
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
      },
      boxShadow: {
        card: '0 1px 3px 0 rgba(0,0,0,.06), 0 1px 2px -1px rgba(0,0,0,.04)',
        'card-md': '0 4px 12px -2px rgba(0,0,0,.08), 0 2px 4px -2px rgba(0,0,0,.04)',
        'card-lg': '0 8px 24px -4px rgba(0,0,0,.10), 0 2px 8px -2px rgba(0,0,0,.06)',
      },
      borderRadius: {
        '2xl': '1rem',
        '3xl': '1.5rem',
      },
    },
  },
  plugins: [],
}
