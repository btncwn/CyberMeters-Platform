import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

// Kept separate from vite.config.js on purpose: the production build pipeline
// stays completely untouched by the test toolchain.
export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    // An explicit http origin — with an opaque origin (about:blank) jsdom hides
    // localStorage/sessionStorage entirely and Node's own undefined-returning
    // webstorage globals win instead.
    environmentOptions: { jsdom: { url: 'http://localhost:3000/' } },
    globals: true,
    setupFiles: ['./src/test/setup.js'],
    include: ['src/**/*.test.{js,jsx}'],
    css: false,
  },
})
