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
    env: {
      VITE_API_BASE_URL: 'http://localhost/api',
    },
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      reportsDirectory: './coverage',
      include: [
        'src/lib/**/*.js',
        'src/utils/**/*.js',
        'src/hooks/**/*.js',
        'src/components/ErrorAlert.jsx',
        'src/components/StatusBadge.jsx',
        'src/components/PlanUsageCard.jsx',
        'src/components/ProtectedRoute.jsx',
        'src/components/SafeBoundary.jsx',
        'src/theme/**/*.js',
      ],
      exclude: [
        'src/**/*.test.{js,jsx}',
        'src/test/**',
        'src/types/**',
        'src/main.jsx',
        'src/utils/preloadMap.js',
      ],
      thresholds: {
        lines: 80,
        functions: 80,
        statements: 80,
        branches: 70,
      },
    },
  },
})
