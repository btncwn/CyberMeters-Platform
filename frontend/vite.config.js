import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import versionManifest from './version-manifest.js'
import publicPagesHtml from './public-pages-html.js'

export default defineConfig({
  plugins: [react(), versionManifest(), publicPagesHtml()],
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes('node_modules/recharts') || id.includes('node_modules/d3-')) {
            return 'vendor-charts';
          }
          if (id.includes('node_modules/lucide-react')) {
            return 'vendor-icons';
          }
          if (id.includes('node_modules/react') || id.includes('node_modules/react-dom') || id.includes('node_modules/react-router')) {
            return 'vendor-core';
          }
        }
      }
    }
  }
})
