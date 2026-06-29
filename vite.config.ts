import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  base: '/static/app/splunk_health_check/',
  build: {
    outDir: 'splunk_app/splunk_health_check/appserver/static',
    emptyOutDir: true,
    rollupOptions: {
      output: {
        format: 'iife',
        entryFileNames: 'app.js',
        assetFileNames: (info) =>
          info.name?.endsWith('.css') ? 'app.css' : info.name ?? 'asset',
      },
    },
  },
})
