import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

const SPLUNK_URL = process.env.SPLUNK_URL ?? 'https://localhost:8000';

export default defineConfig({
  plugins: [react()],
  base: '/static/app/splunk_health_check/',
  server: {
    proxy: {
      '/en-US/splunkd': {
        target: SPLUNK_URL,
        changeOrigin: true,
        secure: false,
      },
    },
  },
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
