import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': process.env.API_PROXY_TARGET || (process.env.VITE_ROUTER_PLATFORM === 'mikrotik' ? 'http://127.0.0.1:8091' : 'http://localhost:8000')
    }
  },
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
  }
})
