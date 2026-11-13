import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath, URL } from 'node:url';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    target: 'es2022',
  },
  server: {
    port: 5173,
    proxy: {
      '/api': { target: 'http://127.0.0.1:8000', changeOrigin: false },
    },
  },
});
