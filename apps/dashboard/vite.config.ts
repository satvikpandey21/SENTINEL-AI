import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const target = env.SENTINEL_API_PROXY_TARGET || 'http://127.0.0.1:8000';
  const url = new URL(target);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) {
    throw new Error('Proxy target must be an HTTP(S) origin without credentials');
  }
  const proxy = { '/api/admin': { target, changeOrigin: false, ws: true } };
  return {
    plugins: [react()],
    server: { host: 'localhost', port: 5173, strictPort: true, allowedHosts: ['localhost'], proxy },
    preview: {
      host: 'localhost',
      port: 5173,
      strictPort: true,
      allowedHosts: ['localhost'],
      proxy,
    },
    build: { sourcemap: false, chunkSizeWarningLimit: 450 },
  };
});
