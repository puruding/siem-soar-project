import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    host: true,
    port: 3000,
    proxy: {
      // AI Copilot API - routes to copilot service
      '/api/v1/chat': {
        target: 'http://localhost:8001',
        changeOrigin: true,
      },
      '/api/v1/nl2sql': {
        target: 'http://localhost:8001',
        changeOrigin: true,
      },
      '/api/v1/summarize': {
        target: 'http://localhost:8001',
        changeOrigin: true,
      },
      '/api/v1/recommend': {
        target: 'http://localhost:8001',
        changeOrigin: true,
      },
      '/api/v1/context': {
        target: 'http://localhost:8001',
        changeOrigin: true,
      },
      // ML Gateway API - routes to ml-gateway service
      '/api/v1/dga': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
      '/api/v1/ueba': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
      '/api/v1/clustering': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
      '/api/v1/models': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
      // Default API - routes to gateway service
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
      // WebSocket for streaming chat
      '/ws': {
        target: 'ws://localhost:8001',
        ws: true,
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
    rollupOptions: {
      output: {
        manualChunks: {
          'react-vendor': ['react', 'react-dom', 'react-router-dom'],
          'ui-vendor': ['@radix-ui/react-dialog', '@radix-ui/react-dropdown-menu', '@radix-ui/react-tabs'],
          'chart-vendor': ['echarts', 'echarts-for-react'],
          'flow-vendor': ['@xyflow/react'],
        },
      },
    },
  },
});
