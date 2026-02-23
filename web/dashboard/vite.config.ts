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
      // ML Gateway API - routes to Python ml-gateway service (port 8000)
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
      // SOAR API - routes to SOAR service
      '/api/v1/playbooks': {
        target: 'http://localhost:8082',
        changeOrigin: true,
      },
      // Assets API - routes to Gateway service
      '/api/v1/assets': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
      // Products API - routes to Gateway service
      '/api/v1/products': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
      // Parsers API - routes to Gateway service
      '/api/v1/parsers': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
      // Alerts API - routes to Gateway (which routes to Alert service)
      '/api/v1/alerts': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
      // Detection API - routes to Detection service
      '/api/v1/detection': {
        target: 'http://localhost:8081',
        changeOrigin: true,
      },
      // Rules API - routes to Gateway service (for demo/dev)
      '/api/v1/rules': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
      // Dashboard API - routes to Gateway service
      '/api/v1/dashboard': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
      // Query API - routes to Gateway (temporary until Query service is implemented)
      '/api/v1/query': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
      // Cases API - routes to Gateway service (for demo/dev)
      '/api/v1/cases': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
      // Events API - routes to Gateway service
      '/api/v1/events': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
      // Pipeline Orchestrator API - routes to pipeline service
      '/api/v1/pipeline': {
        target: 'http://localhost:8095',
        changeOrigin: true,
      },
      // Threat Intelligence API - routes to Gateway service (for demo/dev)
      '/api/v1/ti': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
      // Default API - routes to gateway service
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
      // WebSocket for streaming chat (Copilot)
      '/ws/chat': {
        target: 'ws://localhost:8001',
        ws: true,
        changeOrigin: true,
      },
      // WebSocket for Pipeline events
      '/ws/pipeline': {
        target: 'ws://localhost:8095',
        ws: true,
        changeOrigin: true,
      },
      // WebSocket for SOAR status updates
      '/ws/soar': {
        target: 'ws://localhost:8082',
        ws: true,
        changeOrigin: true,
      },
      // ClickHouse HTTP API
      '/clickhouse': {
        target: 'http://localhost:8123',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/clickhouse/, ''),
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
