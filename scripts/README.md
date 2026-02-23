# Development Scripts

## Gateway Service

### run-gateway-dev.bat (Windows)

Runs the Gateway service in development mode with authentication disabled.

**Features:**
- Sets `AUTH_ENABLED=false` for easy local testing
- Runs on port 8080
- Rate limiting: 100 RPS / 200 burst
- CORS enabled by default
- No Keycloak required

**Usage:**
```cmd
cd siem-soar-project\scripts
run-gateway-dev.bat
```

**Environment Variables Set:**
- `AUTH_ENABLED=false` - Disables JWT/API key authentication
- `PORT=8080` - HTTP server port
- `RATE_LIMIT_RPS=100` - Requests per second per IP
- `RATE_LIMIT_BURST=200` - Burst allowance

**Testing the Gateway:**
```cmd
# Health check
curl http://localhost:8080/health

# List alerts (no auth required in dev mode)
curl http://localhost:8080/api/v1/alerts

# Create alert
curl -X POST http://localhost:8080/api/v1/alerts ^
  -H "Content-Type: application/json" ^
  -d "{\"title\":\"Test Alert\",\"severity\":\"high\"}"
```

**Notes:**
- Uses the pre-compiled `gateway.exe` in `services/gateway/`
- To build from source, uncomment the `go run main.go` line
- For production, always enable authentication via `AUTH_ENABLED=true`

## Frontend + Gateway Together

To run the full stack locally:

1. **Terminal 1 - Gateway:**
   ```cmd
   cd scripts
   run-gateway-dev.bat
   ```

2. **Terminal 2 - Frontend:**
   ```cmd
   cd web\dashboard
   pnpm dev
   ```

3. **Access:**
   - Frontend: http://localhost:5173
   - Gateway API: http://localhost:8080
   - API Docs: (coming soon)

**Proxy Configuration:**

The Vite dev server (`web/dashboard/vite.config.ts`) proxies `/api/*` requests to the Gateway at `http://localhost:8080`, so the frontend can call APIs without CORS issues.

## Linux/macOS Version

Create `run-gateway-dev.sh`:

```bash
#!/bin/bash
cd "$(dirname "$0")/../services/gateway"

export AUTH_ENABLED=false
export PORT=8080
export RATE_LIMIT_RPS=100
export RATE_LIMIT_BURST=200

./gateway  # Or: go run main.go
```

Make executable:
```bash
chmod +x scripts/run-gateway-dev.sh
```
