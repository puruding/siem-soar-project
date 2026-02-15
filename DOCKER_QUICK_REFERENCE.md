# Docker Build Quick Reference

## Individual Service Builds

### Frontend
```bash
# Dashboard (React + Vite)
docker-compose build dashboard
docker-compose build --no-cache dashboard  # Clean build
```

### Go Backend Services
```bash
# API Gateway
docker-compose build gateway

# Detection Engine
docker-compose build detection

# SOAR Engine
docker-compose build soar

# Threat Intelligence
docker-compose build ti

# Query Service
docker-compose build query

# Case Management
docker-compose build case

# Log Collector
docker-compose build collector

# Data Pipeline
docker-compose build pipeline

# Parser Engine
docker-compose build parser
```

### AI/ML Services
```bash
# ML Gateway
docker-compose build ml-gateway
```

## Batch Builds

### Build All Go Services
```bash
docker-compose build gateway detection soar ti query case collector pipeline parser
```

### Build All Services
```bash
docker-compose build
```

### Force Clean Build (No Cache)
```bash
docker-compose build --no-cache
```

### Parallel Build (Faster)
```bash
docker-compose build --parallel
```

## Troubleshooting

### View Build Logs
```bash
# Build with verbose output
docker-compose build --progress=plain SERVICE_NAME

# Example
docker-compose build --progress=plain dashboard
```

### Check Service Build Context
```bash
# Verify what files Docker can see
docker-compose config | grep -A 5 "SERVICE_NAME:"
```

### Clean Docker Build Cache
```bash
# Remove all build cache
docker builder prune -a

# Remove unused images
docker image prune -a
```

### Debug Specific Layer
```bash
# Build and stop at specific layer
docker build --target builder -f services/gateway/Dockerfile .
```

## Verification

### Automated Verification
```bash
# Run verification script
chmod +x verify-docker-builds.sh
./verify-docker-builds.sh
```

### Manual Verification
```bash
# Check if images were built
docker images | grep siem-

# Test run a service
docker-compose up -d SERVICE_NAME
docker-compose logs -f SERVICE_NAME
```

### Health Checks
```bash
# View service status
docker-compose ps

# Check specific service health
docker inspect --format='{{.State.Health.Status}}' siem-SERVICE_NAME
```

## Common Issues

### Issue: "COPY failed: file not found"
**Solution:** Check build context in `docker-compose.yml`:
```yaml
build:
  context: .          # Should be root directory
  dockerfile: ./services/SERVICE/Dockerfile
```

### Issue: "npm ERR! cipm can only install packages..."
**Solution:** Dashboard Dockerfile now handles this automatically with fallback to `npm install`

### Issue: "cannot find package"
**Solution:** Ensure `go.sum` exists:
```bash
cd services/SERVICE_NAME
go mod tidy
```

### Issue: Build is slow
**Solutions:**
1. Add `.dockerignore` to exclude unnecessary files
2. Use `--parallel` flag for multiple services
3. Enable BuildKit: `export DOCKER_BUILDKIT=1`

### Issue: Out of disk space
**Cleanup:**
```bash
# Remove stopped containers
docker container prune

# Remove unused images
docker image prune -a

# Remove build cache
docker builder prune -a

# Nuclear option (removes everything)
docker system prune -a --volumes
```

## Performance Tips

### Enable BuildKit
```bash
# Linux/Mac
export DOCKER_BUILDKIT=1
docker-compose build

# Windows PowerShell
$env:DOCKER_BUILDKIT=1
docker-compose build
```

### Multi-Stage Build Optimization
Current Dockerfiles already use multi-stage builds:
- **Builder stage**: Compiles application
- **Runtime stage**: Minimal production image

### Layer Caching
Dependencies are copied before source code to maximize cache hits:
```dockerfile
# This layer is cached if package.json hasn't changed
COPY package*.json ./
RUN npm install

# This layer only rebuilds if source code changes
COPY . .
RUN npm run build
```

## Development Workflow

### Typical Development Cycle
```bash
# 1. Make code changes
vim services/gateway/main.go

# 2. Rebuild specific service
docker-compose build gateway

# 3. Restart service
docker-compose up -d gateway

# 4. View logs
docker-compose logs -f gateway

# 5. Test
curl http://localhost:8080/health
```

### Hot Reload (Development)
For development with hot reload, use volume mounts instead:
```yaml
# docker-compose.override.yml
services:
  gateway:
    volumes:
      - ./services/gateway:/app
    command: go run main.go  # or air for hot reload
```

## Production Deployment

### Build for Production
```bash
# Build with specific tags
docker-compose -f docker-compose.yml -f docker-compose.prod.yml build

# Tag for registry
docker tag siem-dashboard:latest registry.example.com/siem-dashboard:v1.0.0

# Push to registry
docker push registry.example.com/siem-dashboard:v1.0.0
```

### Verify Security
```bash
# Scan images for vulnerabilities
docker scan siem-dashboard:latest

# Check image size
docker images | grep siem-

# Inspect image layers
docker history siem-dashboard:latest
```

## Resources

- **Docker Compose Docs**: https://docs.docker.com/compose/
- **Multi-Stage Builds**: https://docs.docker.com/build/building/multi-stage/
- **BuildKit**: https://docs.docker.com/build/buildkit/
- **Best Practices**: https://docs.docker.com/develop/dev-best-practices/
