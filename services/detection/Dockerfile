# Build stage
FROM golang:1.23-alpine AS builder

# Set up directory structure to match go.mod replace paths
WORKDIR /app/services/detection

# Copy shared pkg directory (relative to ../../pkg from services/detection)
COPY pkg/ /app/pkg/

# Copy service-specific files
COPY services/detection/go.mod services/detection/go.sum* ./
RUN go mod download || true

# Copy service source code
COPY services/detection/ ./

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /detection .

# Runtime stage
FROM gcr.io/distroless/static-debian12

COPY --from=builder /detection /detection
COPY services/detection/rules/ /app/rules/

EXPOSE 8081

ENTRYPOINT ["/detection"]
