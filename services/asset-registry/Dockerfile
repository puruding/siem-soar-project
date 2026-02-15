# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Install dependencies
RUN apk add --no-cache git ca-certificates

# Copy go mod files
COPY go.mod ./
COPY ../../pkg/config/go.mod ../pkg/config/
COPY ../../pkg/logger/go.mod ../pkg/logger/
COPY ../../pkg/repository/go.mod ../pkg/repository/
COPY ../../pkg/errors/go.mod ../pkg/errors/

# Download dependencies
RUN go mod download

# Copy source
COPY . .
COPY ../../pkg ../pkg

# Build binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /asset-registry .

# Runtime stage
FROM alpine:3.19

WORKDIR /app

# Install ca-certificates for HTTPS
RUN apk --no-cache add ca-certificates tzdata

# Copy binary
COPY --from=builder /asset-registry .

# Create non-root user
RUN adduser -D -g '' appuser
USER appuser

# Expose port
EXPOSE 8090

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8090/health || exit 1

# Run
ENTRYPOINT ["./asset-registry"]
