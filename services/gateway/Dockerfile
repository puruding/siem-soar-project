# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app/services/gateway

# Copy shared pkg directory first
COPY pkg/ /app/pkg/

# Copy service-specific files
COPY services/gateway/go.mod services/gateway/go.sum* ./
RUN go mod download || true

# Copy service source code
COPY services/gateway/ ./

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /gateway .

# Runtime stage
FROM gcr.io/distroless/static-debian12

COPY --from=builder /gateway /gateway

EXPOSE 8080

ENTRYPOINT ["/gateway"]
