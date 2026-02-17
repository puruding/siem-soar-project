# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app/services/collector

# Copy shared pkg directory first
COPY pkg/ /app/pkg/

# Copy service-specific files
COPY services/collector/go.mod services/collector/go.sum* ./
RUN go mod download || true

# Copy service source code
COPY services/collector/ ./

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /collector .

# Runtime stage
FROM gcr.io/distroless/static-debian12

COPY --from=builder /collector /collector

EXPOSE 8086

ENTRYPOINT ["/collector"]
