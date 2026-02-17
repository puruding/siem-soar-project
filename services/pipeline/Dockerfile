# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app/services/pipeline

# Copy shared pkg directory first
COPY pkg/ /app/pkg/

# Copy service-specific files
COPY services/pipeline/go.mod services/pipeline/go.sum* ./
RUN go mod download || true

# Copy service source code
COPY services/pipeline/ ./

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /pipeline .

# Runtime stage
FROM gcr.io/distroless/static-debian12

COPY --from=builder /pipeline /pipeline

EXPOSE 8087

ENTRYPOINT ["/pipeline"]
