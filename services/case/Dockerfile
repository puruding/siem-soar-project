# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Copy shared pkg directory first
COPY pkg/ ./pkg/

# Copy service-specific files
COPY services/case/go.mod services/case/go.sum* ./
RUN go mod download || true

# Copy service source code
COPY services/case/ ./

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /case .

# Runtime stage
FROM gcr.io/distroless/static-debian12

COPY --from=builder /case /case

EXPOSE 8085

ENTRYPOINT ["/case"]
