# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app/services/ti

# Copy shared pkg directory first
COPY pkg/ /app/pkg/

# Copy service-specific files
COPY services/ti/go.mod services/ti/go.sum* ./
RUN go mod download || true

# Copy service source code
COPY services/ti/ ./

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /ti .

# Runtime stage
FROM gcr.io/distroless/static-debian12

COPY --from=builder /ti /ti

EXPOSE 8083

ENTRYPOINT ["/ti"]
