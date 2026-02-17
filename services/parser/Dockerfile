# Build stage
FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app/services/parser

# Copy shared pkg directory first
COPY pkg/ /app/pkg/

# Copy service-specific files
COPY services/parser/go.mod services/parser/go.sum* ./
RUN go mod download || true

# Copy service source code
COPY services/parser/ ./

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /parser .

# Final stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

COPY --from=builder /parser .

# Copy pattern files
COPY services/parser/patterns/ /app/patterns/

# Create non-root user
RUN adduser -D -u 1000 parser
USER parser

EXPOSE 8088

ENTRYPOINT ["/app/parser"]
