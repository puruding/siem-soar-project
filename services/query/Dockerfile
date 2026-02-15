# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Copy shared pkg directory first
COPY pkg/ ./pkg/

# Copy service-specific files
COPY services/query/go.mod services/query/go.sum* ./
RUN go mod download || true

# Copy service source code
COPY services/query/ ./

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /query .

# Runtime stage
FROM gcr.io/distroless/static-debian12

COPY --from=builder /query /query

EXPOSE 8084

ENTRYPOINT ["/query"]
