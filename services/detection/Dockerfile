# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Copy shared pkg directory first
COPY pkg/ ./pkg/

# Copy service-specific files
COPY services/detection/go.mod services/detection/go.sum* ./
RUN go mod download || true

# Copy service source code
COPY services/detection/ ./

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /detection .

# Runtime stage
FROM gcr.io/distroless/static-debian12

COPY --from=builder /detection /detection

EXPOSE 8081

ENTRYPOINT ["/detection"]
