# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Copy shared pkg directory first
COPY pkg/ ./pkg/

# Copy service-specific files
COPY services/soar/go.mod services/soar/go.sum* ./
RUN go mod download || true

# Copy service source code
COPY services/soar/ ./

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /soar .

# Runtime stage
FROM gcr.io/distroless/static-debian12

COPY --from=builder /soar /soar

EXPOSE 8082

ENTRYPOINT ["/soar"]
