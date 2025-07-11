FROM golang:1.24.4-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o tranzia ./cmd/main.go

FROM busybox:1.36.0-uclibc

# Copy the built binary
COPY --from=builder /app/tranzia /usr/local/bin/tranzia

# Default entrypoint with CMD passthrough for CLI usage
ENTRYPOINT ["/usr/local/bin/tranzia"]