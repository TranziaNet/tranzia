FROM golang:1.24.4-alpine AS builder

ARG VERSION=v0.0.0
ARG COMMIT=unknown
ARG DATE=unknown

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath \
    -ldflags="-s -w \
    -X github.com/TranziaNet/tranzia/pkg.Version=${VERSION} \
    -X github.com/TranziaNet/tranzia/pkg.Commit=${COMMIT} \
    -X github.com/TranziaNet/tranzia/pkg.Date=${DATE}" \
    -o tranzia ./cmd/main.go

FROM busybox:1.36.0-uclibc

COPY --from=builder /app/tranzia /usr/local/bin/tranzia

ENTRYPOINT ["/usr/local/bin/tranzia"]