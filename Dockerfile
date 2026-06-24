# Сборка бинарника
FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /phantom-proxy ./cmd/proxy

# Минимальный runtime-образ
FROM alpine:3.20
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /phantom-proxy /app/phantom-proxy
COPY configs/config.yaml /app/configs/config.yaml
EXPOSE 8443
ENTRYPOINT ["/app/phantom-proxy", "-config", "/app/configs/config.yaml"]
