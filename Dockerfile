# ── Build stage ────────────────────────────────────────────────────────────────
FROM golang:1.25-alpine AS builder

WORKDIR /build

COPY src/go/ .

# tidy regenerates go.sum; build a fully static, stripped binary
RUN go mod tidy && \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o honeypot .

# ── Runtime stage ───────────────────────────────────────────────────────────────
# alpine (not scratch) for:
#   ca-certificates  → HTTPS calls to api.goo1.de / Pushover / webhooks
#   wget             → docker-compose healthcheck
FROM alpine:3.21

RUN apk add --no-cache ca-certificates wget

WORKDIR /app

COPY --from=builder /build/honeypot .
COPY src/go/assets/   assets/
COPY src/go/security.txt .

EXPOSE 80

CMD ["./honeypot"]
