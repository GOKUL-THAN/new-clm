# Multi-stage Dockerfile for CLM Control Plane API Server
FROM golang:1.24-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /clm-api ./cmd/api

FROM alpine:3.19
RUN apk --no-cache add ca-certificates tzdata
WORKDIR /app
COPY --from=builder /clm-api /app/clm-api
COPY web /app/web
COPY api /app/api
COPY migrations /app/migrations

ENV PORT=10000
ENV CLM_DATABASE_URL=clm.db
ENV CLM_LOG_LEVEL=info

EXPOSE 10000 8080
ENTRYPOINT ["/app/clm-api"]
