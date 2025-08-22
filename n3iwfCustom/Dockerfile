# Stage 1: Build
FROM golang:1.21-alpine AS builder

# Install tools required for Go modules
RUN apk add --no-cache git

WORKDIR /app
COPY . .

# (opzionale) forza modalità moduli
ENV GO111MODULE=on
ENV CGO_ENABLED=0

RUN go mod tidy
RUN go build -o n3iwf ./cmd/main.go
RUN chmod +x n3iwf

# Stage 2: Runtime (alpine minimal)
FROM alpine:3.19

COPY --from=builder /app/ ./free5gc/n3iwf


