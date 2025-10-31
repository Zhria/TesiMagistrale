# Stage 1: build environment
FROM golang:1.25.2-bookworm AS builder

LABEL maintainer="Free5GC <support@free5gc.org>"
ENV DEBIAN_FRONTEND=noninteractive

# Strumenti e dipendenze native richieste durante il build
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        autoconf \
        libtool \
        pkg-config \
        libmnl-dev \
        libyaml-dev \
        libsctp-dev \
        apt-transport-https \
        ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# Pre-carica le dipendenze Go per sfruttare la cache degli strati Docker
COPY amfCustom/go.mod amfCustom/go.sum ./
RUN go mod download

# Copia il resto del sorgente AMF custom
COPY amfCustom/ .

# Compilazione del binario AMF
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
    go build -o /output/amf ./cmd

# Stage 2: runtime minimale
FROM alpine:3.19

LABEL description="Free5GC AMF custom build" \
      version="custom"

RUN apk add --no-cache \
    ca-certificates \
    libmnl \
    lksctp-tools

WORKDIR /free5gc
RUN mkdir -p cert public config log

# Copia il binario compilato
COPY --from=builder /output/amf ./amf

# Copia configurazioni e certificati di default presenti nel contesto build
COPY cert/ ./cert/
COPY config/ ./config/

EXPOSE 8000

ENTRYPOINT ["./amf"]
