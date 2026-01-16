# Stage 1: build environment (musl-based, compatibile con Alpine runtime)
FROM golang:1.24-bookworm AS builder

LABEL maintainer="Free5GC <support@free5gc.org>"

# Consente di scaricare automaticamente una toolchain Go più recente (>=1.24)
ENV GOTOOLCHAIN=auto

# Strumenti e dipendenze native richieste durante il build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential cmake autoconf automake libtool pkg-config git linux-headers-amd64 libmnl-dev libsctp-dev libyaml-dev

WORKDIR /workspace

# Pre-carica le dipendenze Go per sfruttare la cache degli strati Docker
COPY amfCustom/go.mod amfCustom/go.sum ./
RUN go mod download

# Copia il resto del sorgente AMF custom
COPY amfCustom/ .

# Compilazione del binario AMF basato su musl per Alpine
RUN mkdir -p /output \
    && CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
       go build -o /output/amf ./cmd

# Stage 2: runtime minimale
FROM debian:bookworm-slim

LABEL description="Free5GC AMF custom build" \
      version="custom"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates \
       ethtool \
       iproute2 \
       libmnl0 \
       libsctp1 \
       libyaml-0-2 \
       tzdata \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /free5gc
RUN mkdir -p cert public config log

# Copia il binario compilato
COPY --from=builder /output/amf ./amf

COPY amfCustom/amf-entrypoint.sh /usr/local/bin/amf-entrypoint
RUN chmod +x /usr/local/bin/amf-entrypoint

# Copia configurazioni e certificati di default presenti nel contesto build
COPY cert/ ./cert/
COPY config/ ./config/

EXPOSE 8000

ENTRYPOINT ["/usr/local/bin/amf-entrypoint"]
