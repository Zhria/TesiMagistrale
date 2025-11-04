# Stage 1: build environment (musl-based, compatibile con Alpine runtime)
FROM golang:1.24-alpine AS builder

LABEL maintainer="Free5GC <support@free5gc.org>"

# Consente di scaricare automaticamente una toolchain Go più recente (>=1.24)
ENV GOTOOLCHAIN=auto

# Strumenti e dipendenze native richieste durante il build
RUN apk add --no-cache \
        build-base \
        cmake \
        autoconf \
        automake \
        libtool \
        pkgconf \
        git \
        linux-headers \
        libmnl-dev \
        yaml-dev \
        lksctp-tools-dev

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
FROM alpine:3.19

LABEL description="Free5GC AMF custom build" \
      version="custom"

RUN apk add --no-cache \
    ca-certificates \
    libmnl \
    lksctp-tools \
    yaml \
    tzdata

WORKDIR /free5gc
RUN mkdir -p cert public config log

# Copia il binario compilato
COPY --from=builder /output/amf ./amf

# Copia configurazioni e certificati di default presenti nel contesto build
COPY cert/ ./cert/
COPY config/ ./config/

EXPOSE 8000

ENTRYPOINT ["./amf"]
