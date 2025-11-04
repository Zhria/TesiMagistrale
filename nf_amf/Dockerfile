FROM zhria/amfcustom:latest as builder

#FROM free5gc/amf-base:latest AS builder
FROM alpine:3.15

LABEL description="Free5GC open source 5G Core Network" \
    version="N3IWF Handover Support Patch"

ENV F5GC_MODULE=amf

# Install debug tools ~ 100MB
RUN apk add -U vim strace net-tools curl netcat-openbsd

# Set working dir
WORKDIR /free5gc
RUN mkdir -p config/ log/ cert/

# Copy executable and default certs
COPY --from=builder /free5gc/${F5GC_MODULE} ./
COPY --from=builder /free5gc/cert/${F5GC_MODULE}.pem ./cert/
COPY --from=builder /free5gc/cert/${F5GC_MODULE}.key ./cert/

# Config files volume
VOLUME [ "/free5gc/config" ]

# Certificates (if not using default) volume
VOLUME [ "/free5gc/cert" ]

# Exposed ports
EXPOSE 8000
