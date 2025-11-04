FROM zhria/smfcustom:latest AS builder

FROM debian:bookworm-slim

LABEL description="Free5GC open source 5G Core Network" \
    version="Stage 3"

ENV F5GC_MODULE=smf
ARG DEBUG_TOOLS

# Install runtime deps and optional debug tooling, then clean apt cache
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        libmnl0 \
        libsctp1 \
        libyaml-0-2 \
        tzdata; \
    if [ "$DEBUG_TOOLS" = "true" ]; then \
        apt-get install -y --no-install-recommends \
            vim \
            strace \
            net-tools \
            curl \
            netcat-openbsd; \
    fi; \
    rm -rf /var/lib/apt/lists/*

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
