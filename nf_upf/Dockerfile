# Build UPF and gtp5g-tunnel from local/pinned sources
FROM golang:1.24-bookworm AS builder

ENV GOTOOLCHAIN=auto

RUN apt-get update && apt-get install -y --no-install-recommends build-essential libmnl-dev libyaml-dev

WORKDIR /go/src/free5gc

# Build gtp5g-tunnel (pin to the tag used by go-upf)
RUN git clone --depth 1 --branch v1.4.6 https://github.com/free5gc/go-gtp5gnl.git /tmp/go-gtp5gnl && \
    cd /tmp/go-gtp5gnl/cmd/gogtp5g-tunnel && \
    go build -o /output/gtp5g-tunnel .

# Build UPF from local sources
COPY base/free5gc/NFs/upf/ ./NFs/upf/

RUN cd NFs/upf/cmd && \
    CGO_ENABLED=0 go build -o /output/upf main.go

FROM bitnami/minideb:bullseye

LABEL description="free5GC open source 5G Core Network" \
    version="Stage 3"

ENV F5GC_MODULE=upf
ENV DEBIAN_FRONTEND=noninteractive
ARG DEBUG_TOOLS

# Install debug tools ~ 100MB (if DEBUG_TOOLS is set to true)
RUN if [ "$DEBUG_TOOLS" = "true" ] ; then apt-get update && apt-get install -y vim strace net-tools iputils-ping curl netcat tcpdump; fi

# Install UPF dependencies
RUN apt-get update \
    && apt-get install -y libmnl0 libyaml-0-2 iproute2 iptables iperf3 \
    && apt-get clean

# Set working dir
WORKDIR /free5gc
RUN mkdir -p config/ log/ src/

# Copy executables
COPY --from=builder /output/${F5GC_MODULE} ./
COPY --from=builder /output/gtp5g-tunnel ./gtp5g-tunnel

# Copy source for debug
COPY --from=builder /go/src/free5gc/NFs/upf/ /free5gc/src/upf/

# Config files volume
VOLUME [ "/free5gc/config" ]
