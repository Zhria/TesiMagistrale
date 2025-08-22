FROM n3iwf_local 
FROM alpine:3.15

LABEL description="Free5GC open source 5G Core Network" \
    version="Stage 3"

ENV F5GC_MODULE=n3iwf

#ARG DEBUG_TOOLS

# Install debug tools ~ 100MB
RUN apk add -U vim strace net-tools curl netcat-openbsd 

# Install N3IWF dependencies
RUN apk add -U iproute2

# Set working dir
WORKDIR /free5gc
RUN mkdir -p config/ log/ cert/

# Copy executable and default certs #Copia tutto dalla immagine n3iwf_local dentro la directory free5gc
COPY --from=n3iwf_local /free5gc/${F5GC_MODULE}/ .

# Config files volume
VOLUME [ "/free5gc/config" ]

# Certificates (if not using default) volume
VOLUME [ "/free5gc/cert" ]