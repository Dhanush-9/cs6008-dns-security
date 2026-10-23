FROM internetsystemsconsortium/bind9:9.20

USER root

RUN apk add --no-cache \
    curl \
    iproute2 \
    tcpdump \
    busybox-extras \
    build-base \
    libpcap-dev \
    libpcap \
    arping \
    knot-utils \
    openssl \
    openssl-dev \
    ca-certificates

# Create mount-points for PKI volumes.
# /etc/bind-tls  → resolver TLS cert + key (resolver service)
# /etc/bind-tls  → CA cert (client service)
# The /etc/bind layer in the base image is read-only in the overlay, so we
# can't create subdirs under it at container start — use a sibling directory.
RUN mkdir -p /etc/bind-tls && chmod 755 /etc/bind-tls

WORKDIR /lab

ENTRYPOINT []

CMD ["tail", "-f", "/dev/null"]
