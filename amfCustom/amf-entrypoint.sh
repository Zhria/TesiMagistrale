#!/bin/sh
set -eu

log() {
  echo "[amf-entrypoint] $*" >&2
}

iface="${AMF_IFACE:-eth0}"
fix="${AMF_FIX_SCTP_CHECKSUM_OFFLOAD:-1}"

disable_sctp_checksum_offload() {
  if [ "$fix" = "0" ]; then
    return 0
  fi

  if ! command -v ethtool >/dev/null 2>&1; then
    log "ethtool not found; cannot adjust offloads"
    return 0
  fi

  if ethtool -K "$iface" tx-checksum-sctp off >/dev/null 2>&1; then
    log "Disabled tx-checksum-sctp on $iface"
    return 0
  fi

  if ethtool -K "$iface" tx off >/dev/null 2>&1; then
    log "Disabled tx checksumming on $iface"
    return 0
  fi

  log "Could not disable SCTP checksum offload on $iface (missing NET_ADMIN?)"
}

disable_sctp_checksum_offload || true

if [ "$#" -eq 0 ]; then
  set -- ./amf -c ./config/amfcfg.yaml
fi

exec "$@"
