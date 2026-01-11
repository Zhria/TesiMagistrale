#!/bin/sh
set -eu

disable_offloads="${N3IWF_DISABLE_OFFLOADS:-1}"

log() {
  echo "[n3iwf-entrypoint] $*" >&2
}

disable_iface_offloads() {
  iface="$1"

  if [ "$disable_offloads" = "0" ]; then
    return 0
  fi

  if ! command -v ethtool >/dev/null 2>&1; then
    log "ethtool not found; cannot disable offloads"
    return 1
  fi

  # Some virtual interfaces don't support these toggles; ignore failures.
  if ethtool -K "$iface" gro off gso off tso off >/dev/null 2>&1; then
    log "Disabled GRO/GSO/TSO on $iface"
  fi
}

disable_known_ifaces_once() {
  for path in /sys/class/net/*; do
    iface="$(basename "$path")"
    case "$iface" in
      xfrmi*|ipsec0)
        disable_iface_offloads "$iface" || true
        ;;
    esac
  done
}

if [ "$#" -eq 0 ]; then
  set -- /free5gc/n3iwf/n3iwf -c /free5gc/config/n3iwfcfg.yaml
fi

"$@" &
pid="$!"

trap 'kill -TERM "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true' INT TERM

# Wait a bit for xfrmi* to appear (created by n3iwf at runtime), then disable once.
for _ in $(seq 1 100); do
  disable_known_ifaces_once
  if ls /sys/class/net/xfrmi* >/dev/null 2>&1; then
    break
  fi
  sleep 0.05
done

wait "$pid"
