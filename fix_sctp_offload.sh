fix_sctp_offload() {
  local c="$1" pid
  pid="$(docker inspect -f '{{.State.Pid}}' "$c" 2>/dev/null || true)"
  [[ -n "$pid" && "$pid" != "0" ]] || { echo "[$c] PID non trovato"; return 1; }
  sudo nsenter -t "$pid" -n -- ethtool -K eth0 tx-checksum-sctp off \
    || sudo nsenter -t "$pid" -n -- ethtool -K eth0 tx off
}
fix_sctp_offload amf
fix_sctp_offload n3iwf
