#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-.}"

# Estensioni tipiche degli output asn1c
mapfile -t FILES < <(find "$ROOT" -type f \( -name '*.asn' -o -name '*.c' -o -name '*.h' \) -print)

# Pattern robusti per KPM v01.02 (varie grafie)
PATTERN='(kpm[^A-Za-z0-9]?(v|version)?[^0-9]*0?1[^0-9]*0?2|E2SM[-_ ]?KPM[^0-9]*1[._-]?0?2)'

echo "=== File che citano KPM v01.02 (possibile sorgente v1.02) ==="
grep -RInE --color=never -i "$PATTERN" "${FILES[@]}" || true

echo
echo "Suggerimento: se vuoi una lista “solo file” senza righe:"
grep -RIlE -i "$PATTERN" "${FILES[@]}" || true
