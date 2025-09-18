#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-.}"

# -------------------------------------------------------------------
# 0) Raccogli tutti i file .h/.c/.asn
# -------------------------------------------------------------------
mapfile -t ALL < <(find "$ROOT" -type f \( -name '*.h' -o -name '*.c' -o -name '*.asn' \) -print | sort -u)

# -------------------------------------------------------------------
# 1) Auto-detect: header "entrypoint" KPM v3
#    Criteri:
#      - Nome/path contiene "E2SM-KPM" (non RC)
#      - E NON contiene "E2SM-RC"
#      - E (a) il path suggerisce v3 (es. "v3", "03") O
#        (b) il contenuto cita v3 (commenti generati da asn1c)
# -------------------------------------------------------------------
mapfile -t CANDIDATE_H < <(find "$ROOT" -type f -name '*.h' \
  | grep -Ei 'E2SM[-_]?KPM' \
  | grep -Eiv 'E2SM[-_]?RC' \
  | sort -u)

declare -a H_V3=()

is_v3_path() {
  local p="$1"
  # segnali nel path o nel nome
  echo "$p" | grep -Eqi '/v?0?3[^0-9]?|[-_.]v?0?3[^0-9]?|[-_.]03([-.]|$)' \
    && return 0 || return 1
}

is_v3_content() {
  local f="$1"
  # segnali nel contenuto (commenti tipici asn1c)
  # esempi: "E2SM-KPM-v03.00.asn", "KPM v3", "version 03"
  grep -Eiq 'E2SM[-_ ]?KPM[^0-9]*0?3(\.0+)?|KPM[^0-9]*v0?3|version[^0-9]*0?3' "$f"
}

for h in "${CANDIDATE_H[@]}"; do
  if is_v3_path "$h" || is_v3_content "$h"; then
    H_V3+=("$h")
  fi
done

# fallback prudente: se non ha trovato nulla, usa *tutti* gli E2SM-KPM*.h (non RC)
if [ "${#H_V3[@]}" -eq 0 ]; then
  H_V3=("${CANDIDATE_H[@]}")
fi

if [ "${#H_V3[@]}" -eq 0 ]; then
  echo "Nessun header KPM trovato. Controlla il path ROOT: $ROOT"
  exit 1
fi

# -------------------------------------------------------------------
# 2) Genera un C temporaneo che include tutti gli entrypoint KPM v3
# -------------------------------------------------------------------
TMP_C="$(mktemp /tmp/kpm3_entry_XXXX.c)"
TMP_DEPS="$(mktemp /tmp/kpm3_deps_XXXX.txt)"
trap 'rm -f "$TMP_C" "$TMP_DEPS"' EXIT

{
  echo "/* auto-generated: include closure for KPM v3 */"
  for h in "${H_V3[@]}"; do
    rel="${h#$ROOT/}"
    echo "#include \"$rel\""
  done
} > "$TMP_C"

# -------------------------------------------------------------------
# 3) Risolvi le dipendenze (#include) con gcc -MM
#     -I"$ROOT" di solito basta perché usano include con virgolette
# -------------------------------------------------------------------
# Nota: -w per non far fallire su warning strani degli header generati
if ! gcc -w -std=c11 -I"$ROOT" -MM "$TMP_C" > "$TMP_DEPS"; then
  echo "gcc -MM fallita. Verifica che gli header esistano e siano includibili."
  exit 2
fi

USED_FILES=$(sed -E 's/^[^:]+:\s*//; s/\\$//' "$TMP_DEPS" | tr ' ' '\n' | sed '/^$/d' | sort -u)

# Crea un set di file usati (normalizzati)
declare -A USED_SET=()
while read -r f; do
  [ -z "${f:-}" ] && continue
  # normalizza in path assoluto
  if [[ "$f" != /* ]]; then
    f="$(realpath -m "$f" 2>/dev/null || echo "$f")"
  fi
  USED_SET["$f"]=1
done <<< "$USED_FILES"

# Aggiungi .c “compagni” degli .h usati (se esistono)
for k in "${!USED_SET[@]}"; do
  if [[ "$k" == *.h ]]; then
    cand="${k%.h}.c"
    [ -f "$cand" ] && USED_SET["$cand"]=1
  fi
done

# -------------------------------------------------------------------
# 4) Elenco file NON usati dalla KPM v3
# -------------------------------------------------------------------
echo "=== FILE NON USATI dalla (auto-detected) KPM v3 ==="
declare -a NOT_USED=()
for f in "${ALL[@]}"; do
  rf="$(realpath -m "$f" 2>/dev/null || echo "$f")"
  if [[ -z "${USED_SET["$rf"]+x}" ]]; then
    echo "$f"
    NOT_USED+=("$f")
  fi
done
echo

# -------------------------------------------------------------------
# 5) Tra i NON usati, evidenzia quelli che citano KPM v01.02
# -------------------------------------------------------------------
PAT_V102='(kpm[^A-Za-z0-9]?(v|version)?[^0-9]*0?1[^0-9]*0?2|E2SM[-_ ]?KPM[^0-9]*1[._-]?0?2)'
echo "=== TRA QUESTI, file che citano KPM v01.02 (possibili sorgenti v1.02) ==="
if [ "${#NOT_USED[@]}" -gt 0 ]; then
  grep -RInE -i "$PAT_V102" -- "${NOT_USED[@]}" || true
else
  echo "(Nessuno)"
fi

# -------------------------------------------------------------------
# 6) Suggerimenti operativi
# -------------------------------------------------------------------
cat <<'EOF'

Suggerimenti:
  - Puoi spostare i NON usati in quarantena:
      mkdir -p quarantine
      ./kpm3_detect_prune.sh . | awk '/^=== FILE NON USATI/{flag=1;next} /^$/{flag=0} flag {print}' \
        | while read -r p; do [ -f "$p" ] && mv "$p" quarantine/; done

  - Se alcune include sono in sotto-cartelle con path strani, aggiungi -I extra:
      (modifica la riga gcc -MM aggiungendo -I<altra/dir>)

  - Se vuoi la lista “solo file non usati” senza altre sezioni:
      ./kpm3_detect_prune.sh . | awk '/^=== FILE NON USATI/{f=1;next} /^$/{f=0} f'

EOF
