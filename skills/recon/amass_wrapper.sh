#!/bin/bash
# amass_wrapper.sh — Enumeración REAL de subdominios para el agente Heimdall.
# FORGE_CONTEXT: CIVIL | AmegakureWotan
#
# Doctrina: recon REAL, cero fabricación. Este wrapper NO inventa subdominios.
# Emite en stdout, una entrada por línea:
#   - subdominios descubiertos (FQDN)
#   - direcciones IP resueltas (para que Heimdall las separe por regex)
# Si ninguna herramienta está disponible, sale con código 3 y NO imprime nada,
# de modo que Heimdall reporte ausencia real en lugar de un resultado inventado.
#
# Orden de preferencia (todas pasivas por defecto):
#   1) subfinder  (rápido, pasivo)
#   2) amass enum -passive
#   3) resolución directa del apex vía getent/dig (mínimo verificable)
set -u

TARGET="${1:-}"
if [ -z "$TARGET" ]; then
  echo "[!] uso: amass_wrapper.sh <dominio>" >&2
  exit 2
fi

# Normaliza: quita esquema y www., y punto final.
TARGET="$(echo "$TARGET" | sed -E 's#^https?://##; s#^www\.##; s#\.$##' | tr 'A-Z' 'a-z')"

emitted=0

emit() {
  # dedup simple vía asociación en awk aguas abajo; aquí sólo imprimimos.
  if [ -n "${1:-}" ]; then
    echo "$1"
    emitted=1
  fi
}

# ── 1) subfinder (pasivo) ────────────────────────────────────────────────────
if command -v subfinder >/dev/null 2>&1; then
  # -silent: solo hosts; timeout defensivo para no colgar el pipeline.
  while IFS= read -r host; do
    emit "$host"
  done < <(timeout 60 subfinder -silent -d "$TARGET" 2>/dev/null)
fi

# ── 2) amass enum pasivo ─────────────────────────────────────────────────────
if command -v amass >/dev/null 2>&1; then
  # timeout defensivo agresivo: sin API keys amass puede tardar minutos.
  while IFS= read -r line; do
    # amass emite "sub.dominio (FQDN) --> ... a_record --> 1.2.3.4 (IPAddress)"
    # extraemos el FQDN inicial y cualquier IP.
    fqdn="$(echo "$line" | awk '{print $1}')"
    case "$fqdn" in
      *."$TARGET"|"$TARGET") emit "$fqdn" ;;
    esac
    for ip in $(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}'); do
      emit "$ip"
    done
  done < <(timeout 45 amass enum -passive -d "$TARGET" 2>/dev/null)
fi

# ── 3) Fallback mínimo VERIFICABLE: resolución del apex ──────────────────────
# No inventa subdominios; sólo confirma la IP real del dominio raíz si resuelve.
if [ "$emitted" -eq 0 ]; then
  if command -v dig >/dev/null 2>&1; then
    for ip in $(dig +short A "$TARGET" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}'); do
      emit "$ip"
    done
  elif command -v getent >/dev/null 2>&1; then
    for ip in $(getent ahostsv4 "$TARGET" 2>/dev/null | awk '{print $1}' | sort -u); do
      emit "$ip"
    done
  fi
  # Si el apex resolvió, emitimos también el propio apex como host verificado.
  if [ "$emitted" -eq 1 ]; then
    emit "$TARGET"
  fi
fi

# Sin ninguna evidencia real: salida vacía + código 3 (ausencia, no fabricación).
if [ "$emitted" -eq 0 ]; then
  exit 3
fi
exit 0
