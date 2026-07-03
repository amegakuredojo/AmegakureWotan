#!/usr/bin/env bash
set -euo pipefail

# Despliegue del nodo SearXNG self-hosted (OSINT autónomo).
# Uso: ./deploy.sh

ENV_FILE=".env"
SETTINGS_FILE="searxng/settings.yml"

if [ ! -f "$ENV_FILE" ]; then
  echo "[!] Falta .env — copia .env.example a .env y completa BRAVE_API_KEY."
  exit 1
fi

set -a
source "$ENV_FILE"
set +a

SEARXNG_SECRET="${SEARXNG_SECRET:-$(openssl rand -hex 32)}"

sed -i.bak \
  -e "s#__SECRET_KEY__#${SEARXNG_SECRET}#g" \
  -e "s#__BRAVE_API_KEY__#${BRAVE_API_KEY:-}#g" \
  "$SETTINGS_FILE"

echo "[*] settings.yml actualizado (backup en ${SETTINGS_FILE}.bak)."

docker compose up -d

echo "[*] Esperando arranque del contenedor..."
sleep 6

echo "[*] Verificando API JSON local:"
curl -s "http://127.0.0.1:8080/search?q=test&format=json" | head -c 300
echo
echo "[*] Si ves JSON arriba, el endpoint está listo en http://127.0.0.1:8080/search?format=json"
echo "[*] Verifica salida por Tor: curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org (requiere exponer el puerto de tor si quieres probar desde el host)"
