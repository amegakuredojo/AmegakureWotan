# 🦅 Karasugakure — MCP Config Examples

Configuraciones listas para usar en **AGY (Antigravity)**, **OpenCode** y **Docker Sandboxes**.

---

## Modos de Operación

| Modo | Config | Tor | SearXNG | Kùzu | Uso |
|------|--------|-----|---------|------|-----|
| **Producción** | `antigravity_config.json` | ✅ Requerido | ✅ Docker | `/data` (volumen) | AGY/OpenCode con stack completo |
| **Producción** | `opencode_config.json` | ✅ Requerido | ✅ Docker | `/data` (volumen) | Igual que AGY |
| **Sandbox** | `sandbox_config.json` | ❌ Bypass | 🔧 Configurable | `/tmp/` (efímero) | Sandboxes, CI/CD, dev |

---

## Prerequisitos (modo producción)

El stack de infraestructura debe estar levantado **antes** de que AGY/OpenCode inicialice el MCP:

```bash
cd /home/lugh/AmegakureDojo/Karasugakure

# 1. Levantar infraestructura (Tor + SearXNG) en background
docker compose up -d tor-proxy searxng

# 2. Esperar a que Tor esté listo (~15-30s)
sleep 20

# 3. Verificar que está activo
docker compose ps

# 4. Ahora AGY/OpenCode pueden conectar al MCP
```

> **CRÍTICO:** Sin el paso 1-3, el MCP puede dar timeout en el handshake inicial.

---

## Uso — AGY (Antigravity)

Añadir al archivo de configuración MCP de AGY (`~/.gemini/antigravity-cli/config.json` o similar):

```json
// Contenido de antigravity_config.json
```

---

## Uso — OpenCode

Añadir a la configuración MCP de OpenCode (`.opencode/config.json`):

```json
// Contenido de opencode_config.json
```

---

## Uso — Docker Sandbox (sin Tor / sin SearXNG)

Para entornos aislados donde no hay Tor disponible:

```bash
# Modo sandbox directo:
docker compose -f docker-compose.yml -f docker-compose.sandbox.yml \
  --profile sandbox-mcp run --rm -i --no-TTY --no-deps \
  -e KARASU_SILENT_BOOTSTRAP=true \
  -e KARASU_OPSEC_BYPASS_TOR=true \
  -e SANDBOX_DATA_PATH=/tmp/karasu_sandbox \
  karasu-mcp run
```

O usar `sandbox_config.json` directamente en tu cliente MCP.

---

## Variables de Entorno Clave

| Variable | Default | Descripción |
|----------|---------|-------------|
| `KARASU_OPSEC_BYPASS_TOR` | `false` | `true` = Sandbox mode, Tor no requerido |
| `KARASU_SILENT_BOOTSTRAP` | `false` | `true` = Suprime banners (necesario para MCP) |
| `KARASU_MCP_TOR_TIMEOUT` | `10` | Segundos máx esperando Tor en modo MCP |
| `SANDBOX_DATA_PATH` | `/tmp/karasu_sandbox` | Path de datos en modo sandbox |
| `SANDBOX_SEARXNG_URL` | `http://localhost:8080/search` | URL SearXNG en sandbox |
| `KUZU_DATABASE_PATH` | `/data/karasu_vault.kuzu` | Path de base de datos Kùzu |

---

## Tools MCP Disponibles (v2.0.0)

El MCP Server expone **10 tools** sobre el arsenal completo del framework:

| Tool | Descripción | Tor Requerido |
|------|-------------|---------------|
| `searxng_recon` | Búsqueda OSINT con dorks vía SearXNG | ❌ |
| `heimdall_recon` | DNS, WHOIS, cert history, ASN | ❌ |
| `odin_orchestrate` | Pipeline OSINT completo (todos los agentes) | ⚠️ Para Hel |
| `huginn_humint` | HUMINT, perfiles sociales, HES score | ❌ |
| `hel_darkweb` | Búsqueda Dark Web vía Tor | ✅ Requerido |
| `fenrir_correlate` | Correlación relacional del grafo | ❌ |
| `kuzu_ingest_entity` | Ingesta de entidades en grafo Kùzu | ❌ |
| `kuzu_cypher_query` | Query Cypher read-only (allowlist) | ❌ |
| `audit_verify` | Verificación integridad ledger forense | ❌ |
| `export_graph` | Export completo de grafo como JSON | ❌ |
