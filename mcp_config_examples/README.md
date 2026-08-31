# 🦅 AmegakureWotan — MCP Server Zero-Config (v3.0.0)

Configuraciones listas para usar en **AGY (Antigravity)**, **OpenCode**, **Claude Desktop** y cualquier host (Kali, Parrot, Ubuntu, Debian, openSUSE, Arch, WSL2, macOS).

---

## ⚡ Zero-Config Out-of-the-Box

AmegakureWotan opera de forma **100% agnóstica al sistema operativo y a la red**.
- **Cero dependencias obligatorias de contenedores Docker**.
- **Cero configuración requerida de proxies Tor** (la pila de red usa el stack nativo del host).
- **Grafo Kùzu embebido** automático en `~/.amegakurewotan/vault.kuzu`.
- **Integridad y cadena de custodia militar forense** con HMAC-SHA512 (`timeline.jsonl`).

---

## Modos de Operación

| Modo | Config | Requisitos de Red | Kùzu DB | Uso Principal |
|------|--------|-------------------|---------|---------------|
| **Nativo Zero-Config (Recomendado)** | `antigravity_config.json` | Stack de red del Host | `~/.amegakurewotan/vault.kuzu` | AGY, Claude Desktop, OpenCode, VS Code |
| **Personalizado / Sandbox** | `sandbox_config.json` | Stack de red del Host | Custom via `AMEWOTAN_DATA_DIR` | CI/CD, Sandboxes, entornos de pruebas |
| **OPSEC Reforzado (Opcional)** | Personalizado | Proxychains / Host VPN / Tor | `~/.amegakurewotan/vault.kuzu` | Investigaciones con túneles a nivel de OS |

---

## Configuración Rápida

### 1. AGY (Antigravity) / VS Code / Claude Desktop

Añade a tu archivo de configuración de servidores MCP:

```json
{
  "mcpServers": {
    "amegakurewotan": {
      "type": "stdio",
      "command": "python",
      "args": [
        "-m",
        "amegakurewotan.mcp.server"
      ]
    }
  }
}
```

O si instalaste el paquete vía `pip` / `pipx`:

```json
{
  "mcpServers": {
    "amegakurewotan": {
      "type": "stdio",
      "command": "amewotan-mcp",
      "args": [
        "run"
      ]
    }
  }
}
```

---

## Variables de Entorno Opcionales (Personalizaciones del Usuario)

| Variable | Default | Propósito |
|----------|---------|-----------|
| `AMEWOTAN_DATA_DIR` | `~/.amegakurewotan` | Directorio raíz para reportes, evidencias y grafo |
| `KUZU_DATABASE_PATH` | `~/.amegakurewotan/vault.kuzu` | Ruta personalizada para el grafo Kùzu embebido |
| `OPSEC_TOR_PROXY` | `None` | *(Opcional)* Proxy SOCKS si se desea enrutar vía Tor local |
| `SEARXNG_URL` | `http://127.0.0.1:8080/search` | *(Opcional)* Instancia SearXNG local para dorking |

---

## Herramientas MCP Expuestas

| Tool | Dominio | Descripción |
|------|---------|-------------|
| `searxng_recon` | Search | Búsqueda OSINT pasiva y dorking |
| `heimdall_recon` | Surface | Enumeración DNS, WHOIS, ASN, historial SSL/TLS |
| `odin_orchestrate` | Orchestrator | Pipeline OSINT multi-fuente consolidado |
| `huginn_humint` | Exposure | Análisis de exposición de identidad y perfiles |
| `hel_darkweb` | Leaks | Detección de fugas de credenciales y dark web |
| `fenrir_correlate` | Correlation | Correlación relacional y pivoteo en grafo |
| `kuzu_cypher_query` | Graph | Consultas Cypher read-only sobre entidades y relaciones |
| `audit_verify` | Forensics | Verificación criptográfica HMAC-SHA512 de la cadena de custodia |
| `export_graph` | Graph | Exportación forense de entidades y relaciones en JSON |

