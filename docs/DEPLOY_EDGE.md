# Despliegue Edge — AmegakureWotan (N100 / 8GB)

Guía de despliegue en nodo edge de bajo consumo (Intel N100, 8 GB RAM, SSD SATA).
El grafo probatorio es **Kùzu embebido** (C++, columnar); Neo4j queda FUERA del
núcleo TRL-9 (ver `docs/ADR-001-neo4j.md`). El perfil edge no sostiene Neo4j
Graph-RAG ni Maltego.

---

## 1. Hardware / recursos

| Recurso | Mínimo edge | Nota |
|---------|-------------|------|
| CPU | Intel N100 (4c/4t, 6W) | suficiente para Kùzu + parsers |
| RAM | 8 GB | Kùzu + procesos Python ~1.5 GB pico |
| Disco | 128 GB SSD | timeline + dossiers + imagen podman |
| Red | salida egress controlada | Tor opcional; SearXNG local preferido |

---

## 2. Sistema base

OpenSUSE Tumbleweed / Leap o Debian 12 mínimo. Dependencias del host:

```bash
# Python 3.11+ (3.13 verificado en dev)
python3 --version
# Podman para aislamiento DFIR (velociraptor/volatility/sleuthkit)
sudo zypper in podman openssl       # o: apt install podman openssl
# SearXNG local (fuente L3, evita egress a motores externos)
#   docker/podman compose con searxng/searxng
```

---

## 3. Instalación limpia (wheel, TRL-9)

```bash
cd /home/lugh/AmegakureDojo/Desarrollos/AmegakureWotan
python3 -m build                                   # sdist + wheel
python3 -m venv /opt/amewotan/venv
/opt/amewotan/venv/bin/pip install dist/amegakurewotan-*.whl
/opt/amewotan/venv/bin/amewotan doctrine           # smoke: CLI operativa
```

No usar `pip install -e .` en producción edge: el wheel es el artefacto firmado.

---

## 4. Configuración de datos

```bash
export AMEWOTAN_DATA_DIR=/var/lib/amewotan
mkdir -p "$AMEWOTAN_DATA_DIR"
/opt/amewotan/venv/bin/amewotan roe list           # crea opsec/roe, opsec/keys, evidence/
```

Namespaces persistidos (fuente de verdad: `config.py` `Config.subdirs`):
`opsec/roe`, `opsec/keys`, `evidence`, `reports`, `sessions`, `profiles`.

`.gitignore` excluye operator-local: `sessions/`, `profiles/`, `evidence/*`.

---

## 5. Servicios mínimos

| Servicio | Edge | Arranque |
|----------|------|----------|
| Kùzu (grafo) | embebido | automático al importar `graph.db` |
| SearXNG | podman (local) | `podman compose -f searxng.yml up -d` |
| Tor (opcional) | podman | solo si la RoE lo autoriza |
| DFIR (velociraptor/volatility/sleuthkit) | podman aislado | bajo HITL + RoE, no siempre activo |

---

## 6. Aislamiento DFIR

Los adapters DFIR (`dfir/runner.py`) lanzan contenedores podman SIN red, con
montes `:ro` y límites de recursos. Sin runtime → `tool_unavailable` (auditable,
no fallo). Test de integración: `tests/test_dfir_runner.py` (skippable si no hay
podman en el host).

---

## 7. Endurecimiento operativo

```bash
# Claves de custodia/restauración con permisos 600
chmod 600 "$AMEWOTAN_DATA_DIR"/opsec/keys/*.pem
# RoE firmadas obligatorias en modo operacional (flag, default OFF en dev)
export AMEWOTAN_ENFORCE_SIGNED_ROE=1
```

Con `AMEWOTAN_ENFORCE_SIGNED_ROE=1`, GELSI RECHAZA acciones activas/darkweb/dfir
si `signature_verified=False` (ver `policy/gelsi.py`). En dev (default OFF) se
permite RoE sin firma para pruebas.

---

## 8. Verificación post-despliegue

```bash
/opt/amewotan/venv/bin/amewotan forensic verify        # CADENA ÍNTEGRA
/opt/amewotan/venv/bin/amewotan forensic verify-sign   # FIRMA VÁLIDA
bash scripts/verify_external.sh "$AMEWOTAN_DATA_DIR"/evidence <pubkey>.pem
```

---

*Despliegue bajo doctrina AmegakureDōjō. El wheel firmado + verificación externa
constituyen la atribución no-repudiable del nodo edge.*
