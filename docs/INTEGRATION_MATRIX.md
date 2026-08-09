# Matriz de Integración L3 — AmegakureWotan

Estado real de cada motor externo citado en AmegakureWotan.md tras la Fase C
(WOTAN-F4). Criterio: **honestidad sobre cobertura**. Un motor ausente devuelve
`tool_unavailable` explícito; NUNCA salida fabricada.

| Motor (AmegakureWotan.md) | Capa | Adaptador | Estado | Modo de invocación | Gobernanza |
|---|---|---|---|---|---|
| Heimdall (SearXNG) | L3 recon | `agents.heimdall` | Integrado | API local SearXNG | GELSI pasivo/activo |
| theHarvester | L3 recon | `adapters.l3.theharvester` | **Integrado (honesto)** | binario CLI (PATH) | GELSI pasivo |
| GreyNoise | L3 enrich | `adapters.l3.greynoise` | **Integrado (honesto)** | API (env GREYNOISE_API_KEY) | GELSI pasivo |
| Amass | L3 recon | `skills/recon/amass_wrapper.sh` | Script externo (skills/) | subprocess | GELSI activo (RoE) |
| Recon-ng | L3 recon | — | No integrado (pendiente) | — | — |
| SpiderFoot | L3 recon | — | No integrado (pendiente) | — | — |
| Shodan | L3 enrich | — | No integrado (pendiente) | API (env) | GELSI pasivo |
| Censys | L3 enrich | — | No integrado (pendiente) | API (env) | GELSI pasivo |
| Nuclei | L3 active | skills/ | Script externo | subprocess | GELSI activo (RoE) |
| BBOT | L3 recon | — | No integrado (pendiente) | — | — |
| Maltego | L3 OSINT | — | **Excluido núcleo TRL-9** | GUI propietaria | — |
| Velociraptor | DFIR | `dfir.velociraptor` | Integrado (contenedor) | podman aislado | HITL + RoE |
| Volatility3 | DFIR | `dfir.volatility` | Integrado (contenedor) | podman aislado | HITL + RoE |
| Sleuth Kit | DFIR | `dfir.sleuthkit` | Integrado (contenedor) | podman aislado | HITL + RoE |
| Kùzu (Graph-RAG) | L2 grafo | `graph.*` | **Integrado (fuente de verdad)** | embedded | GELSI pasivo |
| Neo4j (Graph-RAG) | L2 grafo | — | **Excluido núcleo** (ADR-001) | — | — |

## Leyenda

- **Integrado (honesto):** el código invoca el motor real; si falta (clave/binario/
  red) devuelve `tool_unavailable` auditable.
- **No integrado (pendiente):** no hay adaptador; se añade en fase posterior sin
  bloquear TRL-9.
- **Excluido núcleo TRL-9:** decidido fuera de alcance por perfil edge / licencia.

## Contrato de adapter (WOTAN-F4)

Todo adapter L3 NUEVO debe:
1. Recibir credenciales SOLO vía env (nunca hardcodeadas).
2. Pasar por `get_rate_limiter().acquire()` antes de cualquier salida de red.
3. Devolver `{"status": "tool_unavailable", "note": "Sin salida fabricada."}` si el
   motor no está disponible.
4. Estar cubierto por test que verifique el caso `tool_unavailable` Y el caso OK
   mockeado.
