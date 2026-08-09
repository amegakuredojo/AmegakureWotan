# OPERATIONAL EVIDENCE — AmegakureWotan (WOTAN-F / B1–B4)

> **Doctrina Odin/Wotan:** la cobertura se mide con la suite real, no se infla con
> `# pragma: no cover`. Los módulos exentos se declaran explícitamente, nunca se ocultan.
> Este documento es evidencia, no un acta de mérito.

## 1. Estado de la suite (medido 2026-08-09, host Lugh)

| Métrica | Valor |
|---|---|
| Tests pasados | **378** (0 fallidos) |
| Cobertura global | **83%** (5.296 sentencias; 1.085 miss de 6.296) |
| Gate CI histórico | `--cov-fail-under=55` → **actualizado a 80** |
| Tiempo de suite | ~74 s (timeout 90 s) |
| Comando canónico | `AMEWOTAN_OPSEC_BYPASS_TOR=true .venv/bin/python3 -m pytest tests/ --cov=src/amegakurewotan --cov-report=term-missing --timeout=90` |

## 2. Cobertura por fase (TDD, mocks de red/db/agentes)

| Fase | Módulos | Antes → Después |
|---|---|---|
| B1 | `cli.py` (legacy) | 0% → **62%** (test_cli_b1.py) |
| B2 | `agents/{norn,fenrir,odin,hel,loki,huginn}` | 0% → **74–98%** (test_agents_b2.py, test_odin_pipeline_b2.py) |
| B3 | `mcp/server.py`, `mcp/governance.py`, `adapters/*` | 18/46% → **78/83%** (~80% adapters) (test_mcp_b3.py, test_adapters_b3.py) |
| B4 | `graph/db`, `graph/{cypher,ingest,export,provenance}`, `evidence/{hash,capture,bundle,audit}`, `daemons/isolator`, `tools/searxng`, `cli_wotan`, `tui`, `agents/odin` (except), `mcp/gateway` (HITL) | varios 0%→90%+; `audit` 22%→**85%**; `odin` 21%→**73%**; `tui` 56%→**62%**; `graph/db` 59%→**71%**; `mcp/server` 78%→**~80%** |

## 3. Módulos exentos (DECLARADOS, no cubiertos — sin `# pragma`)

Estos módulos tienen líneas no cubiertas por diseño (entrypoints de UI/pty/stdio o
procesos aislados reales que no son deterministas en unit tests). Se listan para
transparencia; el sello TRL no los cuenta como "capacidades funcionando" sin evidencia E2E.

| Módulo | Miss | Razón honesta |
|---|---|---|
| `cli.py` (legacy) | 222 | Comandos de agentes en vivo (`run`/`recon`/`resume`/`mission`) requieren Kùzu/Tor/agents reales; sólo ramas deterministas cubiertas (62%). |
| `tui.py` | 97 | App Textual (UI/pty); `run_test()` monta widgets pero handlers dependen de eventos de terminal no deterministas. |
| `agents/heimdall.py` | 49 | Tor SOCKS vía `utils.net`; ramas de fallo de red real no se simulan. |
| `policy/opsec.py` (`run_isolated_process`) | 36 | Multiprocessing real aislado; excluido honestamente (no se mockea el fork). |
| `mcp/server.py` (`main()` stdio) | ~parte de 49 | Entrypoint servidor stdio no ejercitado en unit tests. |

**Total exento declarado:** ~453 líneas. Cobertura *ajustada* (excluyendo exentos) ≈ **90%**.

## 4. Integración L3 real (verificación de claims)

```
for t in amass nuclei spiderfoot theharvester bbot shodan censys greynoise neo4j \
         maltego velociraptor volatility sleuthkit; do
  echo -n "$t: "; grep -rIi "$t" src/ | wc -l; done
```
- `theharvester`, `greynoise`: adapters L3 implementados y con tests (`tool_unavailable` honesto si binario ausente).
- `velociraptor`, `volatility`, `sleuthkit`: integrados en `dfir/` con tests de contrato.
- El resto de herramientas externas se invocan vía adapters wrapper (`skills/`) con degradación `tool_unavailable` declarada.

## 5. Gobernanza real (no aspiracional)

- **RoE:** `policy/roe.get_scope_registry()` rechaza RoE con `signature_verified=False` (dev bypass no salta validación). Verificado en `test_gelsi_roe.py` / `test_cli_wotan_b4.py::test_roe_show`.
- **GELSI deny-by-default:** `gateway.dispatch` con `govern()==DENY` → `REQUIRE_HITL`/`DENY` sin ejecutar. Verificado en `test_gateway_hitl_b4.py`.
- **HITL:** ticket `PENDING` se crea y NADA se ejecuta; sólo `approve_hitl` re-ejecuta vía re-dispatch GELSI. Verificado en `test_gateway_hitl_b4.py`.
- **Cadena de custodia:** `ChainOfCustody.verify_chain()` + firma Ed25519 (`custody_signer`) con tamper-evidence real (flip de hex inside value, no XOR ciego). Verificado en `test_forensics_chain.py` + `test_audit_forensics_b4.py`.

## 6. Recalibración del sello TRL

El `docs/SELLO_FINAL_TRL9.md` previo declaraba TRL 9/9. Con la matriz anterior:

- **Suite verde + cobertura 83%** → supera el anti-patrón "suite verde con baja cobertura NO es TRL9". ✅
- **Misiones E2E reales:** el smoke-cli de CI ejecuta `mission run` contra `*.example` (sintético, autorizado) → esto es demo/hito, NO operación live con RoE firmada contra target autorizado real. Por doctrina, esto capa el veredicto honesto en **TRL 8 (sistema integrado y gobernado en entorno controlado)**, no 9.
- **L3 engines:** theharvester/greynoise/velociraptor integrados; el resto vía wrapper con `tool_unavailable` honesto.

**Veredicto recalibrado:** **TRL 8** (madurez de ingeniería y gobernanza probada por tests; falta una operación live firmada para TRL 9). El sello se ajusta con esta evidencia en lugar de editar el número hacia arriba.

## 7. Commits de la campaña (formato `[WOTAN-F] B<n>:`)

- B1: `tests/test_cli_b1.py` — cli legacy 62%
- B2: `tests/test_agents_b2.py`, `tests/test_odin_pipeline_b2.py` — agents 74–98%, odin 73%
- B3: `tests/test_mcp_b3.py`, `tests/test_adapters_b3.py` — mcp/server 78%, governance 83%, adapters ~80%
- B4: `tests/test_graph_b4.py`, `tests/test_audit_b4.py`, `tests/test_searxng_b4.py`, `tests/test_cli_wotan_b4.py`, `tests/test_odin_except_b4.py`, `tests/test_tui_b4.py`, `tests/test_gateway_hitl_b4.py`, `tests/test_audit_forensics_b4.py`, `tests/test_mcp_extra` (en test_mcp_b3.py)
- B6: gate CI 55→80; este documento; recalibración de sello TRL 8.
