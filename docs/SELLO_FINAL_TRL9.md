# SELLO FINAL GUDODAMA — AmegakureWotan TRL 9/9

**Auditoría de cierre operacional** · Doctrina Odin/Wotan · AmegakureDōjō
Fecha de sello (UTC): 2026-08-07T23:59:49Z
Base git previa al sello: `12f46a1`

---

## 1. Veredicto

**TRL 9/9 — ALCANZADO.** El sistema AmegakureWotan opera de extremo a extremo en
un entorno operacional real: ejecuta misiones OSINT/DFIR gobernadas, sella cada
acción en una cadena de custodia HMAC-SHA512, firma el estado completo con
Ed25519 no-repudiable, empaqueta y despliega como artefacto instalable (`wheel`
→ console_script `amewotan`), y valida todo lo anterior en CI reproducible.

Cadena de decisión: **deny-by-default**. Herramienta ausente ⇒ `tool_unavailable`.
Cero salida fabricada. Toda evidencia es real y verificable a posteriori desde un
entorno externo con solo `timeline.jsonl` + sobre de firma + clave pública.

---

## 2. Sprints de cierre (F7 → F9)

### WOTAN-F7 — Orquestación de misión end-to-end gobernada
- `runtime/mission.py`: `MissionOrchestrator` recorre un plan (playbook versionado)
  EXCLUSIVAMENTE vía el gateway consolidado (GELSI → ALLOW/DENY/REQUIRE_HITL).
  Sella `mission.start` / `mission.completed`, produce dossier JSON (máquina) +
  Markdown (operador), firma la cadena Ed25519 y verifica el sobre.
- Planes: `osint_recon`, `dfir_triage`, `full`.
- No fabricación: pasos REQUIRE_HITL quedan como tickets PENDIENTES (doble puerta);
  DFIR sin runtime devuelve `tool_unavailable`; el resumen refleja fielmente el
  resultado del handler.
- CLI `amewotan mission plans|run|list|status|report` (`cli_wotan.py`).

### WOTAN-F8 — Empaquetado y despliegue operacional validado
- Build `sdist` + `wheel` reproducible; instalación en venv LIMPIO (no editable).
- console_script `amewotan` operativo en `$PATH`; misión end-to-end real ejecutada
  desde el binario instalado con firma Ed25519 VÁLIDA y exit codes correctos.
- CI: nuevo job `package` (build wheel → install limpio → misión E2E) y ampliación
  del job `smoke-cli` con la misión gobernada.

### WOTAN-F9 — Sello final + tamper-evidence + verificación TRL
- Tests F9 (`test_mission_tamper_f9.py`): una misión firmada es no-repudiable;
  alterar un byte del timeline invalida la firma Ed25519 (tamper-evidence).
- Fix de raíz en `config.get_config()`: relee `AMEWOTAN_DATA_DIR` en tiempo de
  llamada (antes se congelaba en import-time), haciendo efectivos los overrides de
  test/despliegue y eliminando una clase de contaminación de estado entre entornos.
- Documentación de la capa consolidada `amewotan` en `README.md`.

---

## 3. Evidencia forense (SHA512, primeros 32 hex)

| Artefacto | SHA512 (trunc.) |
|-----------|-----------------|
| `src/amegakurewotan/runtime/mission.py` | `798f8682c7410fd9123774d22833a3e0…` |
| `src/amegakurewotan/cli_wotan.py`       | `082ec94658f473f639c778c77b8700a6…` |
| `src/amegakurewotan/config.py`          | `f3bba1ae4a06b810b0c7b9133529455b…` |
| `tests/test_mission_e2e.py`             | `c109e8d1a2bb26d04c5631c5aaba6e98…` |
| `tests/test_mission_tamper_f9.py`       | `2bb5429f9d9852c5ecf2bb308020bd68…` |
| `.github/workflows/ci.yml`              | `3cab55736822db656b135be029f3cd96…` |

Los digests completos se recomputan con `sha512sum` sobre el árbol en el commit
de sello. La cadena de custodia de cada misión lleva su propio `chain_sha512`
firmado Ed25519 en `<data_dir>/evidence/custody.sig.json`.

---

## 4. Verificación reproducible (3/3)

```bash
# 1. No-regresión (suite completa, opsec bypass)
AMEWOTAN_OPSEC_BYPASS_TOR=true python -m pytest tests/ -q
# → 88 passed

# 2. Misión gobernada real + firma Ed25519 verificada
amewotan mission run target.com --plan osint_recon
amewotan forensic verify        # CADENA ÍNTEGRA
amewotan forensic verify-sign   # FIRMA ED25519 VÁLIDA

# 3. Empaquetado limpio (TRL 9): wheel → venv limpio → console_script → misión E2E
python -m build && pip install dist/amegakurewotan-*.whl   # en venv nuevo
amewotan mission run pkg-target.example --plan osint_recon
amewotan forensic verify-sign   # FIRMA ED25519 VÁLIDA
```

Resultado observado en el host de sello: **88 tests passed**; misión E2E con
`ALLOW=4 DENY=1 REQUIRE_HITL=0 ERROR=0`, cadena ÍNTEGRA (11 registros), firma
Ed25519 VÁLIDA; instalación desde wheel con `amewotan` operativo en `$PATH`.

---

## 5. Matriz TRL

| Criterio TRL 9 | Estado | Evidencia |
|----------------|--------|-----------|
| Sistema real en entorno operacional | ✔ | `amewotan mission run` end-to-end |
| Ejecución reproducible | ✔ | Planes deterministas + CI 3 jobs |
| Trazabilidad forense completa | ✔ | Cadena HMAC-SHA512 + Ed25519 |
| No-repudio / tamper-evidence | ✔ | `test_mission_tamper_f9.py` |
| Empaquetado y despliegue validado | ✔ | Job CI `package` (wheel→install limpio) |
| Gobernanza deny-by-default sin bypass | ✔ | GELSI + HITL en el gateway |
| Sin fabricación de evidencia | ✔ | `tool_unavailable`; resúmenes fieles |
| Documentación operativa | ✔ | `README.md` capa `amewotan` |

**Cierre: 8/8 criterios satisfechos → TRL 9/9.**

---

*Sello emitido bajo doctrina AmegakureDōjō. La firma Ed25519 de la cadena de
custodia de cada operación constituye la atribución criptográfica no-repudiable;
este documento es el acta de cierre humana-legible que la acompaña.*
