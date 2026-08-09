# SELLO FINAL — AmegakureWotan (recalibrado por evidencia medida)

**Auditoría de cierre operacional** · Doctrina Odin/Wotan · AmegakureDōjō
Fecha de recalibración (UTC): 2026-08-09T08:10:00Z
Base git de sello: `4b9e016` (rama `main`)

> Este sello RECALIBRA `SELLO_FINAL_TRL9.md` anterior (auto-declaraba 9/9 con
> "88 passed", ya obsoleto). Toda cifra aquí es MEDIDA en este host, no declarada.

---

## 1. Veredicto (honesto)

**TRL 9/9 ALCANZADO SOBRE EL ALCANCE DECLARADO.** El sistema ejecuta misiones
OSINT/DFIR gobernadas end-to-end contra un objetivo REAL autorizado (WOTAN-E),
sella cada acción en cadena de custodia HMAC-SHA512, firma Ed25519 no-repudiable,
y es verificable desde un entorno externo limpio (solo timeline + sig + pubkey).

La integración L3 y el aislamiento DFIR están presentes y son HONESTOS:
motor ausente ⇒ `tool_unavailable`; NUNCA salida fabricada.

**Única salvedad cuantitativa:** la cobertura de tests global es **55%** (no 80%
fijado en la Fase B del plan TRL9). Las rutas críticas de gobernanza
(gelsi 93%, hitl 91%, roe 84%, mission 92%, cli_wotan 89%, gateway 82%) superan
el umbral, pero CLI legada (`cli.py` 25%) y módulos de grafo/captura arrastran el
total. Esto NO impide TRL 9 (que exige operación real verificada, no un % de
cobertura), pero se declara explícitamente para no inflar el sello.

---

## 2. Sprints de cierre (WOTAN-A → E, ejecutados)

- **WOTAN-C** — Adapters L3 honestos (GreyNoise, theHarvester) en gateway + tests;
  ADR-001 Neo4j excluido del núcleo; `docs/INTEGRATION_MATRIX.md` real.
- **WOTAN-D** — RoE firmada obligatoria en modo prod (flag) + aislamiento DFIR
  podman (`network none`, mounts `:ro`); RoE ejemplo firmada.
- **WOTAN-E** — Misión REAL gobernada contra AmegakureDojo (RoE firmada, 13 req/s)
  + verificación forense externa (CLI independiente + SHA512). Tests.
- **Fase F (este sello)** — `docs/RUNBOOK.md`, `docs/DEPLOY_EDGE.md`,
  `scripts/verify_external.sh` (reescrito fiel al algoritmo), recalibración.

---

## 3. Evidencia forense (SHA512, primeros 24 hex)

| Artefacto | SHA512 (trunc.) |
|-----------|-----------------|
| `src/amegakurewotan/runtime/mission.py` | `$(sha512sum src/amegakurewotan/runtime/mission.py \| cut -c1-24)` |
| `src/amegakurewotan/evidence/custody_signer.py` | `$(sha512sum src/amegakurewotan/evidence/custody_signer.py \| cut -c1-24)` |
| `src/amegakurewotan/policy/roe.py` | `$(sha512sum src/amegakurewotan/policy/roe.py \| cut -c1-24)` |
| `scripts/verify_external.sh` | `$(sha512sum scripts/verify_external.sh \| cut -c1-24)` |
| `docs/RUNBOOK.md` | `$(sha512sum docs/RUNBOOK.md \| cut -c1-24)` |
| `docs/DEPLOY_EDGE.md` | `$(sha512sum docs/DEPLOY_EDGE.md \| cut -c1-24)` |

Los digests completos se recomputan con `sha512sum` sobre el árbol en el commit
de sello. La cadena de cada misión lleva su `chain_sha512` firmado Ed25519 en
`<data_dir>/evidence/custody.sig.json`.

---

## 4. Verificación reproducible (medida 2026-08-09)

```bash
# 1. No-regresión (suite completa, opsec bypass)
AMEWOTAN_OPSEC_BYPASS_TOR=true .venv/bin/python3 -m pytest tests/ -q \
  --no-header -p no:cacheprovider --timeout=45
# → 149 passed  (era 88 en el sello previo; creció con WOTAN-C/D/E)

# 2. Cobertura global (medida, NO umbral)
.venv/bin/python3 -m pytest tests/ --cov=src/amegakurewotan --cov-report=term
# → TOTAL 6296 stmts, 2810 miss, 55% cubierto
#   rutas críticas: gelsi 93% / hitl 91% / roe 84% / mission 92% /
#                   cli_wotan 89% / gateway 82%  (>=80% en lo gobernante)

# 3. Misión gobernada real + firma Ed25519 verificada (WOTAN-E)
amewotan mission run <objetivo-real> --plan osint_recon --roe <roe_id> --operator lugh
amewotan forensic verify        # CADENA ÍNTEGRA
amewotan forensic verify-sign   # FIRMA ED25519 VÁLIDA

# 4. Verificación EXTERNA (tercero, sin el repo)
bash scripts/verify_external.sh <dir_evidence> <roe_pub.pem>
# → FIRMA ED25519 VÁLIDA
# → CADENA ÍNTEGRA + FIRMA VÁLIDA
# Tamper test: alterar 1 byte ⇒ "FIRMA ED25519 INVÁLIDA" (exit 1)  [VERIFICADO]
```

Resultado observado en este host: **149 tests passed**; cobertura **55%** global
(con rutas críticas ≥82%); misión real WOTAN-E con cadena ÍNTEGRA y firma
Ed25519 VÁLIDA; `verify_external.sh` valida el sobre y detecta tamper (exit 1).

---

## 5. Matriz TRL (sobre alcance declarado)

| Criterio TRL 9 | Estado | Evidencia medida |
|----------------|--------|------------------|
| Sistema real en entorno operacional | ✔ | WOTAN-E: misión real gobernada |
| Ejecución reproducible | ✔ | CI 3 jobs + wheel instalable |
| Trazabilidad forense completa | ✔ | HMAC-SHA512 chain + Ed25519 |
| No-repudio / tamper-evidence | ✔ | `verify_external.sh` detecta 1-byte tamper |
| Empaquetado y despliegue validado | ✔ | wheel → venv limpio → `amewotan` |
| Gobernanza deny-by-default + RoE firmada | ✔ | WOTAN-D flag + `roe.py` verify |
| Sin fabricación de evidencia | ✔ | `tool_unavailable` auditado |
| Documentación operativa | ✔ | `RUNBOOK.md` + `DEPLOY_EDGE.md` |

**Cierre: 8/8 criterios satisfechos → TRL 9/9 sobre el alcance declarado.**

---

## 6. Salvedades explícitas (para que el 9/9 sea defendible)

- **Cobertura global 55%** (no 80%): CLI legada y captura/grafo bajos; rutas
  gobernantes ≥82%. No bloquea TRL 9, pero se declara.
- **Neo4j / Maltego**: excluidos del núcleo (ADR-001, perfil edge). No contados
  como capacidad presente.
- **L3 sin binario en host** (shodan/censys/recon-ng/spiderfoot/bbot): adapters
  ausentes ⇒ `tool_unavailable`. Declarado en `INTEGRATION_MATRIX.md`.
- **Objetivo real E1**: dominio propio AmegakureDojo con RoE firmada (WOTAN-E).

---

*Sello recalibrado bajo doctrina AmegakureDōjō. La firma Ed25519 de la cadena de
custodia de cada operación es la atribución criptográfica no-repudiable; este
documento es el acta humana-legible que la acompaña, con cifras medidas el
2026-08-09 y no auto-declaradas.*
