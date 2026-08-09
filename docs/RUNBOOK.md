# RUNBOOK — Operador AmegakureWotan

Runbook de operación para el CLI consolidado `amewotan`. Cubre el ciclo de vida
forense gobernado: cargar RoE firmada → correr misión → revisar HITL → verificar
cadena → exportar bundle. Todos los comandos son los reales del entrypoint
(`amegakurewotan.cli_wotan:main`, console_script `amewotan`).

Entorno de datos: `AMEWOTAN_DATA_DIR` (default `~/.amegakurewotan/`). Todo
timeline/custodia vive bajo `<base_dir>/evidence/`, las RoE bajo `<base_dir>/opsec/roe/`.

---

## 0. Prerrequisitos

```bash
# Entorno reproducible
cd /home/lugh/AmegakureDojo/Desarrollos/AmegakureWotan
make setup            # pip install -e ".[dev]" + pytest-timeout
.venv/bin/python3 -m pytest tests/ -q --no-header -p no:cacheprovider --timeout=45

# Opsec: tests/HITL sin Tor real
export AMEWOTAN_OPSEC_BYPASS_TOR=true
```

Consola disponible: `doctrine`, `domains`, `roe`, `mcp`, `forensic`, `hitl`, `mission`.

---

## 1. Doctrina y dominios (situación)

```bash
amewotan doctrine        # principios deny-by-default GELSI
amewotan domains          # lista herramientas consolidadas por dominio
```

---

## 2. Gestión de RoE firmadas (Ed25519)

El registro carga YAML de `<base_dir>/opsec/roe/`. Verifica firma contra
`<base_dir>/opsec/keys/roe_pub.pem` vía `openssl pkeyutl -verify`.

```bash
amewotan roe list         # columna Firma: ✔ verificada / ✘ sin verificar
amewotan roe show <roe_id>
```

### 2.1 Firmar una RoE (ciclo real openssl)

```bash
# 1. Generar par Ed25519 (una vez); la PRIVADA nunca se commitea.
openssl genpkey -algorithm ed25519 -out opsec/keys/roe_priv.pem
chmod 600 opsec/keys/roe_priv.pem
openssl pkey -in opsec/keys/roe_priv.pem -pubout -out opsec/keys/roe_pub.pem

# 2. Firmar el YAML (rawin, igual que verifica roe.py)
openssl pkeyutl -sign -rawin -inkey opsec/keys/roe_priv.pem \
  -in opsec/roe/<roe_id>.yaml -out opsec/roe/<roe_id>.yaml.sig

# 3. Verificar (debe imprimir Success)
openssl pkeyutl -verify -rawin -pubin -inkey opsec/keys/roe_pub.pem \
  -in opsec/roe/<roe_id>.yaml -sigfile opsec/roe/<roe_id>.yaml.sig

# 4. Confirmar en el CLI
amewotan roe list         # → ✔ verificada
```

> `git add` SOLO `opsec/roe/*.yaml`, `*.yaml.sig` y `opsec/keys/roe_pub.pem`.
> La clave privada y `opsec/keys/` quedan en `.gitignore` (operator-local).

---

## 3. Correr una misión gobernada

```bash
amewotan mission plans                       # osint_recon | dfir_triage | full
amewotan mission run <objetivo> \
  --plan osint_recon --roe <roe_id> --operator lugh
```

La misión recorre el playbook EXCLUSIVAMENTE vía `get_gateway().dispatch(...)`.
Cada paso se sella en `timeline.jsonl`; al final se firma Ed25519 y se verifica
el sobre. Salida: `ALLOW / DENY / REQUIRE_HITL / ERROR`, cadena ÍNTEGRA/CORRUPTA,
firma VÁLIDA/NO VÁLIDA, y rutas de dossier JSON + MD.

```bash
amewotan mission list                         # misiones persistidas
amewotan mission status <msn-xxxx>             # estado consolidado
amewotan mission report <msn-xxxx> -f md       # dossier operador
amewotan mission report <msn-xxxx> -f json     # dossier máquina
```

---

## 4. Revisión Human-In-The-Loop (doble puerta)

Pasos `REQUIRE_HITL` quedan como tickets PENDIENTES (no se ejecuta nada).

```bash
amewotan hitl list                            # tickets pendientes
amewotan hitl approve <ticket_id> --by lugh --reason "autorizado por RoE"
amewotan hitl deny  <ticket_id> --reason "fuera de alcance"
```

`approve` re-ejecuta SOLO vía gateway gobernado (vuelve a pasar GELSI); un veto
DENY/scope sigue aplicando.

---

## 5. Verificación de cadena de custodia

```bash
amewotan forensic verify        # HMAC-SHA512 chain → CADENA ÍNTEGRA / CORRUPTA
amewotan forensic verify-sign   # Ed25519 sobre digest → FIRMA VÁLIDA / INVÁLIDA
amewotan forensic tail --n 20   # últimos eventos del timeline
```

Firmar manualmente la cadena (idempotente; re-emite si la clave es la misma):

```bash
amewotan forensic sign          # escribe <base_dir>/evidence/custody.sig.json
```

---

## 6. Verificación externa (tercero, sin el repo)

Un auditor externo valida con SOLO `timeline.jsonl` + `custody.sig.json` + `roe_pub.pem`:

```bash
bash scripts/verify_external.sh <dir_con_timeline_y_sig> <roe_pub.pem>
# → CADENA ÍNTEGRA + FIRMA VÁLIDA   (o falla con tamper-evidence)
```

Ver `docs/EXTERNAL_VERIFICATION.md` para el detalle del algoritmo.

---

## 7. Dispatch directo (sin misión)

```bash
amewotan mcp dispatch recon.deep_osint --target ejemplo.com --roe <roe_id>
amewotan mcp dispatch defense.phishing_detect --args '{"email":"..."}'
```

---

## 8. Fallos comunes

| Síntoma | Causa | Acción |
|---------|-------|--------|
| `✘ sin verificar` en `roe list` | falta `<yaml>.sig` o `roe_pub.pem` | firmar (§2.1) |
| `REQUIRE_HITL` sin ejecutar | paso activo/dfir/darkweb/PII | `amewotan hitl approve` (§4) |
| `signature_valid=NO VÁLIDA` | timeline alterado tras firmar | `forensic verify` + `forensic sign` |
| `tool_unavailable` | motor externo ausente (binario/API) | esperado; NO es fallo |

---

*Runbook bajo doctrina AmegakureDōjō. Cero salida fabricada: `tool_unavailable`
es respuesta válida y auditable.*
