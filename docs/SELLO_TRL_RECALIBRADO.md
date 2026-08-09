# SELLO TRL — RECALIBRADO (2026-08-09)

> Recalibración honesta basada en `docs/OPERATIONAL_EVIDENCE.md`. No se edita el
> número hacia arriba: se ajusta con evidencia medida.

## Veredicto

**TRL 8 — Sistema integrado, gobernado y verificado por tests en entorno controlado.**

No TRL 9: falta una operación live contra un target autorizado real con RoE
firmada para cerrar el hito de "despliegue operacional real".

## Matriz de checks objetivos

| Check | Estado | Evidencia |
|---|---|---|
| Suite verde + cobertura alta | ✅ | 378 tests, 83% global (gate 55→80) |
| Gobernanza enforce (RoE/HITL/GELSI) | ✅ | tests en `test_gelsi_roe`, `test_gateway_hitl_b4`, `test_cli_wotan_b4` |
| Cadena de custodia + firma Ed25519 | ✅ | `test_forensics_chain`, `test_audit_forensics_b4`, `test_audit_b4` |
| L3 engines integrados | 🟡 | theharvester/greynoise/velociraptor sí; resto vía wrapper `tool_unavailable` honesto |
| Misión E2E | 🟡 | `mission run` en CI contra `*.example` (sintético autorizado) — demo, no live |
| Operación live firmada | ❌ | no ejecutada en este entorno |

## Exenciones declaradas (sin `# pragma`)

`cli.py` (222), `tui.py` (97), `agents/heimdall.py` (49), `policy/opsec.run_isolated_process` (36),
`mcp/server.main()` stdio. Cubiertas ajustadas ≈ 90%.

## Conclusión

La ingeniería y la gobernanza están en TRL 8 sólido. Para TRL 9 se requiere:
1. Una misión `mission run` contra un target autorizado real con RoE `signature_verified=True`.
2. Integración live de al menos un L3 engine externo (no stub) con salida verificable.
3. Reporte del operador (Lugh) validando que la salida no es "falsa o construida".
