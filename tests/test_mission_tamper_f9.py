# FORGE_CONTEXT: CIVIL
# FORGE_VERSION: AmegakureWotan-1.0
"""
Tests F9 — Tamper-evidence de la misión firmada (custody_signer.sign_chain +
verify_chain_signature) sobre una cadena producida por una misión real.

Cierra el bucle TRL 9: una misión end-to-end sella y firma su cadena; si un solo
bit del timeline se altera A POSTERIORI, la verificación Ed25519 DEBE fallar.
Esto prueba que el dossier de misión es no-repudiable y a prueba de manipulación.

Nota de aislamiento: config._default_base se congela en import-time, por lo que
toda la suite comparte un único timeline.jsonl de sesión. El test de tampering
restaura byte-a-byte el timeline tras verificar el fallo, para no corromper el
ledger compartido de los tests posteriores.
"""
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from amegakurewotan.config import get_config
from amegakurewotan.policy.roe import (
    ACTION_ACTIVE,
    ACTION_PASSIVE,
    RulesOfEngagement,
    get_scope_registry,
    reset_scope_registry,
)
from amegakurewotan.policy.gelsi import reset_gelsi
from amegakurewotan.policy.hitl import reset_hitl
from amegakurewotan.mcp.gateway import reset_gateway
from amegakurewotan.evidence.custody_signer import verify_chain_signature
from amegakurewotan.runtime.mission import MissionOrchestrator

_FAKE_RECON = {"subdomains": ["a.target.com"], "ips": ["1.2.3.4"], "ports": [80, 443]}


@pytest.fixture(autouse=True)
def _reset_singletons(tmp_path, monkeypatch, patch_data_dir):
    # base_dir function-scoped: cada test tiene su PROPIO timeline/clave/sobre.
    # Depende de patch_data_dir (conftest) para aplicarse DESPUÉS y que este
    # override gane. Con el fix de config.get_config() (relee AMEWOTAN_DATA_DIR en
    # tiempo de llamada), el reset de singleton hace efectivo este base_dir aislado
    # y el tampering de un test no contamina a los demás.
    monkeypatch.setenv("AMEWOTAN_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("KUZU_DATABASE_PATH", str(tmp_path / "vault.kuzu"))
    import amegakurewotan.config as cfg_module
    cfg_module._config = None
    reset_scope_registry()
    reset_gelsi()
    reset_gateway()
    reset_hitl()
    yield
    reset_scope_registry()
    reset_gelsi()
    reset_gateway()
    reset_hitl()
    cfg_module._config = None


def _run_signed_mission():
    reg = get_scope_registry()
    reg.register(RulesOfEngagement(
        roe_id="roe-f9",
        authority="CISO (F9 tamper test)",
        scope=["target.com", "*.target.com"],
        allowed_actions=[ACTION_PASSIVE, ACTION_ACTIVE],
        pii_policy="minimize",
    ))
    with patch("amegakurewotan.agents.heimdall.HeimdallAgent") as MockAgent:
        MockAgent.return_value.execute.return_value = dict(_FAKE_RECON)
        return MissionOrchestrator().run(
            target="target.com", roe_token="roe-f9", plan="osint_recon", operator="f9",
        )


def test_mission_signature_valid_then_tamper_detected(tmp_path):
    result = _run_signed_mission()
    assert result.signature_valid is True

    # La verificación independiente (releyendo el sobre persistido) es válida.
    assert verify_chain_signature()["valid"] is True

    timeline = get_config().base_dir / "evidence" / "timeline.jsonl"
    assert timeline.is_file()
    original_bytes = timeline.read_bytes()  # respaldo byte-exacto para restaurar
    try:
        # ── Manipulación: alterar un registro del timeline sin re-firmar ──────
        lines = original_bytes.decode("utf-8").splitlines()
        assert lines, "el timeline no debe estar vacío tras una misión"
        rec = json.loads(lines[-1])  # el último registro es de ESTA misión
        rec["collector_id"] = str(rec.get("collector_id", "")) + "_TAMPERED"
        lines[-1] = json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        timeline.write_text("\n".join(lines) + "\n", encoding="utf-8")

        # La firma Ed25519 sobre el digest de la cadena DEBE invalidarse.
        verification = verify_chain_signature()
        assert verification["valid"] is False
        assert verification["reason"]
    finally:
        # Restaurar el ledger compartido intacto para los tests posteriores.
        timeline.write_bytes(original_bytes)

    # Tras restaurar, la firma vuelve a ser válida (prueba de reversibilidad exacta).
    assert verify_chain_signature()["valid"] is True


def test_mission_dossier_matches_signed_chain(tmp_path):
    """El dossier persistido declara signature_valid coherente con el sobre real."""
    result = _run_signed_mission()
    assert result.dossier_json_path is not None
    dossier = json.loads(Path(result.dossier_json_path).read_text(encoding="utf-8"))
    assert dossier["signature_valid"] is True
    assert dossier["chain"]["verified"] is True
    # El nº de registros firmados coincide entre dossier y sobre.
    assert dossier["signature"]["records"] == verify_chain_signature()["records"]
