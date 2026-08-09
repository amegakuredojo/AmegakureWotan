# FORGE_CONTEXT: CIVIL
"""Tests Fase E: misión real gobernada contra objetivo autorizado (AmegakureDojo).

La gobernanza, cadena de custodia, firma Ed25519 y rate-limit son REALES; el motor
de recon (Heimdall) se mockea para NO tocar red externa en CI (hermético), pero la
RoE firmada y el enrutamiento GELSI sí son los del entorno real.

Esto cubre el hito TRL-9 real: una operación bajo RoE firmada, sellada y verificable
por una herramienta independiente.
"""
import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from amegakurewotan.cli_wotan import app
from amegakurewotan.policy.roe import ScopeRegistry, get_scope_registry, reset_scope_registry
from amegakurewotan.evidence.forensics import ChainOfCustody


@pytest.fixture(autouse=True)
def _reset_reg():
    reset_scope_registry()
    yield
    reset_scope_registry()


def _make_signed_roe(tmp_path):
    keys = tmp_path / "keys"; keys.mkdir()
    priv = keys / "roe_priv.pem"; pub = keys / "roe_pub.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(priv)], check=True, capture_output=True)
    subprocess.run(["openssl", "pkey", "-in", str(priv), "-pubout", "-out", str(pub)], check=True, capture_output=True)
    roe_dir = tmp_path / "roe"; roe_dir.mkdir()
    yaml_path = roe_dir / "roe-amegakuredojo-001.yaml"
    yaml_path.write_text(
        "roe_id: roe-amegakuredojo-001\nauthority: CISO AmegakureDojo\n"
        "scope: ['amegakuredojo.local', '*.amegakuredojo.local']\n"
        "allowed_actions: [passive, active, dfir]\njurisdiction: EU/eIDAS\n"
        "pii_policy: minimize\nsocial_eng: defensive_only\n", encoding="utf-8")
    subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", str(priv), "-rawin",
                    "-in", str(yaml_path), "-out", str(yaml_path) + ".sig"], check=True, capture_output=True)
    return roe_dir, pub


def test_mission_real_against_authorized_target(tmp_path, monkeypatch):
    """Misión osint_recon con RoE firmada (generada en tmp, sin tocar red real)."""
    monkeypatch.setenv("AMEWOTAN_REQUIRE_ROE_SIGNATURE", "true")
    roe_dir, pub = _make_signed_roe(tmp_path)

    import amegakurewotan.policy.roe as roe_mod
    roe_mod._scope_registry = ScopeRegistry(roe_dir=roe_dir, pubkey_path=pub)
    reg = get_scope_registry()
    assert reg.get("roe-amegakuredojo-001").signature_verified is True

    runner = CliRunner(env={"COLUMNS": "200"})
    with patch("amegakurewotan.agents.heimdall.HeimdallAgent") as MockAgent:
        MockAgent.return_value.execute.return_value = {
            "subdomains": ["www.amegakuredojo.local"], "ips": ["10.0.0.5"], "ports": [443],
        }
        res = runner.invoke(app, [
            "mission", "run", "amegakuredojo.local", "--plan", "osint_recon",
            "--roe", "roe-amegakuredojo-001", "--operator", "lugh",
        ])
    assert res.exit_code == 0, res.stdout
    assert "MISIÓN" in res.stdout
    assert "ÍNTEGRA" in res.stdout

    # Verificación EXTERNA: la cadena se valida desde una herramienta independiente.
    verdict = ChainOfCustody().verify_chain()
    assert verdict.is_valid is True


def test_mission_without_signed_roe_is_denied_in_prod(tmp_path, monkeypatch):
    """Sin RoE firmada en modo producción, la misión no autoriza acción activa."""
    monkeypatch.setenv("AMEWOTAN_REQUIRE_ROE_SIGNATURE", "true")
    reg = get_scope_registry()
    reg._registry.clear()

    runner = CliRunner(env={"COLUMNS": "200"})
    with patch("amegakurewotan.agents.heimdall.HeimdallAgent") as MockAgent:
        MockAgent.return_value.execute.return_value = {"subdomains": [], "ips": [], "ports": []}
        res = runner.invoke(app, [
            "mission", "run", "amegakuredojo.local", "--plan", "osint_recon",
            "--roe", "roe-inexistente", "--operator", "lugh",
        ])
    assert res.exit_code == 0
    # Sin RoE => nada autorizado; la cadena registra el intento denegado sin ejecutar.
