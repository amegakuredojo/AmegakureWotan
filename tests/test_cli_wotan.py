# FORGE_CONTEXT: CIVIL
"""
Tests de la CLI consolidada `amewotan` (cli_wotan). Usa typer.testing.CliRunner
sobre el data dir aislado del conftest. Cubre doctrine/domains, RoE, MCP dispatch,
forensic (verify/sign/verify-sign/tail), HITL y misión end-to-end gobernada.

No fabrica evidencia: siembra la cadena con dispatch REAL (defense.phishing_detect
es ALLOW y no toca red) y verifica lo que el sistema realmente selló.
"""
import json

import pytest
from typer.testing import CliRunner

from amegakurewotan.cli_wotan import app

runner = CliRunner(env={"COLUMNS": "200"})


def _seed_chain():
    """Dispara una operación real ALLOW para que exista cadena que verificar."""
    from amegakurewotan.mcp.gateway import get_gateway

    get_gateway().dispatch(
        "defense.phishing_detect",
        {"subject": "examp1e.com", "params": {"protected_brands": ["example.com"], "body": "verify your password now"}},
    )


def test_doctrine():
    r = runner.invoke(app, ["doctrine"])
    assert r.exit_code == 0
    assert "Doctrina" in r.stdout and "GELSI" in r.stdout


def test_domains_lists_all_domains():
    r = runner.invoke(app, ["domains"])
    assert r.exit_code == 0
    for dom in ("recon", "dfir", "defense", "forensic", "darkweb", "graph"):
        assert dom in r.stdout


def test_roe_list_empty():
    r = runner.invoke(app, ["roe", "list"])
    assert r.exit_code == 0
    assert "No hay RoE" in r.stdout


def test_roe_show_missing():
    r = runner.invoke(app, ["roe", "show", "roe-inexistente"])
    assert r.exit_code == 1
    assert "no encontrada" in r.stdout


def test_mcp_dispatch_defense_allow():
    r = runner.invoke(
        app,
        ["mcp", "dispatch", "defense.phishing_detect",
         "--args", json.dumps({"subject": "examp1e.com", "params": {"protected_brands": ["example.com"]}})],
    )
    assert r.exit_code == 0
    assert "ALLOW" in r.stdout


def test_mcp_dispatch_active_without_roe_denies():
    r = runner.invoke(app, ["mcp", "dispatch", "recon.active_surface", "--target", "target.com"])
    assert r.exit_code == 0
    assert "DENY" in r.stdout


def test_forensic_verify_after_seed():
    _seed_chain()
    r = runner.invoke(app, ["forensic", "verify"])
    assert r.exit_code == 0
    assert "ÍNTEGRA" in r.stdout


def test_forensic_tail_after_seed():
    _seed_chain()
    r = runner.invoke(app, ["forensic", "tail", "--n", "5"])
    assert r.exit_code == 0
    assert "timeline.jsonl" in r.stdout


def test_forensic_sign_and_verify_sign():
    _seed_chain()
    rs = runner.invoke(app, ["forensic", "sign"])
    assert rs.exit_code == 0
    assert "FIRMADA" in rs.stdout
    rv = runner.invoke(app, ["forensic", "verify-sign"])
    assert rv.exit_code == 0
    assert "VÁLIDA" in rv.stdout


def test_hitl_list_empty():
    r = runner.invoke(app, ["hitl", "list"])
    assert r.exit_code == 0
    assert "Sin tickets" in r.stdout


def test_mission_plans():
    r = runner.invoke(app, ["mission", "plans"])
    assert r.exit_code == 0
    assert "osint_recon" in r.stdout


def test_mission_list_empty():
    r = runner.invoke(app, ["mission", "list"])
    assert r.exit_code == 0
    assert "No hay misiones" in r.stdout


def test_mission_status_missing():
    r = runner.invoke(app, ["mission", "status", "msn-inexistente"])
    assert r.exit_code == 1
    assert "no encontrada" in r.stdout


def test_mission_run_osint_recon_end_to_end():
    """Misión gobernada real: recon pasivo ALLOW, activa DENY sin RoE, sellada y firmada.

    Heimdall se mockea para no tocar red (hermético); la gobernanza, sellado y
    firma son los REALES del orquestador.
    """
    from unittest.mock import patch

    with patch("amegakurewotan.agents.heimdall.HeimdallAgent") as MockAgent:
        MockAgent.return_value.execute.return_value = {
            "subdomains": ["a.amegakuredojo.local"], "ips": ["10.0.0.1"], "ports": [443],
        }
        r = runner.invoke(app, ["mission", "run", "amegakuredojo.local", "--plan", "osint_recon", "--operator", "test"])
    assert r.exit_code == 0, r.stdout
    assert "MISIÓN" in r.stdout
    assert "ÍNTEGRA" in r.stdout
    # Tras la misión, aparece en el listado (rich puede truncar el objetivo largo,
    # así que verificamos el prefijo estable del dominio).
    rl = runner.invoke(app, ["mission", "list"])
    assert "amegakuredojo" in rl.stdout


def _run_mission_and_id():
    """Ejecuta una misión hermética y devuelve su mission_id parseando dossiers."""
    from unittest.mock import patch
    from amegakurewotan.runtime.mission import list_missions

    with patch("amegakurewotan.agents.heimdall.HeimdallAgent") as MockAgent:
        MockAgent.return_value.execute.return_value = {"subdomains": [], "ips": [], "ports": []}
        runner.invoke(app, ["mission", "run", "amegakuredojo.local", "--plan", "osint_recon", "--operator", "test"])
    missions = list_missions()
    assert missions, "debe existir al menos una misión"
    return missions[-1]["mission_id"]


def test_mission_status_and_report_roundtrip():
    mid = _run_mission_and_id()
    rs = runner.invoke(app, ["mission", "status", mid])
    assert rs.exit_code == 0
    assert mid in rs.stdout
    rj = runner.invoke(app, ["mission", "report", mid, "--format", "json"])
    assert rj.exit_code == 0
    assert mid in rj.stdout
    rm = runner.invoke(app, ["mission", "report", mid, "--format", "md"])
    assert rm.exit_code == 0


def test_roe_list_and_show_populated():
    """Registra una RoE y verifica list/show poblados."""
    from amegakurewotan.policy.roe import RulesOfEngagement, get_scope_registry, ACTION_PASSIVE

    get_scope_registry().register(RulesOfEngagement(
        roe_id="roe-cli-test", authority="CISO test",
        scope=["amegakuredojo.local"], allowed_actions=[ACTION_PASSIVE], pii_policy="minimize",
    ))
    rl = runner.invoke(app, ["roe", "list"])
    assert rl.exit_code == 0
    assert "roe-cli-test" in rl.stdout
    rs = runner.invoke(app, ["roe", "show", "roe-cli-test"])
    assert rs.exit_code == 0
    assert "amegakuredojo.local" in rs.stdout


def test_hitl_approve_deny_missing_ticket():
    """approve/deny sobre ticket inexistente: error limpio (exit 1), sin traceback."""
    ra = runner.invoke(app, ["hitl", "approve", "hitl-noexiste", "--by", "op"])
    assert ra.exit_code == 1
    assert "HITL error" in ra.stdout
    rd = runner.invoke(app, ["hitl", "deny", "hitl-noexiste", "--reason", "n/a"])
    assert rd.exit_code == 1
    assert "HITL error" in rd.stdout
