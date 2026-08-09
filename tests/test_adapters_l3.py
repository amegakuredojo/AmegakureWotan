# FORGE_CONTEXT: CIVIL
"""Tests de adapters L3 (GreyNoise, theHarvester): integración honesta.

Cubre la doctrina WOTAN-F4:
  • Sin credencial/binario => 'tool_unavailable' EXPLÍCITO, sin salida fabricada.
  • Con credencial/binario mockeado => ejecuta y devuelve el resultado real.
  • Toda salida de red pasa por el rate-limiter (se invoca get_rate_limiter().acquire).
"""
import pytest

from amegakurewotan.adapters.l3 import greynoise as gn_mod
from amegakurewotan.adapters.l3 import theharvester as th_mod
from amegakurewotan.utils.ratelimit import get_rate_limiter, reset_rate_limiter


def test_greynoise_unavailable_without_api_key(monkeypatch):
    monkeypatch.delenv("GREYNOISE_API_KEY", raising=False)
    reset_rate_limiter()
    res = gn_mod.greynoise_ip_report("1.2.3.4")
    assert res["status"] == "tool_unavailable"
    assert res["tool"] == "greynoise"
    assert "Sin salida fabricada" in res["note"]
    assert "GREYNOISE_API_KEY" in res["reason"]


def test_greynoise_ok_with_mocked_response(monkeypatch):
    import requests
    from unittest.mock import patch, MagicMock
    monkeypatch.setenv("GREYNOISE_API_KEY", "test-key")
    reset_rate_limiter()
    mock_resp = MagicMock(); mock_resp.status_code = 200
    mock_resp.json.return_value = {"classification": "malicious", "name": "Example", "noise": True, "riot": False}
    with patch.object(requests, "get", return_value=mock_resp):
        res = gn_mod.greynoise_ip_report("1.2.3.4")
    assert res["status"] == "ok"
    assert res["classification"] == "malicious"
    assert res["ip"] == "1.2.3.4"


def test_greynoise_invokes_rate_limiter(monkeypatch):
    import requests
    from unittest.mock import patch, MagicMock
    monkeypatch.setenv("GREYNOISE_API_KEY", "test-key")
    reset_rate_limiter()
    rl = get_rate_limiter()
    calls = {"n": 0}
    orig = rl.acquire
    def counting(*a, **k):
        calls["n"] += 1
        return orig(*a, **k)
    rl.acquire = counting
    mock_resp = MagicMock(); mock_resp.status_code = 200; mock_resp.json.return_value = {}
    with patch.object(requests, "get", return_value=mock_resp):
        gn_mod.greynoise_ip_report("1.2.3.4")
    assert calls["n"] >= 1


def test_theharvester_unavailable_without_binary(monkeypatch):
    monkeypatch.setattr(th_mod, "_binary", lambda: None)
    reset_rate_limiter()
    res = th_mod.theharvester_run("example.com")
    assert res["status"] == "tool_unavailable"
    assert res["tool"] == "theharvester"
    assert "Sin salida fabricada" in res["note"]


def test_theharvester_ok_with_mocked_binary(monkeypatch):
    import subprocess
    from unittest.mock import patch, MagicMock
    monkeypatch.setattr(th_mod, "_binary", lambda: "/usr/bin/theHarvester")
    reset_rate_limiter()
    mock_proc = MagicMock(); mock_proc.returncode = 0
    mock_proc.stdout = "[*] Emails found for example.com:\nadmin@example.com\n"
    mock_proc.stderr = ""
    with patch.object(subprocess, "run", return_value=mock_proc):
        res = th_mod.theharvester_run("example.com")
    assert res["status"] == "ok"
    assert "admin@example.com" in res["stdout"]


def test_gateway_registers_l3_tools():
    from amegakurewotan.mcp.gateway import get_gateway, reset_gateway
    reset_gateway()
    tools = get_gateway().tools()
    assert "recon.greynoise" in tools
    assert "recon.theharvester" in tools
