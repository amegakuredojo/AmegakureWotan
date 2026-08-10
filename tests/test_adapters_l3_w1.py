# FORGE_CONTEXT: CIVIL
"""Sprint W1 — tests adapters L3 nuevos: Shodan, Censys, SpiderFoot, BBOT, Recon-ng.
Doctrina WOTAN-F4: tool_unavailable explícito + OK mockeado + rate_limiter.
"""
from unittest.mock import MagicMock, patch
import pytest

from amegakurewotan.adapters.l3 import bbot as bb_mod
from amegakurewotan.adapters.l3 import censys as ce_mod
from amegakurewotan.adapters.l3 import recon_ng as rn_mod
from amegakurewotan.adapters.l3 import shodan as sh_mod
from amegakurewotan.adapters.l3 import spiderfoot as sf_mod
from amegakurewotan.utils.ratelimit import reset_rate_limiter


# ── Shodan ──────────────────────────────────────────────────────
def test_shodan_unavailable(monkeypatch):
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    reset_rate_limiter()
    r = sh_mod.shodan_host_info("1.2.3.4")
    assert r["status"] == "tool_unavailable"
    assert "Sin salida fabricada" in r["note"]


def test_shodan_ok(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "fakekey")
    reset_rate_limiter()
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {
        "ports": [80, 443],
        "hostnames": ["x.com"],
        "org": "ACME",
        "country_name": "US",
    }
    with patch("requests.get", return_value=resp):
        r = sh_mod.shodan_host_info("1.2.3.4")
    assert r["status"] == "ok"
    assert 80 in r["ports"]


def test_shodan_search_ok(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "fakekey")
    reset_rate_limiter()
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"total": 1, "matches": [{"ip_str": "1.2.3.4"}]}
    with patch("requests.get", return_value=resp):
        r = sh_mod.shodan_search("apache")
    assert r["status"] == "ok"
    assert r["total"] == 1


# ── Censys ──────────────────────────────────────────────────────
def test_censys_unavailable(monkeypatch):
    monkeypatch.delenv("CENSYS_API_ID", raising=False)
    monkeypatch.delenv("CENSYS_API_SECRET", raising=False)
    reset_rate_limiter()
    r = ce_mod.censys_host_info("1.2.3.4")
    assert r["status"] == "tool_unavailable"


def test_censys_ok(monkeypatch):
    monkeypatch.setenv("CENSYS_API_ID", "fake-id")
    monkeypatch.setenv("CENSYS_API_SECRET", "fake-secret")
    reset_rate_limiter()
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"result": {"services": [{"port": 443}], "labels": []}}
    with patch("requests.get", return_value=resp):
        r = ce_mod.censys_host_info("1.2.3.4")
    assert r["status"] == "ok"
    assert 443 in [s["port"] for s in r["services"]]


def test_censys_search_ok(monkeypatch):
    monkeypatch.setenv("CENSYS_API_ID", "fake-id")
    monkeypatch.setenv("CENSYS_API_SECRET", "fake-secret")
    reset_rate_limiter()
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"result": {"hits": [{"ip": "1.2.3.4"}]}}
    with patch("requests.post", return_value=resp):
        r = ce_mod.censys_search_hosts("services.port: 443")
    assert r["status"] == "ok"
    assert len(r["hits"]) == 1


# ── SpiderFoot ──────────────────────────────────────────────────
def test_spiderfoot_unavailable(monkeypatch):
    monkeypatch.setattr(sf_mod, "_binary", lambda: None)
    reset_rate_limiter()
    r = sf_mod.spiderfoot_scan("example.com")
    assert r["status"] == "tool_unavailable"
    assert "Sin salida fabricada" in r["note"]


def test_spiderfoot_ok(monkeypatch):
    monkeypatch.setattr(sf_mod, "_binary", lambda: "/usr/bin/sf.py")
    reset_rate_limiter()
    proc = MagicMock()
    proc.returncode = 0
    proc.stdout = "domain,IP_ADDRESS,1.2.3.4\n"
    proc.stderr = ""
    with patch("subprocess.run", return_value=proc):
        r = sf_mod.spiderfoot_scan("example.com")
    assert r["status"] == "ok"
    assert "example.com" in r["target"]


# ── BBOT ────────────────────────────────────────────────────────
def test_bbot_unavailable(monkeypatch):
    monkeypatch.setattr(bb_mod, "_binary", lambda: None)
    reset_rate_limiter()
    r = bb_mod.bbot_scan("example.com")
    assert r["status"] == "tool_unavailable"
    assert "Sin salida fabricada" in r["note"]


def test_bbot_ok(monkeypatch):
    monkeypatch.setattr(bb_mod, "_binary", lambda: "/usr/bin/bbot")
    reset_rate_limiter()
    proc = MagicMock()
    proc.returncode = 0
    proc.stdout = "[DNS_NAME] sub.example.com\n"
    proc.stderr = ""
    with patch("subprocess.run", return_value=proc):
        r = bb_mod.bbot_scan("example.com")
    assert r["status"] == "ok"


# ── Recon-ng ────────────────────────────────────────────────────
def test_reconng_unavailable(monkeypatch):
    monkeypatch.setattr(rn_mod, "_binary", lambda: None)
    reset_rate_limiter()
    r = rn_mod.reconng_run_module("recon/domains-hosts/hackertarget", "example.com")
    assert r["status"] == "tool_unavailable"
    assert "Sin salida fabricada" in r["note"]


def test_reconng_ok(monkeypatch):
    monkeypatch.setattr(rn_mod, "_binary", lambda: "/usr/bin/recon-cli")
    reset_rate_limiter()
    proc = MagicMock()
    proc.returncode = 0
    proc.stdout = "[host] sub.example.com\n"
    proc.stderr = ""
    with patch("subprocess.run", return_value=proc):
        r = rn_mod.reconng_run_module("recon/domains-hosts/hackertarget", "example.com")
    assert r["status"] == "ok"
    assert "example.com" in r["target"]


# ── Gateway — registro de nuevas tools ──────────────────────────
def test_gateway_registers_all_new_l3_tools():
    from amegakurewotan.mcp.gateway import get_gateway, reset_gateway

    reset_gateway()
    tools = get_gateway().tools()
    for t in [
        "recon.shodan",
        "recon.censys",
        "recon.spiderfoot",
        "recon.bbot",
        "recon.recon_ng",
    ]:
        assert t in tools, f"Tool faltante en gateway: {t}"
