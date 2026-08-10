# FORGE_CONTEXT: CIVIL
"""W3 — Cobertura policy/opsec.py: get_active_proxies, verify_network_route,
run_isolated_process. Sin salida fabricada.
"""
from unittest.mock import MagicMock, patch
import pytest

from amegakurewotan.policy import opsec as opsec_mod


# ── get_active_proxies ──────────────────────────────────────────
def test_get_active_proxies_empty_pool(monkeypatch):
    monkeypatch.setattr(opsec_mod, "check_tor_socks_proxy", lambda *a, **k: False)
    monkeypatch.setenv("OPSEC_TOR_PROXY_POOL", "socks5://127.0.0.1:9050")
    result = opsec_mod.get_active_proxies()
    assert result == []


def test_get_active_proxies_one_up(monkeypatch):
    monkeypatch.setattr(opsec_mod, "check_tor_socks_proxy", lambda *a, **k: True)
    monkeypatch.setenv("OPSEC_TOR_PROXY_POOL", "socks5://127.0.0.1:9050")
    result = opsec_mod.get_active_proxies()
    assert len(result) == 1


# ── verify_network_route ────────────────────────────────────────
def test_verify_network_route_normal_clear(monkeypatch):
    monkeypatch.setattr(opsec_mod, "get_active_proxies", lambda: ["socks5://127.0.0.1:9050"])
    opsec_mod.verify_network_route("https://example.com", agent_name="heimdall")


def test_verify_network_route_sensitive_no_proxy(monkeypatch):
    monkeypatch.setattr(opsec_mod, "get_active_proxies", lambda: [])
    with pytest.raises(opsec_mod.OPSECViolationException):
        opsec_mod.verify_network_route("https://example.com", agent_name="hel")


def test_verify_network_route_onion_no_proxy(monkeypatch):
    monkeypatch.setattr(opsec_mod, "get_active_proxies", lambda: [])
    with pytest.raises(opsec_mod.OPSECViolationException):
        opsec_mod.verify_network_route("http://abc123.onion/page")


# ── run_isolated_process ────────────────────────────────────────
def test_run_isolated_ok(monkeypatch):
    q_mock = MagicMock()
    q_mock.empty.return_value = False
    q_mock.get.return_value = (True, 42)
    p_mock = MagicMock()
    p_mock.is_alive.return_value = False
    with (
        patch("amegakurewotan.policy.opsec.Queue", return_value=q_mock),
        patch("amegakurewotan.policy.opsec.Process", return_value=p_mock),
    ):
        result = opsec_mod.run_isolated_process(lambda: 42)
    assert result == 42


def test_run_isolated_timeout(monkeypatch):
    q_mock = MagicMock()
    q_mock.empty.return_value = True
    p_mock = MagicMock()
    p_mock.is_alive.return_value = True
    monkeypatch.setenv("AMEWOTAN_ISOLATION_TIMEOUT", "1")
    with (
        patch("amegakurewotan.policy.opsec.Queue", return_value=q_mock),
        patch("amegakurewotan.policy.opsec.Process", return_value=p_mock),
    ):
        with pytest.raises(TimeoutError):
            opsec_mod.run_isolated_process(lambda: None)


def test_run_isolated_exception(monkeypatch):
    q_mock = MagicMock()
    q_mock.empty.return_value = False
    q_mock.get.return_value = (False, ValueError("boom"))
    p_mock = MagicMock()
    p_mock.is_alive.return_value = False
    with (
        patch("amegakurewotan.policy.opsec.Queue", return_value=q_mock),
        patch("amegakurewotan.policy.opsec.Process", return_value=p_mock),
    ):
        with pytest.raises(ValueError):
            opsec_mod.run_isolated_process(lambda: None)
