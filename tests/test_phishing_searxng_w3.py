# FORGE_CONTEXT: CIVIL
"""W3 — Cobertura defense/phishing.py + tools/searxng.py."""
from unittest.mock import MagicMock, patch
import pytest

from amegakurewotan.defense.phishing import phishing_detect
from amegakurewotan.tools.searxng import query_searxng


# ── phishing_detect ─────────────────────────────────────────────
def test_phishing_no_input():
    r = phishing_detect("")
    assert r["verdict"] == "no_input"
    assert r["risk_score"] == 0


def test_phishing_ip_url():
    r = phishing_detect("http://192.168.1.1/login")
    assert r["risk_score"] >= 30
    assert any("IP" in s for s in r["signals"])


def test_phishing_suspicious_tld():
    r = phishing_detect("http://paypal.xyz/verify")
    assert r["risk_score"] >= 20


def test_phishing_typosquat():
    r = phishing_detect("http://paypa1.com/login", protected_brands=["paypal.com"])
    assert r["risk_score"] >= 35
    assert "typosquatting" in r["signals"][0]


def test_phishing_urgency_body():
    r = phishing_detect(
        "http://example.com",
        body="Please verify your account credentials immediately or it will be suspended",
    )
    assert r["risk_score"] >= 10


def test_phishing_subdomain_chain():
    r = phishing_detect("http://a.b.c.d.example.com/login")
    assert any("subdominios" in s for s in r["signals"])


def test_phishing_high_verdict():
    r = phishing_detect(
        "http://192.168.1.1/login",
        body="verify account suspended immediately",
        protected_brands=["paypal.com"],
    )
    assert r["verdict"] in ("medium", "high")


# ── searxng.py — query_searxng ──────────────────────────────────
def test_searxng_ok(monkeypatch):
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = {"results": [{"title": "t", "url": "http://x.com"}]}
    with patch("httpx.Client") as mock_client:
        mock_client.return_value.__enter__.return_value.get.return_value = mock_resp
        results = query_searxng("com.genevachat.staging")
    assert len(results) == 1
    assert results[0]["title"] == "t"


def test_searxng_retry_failure(monkeypatch):
    import httpx

    with patch("httpx.Client") as mock_client:
        mock_client.return_value.__enter__.return_value.get.side_effect = httpx.HTTPError(
            "conn refused"
        )
        with pytest.raises(RuntimeError, match="SearXNG query falló"):
            query_searxng("test")


def test_searxng_with_engines(monkeypatch):
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = {"results": []}
    with patch("httpx.Client") as mock_client:
        mock_client.return_value.__enter__.return_value.get.return_value = mock_resp
        results = query_searxng("test", engines="google,github", categories="it")
    assert results == []
