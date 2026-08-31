# FORGE_CONTEXT: CIVIL
# FORGE_VERSION: 3.0
# FORGE_DATE: 2026-08-31T06:00:00Z
"""Fase B4 (complemento) — cobertura de tools/searxng.py con httpx mock.

Sube tools/searxng de ~25% a >=80% ejercitando query_searxng (Tier 1 SearXNG,
Tier 2 fallback DDG nativo, parseo de HTML/Lite, y SearxNGSearchTool._run).
Sin red real: se parchea httpx.Client o los helpers internos.
"""
from unittest.mock import MagicMock

import pytest

import amegakurewotan.tools.searxng as sx_mod


def _client_mock(results, raise_exc=None):
    client = MagicMock()
    resp = MagicMock()
    if raise_exc:
        resp.raise_for_status.side_effect = raise_exc
        resp.json.return_value = {}
    else:
        resp.raise_for_status.return_value = None
        resp.json.return_value = {"results": results}
    client.__enter__.return_value = client
    client.get.return_value = resp
    return client


def test_query_searxng_tier1_ok(monkeypatch):
    """Tier 1 SearXNG local responde correctamente."""
    monkeypatch.setattr(sx_mod.httpx, "Client", lambda *a, **k: _client_mock([{"title": "x", "url": "https://x.com", "content": "c"}]))
    res = sx_mod.query_searxng("test", max_results=5)
    assert res == [{"title": "x", "url": "https://x.com", "content": "c"}]


def test_query_searxng_tier1_empty(monkeypatch):
    """Tier 1 SearXNG local responde lista vacía."""
    monkeypatch.setattr(sx_mod.httpx, "Client", lambda *a, **k: _client_mock([]))
    assert sx_mod.query_searxng("test") == []


def test_query_fallback_to_native(monkeypatch):
    """Si SearXNG falla, query_searxng activa el motor nativo Tier 2."""
    import httpx
    # SearXNG falla con ConnectError
    searxng_fail = MagicMock()
    searxng_fail.__enter__.return_value = searxng_fail
    searxng_fail.get.side_effect = httpx.ConnectError("refused")
    
    # Motor nativo devuelve resultados simulados
    native_results = [{"title": "DDG Result", "url": "https://example.com", "content": "ok"}]
    monkeypatch.setattr(sx_mod, "_native_ddg_search", lambda *a, **k: native_results)
    monkeypatch.setattr(sx_mod.httpx, "Client", lambda *a, **k: searxng_fail)

    res = sx_mod.query_searxng("test fallback")
    assert res == native_results


def test_query_all_fail_returns_empty(monkeypatch):
    """Si todos los tiers fallan, retorna lista vacía en vez de lanzar excepción."""
    # SearXNG falla
    client = MagicMock()
    client.__enter__.return_value = client
    client.get.side_effect = Exception("no network")
    monkeypatch.setattr(sx_mod.httpx, "Client", lambda *a, **k: client)
    # Nativo falla
    monkeypatch.setattr(sx_mod, "_native_ddg_search", lambda *a, **k: [])

    res = sx_mod.query_searxng("test empty")
    assert res == []


def test_parse_ddg_lite():
    """Verifica parseo HTML de DuckDuckGo Lite."""
    sample_html = """
    <html>
      <body>
        <table>
          <tr>
            <td><a class="result-link" href="https://target.com">Target Title</a></td>
          </tr>
          <tr>
            <td class="result-snippet">Snippet of the target website</td>
          </tr>
        </table>
      </body>
    </html>
    """
    results = sx_mod._parse_ddg_lite(sample_html, max_results=5)
    assert len(results) == 1
    assert results[0]["title"] == "Target Title"
    assert results[0]["url"] == "https://target.com"
    assert results[0]["content"] == "Snippet of the target website"


def test_parse_ddg_html():
    """Verifica parseo HTML clásico de DuckDuckGo."""
    sample_html = """
    <html>
      <body>
        <div class="result">
          <h2 class="result__title"><a href="https://target2.com">Target 2 Title</a></h2>
          <div class="result__snippet">Snippet 2 content</div>
        </div>
      </body>
    </html>
    """
    results = sx_mod._parse_ddg_html(sample_html, max_results=5)
    assert len(results) == 1
    assert results[0]["title"] == "Target 2 Title"
    assert results[0]["url"] == "https://target2.com"
    assert results[0]["content"] == "Snippet 2 content"


@pytest.mark.skipif(sx_mod.SearxNGSearchTool is None, reason="langchain no instalado")
def test_tool_run(monkeypatch):
    monkeypatch.setattr(sx_mod.httpx, "Client", lambda *a, **k: _client_mock([{"title": "y", "url": "http://y", "content": "c"}]))
    out = sx_mod.SearxNGSearchTool()._run("dork")
    assert "y" in out
