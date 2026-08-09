# FORGE_CONTEXT: CIVIL
"""Fase B4 (complemento) — cobertura de tools/searxng.py con httpx mock.

Sube tools/searxng de ~25% a >=80% ejercitando query_searxng (200/JSON ok,
vacio, error->retry->RuntimeError) y el SearxNGSearchTool._run. Sin red real:
se parchea httpx.Client para devolver un response mock.
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


def test_query_ok(monkeypatch):
    monkeypatch.setattr(sx_mod.httpx, "Client", lambda *a, **k: _client_mock([{"title": "x"}]))
    res = sx_mod.query_searxng("test", max_results=5)
    assert res == [{"title": "x"}]


def test_query_empty(monkeypatch):
    monkeypatch.setattr(sx_mod.httpx, "Client", lambda *a, **k: _client_mock([]))
    assert sx_mod.query_searxng("test") == []


def test_query_retry_then_fail(monkeypatch):
    import httpx
    client = _client_mock(None, raise_exc=httpx.HTTPError("boom"))
    # forzar que TODOS los intentos fallen
    client.get.return_value.raise_for_status.side_effect = httpx.HTTPError("boom")
    monkeypatch.setattr(sx_mod.httpx, "Client", lambda *a, **k: client)
    with pytest.raises(RuntimeError):
        sx_mod.query_searxng("test")


@pytest.mark.skipif(sx_mod.SearxNGSearchTool is None, reason="langchain no instalado")
def test_tool_run(monkeypatch):
    monkeypatch.setattr(sx_mod.httpx, "Client", lambda *a, **k: _client_mock([{"title": "y"}]))
    out = sx_mod.SearxNGSearchTool()._run("dork")
    assert "y" in out
