# FORGE_CONTEXT: CIVIL
# FORGE_VERSION: 3.0
"""
Tests de integración Zero-Config para AmegakureWotan MCP Server.
Verifica que el servidor y los componentes forenses arrancan y operan
de forma 100% nativa sin Docker, sin Tor y sin variables de entorno obligatorias.
"""
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest
import os

from amegakurewotan.config import get_config
from amegakurewotan.graph.db import GraphDB
from amegakurewotan.utils.net import make_request
from amegakurewotan.mcp.server import list_tools, _validate_cypher_allowlist
from amegakurewotan.mcp.gateway import get_gateway


def test_zero_config_paths_and_initialization(tmp_path, monkeypatch):
    """Verifica que la configuración por defecto usa rutas de usuario y crea carpetas sin permisos de root."""
    monkeypatch.setenv("AMEWOTAN_DATA_DIR", str(tmp_path / "wotan_user"))
    import amegakurewotan.config as cfg_mod
    cfg_mod._config = None
    
    cfg = cfg_mod.get_config()
    cfg.init_dirs()
    
    assert (tmp_path / "wotan_user" / "evidence").exists()
    assert (tmp_path / "wotan_user" / "reports").exists()
    assert (tmp_path / "wotan_user" / "sessions").exists()
    assert cfg.kuzu.database_path.endswith("vault.kuzu")


def test_zero_config_direct_request_without_tor(monkeypatch):
    """Verifica que make_request realiza peticiones limpias sin obligar Tor ni dormir en jitter."""
    with patch("requests.request") as mock_req:
        mock_req.return_value = MagicMock(status_code=200, text="<html>OK</html>")
        
        resp = make_request("https://target.example.com", timeout=5.0)
        assert resp.status_code == 200
        assert mock_req.called
        
        args, kwargs = mock_req.call_args
        # Sin proxies forzados por defecto
        assert kwargs.get("proxies") == {}


def test_zero_config_kuzu_graph_embedded(tmp_path, monkeypatch):
    """Verifica que el grafo Kùzu embebido funciona localmente en memoria/directorio de usuario."""
    monkeypatch.setenv("AMEWOTAN_DATA_DIR", str(tmp_path / "wotan_graph"))
    monkeypatch.setenv("KUZU_DATABASE_PATH", str(tmp_path / "wotan_graph" / "test_kuzu.db"))
    import amegakurewotan.config as cfg_mod
    cfg_mod._config = None
    
    db = GraphDB()
    conn = db.connect()
    assert conn is not None
    assert db.check_connection() is True


@pytest.mark.asyncio
async def test_zero_config_mcp_tools_exposed():
    """Verifica que el servidor MCP expone todas las herramientas al cliente LLM."""
    tools = await list_tools()
    assert len(tools) >= 10
    tool_names = [t.name for t in tools]
    assert "searxng_recon" in tool_names
    assert "heimdall_recon" in tool_names
    assert "odin_orchestrate" in tool_names
    assert "kuzu_cypher_query" in tool_names
    assert "audit_verify" in tool_names


def test_zero_config_gateway_handlers():
    """Verifica que el gateway consolidado tiene registrados los dominios de inteligencia."""
    gw = get_gateway()
    tools = gw.tools()
    assert "recon.passive_scan" in tools
    assert "graph.query" in tools
    assert "forensic.verify" in tools
    assert "defense.phishing_detect" in tools
