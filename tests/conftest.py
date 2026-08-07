# FORGE_CONTEXT: CIVIL
# FORGE_VERSION: 3.0
# FORGE_DATE: 2026-07-05T15:43:00Z
"""
conftest.py — Fixtures globales para test suite de AmegakureWotan.
FIX-06: Provee mocks de paths Docker, Tor proxy y SearXNG para ejecutar
tests en host sin necesitar el stack Docker completo activo.

Prerequisitos: pytest, pytest-asyncio, freezegun
"""
import os
import json
import pytest
import tempfile
import hashlib
import hmac
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CONSTANTES DE TEST
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TEST_TARGET: str = "testtarget.example.com"
TEST_USERNAME: str = "testuser_amegakurewotan"
TEST_QUERY: str = "site:testtarget.example.com filetype:pdf"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# FIXTURE: Directorio de datos temporal aislado
# Reemplaza /data y /app (hardcodeados para Docker) por tmpdir del host
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
@pytest.fixture(scope="session")
def tmp_data_dir(tmp_path_factory):
    """
    Directorio de datos temporal para toda la sesión de tests.
    Reemplaza AMEWOTAN_DATA_DIR=/data del contenedor Docker.
    """
    data_dir = tmp_path_factory.mktemp("amegakurewotan_data")
    # Crear estructura de directorios esperada
    for subdir in [
        "evidence", "evidence/screenshots", "evidence/html",
        "evidence/transcripts", "evidence/hashes",
        "opsec", "opsec/keys", "sessions", "reports", "graph/db"
    ]:
        (data_dir / subdir).mkdir(parents=True, exist_ok=True)
    return data_dir


@pytest.fixture(autouse=True)
def patch_data_dir(tmp_data_dir, monkeypatch):
    """
    Auto-fixture: parchea AMEWOTAN_DATA_DIR en todos los tests.
    Redirige paths Docker (/data) a directorio temporal del host.
    """
    monkeypatch.setenv("AMEWOTAN_DATA_DIR", str(tmp_data_dir))
    monkeypatch.setenv("KUZU_DATABASE_PATH", str(tmp_data_dir / "amegakurewotan_vault.kuzu"))
    # Forzar bypass Tor en tests (no hay contenedor tor-proxy)
    monkeypatch.setenv("AMEWOTAN_OPSEC_BYPASS_TOR", "true")
    # Reset singleton de config para que tome los nuevos valores
    import amegakurewotan.config as cfg_module
    cfg_module._config = None
    yield
    # Cleanup: reset config singleton post-test
    cfg_module._config = None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# FIXTURE: Mock de Tor proxy
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
@pytest.fixture
def mock_tor_proxy():
    """
    Mock del Tor SOCKS5 proxy para tests que no requieren Tor real.
    Parchea check_tor_socks_proxy para retornar True siempre.
    """
    with patch("amegakurewotan.policy.opsec.check_tor_socks_proxy", return_value=True):
        with patch("amegakurewotan.policy.opsec.get_active_proxies",
                   return_value=["socks5h://127.0.0.1:9050"]):
            yield


@pytest.fixture
def mock_tor_proxy_down():
    """Mock del Tor proxy CAÍDO para tests de OPSEC enforcement."""
    with patch("amegakurewotan.policy.opsec.check_tor_socks_proxy", return_value=False):
        with patch("amegakurewotan.policy.opsec.get_active_proxies", return_value=[]):
            yield


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# FIXTURE: Mock de SearXNG
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
@pytest.fixture
def mock_searxng():
    """Mock de SearXNG que retorna resultados deterministas para tests."""
    fake_results = [
        {
            "title": "TestTarget - Página Principal",
            "url": f"https://{TEST_TARGET}/",
            "content": "Lorem ipsum OSINT test content",
            "engine": "google",
            "score": 0.9,
        },
        {
            "title": "TestTarget GitHub",
            "url": f"https://github.com/testtarget",
            "content": "Repositorio de TestTarget",
            "engine": "github",
            "score": 0.7,
        },
    ]
    with patch("amegakurewotan.tools.searxng.query_searxng", return_value=fake_results):
        yield fake_results


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# FIXTURE: Mock de Kùzu DB
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
@pytest.fixture
def mock_kuzu_db(tmp_data_dir):
    """
    Kùzu DB real en directorio temporal (no mock — usa embedded DB real).
    Garantiza aislamiento entre tests sin necesitar Docker.
    """
    import kuzu
    db_path = str(tmp_data_dir / "test_vault.kuzu")
    db = kuzu.Database(db_path)
    conn = kuzu.Connection(db)
    # Schema mínimo
    try:
        conn.execute("CREATE NODE TABLE IF NOT EXISTS Entity (id STRING, type STRING, PRIMARY KEY (id))")
        conn.execute("CREATE REL TABLE IF NOT EXISTS LINKS_TO (FROM Entity TO Entity, context STRING)")
    except Exception:
        pass
    yield conn
    # Cleanup automático por tmp_path_factory


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# FIXTURE: Forensic Audit Ledger en tmpdir
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
@pytest.fixture
def audit_ledger(tmp_data_dir):
    """ForensicAuditLedger inicializado en directorio temporal."""
    from amegakurewotan.evidence.audit import ForensicAuditLedger
    ledger = ForensicAuditLedger()
    return ledger


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# FIXTURE: Mock de subprocesos externos (nmap, whois, amass)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
@pytest.fixture
def mock_subprocesses():
    """
    Mock de subprocess.run para nmap, whois y amass.
    Retorna output determinista sin ejecutar herramientas reales.
    """
    fake_whois = """
origin:         AS12345
org-name:       TestOrg LLC
cidr:           1.2.3.0/24
"""
    fake_nmap = """Starting Nmap
Host: 1.2.3.4 ()
PORT   STATE SERVICE
80/tcp open  http
443/tcp open  https
"""
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = fake_whois
    mock_result.stderr = ""

    with patch("subprocess.run", return_value=mock_result):
        yield mock_result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# FIXTURE: Mock de HTTP (requests / httpx)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
@pytest.fixture
def mock_http():
    """
    Mock de httpx.Client y requests.Session para evitar requests reales.
    Retorna 200 con JSON vacío por defecto.
    """
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"results": []}
    mock_response.text = "{}"
    mock_response.content = b"{}"
    mock_response.headers = {"Content-Type": "application/json"}
    mock_response.raise_for_status = MagicMock()

    with patch("httpx.Client") as mock_httpx_client:
        mock_httpx_client.return_value.__enter__.return_value.get.return_value = mock_response
        with patch("requests.Session") as mock_requests_session:
            mock_requests_session.return_value.__enter__.return_value.get.return_value = mock_response
            yield mock_response


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# FIXTURE: Sandbox mode completo (todos los mocks combinados)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
@pytest.fixture
def sandbox_mode(mock_tor_proxy, mock_searxng, mock_subprocesses, mock_http):
    """
    Fixture combinada: activa todos los mocks para ejecutar tests
    completamente offline sin Docker ni herramientas externas.
    Ideal para CI/CD y sandboxes aislados.
    """
    yield {
        "tor_proxy": mock_tor_proxy,
        "searxng": mock_searxng,
        "subprocesses": mock_subprocesses,
        "http": mock_http,
    }
