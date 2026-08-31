# FORGE_CONTEXT: CIVIL
"""W3 — Cobertura daemons/isolator.py con stem + requests mockeados."""
import sys
import types
from unittest.mock import MagicMock, patch
import pytest

# stem stub si no está instalado
stem_stub = types.ModuleType("stem")
stem_stub.Signal = MagicMock()
signal_stub = types.ModuleType("stem.control")
signal_stub.Controller = MagicMock()
sys.modules.setdefault("stem", stem_stub)
sys.modules.setdefault("stem.control", signal_stub)

from amegakurewotan.daemons.isolator import TorIsolatorDaemon


def test_get_host_real_ip_ok():
    daemon = TorIsolatorDaemon()
    r = MagicMock()
    r.status_code = 200
    r.text = "1.2.3.4"
    with patch("requests.get", return_value=r):
        ip = daemon._get_host_real_ip()
    assert ip == "1.2.3.4"


def test_get_host_real_ip_failure():
    daemon = TorIsolatorDaemon()
    with patch("requests.get", side_effect=Exception("timeout")):
        ip = daemon._get_host_real_ip()
    assert ip == "UNKNOWN"


def test_rotate_identity(monkeypatch):
    daemon = TorIsolatorDaemon()
    ctrl_mock = MagicMock()
    ctrl_mock.__enter__ = lambda s: s
    ctrl_mock.__exit__ = MagicMock(return_value=False)
    signal_stub.Controller.from_port.return_value = ctrl_mock
    daemon.rotate_identity()


def test_start_stop():
    daemon = TorIsolatorDaemon()
    with (
        patch.object(daemon, "_get_host_real_ip", return_value="5.6.7.8"),
        patch.object(daemon, "_monitor_leak", return_value=None),
    ):
        daemon.start()
        assert daemon.is_running
        daemon.stop()
        assert not daemon.is_running


def test_trigger_kill_switch():
    daemon = TorIsolatorDaemon()
    daemon.is_running = True
    daemon._trigger_kill_switch("test kill")
    assert daemon.is_running is False

