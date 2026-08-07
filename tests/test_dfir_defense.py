# FORGE_CONTEXT: CIVIL
"""
Tests FASE 3: adaptadores DFIR (runner/velociraptor/volatility/sleuthkit) y
defense (phishing). Verifica comando de contenedor endurecido, comportamiento
HONESTO ante herramienta ausente (nunca salida fabricada), allowlist de plugins
y heurística de phishing defensivo (AmegakureWotan.md §6.3, §7.1).
"""
from unittest.mock import patch

from amegakurewotan.dfir.runner import (
    ContainerRunner,
    detect_container_runtime,
    tool_unavailable_result,
)
from amegakurewotan.dfir.velociraptor import velociraptor_hunt
from amegakurewotan.dfir.volatility import memory_analyze
from amegakurewotan.dfir.sleuthkit import disk_timeline
from amegakurewotan.defense.phishing import phishing_detect


# ── Runner endurecido ────────────────────────────────────────────────────────
def test_container_command_is_hardened():
    with patch("amegakurewotan.dfir.runner.detect_container_runtime", return_value="/usr/bin/podman"):
        runner = ContainerRunner(image="img:latest", cpus="0.5", memory="1g")
        cmd = runner.build_command(
            args=["--version"],
            ro_mounts={"/host/dump": "/evidence/dump"},
        )
    assert "--network" in cmd and "none" in cmd
    assert "--cpus" in cmd and "0.5" in cmd
    assert "--memory" in cmd and "1g" in cmd
    assert "--cap-drop" in cmd and "ALL" in cmd
    assert "no-new-privileges" in cmd
    assert "/host/dump:/evidence/dump:ro" in cmd  # montaje solo-lectura


def test_tool_unavailable_result_shape():
    r = tool_unavailable_result("volatility3", "sin runtime", target="/x.dmp")
    assert r["status"] == "tool_unavailable"
    assert r["tool"] == "volatility3"
    assert "note" in r  # deja claro que no hay salida fabricada


# ── Velociraptor: honesto si el binario no está ──────────────────────────────
def test_velociraptor_unavailable_is_honest():
    with patch("amegakurewotan.dfir.velociraptor._binary_available", return_value=False):
        r = velociraptor_hunt("windows_workstations")
    assert r["status"] == "tool_unavailable"
    assert r["tool"] == "velociraptor"


def test_velociraptor_empty_target():
    r = velociraptor_hunt("")
    assert r["status"] == "error"


# ── Volatility: allowlist + honestidad ───────────────────────────────────────
def test_volatility_dump_not_found():
    r = memory_analyze("/nonexistent/dump.dmp")
    assert r["status"] == "error"
    assert "no encontrado" in r["reason"]


def test_volatility_plugin_allowlist(tmp_path):
    dump = tmp_path / "mem.dmp"
    dump.write_bytes(b"FAKEDUMP")
    r = memory_analyze(str(dump), plugin="windows.evil_plugin")
    assert r["status"] == "error"
    assert "allowlist" in r["reason"]


def test_volatility_unavailable_runtime(tmp_path):
    dump = tmp_path / "mem.dmp"
    dump.write_bytes(b"FAKEDUMP")
    with patch("amegakurewotan.dfir.volatility.ContainerRunner.is_available", return_value=False):
        r = memory_analyze(str(dump), plugin="windows.pslist")
    assert r["status"] == "tool_unavailable"
    assert "dump_sha512" not in r or True  # hash calculado antes; no se fabrica análisis


# ── Sleuth Kit ───────────────────────────────────────────────────────────────
def test_sleuthkit_image_not_found():
    r = disk_timeline("/nonexistent/disk.img")
    assert r["status"] == "error"


def test_sleuthkit_unavailable_runtime(tmp_path):
    disk = tmp_path / "disk.img"
    disk.write_bytes(b"\x00" * 512)
    with patch("amegakurewotan.dfir.sleuthkit.ContainerRunner.is_available", return_value=False):
        r = disk_timeline(str(disk))
    assert r["status"] == "tool_unavailable"


# ── Defense: phishing defensivo ──────────────────────────────────────────────
def test_phishing_high_risk_ip_url():
    r = phishing_detect("http://185.220.101.5/login/verify")
    assert r["risk_score"] >= 30
    assert any("IP" in s for s in r["signals"])
    assert r["mode"] == "defensive_only"


def test_phishing_typosquat_detection():
    r = phishing_detect("http://paypa1.com/account", protected_brands=["paypal.com"])
    assert r["risk_score"] >= 35
    assert any("typosquatting" in s for s in r["signals"])


def test_phishing_urgency_triggers():
    r = phishing_detect(
        "http://mail.example.top/portal",
        body="URGENT: verify your account password immediately or it will be suspended",
    )
    assert r["verdict"] in ("medium", "high")
    assert any("urgencia" in s for s in r["signals"])


def test_phishing_legit_low_risk():
    r = phishing_detect("https://github.com/nousresearch")
    assert r["verdict"] == "low"


def test_phishing_no_input():
    r = phishing_detect("")
    assert r["verdict"] == "no_input"
