# FORGE_CONTEXT: CIVIL
"""Tests Fase D: RoE firmada OBLIGATORIA (modo producción) + aislamiento DFIR.

Fase D (WOTAN-F4): en modo producción (AMEWOTAN_REQUIRE_ROE_SIGNATURE=true) una
RoE cuya firma no se verifica debe ser RECHAZADA; con firma válida se acepta.
Además se verifica el aislamiento DFIR endurecido vía podman.
"""
import os

import pytest

from amegakurewotan.policy.roe import (
    ACTION_ACTIVE,
    ACTION_DFIR,
    ACTION_PASSIVE,
    RulesOfEngagement,
    ScopeRegistry,
    get_scope_registry,
    reset_scope_registry,
)
from amegakurewotan.dfir.runner import ContainerRunner


def _make_reg(tmp_path, require_sig):
    # Aislamiento: registry propio en tmp_path, clave pública ausente (=> firma no verificable).
    reg = ScopeRegistry(roe_dir=tmp_path / "roe", pubkey_path=tmp_path / "nopub.pem")
    reg.register(RulesOfEngagement(
        roe_id="roe-unsigned",
        authority="test",
        scope=["target.com", "*.target.com"],
        allowed_actions=[ACTION_PASSIVE, ACTION_ACTIVE, ACTION_DFIR],
        pii_policy="minimize",
    ))
    return reg


def test_roe_unverified_allowed_in_dev_mode(tmp_path, monkeypatch):
    monkeypatch.setenv("AMEWOTAN_REQUIRE_ROE_SIGNATURE", "false")
    reg = _make_reg(tmp_path, False)
    # Sin clave pública => signature_verified=False, pero en dev mode se permite.
    assert reg.get("roe-unsigned").signature_verified is False
    assert reg.is_authorized("target.com", "roe-unsigned") is True


def test_roe_unverified_rejected_in_prod_mode(tmp_path, monkeypatch):
    monkeypatch.setenv("AMEWOTAN_REQUIRE_ROE_SIGNATURE", "true")
    reg = _make_reg(tmp_path, True)
    # Modo producción: firma no verificada => DENEGADA (RoE no autenticada).
    assert reg.get("roe-unsigned").signature_verified is False
    assert reg.is_authorized("target.com", "roe-unsigned") is False


def test_roe_signed_accepted_in_prod_mode(tmp_path, monkeypatch):
    """RoE firmada con clave pública válida se acepta incluso en modo producción."""
    monkeypatch.setenv("AMEWOTAN_REQUIRE_ROE_SIGNATURE", "true")
    # Genera clave Ed25519 y firma la RoE en tmp_path.
    import subprocess
    keys = tmp_path / "keys"
    keys.mkdir()
    priv = keys / "roe_priv.pem"
    pub = keys / "roe_pub.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(priv)],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "pkey", "-in", str(priv), "-pubout", "-out", str(pub)],
                   check=True, capture_output=True)

    roe_dir = tmp_path / "roe"
    roe_dir.mkdir()
    yaml_path = roe_dir / "roe-signed.yaml"
    yaml_path.write_text(
        "roe_id: roe-signed\nauthority: test\n"
        "scope: [target.com, '*.target.com']\n"
        "allowed_actions: [passive, active, dfir]\npii_policy: minimize\n",
        encoding="utf-8",
    )
    subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", str(priv),
                    "-rawin", "-in", str(yaml_path), "-out", str(yaml_path) + ".sig"],
                   check=True, capture_output=True)

    reg = ScopeRegistry(roe_dir=roe_dir, pubkey_path=pub)
    assert reg.get("roe-signed").signature_verified is True
    assert reg.is_authorized("target.com", "roe-signed") is True


def test_dfir_isolation_network_none(tmp_path, monkeypatch):
    """El ejecutor DFIR impone --network none (sin salida de red) en contenedores."""
    monkeypatch.setattr("amegakurewotan.dfir.runner.detect_container_runtime", lambda: "/usr/bin/podman")
    runner = ContainerRunner(image="docker.io/library/hello-world:latest", network="none")
    cmd = runner.build_command([""], ro_mounts={str(tmp_path / "x"): "/x"})
    assert "--network" in cmd and cmd[cmd.index("--network") + 1] == "none"
    # Sin cap-add, con cap-drop ALL y no-new-privileges.
    assert "--cap-drop" in cmd
    assert "--security-opt" in cmd and "no-new-privileges" in cmd
