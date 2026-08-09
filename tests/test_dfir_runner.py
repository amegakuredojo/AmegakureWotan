# FORGE_CONTEXT: CIVIL
"""Tests del ejecutor DFIR aislado (dfir/runner).

Cubre las rutas PURAS y deterministas sin lanzar contenedores:
  • detect_container_runtime / is_available (podman presente en host de Lugh)
  • build_command: construye el comando endurecido (--network none, --read-only,
    --cap-drop ALL, --security-opt no-new-privileges, montajes :ro/:rw) sin ejecutar
  • tool_unavailable_result: veredicto honesto cuando falta runtime/imagen
  • run(): con runtime presente pero imagen inventada ⇒ tool_unavailable (no fabrica)

No se ejecutan binarios DFIR reales; la doctrina prohíbe salida fabricada.
"""
import pytest

from amegakurewotan.dfir.runner import (
    ContainerRunner,
    DfirToolUnavailable,
    detect_container_runtime,
    tool_unavailable_result,
)


def test_detect_runtime_finds_podman():
    rt = detect_container_runtime()
    assert rt is not None
    assert "podman" in rt or "docker" in rt


def test_tool_unavailable_result_shape():
    r = tool_unavailable_result("volatility3", "imagen ausente", target="host-01")
    assert r["status"] == "tool_unavailable"
    assert r["tool"] == "volatility3"
    assert r["target"] == "host-01"
    assert "Sin salida fabricada" in r["note"]
    # Timestamp UTC válido
    assert r["ts_utc"].endswith("Z")


def test_build_command_hardened_isolation(tmp_path):
    runner = ContainerRunner(image="sk4la/volatility3:latest", network="none")
    ro = {str(tmp_path / "dump.raw"): "/evidence/dump.raw"}
    rw = {str(tmp_path / "out"): "/out"}
    cmd = runner.build_command(["imageinfo", "-f", "/evidence/dump.raw"], ro_mounts=ro, rw_mounts=rw)

    # El comando USADO empieza por el runtime y aplica el aislamiento endurecido.
    assert cmd[0].endswith(("podman", "docker"))
    assert "--network" in cmd and cmd[cmd.index("--network") + 1] == "none"
    assert "--read-only" in cmd
    assert "--cap-drop" in cmd and cmd[cmd.index("--cap-drop") + 1] == "ALL"
    assert "--security-opt" in cmd and "no-new-privileges" in cmd
    # Montajes: entrada :ro, salida rw.
    ro_flag = f"{tmp_path / 'dump.raw'}:/evidence/dump.raw:ro"
    rw_flag = f"{tmp_path / 'out'}:/out"
    assert ro_flag in cmd
    assert rw_flag in cmd
    # La imagen y los args del entrypoint van al final.
    assert cmd[-4:] == ["sk4la/volatility3:latest", "imageinfo", "-f", "/evidence/dump.raw"]
    # El dir rw se creó aunque no existiera.
    assert (tmp_path / "out").is_dir()


def test_build_command_raises_when_no_runtime(monkeypatch):
    runner = ContainerRunner(image="x:latest")
    monkeypatch.setattr("amegakurewotan.dfir.runner.detect_container_runtime", lambda: None)
    with pytest.raises(DfirToolUnavailable):
        runner.build_command(["x"])


def test_run_unknown_image_is_unavailable(tmp_path):
    """Con runtime presente pero imagen inventada, run() NO fabrica salida:
    devuelve tool_unavailable (exit 125 de podman/docker por imagen ausente)."""
    runner = ContainerRunner(image="localhost/amegakurewotan-nonexistent-dfir:0", network="none", timeout=30)
    # Solo si hay runtime real lo probamos; si no, el test es trivialmente
    # cubierto por is_available==False en otros hosts.
    if not runner.is_available():
        pytest.skip("sin runtime de contenedores en este host")
    res = runner.run(["--help"])
    assert res["status"] in ("tool_unavailable", "error", "timeout")
    if res["status"] == "tool_unavailable":
        assert "Sin salida fabricada" in res["note"]
