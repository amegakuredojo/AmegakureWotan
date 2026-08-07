# PROTOCOLO: AMEGAKURE_FORGE | DESARROLLO
# FORGE_CONTEXT: CIVIL
# FORGE_VERSION: AmegakureWotan-1.0
"""
Módulo: amegakurewotan.cli_wotan
Contexto: CIVIL — Consolidación AmegakureWotan (capa L5, interfaz de operador)

Propósito:
    CLI consolidada `amewotan` de la plataforma AmegakureWotan. Expone el MCP
    consolidado (gateway por dominios bajo gobernanza GELSI), gestión de RoE y
    verificación de la cadena de custodia (timeline.jsonl).

    NO reemplaza el CLI `amewotan` histórico: lo complementa. `karasu` sigue
    operando el harness OSINT original; `amewotan` opera la capa consolidada
    con GELSI/RoE/DFIR/defense.
"""
from __future__ import annotations

__version__ = "1.0.0"
__forge_context__ = "CIVIL"

import json
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

app = typer.Typer(
    help="AmegakureWotan — plataforma OSINT/DFIR consolidada de grado militar-forense.",
    no_args_is_help=True,
)
roe_app = typer.Typer(help="Gestión de Reglas de Empeño (RoE) firmadas.")
mcp_app = typer.Typer(help="MCP consolidado: dispatch de herramientas por dominio bajo GELSI.")
forensic_app = typer.Typer(help="Cadena de custodia consolidada (timeline.jsonl).")
app.add_typer(roe_app, name="roe")
app.add_typer(mcp_app, name="mcp")
app.add_typer(forensic_app, name="forensic")
hitl_app = typer.Typer(help="Cola Human-In-The-Loop (doble puerta GELSI para dfir/darkweb/evasive/PII).")
app.add_typer(hitl_app, name="hitl")


@app.command()
def doctrine() -> None:
    """Muestra la doctrina Odin/Wotan activa (perfil doctrinal de la plataforma)."""
    console.print(Panel.fit(
        "[bold cyan]AmegakureWotan[/bold cyan] — kernel de orquestación bajo doctrina Odin.\n\n"
        "[bold]Principios (deny-by-default):[/bold]\n"
        " • L0 GELSI evalúa TODA acción: ALLOW / DENY / REQUIRE_HITL.\n"
        " • Ingeniería social OFENSIVA: prohibida a nivel de plataforma.\n"
        " • Acciones activas/evasivas/darkweb/dfir: exigen RoE firmada.\n"
        " • Evidencia sobre intuición: todo se sella en timeline.jsonl (HMAC-SHA512).\n"
        " • Herramienta ausente ⇒ tool_unavailable; NUNCA salida fabricada.",
        title="Doctrina Wotan", border_style="cyan",
    ))


@app.command()
def domains() -> None:
    """Lista los dominios y herramientas del MCP consolidado."""
    from amegakurewotan.mcp.gateway import get_gateway, MCP_NAME

    gw = get_gateway()
    table = Table(title=f"{MCP_NAME} — herramientas consolidadas")
    table.add_column("Dominio", style="cyan")
    table.add_column("Herramienta", style="green")
    for tool in gw.tools():
        domain = tool.split(".")[0]
        table.add_row(domain, tool)
    console.print(table)


# ── RoE ──────────────────────────────────────────────────────────────────────
@roe_app.command("list")
def roe_list() -> None:
    """Lista las RoE cargadas y su estado de firma."""
    from amegakurewotan.policy.roe import get_scope_registry

    reg = get_scope_registry()
    ids = reg.list_roe()
    if not ids:
        console.print("[yellow]No hay RoE cargadas. Coloca YAML firmados en opsec/roe/.[/yellow]")
        return
    table = Table(title="Reglas de Empeño")
    table.add_column("RoE ID", style="cyan")
    table.add_column("Autoridad")
    table.add_column("Acciones", style="green")
    table.add_column("Firma", style="magenta")
    for rid in ids:
        roe = reg.get(rid)
        if roe is None:
            continue
        table.add_row(
            rid, roe.authority, ",".join(roe.allowed_actions),
            "✔ verificada" if roe.signature_verified else "✘ sin verificar",
        )
    console.print(table)


@roe_app.command("show")
def roe_show(roe_id: str) -> None:
    """Muestra el detalle de una RoE."""
    from amegakurewotan.policy.roe import get_scope_registry

    roe = get_scope_registry().get(roe_id)
    if roe is None:
        console.print(f"[red]RoE '{roe_id}' no encontrada.[/red]")
        raise typer.Exit(code=1)
    console.print_json(json.dumps({
        "roe_id": roe.roe_id, "authority": roe.authority, "scope": roe.scope,
        "exclusions": roe.exclusions, "allowed_actions": roe.allowed_actions,
        "jurisdiction": roe.jurisdiction, "not_before": roe.not_before,
        "not_after": roe.not_after, "pii_policy": roe.pii_policy,
        "social_eng": roe.social_eng, "signature_verified": roe.signature_verified,
    }))


# ── MCP dispatch ─────────────────────────────────────────────────────────────
@mcp_app.command("dispatch")
def mcp_dispatch(
    tool: str = typer.Argument(..., help="Herramienta dominio.tool (ver 'amewotan domains')."),
    target: Optional[str] = typer.Option(None, "--target", "-t"),
    roe_token: Optional[str] = typer.Option(None, "--roe", "-r"),
    args_json: Optional[str] = typer.Option(None, "--args", help="JSON de argumentos adicionales."),
) -> None:
    """Enruta una herramienta consolidada a través del gateway (GELSI + custodia)."""
    from amegakurewotan.mcp.gateway import get_gateway

    arguments = {}
    if args_json:
        arguments = json.loads(args_json)
    if target:
        arguments["target"] = target
    if roe_token:
        arguments["roe_token"] = roe_token

    result = get_gateway().dispatch(tool, arguments)
    color = {"ALLOW": "green", "DENY": "red", "REQUIRE_HITL": "yellow"}.get(result.decision, "white")
    console.print(Panel.fit(
        f"[bold {color}]{result.decision}[/bold {color}]  ok={result.ok}\n"
        f"roe_ref={result.roe_ref}\nreasons={'; '.join(result.reasons)}",
        title=f"MCP dispatch: {tool}", border_style=color,
    ))
    if result.data is not None:
        console.print_json(json.dumps(result.data, default=str))
    if result.error:
        console.print(f"[red]error:[/red] {result.error}")


# ── Forensic ─────────────────────────────────────────────────────────────────
@forensic_app.command("verify")
def forensic_verify() -> None:
    """Verifica la integridad completa de la cadena de custodia consolidada."""
    from amegakurewotan.evidence.forensics import ChainOfCustody

    result = ChainOfCustody().verify_chain()
    if result.is_valid:
        console.print(Panel.fit(
            f"[bold green]CADENA ÍNTEGRA[/bold green]\nregistros verificados: {result.checked_records}",
            title="timeline.jsonl", border_style="green",
        ))
    else:
        console.print(Panel.fit(
            f"[bold red]CADENA CORRUPTA[/bold red]\ncorrupciones: {len(result.corruptions)}",
            title="timeline.jsonl", border_style="red",
        ))
        console.print_json(json.dumps(result.corruptions, default=str))
        raise typer.Exit(code=1)


@forensic_app.command("sign")
def forensic_sign() -> None:
    """Sella la cadena de custodia consolidada con firma Ed25519 no-repudiable (openssl).

    Calcula el digest SHA-512 de toda la cadena y lo firma Ed25519. El sobre
    (custody.sig.json) vive APARTE del timeline. Idempotente: re-emite si la
    clave es la misma.
    """
    from amegakurewotan.evidence.custody_signer import sign_chain

    overlay = sign_chain()
    console.print(Panel.fit(
        f"[bold green]CADENA FIRMADA (Ed25519)[/bold green]\n"
        f"registros: {overlay['records']}\n"
        f"chain_sha512: {overlay['chain_sha512'][:32]}...\n"
        f"pubkey_sha256: {overlay['pubkey_sha256'][:32]}...\n"
        f"ts_utc: {overlay['ts_utc']}",
        title="custody.sig.json", border_style="green",
    ))


@forensic_app.command("verify-sign")
def forensic_verify_sign() -> None:
    """Verifica la firma Ed25519 de la cadena contra el sobre persistido (tamper-evidence)."""
    from amegakurewotan.evidence.custody_signer import verify_chain_signature

    res = verify_chain_signature()
    if res["valid"]:
        console.print(Panel.fit(
            f"[bold green]FIRMA ED25519 VÁLIDA[/bold green]\n"
            f"registros: {res['records']}\nchain_sha512: {res['chain_sha512'][:32]}...",
            title="custody.sig.json", border_style="green",
        ))
    else:
        console.print(Panel.fit(
            f"[bold red]FIRMA INVÁLIDA[/bold red]\n{res['reason']}",
            title="custody.sig.json", border_style="red",
        ))
        raise typer.Exit(code=1)


@forensic_app.command("tail")
def forensic_tail(n: int = typer.Option(10, "--n", help="Últimos N eventos.")) -> None:
    """Muestra los últimos eventos de la cadena de custodia."""
    from amegakurewotan.evidence.forensics import ChainOfCustody

    records = ChainOfCustody().read_all()[-n:]
    table = Table(title=f"Últimos {len(records)} eventos — timeline.jsonl")
    table.add_column("seq", style="cyan")
    table.add_column("ts_utc")
    table.add_column("collector", style="green")
    table.add_column("event_type", style="magenta")
    table.add_column("roe_ref")
    for r in records:
        table.add_row(str(r.get("seq")), r.get("ts_utc", ""), r.get("collector_id", ""),
                      r.get("event_type", ""), str(r.get("roe_ref")))
    console.print(table)


def main() -> None:
    app()


# ── HITL (doble puerta GELSI) ──────────────────────────────────────────────────
@hitl_app.command("list")
def hitl_list() -> None:
    """Lista los tickets Human-In-The-Loop pendientes."""
    from amegakurewotan.policy.hitl import get_hitl

    pending = get_hitl().list_pending()
    if not pending:
        console.print("[yellow]Sin tickets HITL pendientes.[/yellow]")
        return
    table = Table(title="Tickets HITL pendientes")
    table.add_column("Ticket", style="cyan")
    table.add_column("Tool", style="green")
    table.add_column("Acción", style="magenta")
    table.add_column("Target")
    table.add_column("RoE")
    for t in pending:
        table.add_row(t.ticket_id, t.tool, t.action_type, t.target or "-", t.roe_ref or "-")
    console.print(table)


@hitl_app.command("approve")
def hitl_approve(
    ticket_id: str = typer.Argument(..., help="ID del ticket HITL (hitl-...)."),
    by: str = typer.Option("operator", "--by", help="Quién aprueba."),
    reason: Optional[str] = typer.Option(None, "--reason", help="Justificación."),
) -> None:
    """Aprueba un ticket y re-ejecuta la acción SOLO vía gateway gobernado."""
    from amegakurewotan.mcp.gateway import get_gateway

    res = get_gateway().approve_hitl(ticket_id, by=by, reason=reason)
    color = "green" if res.ok else "red"
    console.print(Panel.fit(
        f"[bold {color}]HITL {ticket_id} → {res.decision}[/bold {color}]  ok={res.ok}\n"
        f"razones={'; '.join(res.reasons)}",
        title=f"hitl.approve {ticket_id}", border_style=color,
    ))


@hitl_app.command("deny")
def hitl_deny(
    ticket_id: str = typer.Argument(..., help="ID del ticket HITL (hitl-...)."),
    reason: Optional[str] = typer.Option(None, "--reason", help="Justificación."),
) -> None:
    """Denega un ticket HITL (no ejecuta nada; se sella en la cadena)."""
    from amegakurewotan.mcp.gateway import get_gateway

    res = get_gateway().deny_hitl(ticket_id, reason=reason)
    console.print(Panel.fit(
        f"[bold red]HITL {ticket_id} → DENIED[/bold red]\n{res.reasons[0] if res.reasons else ''}",
        title=f"hitl.deny {ticket_id}", border_style="red",
    ))


if __name__ == "__main__":
    main()
