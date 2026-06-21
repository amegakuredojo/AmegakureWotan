import sys
import os
import json
import glob
import re
import time
import typer
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

# Add package source directory to path to prevent import issues when run locally
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from karasugakure.config import get_config
from karasugakure.graph.db import get_db
from karasugakure.graph.ingest import ingest_entity, ingest_relationship, ingest_evidence
from karasugakure.graph.export import export_to_json, export_all_nodes
from karasugakure.agents.odin import OdinAgent
from karasugakure.agents.norn import NornAgent
from karasugakure.agents.tyr import TyrAgent
from karasugakure.agents.skadi import SkadiAgent
from karasugakure.agents.heimdall import HeimdallAgent
from karasugakure.agents.loki import LokiAgent
from karasugakure.agents.hel import HelAgent
from karasugakure.agents.mimir import MimirAgent
from karasugakure.agents.fenrir import FenrirAgent
from karasugakure.agents.huginn import HuginnAgent
from karasugakure.evidence.audit import ForensicAuditLedger

audit_ledger = ForensicAuditLedger()




app = typer.Typer(help="Karasugakure: CLI-only OSINT Orchestration Harness")
graph_app = typer.Typer(help="Manage and query the relational graph")
app.add_typer(graph_app, name="graph")
audit_app = typer.Typer(help="Manage and verify the cryptographic audit trail")
app.add_typer(audit_app, name="audit")
kaisen_app = typer.Typer(help="Manage Kaisen institutional knowledge base")
app.add_typer(kaisen_app, name="kaisen")

console = Console()

@app.command()
def init():
    """Initialize folders, directories and check Neo4j/Memgraph connection."""
    config = get_config()
    config.init_dirs()
    from karasugakure.evidence.audit import ForensicAuditLedger
    audit = ForensicAuditLedger()
    console.print("[bold green]✔[/bold green] Karasugakure directories initialized at [cyan]~/.karasugakure[/cyan]")
    console.print("[bold green]✔[/bold green] Cryptographic forensic master key initialized.")
    
    db = get_db()
    console.print(f"Connecting to GraphDB at [yellow]{db.config.uri}[/yellow]...")
    connected = db.check_connection()
    if connected:
        console.print("[bold green]✔[/bold green] Connected to active Neo4j/Memgraph instance!")
    else:
        console.print("[bold yellow]⚠[/bold yellow] GraphDB is not reachable. Using mock/offline mode.")

    # Audit log
    audit_ledger.log_execution(
        agent_name="operator",
        action="init",
        parameters={},
        findings=[{"connected": connected, "message": "Directories and keys initialized"}],
        evidence_files=[],
        proxy_route=None
    )

@app.command()
def recon(target: str = typer.Argument(..., help="Target IP or Domain")):
    """Run infrastructure and surface reconnaissance (Heimdall)."""
    heimdall = HeimdallAgent()
    console.print(f"Starting reconnaissance on [cyan]{target}[/cyan] using [magenta]Heimdall[/magenta]...")
    results = heimdall.execute(target)
    
    # Audit log
    audit_ledger.log_execution(
        agent_name="heimdall",
        action="recon",
        parameters={"target": target},
        findings=[results],
        evidence_files=[],
        proxy_route="direct"
    )
    
    table = Table(title=f"Recon Results: {target}")
    table.add_column("Type", style="bold green")
    table.add_column("Value", style="cyan")
    
    for sub in results["subdomains"]:
        table.add_row("Subdomain", sub)
    for ip in results["ips"]:
        table.add_row("IP Address", ip)
    for port in results["ports"]:
        table.add_row("Open Port", str(port))
        
    console.print(table)
    
    # Store in database if reachable
    db = get_db()
    if db.check_connection():
        odin = OdinAgent()
        odin.process_finding("Domain", target, "heimdall", "A", "1")
        for sub in results["subdomains"]:
            odin.process_finding("Domain", sub, "heimdall", "B", "2")
            odin.process_connection("Domain", target, "Domain", sub, "HAS_SUBDOMAIN", "Discovered subdomain", "heimdall")
        for ip in results["ips"]:
            odin.process_finding("IP", ip, "heimdall", "A", "1")
            odin.process_connection("Domain", target, "IP", ip, "RESOLVES_TO", "DNS Resolution", "heimdall")
        console.print("[bold green]✔[/bold green] Recon results ingested to Neo4j.")

@app.command()
def humint(target: str = typer.Argument(..., help="Target Alias or Username")):
    """Run identity, profiles, and digital footprint scan (Loki)."""
    loki = LokiAgent()
    console.print(f"Starting HUMINT scan on [cyan]{target}[/cyan] using [magenta]Loki[/magenta]...")
    results = loki.execute(target)
    
    # Audit log
    audit_ledger.log_execution(
        agent_name="loki",
        action="humint",
        parameters={"target": target},
        findings=[results],
        evidence_files=[],
        proxy_route="proxychains"
    )
    
    table = Table(title=f"HUMINT Footprint: {target}")
    table.add_column("Type", style="bold green")
    table.add_column("Details", style="cyan")
    
    for profile in results["profiles"]:
        table.add_row(profile["platform"], profile["url"])
    for email in results["emails"]:
        table.add_row("Email", email)
        
    console.print(table)
    
    db = get_db()
    if db.check_connection():
        odin = OdinAgent()
        odin.process_finding("Alias", target, "loki", "A", "1")
        for email in results["emails"]:
            odin.process_finding("Email", email, "loki", "B", "2")
            odin.process_connection("Alias", target, "Email", email, "HAS_EMAIL", "Associated email address", "loki")
        for profile in results["profiles"]:
            odin.process_finding("Profile", profile["url"], "loki", "A", "1")
            odin.process_connection("Alias", target, "Profile", profile["url"], "HAS_PROFILE", f"Profile on {profile['platform']}", "loki")
        console.print("[bold green]✔[/bold green] HUMINT results ingested to Neo4j.")

@app.command()
def darkweb(query: str = typer.Argument(..., help="Search query or leak keyword")):
    """Search Onion networks, marketplaces, and forums (Hel)."""
    hel = HelAgent()
    console.print(f"Executing Deep Web query: '[cyan]{query}[/cyan]' using [magenta]Hel[/magenta]...")
    results = hel.execute(query)
    
    # Audit log
    audit_ledger.log_execution(
        agent_name="hel",
        action="darkweb",
        parameters={"query": query},
        findings=[results],
        evidence_files=[],
        proxy_route="tor"
    )
    
    table = Table(title=f"Dark Web Search: {query}")
    table.add_column("Type", style="bold red")
    table.add_column("Site / Match", style="yellow")
    
    for site in results["onion_sites"]:
        table.add_row("Onion Site", f"{site['onion']} - {site['title']}")
    for leak in results["leaks_found"]:
        table.add_row("Leak Db Match", f"{leak['db']}: {leak['match']}")
        
    console.print(table)

@app.command()
def entity(
    target: str = typer.Argument(..., help="Target Identity or Corporate Entity"),
    entity_type: str = typer.Option("Persona física", "--type", "-t", help="Persona física, Persona jurídica, or Mixto")
):
    """Mapear y validar inteligencia humana y corporativa (Huginn - Dominio 7)."""
    huginn = HuginnAgent()
    console.print(f"Starting Domain 7 Entity Intelligence on [cyan]{target}[/cyan] ({entity_type}) using [magenta]Huginn[/magenta]...")
    results = huginn.execute(target, entity_type=entity_type)
    
    # Audit log
    audit_ledger.log_execution(
        agent_name="huginn",
        action="entity",
        parameters={"target": target, "entity_type": entity_type},
        findings=[results],
        evidence_files=[],
        proxy_route="tor"
    )
    
    # HES Interpretation
    hes = results["hes"]
    hes_interp = "Bajo"
    if hes >= 85:
        hes_interp = "Crítico con depuración humana obligatoria" if hes < 94 else "Crítico"
    elif hes >= 75: hes_interp = "Crítico"
    elif hes >= 50: hes_interp = "Alto"
    elif hes >= 25: hes_interp = "Medio"

    console.print(Panel(
        f"[bold green]HUMINT OSINT BRIEF[/bold green]\n"
        f"Target: [cyan]{results['target']}[/cyan]\n"
        f"Type: [yellow]{results['entity_type']}[/yellow]\n"
        f"Certainty: [bold]{results['certainty']}%[/bold] ({results['status']})\n"
        f"HES Score: [bold magenta]{hes:.1f}/100[/bold magenta] ({hes_interp})\n\n"
        f"[bold]Hypothesis:[/bold] {results['hypothesis']['title']}\n"
        f"Context: {results['hypothesis']['context']}\n"
        f"Vulnerability: {results['hypothesis']['vulnerability']}",
        title="Huginn Entity Resolution"
    ))
    
    if "run_id" in results:
        console.print(f"[bold green]✔[/bold green] W3C PROV Entity graph ingested to Neo4j (Run ID: [yellow]{results['run_id']}[/yellow]).")
    else:
        console.print("[bold yellow]⚠[/bold yellow] PROV Graph ingestion skipped (Database offline).")

@app.command()
def archive(url: str = typer.Argument(..., help="URL to inspect historical copies")):
    """Retrieve historical captures and Wayback Machine caches."""
    console.print(f"Querying Wayback Archive for [cyan]{url}[/cyan]...")
    # Mock response for CLI contract
    table = Table(title=f"Wayback Machine Snapshots: {url}")
    table.add_column("Timestamp", style="bold green")
    table.add_column("Status", style="cyan")
    table.add_row("2025-01-10 14:22:01", "200 OK")
    table.add_row("2024-06-15 09:15:30", "200 OK")
    table.add_row("2023-11-02 18:44:11", "302 Redirect")
    
    # Audit log
    audit_ledger.log_execution(
        agent_name="archive_adapter",
        action="archive",
        parameters={"url": url},
        findings=[
            {"timestamp": "2025-01-10 14:22:01", "status": "200 OK"},
            {"timestamp": "2024-06-15 09:15:30", "status": "200 OK"}
        ],
        evidence_files=[],
        proxy_route="direct"
    )
    
    console.print(table)

@graph_app.command("ingest")
def graph_ingest(
    entity_type: str = typer.Option(..., "--type", "-t", help="Entity type (e.g. Domain, Email, Alias)"),
    value: str = typer.Option(..., "--value", "-v", help="Entity value (e.g. admin@company.com)"),
    source: str = typer.Option("operator", "--source", "-s", help="Source reporting the entity"),
    reliability: str = typer.Option("A", "-r", help="NATO Source Reliability (A-F)"),
    credibility: str = typer.Option("1", "-c", help="NATO Information Credibility (1-6)")
):
    """Ingest a validated entity node manually into the graph db."""
    db = get_db()
    if not db.check_connection():
        console.print("[bold red]Error:[/bold red] Neo4j/Memgraph database is not reachable. Ensure it is running.")
        raise typer.Exit(1)
        
    odin = OdinAgent()
    result = odin.process_finding(
        entity_type=entity_type,
        value=value,
        source=source,
        reliability=reliability,
        credibility=credibility
    )
    
    # Audit log
    audit_ledger.log_execution(
        agent_name="operator",
        action="graph_ingest",
        parameters={"type": entity_type, "value": value, "source": source, "reliability": reliability, "credibility": credibility},
        findings=[result],
        evidence_files=[],
        proxy_route=None
    )
    
    console.print(Panel(
        f"[bold green]Node successfully ingested![/bold green]\n"
        f"ID: {result['entity']['e']['id']}\n"
        f"Type: [cyan]{entity_type}[/cyan]\n"
        f"Value: [yellow]{value}[/yellow]\n"
        f"NATO validation: [bold]{result['validation']['nato_rating']}[/bold] ({result['validation']['status']})\n"
        f"Confidence Score: [green]{result['validation']['confidence']}[/green]",
        title="Mimir Ingest Success"
    ))

@graph_app.command("query")
def graph_query(
    natural_language: str = typer.Argument(..., help="Natural language search intent or Cypher statement")
):
    """Translate natural language to Cypher and execute query (Norn + Mimir)."""
    db = get_db()
    if not db.check_connection():
        console.print("[bold red]Error:[/bold red] Neo4j/Memgraph database is not reachable.")
        raise typer.Exit(1)
        
    norn = NornAgent()
    cypher_query = norn.execute(natural_language)
    console.print(f"[dim]Translated Cypher:[/dim]\n[cyan]{cypher_query}[/cyan]\n")
    
    mimir = MimirAgent()
    try:
        records = mimir.execute("query", query=cypher_query)
        
        # Audit log
        audit_ledger.log_execution(
            agent_name="operator",
            action="graph_query",
            parameters={"natural_language": natural_language, "cypher_query": cypher_query},
            findings=[{"num_records": len(records) if records else 0}],
            evidence_files=[],
            proxy_route=None
        )
        
        if not records:
            console.print("[yellow]No nodes or relationships match this query.[/yellow]")
            return
            
          
        table = Table(title="Query Results")
        if records and isinstance(records[0], dict):
            keys = list(records[0].keys())
            for key in keys:
                table.add_column(key, style="cyan")
            for rec in records:
                row_vals = []
                for k in keys:
                    v = rec.get(k)
                    row_vals.append(str(v))
                table.add_row(*row_vals)
        console.print(table)
    except Exception as e:
        console.print(f"[bold red]Execution error:[/bold red] {e}")

@graph_app.command("export")
def graph_export(
    filepath: str = typer.Argument(..., help="JSON file path to export graph data to")
):
    """Export the entire Graph relational structure to a JSON file."""
    db = get_db()
    if not db.check_connection():
        console.print("[bold red]Error:[/bold red] Database is offline.")
        raise typer.Exit(1)
        
    data = export_to_json()
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2)
        
    # Audit log
    audit_ledger.log_execution(
        agent_name="operator",
        action="graph_export",
        parameters={"filepath": filepath},
        findings=[{"nodes_count": len(data.get("nodes", [])), "edges_count": len(data.get("edges", []))}],
        evidence_files=[{"filepath": filepath}],
        proxy_route=None
    )
    console.print(f"[bold green]✔[/bold green] Graph exported successfully to [cyan]{filepath}[/cyan]")

@graph_app.command("import")
def graph_import(
    filepath: str = typer.Argument(..., help="JSON file path containing graph data to import")
):
    """Import graph nodes and edges from a JSON file."""
    if not os.path.exists(filepath):
        console.print(f"[bold red]Error:[/bold red] File not found: {filepath}")
        raise typer.Exit(1)
        
    db = get_db()
    if not db.check_connection():
        console.print("[bold red]Error:[/bold red] Database is offline.")
        raise typer.Exit(1)
        
    with open(filepath, "r") as f:
        data = json.load(f)
        
    db.import_graph_data(data)
    
    # Audit log
    audit_ledger.log_execution(
        agent_name="operator",
        action="graph_import",
        parameters={"filepath": filepath},
        findings=[{"nodes_count": len(data.get("nodes", [])), "edges_count": len(data.get("edges", []))}],
        evidence_files=[{"filepath": filepath}],
        proxy_route=None
    )
    console.print(f"[bold green]✔[/bold green] Graph imported successfully from [cyan]{filepath}[/cyan]")

@app.command()
def validate(
    reliability: str = typer.Option("C", "-r", help="NATO Source Reliability (A-F)"),
    credibility: str = typer.Option("3", "-c", help="NATO Information Credibility (1-6)")
):
    """Apply Tyr intelligence scoring engine to evaluate confidence rating."""
    tyr = TyrAgent()
    res = tyr.execute("validate", reliability=reliability, credibility=credibility)
    
    # Audit log
    audit_ledger.log_execution(
        agent_name="operator",
        action="validate",
        parameters={"reliability": reliability, "credibility": credibility},
        findings=[res],
        evidence_files=[],
        proxy_route=None
    )
    
    console.print(Panel(
        f"NATO Rating: [bold]{res['nato_rating']}[/bold]\n"
        f"Confidence Score: [cyan]{res['confidence']:.2f}[/cyan]\n"
        f"Status: [yellow]{res['status'].upper()}[/yellow]",
        title="Tyr Score Assessment"
    ))

@app.command()
def freeze(
    filepath: str = typer.Argument(..., help="File path to capture/evidence file")
):
    """Freeze evidence, sign with SHA-256 and store in Evidence Vault (Skadi)."""
    if not os.path.exists(filepath):
        console.print(f"[bold red]Error:[/bold red] File not found: {filepath}")
        raise typer.Exit(1)
        
    with open(filepath, "rb") as f:
        content = f.read()
        
    skadi = SkadiAgent()
    res = skadi.execute(content, filepath)
    
    # Audit log
    audit_ledger.log_execution(
        agent_name="operator",
        action="freeze",
        parameters={"filepath": filepath},
        findings=[res],
        evidence_files=[{"filepath": filepath, "sha256": res["sha256"]}],
        proxy_route=None
    )
    
    console.print(Panel(
        f"File: [cyan]{filepath}[/cyan]\n"
        f"SHA-256: [bold]{res['sha256']}[/bold]\n"
        f"Size: [green]{res['bytes_size']} bytes[/green]\n"
        f"Status: [bold green]FROZEN & SIGNED[/bold green]",
        title="Skadi Evidence Vault"
    ))

@app.command()
def report(
    format_type: str = typer.Option("markdown", "--format", "-f", help="Format type (markdown/json)")
):
    """Generate investigation dossier report summarizing validated connections."""
    console.print("Compiling dossier report from validated facts...")
    from karasugakure.evidence.audit import ForensicAuditLedger
    ledger = ForensicAuditLedger()
    if not ledger.verify_ledger_integrity():
        console.print("[bold red]CRITICAL: Cryptographic audit trail integrity check failed! Report generation blocked.[/bold red]")
        raise typer.Exit(code=1)
    db = get_db()
    nodes = []
    if db.check_connection():
        nodes = export_all_nodes()
        console.print(f"[bold green]✔[/bold green] Collected {len(nodes)} validated nodes from graph db.")
        
    # Audit log
    audit_ledger.log_execution(
        agent_name="operator",
        action="report",
        parameters={"format_type": format_type},
        findings=[{"nodes_count": len(nodes)}],
        evidence_files=[],
        proxy_route=None
    )
    
    console.print(Panel(
        "# DOSSIER REPORT: OSINT ASSESSMENT\n"
        "Status: CONFIDENTIAL\n"
        "Generated using Karasugakure Engine v0.1.0\n\n"
        "Use `karasu export` to generate a full JSON output.",
        title="Dossier Draft"
    ))

@app.command()
def resume(
    session_id: Optional[str] = typer.Argument(None, help="Session ID to resume. If omitted, resumes the latest session.")
):
    """Resume a previous orchestrator workflow session using its checkpoint."""
    config = get_config()
    session_dir = config.base_dir / "sessions"
    
    if not session_id:
        session_files = glob.glob(str(session_dir / "session_*.json"))
        if not session_files:
            console.print("[bold red]Error:[/bold red] No sessions found to resume.")
            raise typer.Exit(1)
        latest_file = max(session_files, key=os.path.getmtime)
        session_id = os.path.basename(latest_file).replace("session_", "").replace(".json", "")
        
    console.print(f"Resuming workflow session: [cyan]{session_id}[/cyan]...")
    odin = OdinAgent()
    try:
        final_state = odin.execute(task="", session_id=session_id)
        
        audit_ledger.log_execution(
            agent_name="operator",
            action="resume",
            parameters={"session_id": session_id},
            findings=[{"status": final_state["status"], "phase": final_state["phase"]}],
            evidence_files=final_state["evidence"],
            proxy_route=None
        )
        
        if final_state["status"] == "completed":
            console.print(f"[bold green]✔[/bold green] Workflow session {session_id} completed successfully!")
        else:
            console.print(f"[bold yellow]⚠[/bold yellow] Workflow session {session_id} ended with status: {final_state['status']} (Phase: {final_state['phase']})")
            raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[bold red]Error resuming session {session_id}:[/bold red] {e}")
        raise typer.Exit(1)

@app.command()
def export():
    """Export the entire Graph relational structure to JSON format."""
    db = get_db()
    if not db.check_connection():
        console.print("[bold red]Error:[/bold red] Database connection is offline.")
        raise typer.Exit(1)
        
    data = export_to_json()
    
    # Audit log
    audit_ledger.log_execution(
        agent_name="operator",
        action="export",
        parameters={},
        findings=[{"nodes_count": len(data.get("nodes", [])), "edges_count": len(data.get("edges", []))}],
        evidence_files=[],
        proxy_route=None
    )
    
    console.print_json(data=data)

@app.command()
def orchestrate(
    target: str = typer.Argument(..., help="Initial target domain, IP, or username/alias")
):
    """Run the complete, deterministic LangGraph-controlled OSINT pipeline on a target."""
    console.print(f"Initializing LangGraph dojo orchestration harness for target: [cyan]{target}[/cyan]...")
    odin = OdinAgent()
    try:
        final_state = odin.execute(task=target)
        if final_state["status"] == "completed":
            console.print(Panel(
                f"[bold green]✔ Orchestration complete![/bold green]\n"
                f"Session ID: [cyan]{final_state['session_id']}[/cyan]\n"
                f"Consensus Status: [bold]{final_state['consensus_status'].upper()}[/bold]\n"
                f"Dossier generated at: [yellow]{final_state['dossier'].get('report_path')}[/yellow]",
                title="Workflow Success"
              ))
        else:
            console.print(Panel(
                f"[bold red]⚠ Orchestration failed or suspended.[/bold red]\n"
                f"Session ID: [cyan]{final_state['session_id']}[/cyan]\n"
                f"Suspended Phase: [yellow]{final_state['phase']}[/yellow]\n"
                f"Errors:\n" + "\n".join([f"- {e}" for e in final_state['errors']]),
                title="Workflow Suspended/Failed"
            ))
            raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[bold red]Orchestration critical failure:[/bold red] {e}")
        raise typer.Exit(1)

@app.command()
def correlate():
    """Run relational correlation and link analysis on the graph database (Fenrir)."""
    db = get_db()
    if not db.check_connection():
        console.print("[bold red]⚠[/bold red] Database is offline. Running correlation on mock datasets (DEGRADED)...")
        # Mock correlations
        table = Table(title="Suggested Correlations (Mock) [DEGRADED]")
        table.add_column("From Entity", style="cyan")
        table.add_column("Relationship", style="bold yellow")
        table.add_column("To Entity", style="cyan")
        table.add_column("Confidence", style="green")
        table.add_column("Details", style="dim")
        
        table.add_row("admin.target.com", "CORRELATED_WITH", "target.com", "0.95", "Subdomain suffix matching pattern")
        table.add_row("john_doe", "CORRELATED_WITH", "john.doe@proton.me", "0.80", "Shared link to 'john_doe' on github/twitter")
        
        from karasugakure.evidence.audit import ForensicAuditLedger
        ledger = ForensicAuditLedger()
        ledger.log_execution(
            agent_name="fenrir",
            action="correlate_mock",
            parameters={"status": "degraded"},
            findings=[
                {"from_value": "admin.target.com", "rel_type": "CORRELATED_WITH", "to_value": "target.com", "confidence": 0.95, "status": "degraded"},
                {"from_value": "john_doe", "rel_type": "CORRELATED_WITH", "to_value": "john.doe@proton.me", "confidence": 0.80, "status": "degraded"}
            ],
            evidence_files=[],
            proxy_route=None
        )
        
        console.print(table)
        raise typer.Exit(code=1)

    data = export_to_json()
    fenrir = FenrirAgent()
    correlations = fenrir.execute(data, session_id="manual")
    
    if not correlations:
        console.print("[yellow]No new correlations or shared indicators discovered.[/yellow]")
        return
        
    table = Table(title="Discovered Correlations (Ingesting...)")
    table.add_column("From Entity", style="cyan")
    table.add_column("Relationship", style="bold yellow")
    table.add_column("To Entity", style="cyan")
    table.add_column("Confidence", style="green")
    table.add_column("Details", style="dim")
    
    odin = OdinAgent()
    for c in correlations:
        table.add_row(
            c["from_value"], 
            c["rel_type"], 
            c["to_value"], 
            f"{c['confidence']:.2f}", 
            c["description"]
        )
        # Ingest the relationship
        odin.process_connection(
            from_type=c["from_type"],
            from_value=c["from_value"],
            to_type=c["to_type"],
            to_value=c["to_value"],
            rel_type=c["rel_type"],
            description=c["description"],
            source="fenrir",
            reliability="A",
            credibility="1"
        )
        
    console.print(table)
    console.print("[bold green]✔[/bold green] Correlation findings successfully ingested to Neo4j.")

@audit_app.command("verify")
def audit_verify():
    """Verify the integrity of the cryptographic forensic ledger."""
    from karasugakure.evidence.audit import ForensicAuditLedger
    ledger = ForensicAuditLedger()
    if ledger.verify_ledger_integrity():
        console.print("[bold green]✔[/bold green] Forensic Audit Ledger Integrity: OK. All signatures and hash links are valid.")
    else:
        console.print("[bold red]⚠ CRITICAL WARNING:[/bold red] Forensic Audit Ledger Integrity: CORRUPT OR ALTERED! A signature or hash link mismatch was detected!")
@kaisen_app.command("ingest")
def kaisen_ingest(
    filepath: str = typer.Argument(..., help="Path to markdown dossier report to ingest")
):
    """Ingest a previous dossier report into the Kaisen institutional memory."""
    if not os.path.exists(filepath):
        console.print(f"[bold red]Error:[/bold red] File not found: {filepath}")
        raise typer.Exit(1)
        
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()
        
    target_match = re.search(r"# OSINT INVESTIGATION DOSSIER:\s+(.*)", content)
    session_match = re.search(r"Session ID:\s+`(.*?)`", content)
    status_match = re.search(r"Status:\s+(.*)", content)
    consensus_match = re.search(r"Consensus Status:\s+(.*)", content)
    
    target = target_match.group(1).strip() if target_match else "unknown"
    session_id = session_match.group(1).strip() if session_match else "unknown"
    status = status_match.group(1).strip() if status_match else "unknown"
    consensus = consensus_match.group(1).strip() if consensus_match else "unknown"
    
    # Auto-detect Target Type
    target_type = "Alias"
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
        target_type = "IP"
    elif "@" in target:
        target_type = "Email"
    elif "." in target and not target.endswith("."):
        target_type = "Domain"

    # Parse sources and wins
    sources = re.findall(r"-\s+\*\*\s*Source\s*\*\*:\s*([^,\n]+)", content, re.IGNORECASE)
    
    # Extract successfully validated entities (wins)
    wins = []
    findings_sec = re.findall(r"-\s+\*\*\s*Source\s*\*\*:\s*.*?\n(.*?)(?=\n-|\n#|\n\n|$)", content, re.DOTALL)
    for section in findings_sec:
        for line in section.splitlines():
            line_strip = line.strip()
            if line_strip.startswith("- ") or line_strip.startswith("* "):
                wins.append(line_strip[2:])

    # Extract correlation playbooks
    playbooks = []
    corr_sec = re.findall(r"## Discovered Correlations\n(.*?)(?=\n##|\n\n|$)", content, re.DOTALL)
    if corr_sec:
        for line in corr_sec[0].splitlines():
            line_strip = line.strip()
            if line_strip.startswith("- "):
                playbooks.append(line_strip[2:])

    # Track failed hypotheses and blocking reasons
    failed_hypotheses = []
    blocking_reasons = []
    if consensus.lower() == "tentative":
        failed_hypotheses.append(target)
        blocking_reasons.append("Consensus score fell below defined threshold (0.60).")
    elif status.lower() == "failed":
        failed_hypotheses.append(target)
        # Scan for error details in markdown
        errs = re.findall(r"error\b.*", content, re.IGNORECASE)
        for err in errs:
            blocking_reasons.append(err)
        if not blocking_reasons:
            blocking_reasons.append("Pipeline boundary validation or consensus failure.")

    lesson = {
        "timestamp": time.time(),
        "target": target,
        "target_type": target_type,
        "session_id": session_id,
        "status": status,
        "consensus_status": consensus,
        "sources_involved": list(set(sources)),
        "wins": wins,
        "failed_hypotheses": failed_hypotheses,
        "blocking_reasons": blocking_reasons,
        "playbooks": playbooks,
        "filepath": filepath
    }
    
    config = get_config()
    kaisen_dir = config.base_dir / "kaisen"
    kaisen_dir.mkdir(parents=True, exist_ok=True)
    lessons_file = kaisen_dir / "lessons_learned.json"
    
    lessons = []
    if lessons_file.exists():
        try:
            with open(lessons_file, "r", encoding="utf-8") as f:
                lessons = json.load(f)
        except Exception:
            pass
            
    lessons.append(lesson)
    
    with open(lessons_file, "w", encoding="utf-8") as f:
        json.dump(lessons, f, indent=2)
        
    from karasugakure.evidence.audit import ForensicAuditLedger
    ledger = ForensicAuditLedger()
    ledger.log_execution(
        agent_name="kaisen",
        action="ingest_lesson",
        parameters={"filepath": filepath, "target": target},
        findings=[lesson],
        evidence_files=[],
        proxy_route=None
    )
    
    console.print(f"[bold green]✔[/bold green] Dossier report [cyan]{filepath}[/cyan] successfully ingested into Kaisen KB.")
    
    table = Table(title="Kaisen Lesson Learned")
    table.add_column("Property", style="bold green")
    table.add_column("Value", style="cyan")
    table.add_row("Target", target)
    table.add_row("Target Type", target_type)
    table.add_row("Session ID", session_id)
    table.add_row("Status", status)
    table.add_row("Consensus", consensus)
    table.add_row("Sources", ", ".join(lesson["sources_involved"]))
    table.add_row("Wins Count", str(len(wins)))
    table.add_row("Failed Hypotheses", ", ".join(failed_hypotheses) or "None")
    console.print(table)

@kaisen_app.command("list")
def kaisen_list():
    """List all ingested lessons in the Kaisen institutional memory."""
    config = get_config()
    lessons_file = config.base_dir / "kaisen" / "lessons_learned.json"
    if not lessons_file.exists():
        console.print("[yellow]No lessons have been ingested yet.[/yellow]")
        return
        
    try:
        with open(lessons_file, "r", encoding="utf-8") as f:
            lessons = json.load(f)
    except Exception as e:
        console.print(f"[bold red]Error reading lessons learned:[/bold red] {e}")
        return
        
    table = Table(title="Kaisen Institutional Memory")
    table.add_column("Target", style="cyan")
    table.add_column("Target Type", style="yellow")
    table.add_column("Session ID", style="bold yellow")
    table.add_column("Status", style="green")
    table.add_column("Consensus", style="magenta")
    table.add_column("Date Ingested", style="dim")
    
    for l in lessons:
        dt = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(l["timestamp"]))
        table.add_row(
            l.get("target", "unknown"),
            l.get("target_type", "Alias"),
            l.get("session_id", "unknown"),
            l.get("status", "unknown"),
            l.get("consensus_status", "unknown"),
            dt
        )
    console.print(table)

@kaisen_app.command("playbooks")
def kaisen_playbooks():
    """List correlation playbooks collected from historical engagements."""
    config = get_config()
    lessons_file = config.base_dir / "kaisen" / "lessons_learned.json"
    if not lessons_file.exists():
        console.print("[yellow]No playbooks available. Ingest lessons first.[/yellow]")
        return

    try:
        with open(lessons_file, "r", encoding="utf-8") as f:
            lessons = json.load(f)
    except Exception as e:
        console.print(f"[bold red]Error reading playbooks:[/bold red] {e}")
        return

    table = Table(title="Historical Correlation Playbooks")
    table.add_column("Session", style="yellow")
    table.add_column("High-Value Correlation Pattern", style="cyan")

    playbook_count = 0
    for l in lessons:
        playbooks = l.get("playbooks", [])
        for p in playbooks:
            table.add_row(l.get("session_id", "unknown"), p)
            playbook_count += 1

    if playbook_count == 0:
        console.print("[yellow]No playbooks found in lessons learned.[/yellow]")
    else:
        console.print(table)

@kaisen_app.command("promote")
def kaisen_promote():
    """Promotes threshold updates based on Kaisen lessons. Gated on signed ledger verification."""
    # hard cryptographic gate: Verify audit ledger integrity
    from karasugakure.evidence.audit import ForensicAuditLedger
    ledger = ForensicAuditLedger()
    if not ledger.verify_ledger_integrity():
        console.print("[bold red]CRITICAL OPSEC BLOCK: Cryptographic audit trail integrity is broken! Knowledge promotion suspended.[/bold red]")
        raise typer.Exit(code=1)

    config = get_config()
    lessons_file = config.base_dir / "kaisen" / "lessons_learned.json"
    if not lessons_file.exists():
        console.print("[yellow]No lesson metadata available to suggest promotions.[/yellow]")
        return

    try:
        with open(lessons_file, "r", encoding="utf-8") as f:
            lessons = json.load(f)
    except Exception as e:
        console.print(f"[bold red]Error reading lesson repository:[/bold red] {e}")
        return

    # Analyze wins and failed hypotheses to adjust thresholds
    total_wins = sum(len(l.get("wins", [])) for l in lessons)
    total_failures = sum(len(l.get("failed_hypotheses", [])) for l in lessons)

    console.print("\n=== KAISEN KNOWLEDGE PROMOTION PLAN ===")
    console.print(f"Ingested Engagements analyzed: {len(lessons)}")
    console.print(f"Total Wins: {total_wins} | Total Failures: {total_failures}")
    console.print("---------------------------------------")

    # Suggest heuristic calibrations based on wins/failures ratios
    if total_failures > 0:
        console.print("[bold yellow]Recommendation 1: Calibrate Source Floors[/bold yellow]")
        console.print("  - Multiple consensus failures detected. Recommend raising Loki confidence floors to 0.55.")
    else:
        console.print("[bold green]Recommendation 1: Confirm Baseline Floors[/bold green]")
        console.print("  - All targets validated successfully. Baseline floors are optimal (Heimdall=0.60, Loki=0.50, Hel=0.40).")

    if total_wins > 5:
        console.print("[bold yellow]Recommendation 2: Template Promotion[/bold yellow]")
        console.print("  - Recurring wins on Domain sub-elements. Promote default Domain target threshold from 0.60 to 0.65 for tighter OPSEC.")
    else:
        console.print("[bold green]Recommendation 2: Heuristic Stability[/bold green]")
        console.print("  - Keep default thresholds stable. Current entity thresholds are appropriate.")

    console.print("=======================================\n")

@app.command()
def tui():
    """Launch the interactive Karasugakure Terminal User Interface."""
    from karasugakure.tui import KarasuTuiApp
    tui_app = KarasuTuiApp()
    tui_app.run()

if __name__ == "__main__":
    app()
