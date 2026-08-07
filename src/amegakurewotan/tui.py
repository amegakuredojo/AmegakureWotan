import os
import json
import time
import random
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional

from rich.text import Text
from rich.table import Table
from rich.panel import Panel
from rich.console import RenderableType

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Header, Footer, Static, Input, Button, Label, TabbedContent, TabPane, RichLog, Select, Tree
from textual.reactive import reactive
from textual.binding import Binding

from amegakurewotan.config import get_config
from amegakurewotan.graph.db import get_db
from amegakurewotan.evidence.audit import ForensicAuditLedger
from amegakurewotan.policy.vault import CredentialVault
from amegakurewotan.policy.opsec import check_tor_socks_proxy, get_active_proxies
from amegakurewotan.agents.odin import OdinAgent

logger = logging.getLogger("amegakurewotan.tui")

class SystemStatusWidget(Static):
    """Renders Tor proxies, Kùzu, and GPG Vault active status."""
    
    def on_mount(self) -> None:
        self.set_interval(3.0, self.update_status)
        self.update_status()

    def update_status(self) -> None:
        config = get_config()
        db = get_db()
        
        # 1. Kùzu Status
        db_ok = db.check_connection()
        db_txt = "[bold green]ONLINE[/bold green]" if db_ok else "[bold red]OFFLINE[/bold red]"
        
        # 2. Tor Proxies Status
        active_tor = get_active_proxies()
        if active_tor:
            tor_txt = f"[bold green]ACTIVE ({len(active_tor)} node/s)[/bold green]"
        else:
            tor_txt = "[bold red]OFFLINE[/bold red]"
            
        # 3. Vault Status
        vault_file = config.base_dir / "opsec" / "credentials.json.gpg"
        key_file = config.base_dir / "opsec" / "keys" / "audit_master.key"
        if key_file.exists():
            vault_txt = "[bold green]LOCKED & SECURED[/bold green]"
            if vault_file.exists():
                vault_txt += f" ({vault_file.stat().st_size} bytes)"
        else:
            vault_txt = "[bold yellow]UNINITIALIZED[/bold yellow]"

        # Compile status grid
        table = Table.grid(padding=(0, 2))
        table.add_column("Service", style="bold cyan")
        table.add_column("Status")
        table.add_row("GraphDB (Kùzu)", db_txt)
        table.add_row("Tor Proxy Pool", tor_txt)
        table.add_row("GPG Credentials", vault_txt)
        
        self.update(Panel(
            table,
            title="[bold green]System OPSEC & Infrastructure[/bold green]",
            border_style="green"
        ))

class LogStreamer(RichLog):
    """Custom logs viewer log-stream component."""
    def __init__(self, **kwargs):
        super().__init__(max_lines=500, min_width=80, wrap=True, **kwargs)

class GraphTreeWidget(Static):
    """Pulls node relationships from Kùzu and visualizes them hierarchically in a tactical tree layout."""
    
    def on_mount(self) -> None:
        self.set_interval(5.0, self.refresh_graph_tree)
        self.refresh_graph_tree()

    def refresh_graph_tree(self) -> None:
        db = get_db()
        if not db.check_connection():
            self.update(Panel(
                "[bold red]Cannot load graph: Kùzu database is OFFLINE.[/bold red]",
                title="Graph Explorer",
                border_style="red"
            ))
            return

        try:
            # Get latest activities to show active targets
            targets_res = db.execute_query("MATCH (a:Activity) RETURN a.run_id AS run_id, a.target_id AS target, a.created_at AS ts ORDER BY a.created_at DESC LIMIT 5")
            
            # Fetch node summaries
            counts = db.execute_query("MATCH (n) RETURN labels(n)[0] as label, count(n) as count")
            
            summary_lines = []
            for c in counts:
                lbl = c.get("label", "Unknown")
                cnt = c.get("count", 0)
                if lbl != "AuditRecord": # Skip audit ledger nodes in visual graph summary
                    summary_lines.append(f"  - [cyan]{lbl}[/cyan]: {cnt} nodes")

            # Load primary relationships
            rels = db.execute_query("""
                MATCH (a)-[r]->(b)
                WHERE NOT a:AuditRecord AND NOT b:AuditRecord
                RETURN labels(a)[0] as a_lbl, a.value as a_val, type(r) as rel, labels(b)[0] as b_lbl, b.value as b_val
                LIMIT 25
            """)
            
            tree_lines = []
            tree_lines.append("[bold green]⬤ OSINT Intelligence Graph[/bold green]")
            tree_lines.append("──────────────────────────────")
            
            # Group relationships by source node to build tree
            grouped = {}
            for r in rels:
                src = f"{r['a_val']} ({r['a_lbl']})"
                if src not in grouped:
                    grouped[src] = []
                grouped[src].append(f"  └── [[yellow]{r['rel']}[/yellow]] ──► [cyan]{r['b_val']}[/cyan] ({r['b_lbl']})")

            if not grouped:
                tree_lines.append("  [yellow]No entities ingested yet. Launch a scan target to begin.[/yellow]")
            else:
                for src, edges in grouped.items():
                    tree_lines.append(f"[bold white]{src}[/bold white]")
                    for edge in edges:
                        tree_lines.append(edge)
            
            text_payload = "\n".join(tree_lines)
            
            grid = Table.grid(padding=(0, 4))
            grid.add_column("Summary", width=30)
            grid.add_column("Hierarchy")
            
            summary_panel = "\n".join(["[bold green]Database Summary[/bold green]", ""] + summary_lines)
            grid.add_row(summary_panel, text_payload)
            
            self.update(Panel(
                grid,
                title="[bold green]Network Node-Link Graph Explorer[/bold green]",
                border_style="green"
            ))
        except Exception as e:
            self.update(Panel(
                f"[bold red]Failed to retrieve graph details: {e}[/bold red]",
                title="Graph Explorer",
                border_style="red"
            ))

class LedgerIntegrityWidget(Static):
    """Performs live integrity checks on the blockchain-like forensic ledger and prints certificates."""

    def on_mount(self) -> None:
        self.set_interval(6.0, self.check_ledger)
        self.check_ledger()

    def check_ledger(self) -> None:
        ledger = ForensicAuditLedger()
        status_ok = ledger.verify_ledger_integrity()
        
        # Read last 3 ledger records from file system for inspection
        records = []
        if ledger.ledger_path.exists():
            try:
                with open(ledger.ledger_path, "r") as f:
                    for line in f:
                        if line.strip():
                            records.append(json.loads(line))
            except Exception:
                pass

        table = Table(title="Recent Forensic Log Chain Block Entries", expand=True)
        table.add_column("Time", style="dim", width=12)
        table.add_column("Agent", style="yellow", width=10)
        table.add_column("Action", style="cyan", width=12)
        table.add_column("HMAC Signature (Prefix)", style="magenta", width=16)
        table.add_column("Block Hash (Prefix)", style="bold white", width=16)
        
        for r in records[-4:]:
            payload = r.get("payload", {})
            ts = payload.get("timestamp", 0.0)
            time_str = time.strftime("%H:%M:%S", time.localtime(ts))
            table.add_row(
                time_str,
                payload.get("agent", "unknown"),
                payload.get("action", "unknown"),
                r.get("signature", "")[:12] + "...",
                r.get("record_hash", "")[:12] + "..."
            )
            
        status_banner = ""
        if status_ok:
            status_banner = "[bold green]✔ FORENSIC LEDGER INTEGRITY: SECURE & VERIFIED[/bold green]\nChain Link: unbroken | HMAC signatures: authentic"
            border_style = "green"
        else:
            status_banner = "[bold red]⚠ CRITICAL FORENSIC LEDGER BREACH DETECTED![/bold red]\nA signature or hash-chain link mismatch was detected. Chain is CORRUPT."
            border_style = "red"

        self.update(Panel(
            Vertical(
                Static(status_banner),
                Static(""),
                Static(table)
            ),
            title="[bold green]Criptographic Ledger Chain-of-Custody[/bold green]",
            border_style=border_style
        ))

class VaultEditor(Static):
    """Tactical panel to register, list, and wipe API keys inside the GPG credential vault."""
    
    def on_mount(self) -> None:
        self.refresh_keys()

    def refresh_keys(self) -> None:
        vault = CredentialVault()
        creds = vault.list_credentials()
        
        table = Table(title="Registered Enterprise API Subscriptions", expand=True)
        table.add_column("Service Name", style="bold cyan")
        table.add_column("API Key Token (Obfuscated)", style="yellow")
        
        for s, k in creds.items():
            obfuscated = k[:4] + "*" * (len(k) - 4) if len(k) > 4 else "****"
            table.add_row(s, obfuscated)
            
        self.update(Panel(
            Vertical(
                Static("[bold green]Credentials Vault Status[/bold green] (Symmetrically encrypted via GnuPG)"),
                Static(""),
                Static(table)
            ),
            title="[bold green]API Keys Manager[/bold green]",
            border_style="green"
        ))

class KarasuTuiApp(App):
    """The main AmegakureWotan Terminal User Interface App."""
    
    CSS = """
    Screen {
        background: #080808;
    }
    
    #main-layout {
        height: 100%;
    }
    
    #sidebar {
        width: 35;
        background: #0d0d0d;
        border-right: tall green;
        height: 100%;
        padding: 1;
    }
    
    #workspace-container {
        height: 100%;
        padding: 1;
    }
    
    .panel-block {
        margin-bottom: 1;
    }
    
    #console-pane {
        height: 12;
        border-top: double green;
        background: #020202;
    }
    
    #target-input {
        background: #111;
        border: tall cyan;
        color: #fff;
        margin-bottom: 1;
    }
    
    .button-scan {
        background: green;
        color: white;
        border: none;
        width: 100%;
        height: 3;
    }
    """
    
    BINDINGS = [
        Binding("q", "quit", "Quit TUI", show=True),
        Binding("ctrl+s", "scan", "Launch Target Scan", show=True),
        Binding("ctrl+r", "refresh", "Refresh TUI Graph", show=True),
        Binding("ctrl+k", "manage_keys", "Manage Credentials", show=True),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="main-layout"):
            with Vertical(id="sidebar"):
                yield SystemStatusWidget(classes="panel-block")
                yield Label("[bold green]Target Seed Input:[/bold green]")
                yield Input(placeholder="target.com or @username", id="target-input")
                yield Label("[bold green]Scans Options:[/bold green]")
                yield Select(
                    options=[
                        ("Full Workflow (Odin)", "full"),
                        ("HUMINT Footprint (Loki)", "humint"),
                        ("Recon DNS (Heimdall)", "recon"),
                        ("Onion Spider (Hel)", "darkweb")
                    ],
                    value="full",
                    id="scan-mode"
                )
                yield Static("")
                yield Button("LAUNCH OSINT ENGINE", id="btn-scan", variant="success")
            
            with Vertical(id="workspace-container"):
                with TabbedContent(id="tabs"):
                    with TabPane("Graph Explorer", id="tab-graph"):
                        yield GraphTreeWidget(id="graph-viewer")
                    with TabPane("Forensic Ledger Chain", id="tab-ledger"):
                        yield LedgerIntegrityWidget(id="ledger-viewer")
                    with TabPane("Credentials GPG Vault", id="tab-vault"):
                        with Container(id="vault-container"):
                            yield VaultEditor(id="vault-viewer")
                            yield Label("[bold cyan]Add Service API Key (format: service,key):[/bold cyan]")
                            yield Input(placeholder="shodan,yourkey123", id="key-input")
                            yield Button("Register Credential", id="btn-add-key", variant="primary")
                with Vertical(id="console-pane"):
                    yield Label("[bold green]Console Execution Stream[/bold green] (Odin logs):")
                    yield LogStreamer(id="console-logs")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "AMEWOTANGAKURE OSINT CONTROL PANEL"
        self.sub_title = "Tactical Intelligence & Forensic Graph Harness"
        
        log_widget = self.query_one("#console-logs", LogStreamer)
        log_widget.write("[bold green][SYSTEM] AmegakureWotan TUI successfully initialized.[/bold green]")
        log_widget.write("[bold green][SYSTEM] Monospace Cyber-Tactical theme active. SSH terminal secure.[/bold green]")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-scan":
            self.action_scan()
        elif event.button.id == "btn-add-key":
            self.add_key_to_vault()

    def add_key_to_vault(self) -> None:
        inp = self.query_one("#key-input", Input)
        log_widget = self.query_one("#console-logs", LogStreamer)
        text = inp.value.strip()
        if not text or "," not in text:
            log_widget.write("[bold red][VAULT ERROR] Invalid format. Use: service,key[/bold red]")
            return
            
        parts = text.split(",", 1)
        srv = parts[0].strip()
        key = parts[1].strip()
        
        try:
            vault = CredentialVault()
            vault.set_credential(srv, key)
            log_widget.write(f"[bold green][VAULT] Successfully registered API key for: '{srv}'[/bold green]")
            inp.value = ""
            
            # Refresh Vault UI
            self.query_one("#vault-viewer", VaultEditor).refresh_keys()
        except Exception as e:
            log_widget.write(f"[bold red][VAULT ERROR] Failed to store key: {e}[/bold red]")

    def action_scan(self) -> None:
        target_inp = self.query_one("#target-input", Input)
        scan_mode_sel = self.query_one("#scan-mode", Select)
        log_widget = self.query_one("#console-logs", LogStreamer)
        
        target = target_inp.value.strip()
        if not target:
            log_widget.write("[bold red][ERROR] Target seed input cannot be empty.[/bold red]")
            return
            
        mode = scan_mode_sel.value
        log_widget.write(f"[bold green][ENGINE] Launching '{mode}' scan for target: [cyan]{target}[/cyan]...[/bold green]")
        
        # Disable button during scan execution to prevent overlapping
        btn = self.query_one("#btn-scan", Button)
        btn.disabled = True
        
        # We run the scan asynchronously to prevent freezing the TUI thread!
        self.run_worker(self.execute_agent_scan(target, mode))

    async def execute_agent_scan(self, target: str, mode: str) -> None:
        log_widget = self.query_one("#console-logs", LogStreamer)
        btn = self.query_one("#btn-scan", Button)
        
        try:
            # Helper to run scan in separate thread / worker context
            if mode == "full":
                odin = OdinAgent()
                # Run the LangGraph orchestration pipeline
                loop = await self.run_scan_thread(odin.execute, target)
                log_widget.write(f"[bold green][ENGINE] Scan completed successfully. Session: {loop.get('session_id')}[/bold green]")
                log_widget.write(f"[bold green][ENGINE] Status: {loop.get('status')} | Consensus: {loop.get('consensus_status')}[/bold green]")
            elif mode == "humint":
                from amegakurewotan.agents.loki import LokiAgent
                loki = LokiAgent()
                res = await self.run_scan_thread(loki.execute, target)
                log_widget.write(f"[bold green][ENGINE] Loki scan complete. Found profiles: {len(res.get('profiles', []))} | emails: {len(res.get('emails', []))}[/bold green]")
            elif mode == "recon":
                from amegakurewotan.agents.heimdall import HeimdallAgent
                heim = HeimdallAgent()
                res = await self.run_scan_thread(heim.execute, target)
                log_widget.write(f"[bold green][ENGINE] Heimdall scan complete. Subdomains: {len(res.get('subdomains', []))} | IPs: {len(res.get('ips', []))}[/bold green]")
            elif mode == "darkweb":
                from amegakurewotan.agents.hel import HelAgent
                hel = HelAgent()
                res = await self.run_scan_thread(hel.execute, target)
                log_widget.write(f"[bold green][ENGINE] Hel onion search complete. Onion sites found: {len(res.get('onion_sites', []))}[/bold green]")
                
            # Refresh components
            self.query_one("#graph-viewer", GraphTreeWidget).refresh_graph_tree()
            self.query_one("#ledger-viewer", LedgerIntegrityWidget).check_ledger()
            
        except Exception as e:
            log_widget.write(f"[bold red][ENGINE FAILURE] Execution error: {e}[/bold red]")
        finally:
            btn.disabled = False

    async def run_scan_thread(self, func, *args):
        import anyio
        # Run synchronous agents blocking CPU execution inside anyio's worker threads
        return await anyio.to_thread.run_sync(func, *args)

    def action_refresh(self) -> None:
        log_widget = self.query_one("#console-logs", LogStreamer)
        log_widget.write("[SYSTEM] Force refreshing Kùzu graph & audit log displays...")
        self.query_one("#graph-viewer", GraphTreeWidget).refresh_graph_tree()
        self.query_one("#ledger-viewer", LedgerIntegrityWidget).check_ledger()

    def action_manage_keys(self) -> None:
        tabs = self.query_one("#tabs", TabbedContent)
        tabs.active = "tab-vault" # Focus Vault tab

if __name__ == "__main__":
    app = KarasuTuiApp()
    app.run()
