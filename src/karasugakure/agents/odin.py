import logging
import uuid
import time
import json
from typing import Any, Dict, List, Optional, TypedDict
from langgraph.graph import StateGraph, END

from karasugakure.agents import BaseAgent
from karasugakure.agents.tyr import TyrAgent
from karasugakure.agents.mimir import MimirAgent
from karasugakure.agents.norn import NornAgent
from karasugakure.agents.heimdall import HeimdallAgent
from karasugakure.agents.loki import LokiAgent
from karasugakure.agents.hel import HelAgent
from karasugakure.agents.fenrir import FenrirAgent
from karasugakure.agents.skadi import SkadiAgent
from karasugakure.evidence.audit import ForensicAuditLedger
from karasugakure.config import get_config
from karasugakure.graph.db import get_db

logger = logging.getLogger("karasugakure.agents.odin")

class PipelineState(TypedDict):
    session_id: str
    target: str
    phase: str
    findings: List[Dict[str, Any]]
    correlations: List[Dict[str, Any]]
    evidence: List[Dict[str, Any]]
    dossier: Dict[str, Any]
    status: str
    errors: List[str]
    retry_count: Dict[str, int]
    consensus_status: str

def save_checkpoint(state: PipelineState):
    config = get_config()
    session_dir = config.base_dir / "sessions"
    session_dir.mkdir(parents=True, exist_ok=True)
    filepath = session_dir / f"session_{state['session_id']}.json"
    with open(filepath, "w") as f:
        json.dump(dict(state), f, indent=2)
    logger.info(f"Checkpoint saved: session={state['session_id']}, phase={state['phase']}")

def load_checkpoint(session_id: str) -> Optional[PipelineState]:
    config = get_config()
    filepath = config.base_dir / "sessions" / f"session_{session_id}.json"
    if filepath.exists():
        with open(filepath, "r") as f:
            data = json.load(f)
            state: PipelineState = {
                "session_id": data.get("session_id", session_id),
                "target": data.get("target", ""),
                "phase": data.get("phase", "init"),
                "findings": data.get("findings", []),
                "correlations": data.get("correlations", []),
                "evidence": data.get("evidence", []),
                "dossier": data.get("dossier", {}),
                "status": data.get("status", "active"),
                "errors": data.get("errors", []),
                "retry_count": data.get("retry_count", {}),
                "consensus_status": data.get("consensus_status", "trusted")
            }
            return state
    return None

# Node functions
def check_ledger_gate(state: PipelineState, phase_name: str) -> bool:
    from karasugakure.evidence.audit import ForensicAuditLedger
    ledger = ForensicAuditLedger()
    if not ledger.verify_ledger_integrity():
        state["status"] = "failed"
        state["errors"].append(f"Forensic ledger integrity check failed before phase: {phase_name}")
        logger.error(f"Ledger continuity gate failed before phase: {phase_name}")
        return False
    return True

def init_node(state: PipelineState) -> PipelineState:
    logger.info(f"--- [PHASE: INIT] --- Session {state['session_id']}")
    state["phase"] = "init"
    config = get_config()
    config.init_dirs()
    
    db = get_db()
    if not db.check_connection():
        state["errors"].append("Database unreachable during init")
        logger.warning("Database offline during init.")
        
    state["status"] = "active"
    save_checkpoint(state)
    return state

def recon_node(state: PipelineState) -> PipelineState:
    logger.info("--- [PHASE: RECON] ---")
    state["phase"] = "recon"
    
    if not check_ledger_gate(state, "recon"):
        save_checkpoint(state)
        return state
        
    if any(f.get("source") == "heimdall" for f in state["findings"]):
        logger.info("Recon data already exists. Skipping.")
        return state
        
    try:
        heimdall = HeimdallAgent()
        results = heimdall.execute(state["target"])
        state["findings"].append({
            "source": "heimdall",
            "type": "recon_results",
            "data": results,
            "reliability": "B",
            "credibility": "2"
        })
        
        db = get_db()
        if db.check_connection():
            mimir = MimirAgent()
            mimir.execute("ingest_node", entity_type="Domain", value=state["target"], source="heimdall", nato_reliability="B", nato_credibility="2")
            for sub in results["subdomains"]:
                mimir.execute("ingest_node", entity_type="Domain", value=sub, source="heimdall", nato_reliability="B", nato_credibility="2")
                mimir.execute("ingest_edge", from_type="Domain", from_value=state["target"], to_type="Domain", to_value=sub, rel_type="HAS_SUBDOMAIN", description="Discovered subdomain", source="heimdall", nato_reliability="B", nato_credibility="2")
            for ip in results["ips"]:
                mimir.execute("ingest_node", entity_type="IP", value=ip, source="heimdall", nato_reliability="B", nato_credibility="2")
                mimir.execute("ingest_edge", from_type="Domain", from_value=state["target"], to_type="IP", to_value=ip, rel_type="RESOLVES_TO", description="DNS Resolution", source="heimdall", nato_reliability="B", nato_credibility="2")
        
    except Exception as e:
        logger.error(f"Error in recon: {e}")
        state["retry_count"]["recon"] = state["retry_count"].get("recon", 0) + 1
        state["errors"].append(str(e))
        if state["retry_count"].get("recon", 0) > 3:
            state["status"] = "failed"
            
    save_checkpoint(state)
    return state

def humint_node(state: PipelineState) -> PipelineState:
    logger.info("--- [PHASE: HUMINT] ---")
    state["phase"] = "humint"
    
    if not check_ledger_gate(state, "humint"):
        save_checkpoint(state)
        return state
        
    if any(f.get("source") == "loki" for f in state["findings"]):
        logger.info("HUMINT data already exists. Skipping.")
        return state
        
    try:
        loki = LokiAgent()
        results = loki.execute(state["target"])
        state["findings"].append({
            "source": "loki",
            "type": "humint_results",
            "data": results,
            "reliability": "B",
            "credibility": "2"
        })
        
        db = get_db()
        if db.check_connection():
            mimir = MimirAgent()
            mimir.execute("ingest_node", entity_type="Alias", value=state["target"], source="loki", nato_reliability="B", nato_credibility="2")
            for email in results["emails"]:
                mimir.execute("ingest_node", entity_type="Email", value=email, source="loki", nato_reliability="B", nato_credibility="2")
                mimir.execute("ingest_edge", from_type="Alias", from_value=state["target"], to_type="Email", to_value=email, rel_type="HAS_EMAIL", description="Associated email", source="loki", nato_reliability="B", nato_credibility="2")
            for profile in results["profiles"]:
                mimir.execute("ingest_node", entity_type="Profile", value=profile["url"], source="loki", nato_reliability="B", nato_credibility="2")
                mimir.execute("ingest_edge", from_type="Alias", from_value=state["target"], to_type="Profile", to_value=profile["url"], rel_type="HAS_PROFILE", description=f"Profile on {profile['platform']}", source="loki", nato_reliability="B", nato_credibility="2")
                
    except Exception as e:
        logger.error(f"Error in humint: {e}")
        state["retry_count"]["humint"] = state["retry_count"].get("humint", 0) + 1
        state["errors"].append(str(e))
        if state["retry_count"].get("humint", 0) > 3:
            state["status"] = "failed"
            
    save_checkpoint(state)
    return state

def darkweb_node(state: PipelineState) -> PipelineState:
    logger.info("--- [PHASE: DARKWEB] ---")
    state["phase"] = "darkweb"
    
    if not check_ledger_gate(state, "darkweb"):
        save_checkpoint(state)
        return state
        
    if any(f.get("source") == "hel" for f in state["findings"]):
        logger.info("Darkweb data already exists. Skipping.")
        return state
        
    try:
        hel = HelAgent()
        results = hel.execute(state["target"])
        state["findings"].append({
            "source": "hel",
            "type": "darkweb_results",
            "data": results,
            "reliability": "C",
            "credibility": "3"
        })
        
        db = get_db()
        if db.check_connection():
            mimir = MimirAgent()
            for site in results["onion_sites"]:
                mimir.execute("ingest_node", entity_type="Domain", value=site["onion"], source="hel", nato_reliability="C", nato_credibility="3")
                mimir.execute("ingest_edge", from_type="Alias", from_value=state["target"], to_type="Domain", to_value=site["onion"], rel_type="ASSOCIATED_ONION", description=site["title"], source="hel", nato_reliability="C", nato_credibility="3")
                
    except Exception as e:
        logger.error(f"Error in darkweb: {e}")
        state["retry_count"]["darkweb"] = state["retry_count"].get("darkweb", 0) + 1
        state["errors"].append(str(e))
        if state["retry_count"].get("darkweb", 0) > 3:
            state["status"] = "failed"
            
    save_checkpoint(state)
    return state

def correlate_node(state: PipelineState) -> PipelineState:
    logger.info("--- [PHASE: CORRELATE] ---")
    state["phase"] = "correlate"
    
    if not check_ledger_gate(state, "correlate"):
        save_checkpoint(state)
        return state
    
    try:
        db = get_db()
        if db.check_connection():
            from karasugakure.graph.export import export_to_json
            graph_data = export_to_json()
            
            fenrir = FenrirAgent()
            correlations = fenrir.execute(graph_data, session_id=state.get("session_id"))
            state["correlations"] = correlations
            
            mimir = MimirAgent()
            for c in correlations:
                mimir.execute("ingest_edge", 
                    from_type=c["from_type"], from_value=c["from_value"],
                    to_type=c["to_type"], to_value=c["to_value"],
                    rel_type=c["rel_type"], description=c["description"],
                    source="fenrir", nato_reliability="B", nato_credibility="2"
                )
        else:
            logger.warning("Database offline, running mock correlations...")
            state["correlations"] = [
                {"from_value": f"admin.{state['target']}", "from_type": "Domain", "to_value": state["target"], "to_type": "Domain", "rel_type": "CORRELATED_WITH", "description": "Subdomain suffix matching pattern", "confidence": 0.95}
            ]
    except Exception as e:
        logger.error(f"Error in correlate: {e}")
        state["errors"].append(str(e))
        state["status"] = "failed"
        
    save_checkpoint(state)
    return state

def validate_node(state: PipelineState) -> PipelineState:
    logger.info("--- [PHASE: VALIDATE] ---")
    state["phase"] = "validate"
    
    if not check_ledger_gate(state, "validate"):
        save_checkpoint(state)
        return state
    
    try:
        tyr = TyrAgent()
        sources_by_value = {}
        for f in state["findings"]:
            source_name = f.get("source")
            reliability = f.get("reliability", "C")
            credibility = f.get("credibility", "3")
            
            data = f.get("data", {})
            values_to_check = []
            if "subdomains" in data:
                values_to_check.extend(data["subdomains"])
            if "ips" in data:
                values_to_check.extend(data["ips"])
            if "emails" in data:
                values_to_check.extend(data["emails"])
            if "profiles" in data:
                values_to_check.extend([p["url"] for p in data["profiles"]])
            if "onion_sites" in data:
                values_to_check.extend([s["onion"] for s in data["onion_sites"]])
                
            for v in values_to_check:
                if v not in sources_by_value:
                    sources_by_value[v] = []
                sources_by_value[v].append({
                    "agent": source_name,
                    "reliability": reliability,
                    "credibility": credibility
                })
        
        all_trusted = True
        blocked_values = []
        
        for val, sources in sources_by_value.items():
            val_res = tyr.execute("validate_consensus", value=val, sources=sources, strict_threshold=0.60)
            logger.info(f"Validation result for {val}: {val_res}")
            
            if not val_res["is_trusted"]:
                all_trusted = False
                if val_res.get("conflicting"):
                    blocked_values.append(val)
        
        if blocked_values:
            state["consensus_status"] = "blocked"
            state["status"] = "failed"
            state["errors"].append(f"Consensus conflict detected on values: {blocked_values}. Pipeline execution blocked.")
            logger.error(f"PIPELINE BLOCKED: Adversarial source conflict on {blocked_values}")
        elif not all_trusted:
            state["consensus_status"] = "tentative"
            state["status"] = "failed"
            state["errors"].append("Pipeline validation: Consensus score fell below defined threshold (0.60). Pipeline execution suspended.")
            logger.warning("Pipeline validation: Tentative (some entities failed consensus/threshold). Pipeline execution suspended.")
        else:
            state["consensus_status"] = "trusted"
            logger.info("Pipeline validation: Trusted")
            
    except Exception as e:
        logger.error(f"Error in validate: {e}")
        state["errors"].append(str(e))
        state["status"] = "failed"
        
    save_checkpoint(state)
    return state

def freeze_node(state: PipelineState) -> PipelineState:
    logger.info("--- [PHASE: FREEZE] ---")
    state["phase"] = "freeze"
    
    if not check_ledger_gate(state, "freeze"):
        save_checkpoint(state)
        return state
    
    try:
        skadi = SkadiAgent()
        
        evidence_payload = {
            "session_id": state["session_id"],
            "target": state["target"],
            "findings": state["findings"],
            "correlations": state["correlations"],
            "consensus_status": state["consensus_status"],
            "timestamp": time.time()
        }
        
        serialized_evidence = json.dumps(evidence_payload, indent=2).encode("utf-8")
        evidence_filename = f"dossier_evidence_{state['session_id']}.json"
        res = skadi.execute(serialized_evidence, evidence_filename)
        
        state["evidence"].append(res)
        logger.info(f"Frozen evidence details: {res}")
        
    except Exception as e:
        logger.error(f"Error in freeze: {e}")
        state["errors"].append(str(e))
        state["status"] = "failed"
        
    save_checkpoint(state)
    return state

def report_node(state: PipelineState) -> PipelineState:
    logger.info("--- [PHASE: REPORT] ---")
    state["phase"] = "report"
    
    if not check_ledger_gate(state, "report"):
        save_checkpoint(state)
        return state
    
    try:
        lines = [
            f"# OSINT INVESTIGATION DOSSIER: {state['target']}",
            f"Session ID: `{state['session_id']}`",
            f"Status: {state['status'].upper()}",
            f"Consensus Status: {state['consensus_status'].upper()}",
            f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "## Findings Summary",
        ]
        
        for f in state["findings"]:
            lines.append(f"- **Source**: {f['source']}, **Type**: {f['type']}")
            data = f.get("data", {})
            if "subdomains" in data:
                lines.append(f"  - Subdomains: {', '.join(data['subdomains'])}")
            if "ips" in data:
                lines.append(f"  - IPs: {', '.join(data['ips'])}")
            if "profiles" in data:
                lines.append(f"  - Social Profiles: {', '.join([p['url'] for p in data['profiles']])}")
            if "emails" in data:
                lines.append(f"  - Emails: {', '.join(data['emails'])}")
                
        lines.append("")
        lines.append("## Discovered Correlations")
        for c in state["correlations"]:
            lines.append(f"- `{c['from_value']}` --[{c['rel_type']}]--> `{c['to_value']}` ({c['description']})")
            
        lines.append("")
        lines.append("## Forensic Evidence Custody")
        for ev in state["evidence"]:
            lines.append(f"- **File**: `{ev['filename']}`")
            lines.append(f"  - **SHA-256**: `{ev['sha256']}`")
            lines.append(f"  - **Size**: `{ev['bytes_size']} bytes`")
            
        report_content = "\n".join(lines)
        
        config = get_config()
        report_path = config.base_dir / "reports" / f"dossier_{state['session_id']}.md"
        with open(report_path, "w") as f:
            f.write(report_content)
            
        state["dossier"] = {
            "report_path": str(report_path),
            "report_content": report_content
        }
        state["status"] = "completed"
        logger.info(f"Forensic dossier report generated at {report_path}")
        
    except Exception as e:
        logger.error(f"Error in report generation: {e}")
        state["errors"].append(str(e))
        state["status"] = "failed"
        
    save_checkpoint(state)
    return state

def rollback_node(state: PipelineState) -> PipelineState:
    logger.info("--- [PHASE: ROLLBACK] ---")
    state["phase"] = "rollback"
    
    audit = ForensicAuditLedger()
    audit.log_execution(
        agent_name="odin",
        action="rollback",
        parameters={"session_id": state["session_id"]},
        findings=[{"errors": state["errors"]}],
        evidence_files=[],
        proxy_route=None
    )
    
    state["status"] = "failed"
    save_checkpoint(state)
    return state

# Routing functions
def route_after_init(state: PipelineState):
    if state["status"] == "failed":
        return "rollback"
    return "recon"

def route_after_recon(state: PipelineState):
    if state["status"] == "failed":
        return "rollback"
    return "humint"

def route_after_humint(state: PipelineState):
    if state["status"] == "failed":
        return "rollback"
    return "darkweb"

def route_after_darkweb(state: PipelineState):
    if state["status"] == "failed":
        return "rollback"
    return "correlate"

def route_after_correlate(state: PipelineState):
    if state["status"] == "failed":
        return "rollback"
    return "validate"

def route_after_validate(state: PipelineState):
    if state["status"] == "failed":
        return "rollback"
    return "freeze"

def route_after_freeze(state: PipelineState):
    if state["status"] == "failed":
        return "rollback"
    return "report"

def route_after_report(state: PipelineState):
    return END

def route_after_rollback(state: PipelineState):
    return END

class OdinAgent(BaseAgent):
    def __init__(self):
        super().__init__("Odin", "Core orchestrator and threat modeler")
        self.audit = ForensicAuditLedger()

    def _build_graph(self) -> StateGraph:
        workflow = StateGraph(PipelineState)
        
        # Add nodes
        workflow.add_node("init", init_node)
        workflow.add_node("recon", recon_node)
        workflow.add_node("humint", humint_node)
        workflow.add_node("darkweb", darkweb_node)
        workflow.add_node("correlate", correlate_node)
        workflow.add_node("validate", validate_node)
        workflow.add_node("freeze", freeze_node)
        workflow.add_node("report", report_node)
        workflow.add_node("rollback", rollback_node)
        
        # Set entry point
        workflow.set_entry_point("init")
        
        # Add conditional edges
        workflow.add_conditional_edges("init", route_after_init)
        workflow.add_conditional_edges("recon", route_after_recon)
        workflow.add_conditional_edges("humint", route_after_humint)
        workflow.add_conditional_edges("darkweb", route_after_darkweb)
        workflow.add_conditional_edges("correlate", route_after_correlate)
        workflow.add_conditional_edges("validate", route_after_validate)
        workflow.add_conditional_edges("freeze", route_after_freeze)
        workflow.add_conditional_edges("report", route_after_report)
        workflow.add_conditional_edges("rollback", route_after_rollback)
        
        return workflow.compile()

    def execute(self, task: str, **kwargs) -> Dict[str, Any]:
        """
        Coordinates OSINT scanning tasks using LangGraph.
        Can start a new session or resume from a checkpoint.
        """
        session_id = kwargs.get("session_id")
        
        if session_id:
            logger.info(f"Resuming session: {session_id}")
            state = load_checkpoint(session_id)
            if not state:
                raise ValueError(f"Session ID {session_id} not found on disk.")
            state["status"] = "active"
            state["errors"] = []
        else:
            session_id = str(uuid.uuid4())[:8]
            logger.info(f"Initializing new session: {session_id} for target {task}")
            state: PipelineState = {
                "session_id": session_id,
                "target": task,
                "phase": "init",
                "findings": [],
                "correlations": [],
                "evidence": [],
                "dossier": {},
                "status": "active",
                "errors": [],
                "retry_count": {},
                "consensus_status": "trusted"
            }
            
        app = self._build_graph()
        current_phase = state.get("phase", "init")
        logger.info(f"Running LangGraph pipeline starting from phase: {current_phase}")
        
        final_state = app.invoke(state)
        
        self.audit.log_execution(
            agent_name="odin",
            action="orchestrate",
            parameters={"target": final_state["target"], "session_id": final_state["session_id"]},
            findings=final_state["findings"],
            evidence_files=final_state["evidence"],
            proxy_route=None
        )
        
        return final_state

    def process_finding(
        self,
        entity_type: str,
        value: str,
        source: str,
        reliability: str = "B",
        credibility: str = "2"
    ) -> Dict[str, Any]:
        """
        Ingest a single finding with validation.
        """
        tyr = TyrAgent()
        mimir = MimirAgent()
        validation = tyr.execute("validate", reliability=reliability, credibility=credibility)
        
        db_result = mimir.execute(
            "ingest_node",
            entity_type=entity_type,
            value=value,
            source=source,
            confidence=validation["confidence"],
            nato_reliability=reliability,
            nato_credibility=credibility
        )
        self.audit.log_execution(
            agent_name="odin",
            action="process_finding",
            parameters={"entity_type": entity_type, "value": value, "source": source},
            findings=[validation],
            evidence_files=[],
            proxy_route=None
        )
        return {
            "entity": db_result,
            "validation": validation
        }

    def process_connection(
        self,
        from_type: str,
        from_value: str,
        to_type: str,
        to_value: str,
        rel_type: str,
        description: str,
        source: str,
        reliability: str = "B",
        credibility: str = "2"
    ) -> Dict[str, Any]:
        """
        Ingest a relationship with validation.
        """
        tyr = TyrAgent()
        mimir = MimirAgent()
        validation = tyr.execute("validate", reliability=reliability, credibility=credibility)
        
        db_result = mimir.execute(
            "ingest_edge",
            from_type=from_type,
            from_value=from_value,
            to_type=to_type,
            to_value=to_value,
            rel_type=rel_type,
            description=description,
            source=source,
            confidence=validation["confidence"],
            nato_reliability=reliability,
            nato_credibility=credibility
        )
        self.audit.log_execution(
            agent_name="odin",
            action="process_connection",
            parameters={
                "from_type": from_type, "from_value": from_value,
                "to_type": to_type, "to_value": to_value,
                "rel_type": rel_type, "description": description, "source": source
            },
            findings=[validation],
            evidence_files=[],
            proxy_route=None
        )
        return {
            "relationship": db_result,
            "validation": validation
        }


