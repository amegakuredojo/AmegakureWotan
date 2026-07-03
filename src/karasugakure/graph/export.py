import os
import uuid
import time
import json
import hashlib
from typing import Any, Dict, List
from karasugakure.graph.db import get_db

def export_all_nodes() -> List[Dict[str, Any]]:
    """Retrieves all nodes from the graph."""
    db = get_db()
    node_tables = [t for t in db._known_tables if t not in (
        "WAS_ASSOCIATED_WITH", "WAS_GENERATED_BY", "WAS_ATTRIBUTED_TO", 
        "WAS_DERIVED_FROM", "USED", "RESOLVES_TO", "HAS_SUBDOMAIN", 
        "HAS_PROFILE", "HAS_EMAIL", "CORRELATED_WITH"
    )]
    
    nodes = []
    for table in node_tables:
        try:
            records = db.execute_query(f"MATCH (n:{table}) RETURN n")
            for rec in records:
                n_dict = rec.get("n")
                if isinstance(n_dict, dict):
                    props = {k: v for k, v in n_dict.items() if not k.startswith("_")}
                    nodes.append({
                        "labels": [n_dict.get("_label", table)],
                        "properties": props
                    })
        except Exception:
            pass
    return nodes

def export_all_relationships() -> List[Dict[str, Any]]:
    """Retrieves all relationships from the graph."""
    db = get_db()
    rel_types = [
        "WAS_ASSOCIATED_WITH", "WAS_GENERATED_BY", "WAS_ATTRIBUTED_TO", 
        "WAS_DERIVED_FROM", "USED", "RESOLVES_TO", "HAS_SUBDOMAIN", 
        "HAS_PROFILE", "HAS_EMAIL", "CORRELATED_WITH"
    ]
    
    edges = []
    for rel in rel_types:
        if rel.upper() not in db._known_tables:
            continue
        try:
            records = db.execute_query(f"MATCH (a)-[r:{rel}]->(b) RETURN a, r, b")
            for rec in records:
                a_dict = rec.get("a")
                b_dict = rec.get("b")
                r_dict = rec.get("r")
                if isinstance(a_dict, dict) and isinstance(b_dict, dict):
                    props = {}
                    if isinstance(r_dict, dict):
                        props = {k: v for k, v in r_dict.items() if not k.startswith("_")}
                    edges.append({
                        "source_labels": [a_dict.get("_label", "Entity")],
                        "source_value": a_dict.get("value", a_dict.get("id")),
                        "relationship": rel,
                        "properties": props,
                        "target_labels": [b_dict.get("_label", "Entity")],
                        "target_value": b_dict.get("value", b_dict.get("id"))
                    })
        except Exception:
            pass
    return edges

def export_to_json(
    run_id: str = None,
    schema_version: str = "9.4",
    operator_id: str = None,
    target_id: str = None,
    timestamp: float = None,
    evidence_hash: str = None,
    hypothesis_id: str = None,
    phase_id: str = None
) -> Dict[str, Any]:
    """Compiles the whole graph database into a simple node-link JSON model including execution contract metadata."""
    nodes = export_all_nodes()
    edges = export_all_relationships()
    
    # Enforce default / dynamic fallback values for execution contract
    run_id_val = run_id or os.environ.get("KARASU_RUN_ID") or str(uuid.uuid4())
    operator_id_val = operator_id or os.environ.get("KARASU_OPERATOR_ID") or "operator-default"
    target_id_val = target_id or os.environ.get("KARASU_TARGET_ID") or "target-default"
    timestamp_val = timestamp or time.time()
    
    if not evidence_hash:
        # Generate hash based on current nodes & edges
        serialized = json.dumps({"nodes": nodes, "edges": edges}, sort_keys=True)
        evidence_hash_val = hashlib.sha256(serialized.encode('utf-8')).hexdigest()
    else:
        evidence_hash_val = evidence_hash
        
    hypothesis_id_val = hypothesis_id or os.environ.get("KARASU_HYPOTHESIS_ID") or f"hyp-{uuid.uuid4()}"
    phase_id_val = phase_id or os.environ.get("KARASU_PHASE_ID") or "export"

    return {
        "run_id": run_id_val,
        "schema_version": schema_version,
        "operator_id": operator_id_val,
        "target_id": target_id_val,
        "timestamp": timestamp_val,
        "evidence_hash": evidence_hash_val,
        "hypothesis_id": hypothesis_id_val,
        "phase_id": phase_id_val,
        "nodes": nodes,
        "edges": edges
    }

