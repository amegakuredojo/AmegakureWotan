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
    query = "MATCH (n) RETURN labels(n) as labels, properties(n) as properties"
    return db.execute_query(query)

def export_all_relationships() -> List[Dict[str, Any]]:
    """Retrieves all relationships from the graph."""
    db = get_db()
    query = """
    MATCH (a)-[r]->(b)
    RETURN 
        labels(a) as source_labels, 
        a.value as source_value, 
        type(r) as relationship, 
        properties(r) as properties,
        labels(b) as target_labels,
        b.value as target_value
    """
    return db.execute_query(query)

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

