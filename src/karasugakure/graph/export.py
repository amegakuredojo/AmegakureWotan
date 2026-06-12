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

def export_to_json() -> Dict[str, Any]:
    """Compiles the whole graph database into a simple node-link JSON model."""
    nodes = export_all_nodes()
    edges = export_all_relationships()
    return {
        "nodes": nodes,
        "edges": edges
    }
