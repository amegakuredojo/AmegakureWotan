import uuid
from typing import Any, Dict, Optional
from karasugakure.graph.db import get_db
from karasugakure.graph.cypher import (
    create_entity_query,
    create_relationship_query,
    link_evidence_query
)

def ingest_entity(
    entity_type: str,
    value: str,
    source: str,
    confidence: float = 1.0,
    nato_reliability: str = "A",
    nato_credibility: str = "1"
) -> Dict[str, Any]:
    """Ingests a single entity into Neo4j/Memgraph."""
    db = get_db()
    query = create_entity_query(entity_type)
    params = {
        "id": str(uuid.uuid4()),
        "value": value,
        "source": source,
        "confidence": confidence,
        "nato_reliability": nato_reliability,
        "nato_credibility": nato_credibility
    }
    results = db.execute_query(query, params)
    return results[0] if results else {}

def ingest_relationship(
    from_type: str,
    from_value: str,
    to_type: str,
    to_value: str,
    rel_type: str,
    description: str,
    source: str,
    confidence: float = 1.0,
    nato_reliability: str = "A",
    nato_credibility: str = "1"
) -> Dict[str, Any]:
    """Ingests a relationship between two entities."""
    db = get_db()
    query = create_relationship_query(from_type, to_type, rel_type)
    params = {
        "id": str(uuid.uuid4()),
        "from_value": from_value,
        "to_value": to_value,
        "description": description,
        "source": source,
        "confidence": confidence,
        "nato_reliability": nato_reliability,
        "nato_credibility": nato_credibility
    }
    results = db.execute_query(query, params)
    return results[0] if results else {}

def ingest_evidence(
    entity_type: str,
    entity_value: str,
    hash_val: str,
    ev_type: str,
    location: str,
    nato_reliability: str = "A",
    nato_credibility: str = "1"
) -> Dict[str, Any]:
    """Ingests evidence and links it to an entity."""
    db = get_db()
    query = link_evidence_query(entity_type)
    params = {
        "id": str(uuid.uuid4()),
        "entity_value": entity_value,
        "hash": hash_val,
        "type": ev_type,
        "location": location,
        "nato_reliability": nato_reliability,
        "nato_credibility": nato_credibility
    }
    results = db.execute_query(query, params)
    return results[0] if results else {}
