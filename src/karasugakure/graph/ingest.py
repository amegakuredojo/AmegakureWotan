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
    """Ingests a relationship between two entities using a transaction."""
    db = get_db()
    
    # 1. Create queries and parameters for both entities and relationship
    entity1_query = create_entity_query(from_type)
    entity1_params = {
        "id": str(uuid.uuid4()),
        "value": from_value,
        "source": source,
        "confidence": confidence,
        "nato_reliability": nato_reliability,
        "nato_credibility": nato_credibility
    }
    
    entity2_query = create_entity_query(to_type)
    entity2_params = {
        "id": str(uuid.uuid4()),
        "value": to_value,
        "source": source,
        "confidence": confidence,
        "nato_reliability": nato_reliability,
        "nato_credibility": nato_credibility
    }
    
    rel_query = create_relationship_query(from_type, to_type, rel_type)
    rel_params = {
        "id": str(uuid.uuid4()),
        "from_value": from_value,
        "to_value": to_value,
        "description": description,
        "source": source,
        "confidence": confidence,
        "nato_reliability": nato_reliability,
        "nato_credibility": nato_credibility
    }
    
    operations = [
        (entity1_query, entity1_params),
        (entity2_query, entity2_params),
        (rel_query, rel_params)
    ]
    
    results = db.execute_transaction(operations)
    # The last result is the relationship
    return results[-1][0] if (results and len(results) > 2 and results[-1]) else {}

def ingest_evidence(
    entity_type: str,
    entity_value: str,
    hash_val: str,
    ev_type: str,
    location: str,
    nato_reliability: str = "A",
    nato_credibility: str = "1"
) -> Dict[str, Any]:
    """Ingests evidence and links it to an entity using a transaction."""
    db = get_db()
    
    # Ensure entity exists
    entity_query = create_entity_query(entity_type)
    entity_params = {
        "id": str(uuid.uuid4()),
        "value": entity_value,
        "source": "evidence",
        "confidence": 1.0,
        "nato_reliability": nato_reliability,
        "nato_credibility": nato_credibility
    }
    
    evidence_query = link_evidence_query(entity_type)
    evidence_params = {
        "id": str(uuid.uuid4()),
        "entity_value": entity_value,
        "hash": hash_val,
        "type": ev_type,
        "location": location,
        "nato_reliability": nato_reliability,
        "nato_credibility": nato_credibility
    }
    
    operations = [
        (entity_query, entity_params),
        (evidence_query, evidence_params)
    ]
    
    results = db.execute_transaction(operations)
    return results[-1][0] if (results and len(results) > 1 and results[-1]) else {}
