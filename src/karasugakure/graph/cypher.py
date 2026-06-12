from typing import Any, Dict

def create_entity_query(entity_type: str) -> str:
    """
    Generates a Cypher query to merge/create an OSINT entity node.
    Validates properties and prevents duplicate entities based on type and value.
    """
    # Sanitize entity_type to be a safe label
    safe_label = "".join(c for c in entity_type if c.isalnum())
    if not safe_label:
        safe_label = "Entity"
        
    return f"""
    MERGE (e:{safe_label} {{value: $value}})
    ON CREATE SET
        e.id = $id,
        e.source = $source,
        e.confidence = $confidence,
        e.nato_reliability = $nato_reliability,
        e.nato_credibility = $nato_credibility,
        e.created_at = timestamp(),
        e.updated_at = timestamp()
    ON MATCH SET
        e.updated_at = timestamp(),
        e.confidence = CASE WHEN $confidence > e.confidence THEN $confidence ELSE e.confidence END,
        e.source = e.source + ", " + $source
    RETURN e
    """

def create_relationship_query(from_type: str, to_type: str, rel_type: str) -> str:
    """
    Generates a Cypher query to connect two entities with an edge.
    """
    safe_from = "".join(c for c in from_type if c.isalnum())
    safe_to = "".join(c for c in to_type if c.isalnum())
    safe_rel = "".join(c for c in rel_type if c.isalnum() or c == "_").upper()
    
    return f"""
    MATCH (a:{safe_from} {{value: $from_value}})
    MATCH (b:{safe_to} {{value: $to_value}})
    MERGE (a)-[r:{safe_rel}]->(b)
    ON CREATE SET
        r.id = $id,
        r.description = $description,
        r.confidence = $confidence,
        r.source = $source,
        r.nato_reliability = $nato_reliability,
        r.nato_credibility = $nato_credibility,
        r.created_at = timestamp()
    RETURN r
    """

def link_evidence_query(entity_type: str) -> str:
    """
    Generates a Cypher query to create an evidence node and link it to an entity.
    """
    safe_label = "".join(c for c in entity_type if c.isalnum())
    return f"""
    MATCH (e:{safe_label} {{value: $entity_value}})
    MERGE (ev:Evidence {{hash: $hash}})
    ON CREATE SET
        ev.id = $id,
        ev.type = $type,
        ev.location = $location,
        ev.timestamp = timestamp(),
        ev.nato_reliability = $nato_reliability,
        ev.nato_credibility = $nato_credibility
    MERGE (e)-[r:HAS_EVIDENCE]->(ev)
    RETURN ev
    """
