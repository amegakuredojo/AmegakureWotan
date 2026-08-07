from typing import Any, Dict, List, Optional
from amegakurewotan.agents import BaseAgent
from amegakurewotan.graph.ingest import ingest_entity, ingest_relationship, ingest_evidence
from amegakurewotan.graph.db import get_db

class MimirAgent(BaseAgent):
    def __init__(self):
        super().__init__("Mimir", "Historical memory and relational archive")

    def execute(self, action: str, **kwargs) -> Any:
        """
        Executes database operations.
        Supported actions: 'ingest_node', 'ingest_edge', 'ingest_evidence', 'query'.
        """
        if action == "ingest_node":
            return ingest_entity(
                entity_type=kwargs.get("entity_type", "Entity"),
                value=kwargs.get("value"),
                source=kwargs.get("source", "mimir"),
                confidence=kwargs.get("confidence", 1.0),
                nato_reliability=kwargs.get("nato_reliability", "A"),
                nato_credibility=kwargs.get("nato_credibility", "1")
            )
        elif action == "ingest_edge":
            return ingest_relationship(
                from_type=kwargs.get("from_type"),
                from_value=kwargs.get("from_value"),
                to_type=kwargs.get("to_type"),
                to_value=kwargs.get("to_value"),
                rel_type=kwargs.get("rel_type"),
                description=kwargs.get("description", ""),
                source=kwargs.get("source", "mimir"),
                confidence=kwargs.get("confidence", 1.0),
                nato_reliability=kwargs.get("nato_reliability", "A"),
                nato_credibility=kwargs.get("nato_credibility", "1")
            )
        elif action == "ingest_evidence":
            return ingest_evidence(
                entity_type=kwargs.get("entity_type"),
                entity_value=kwargs.get("entity_value"),
                hash_val=kwargs.get("hash_val"),
                ev_type=kwargs.get("ev_type"),
                location=kwargs.get("location"),
                nato_reliability=kwargs.get("nato_reliability", "A"),
                nato_credibility=kwargs.get("nato_credibility", "1")
            )
        elif action == "query":
            db = get_db()
            cypher_query = kwargs.get("query")
            params = kwargs.get("parameters", {})
            return db.execute_query(cypher_query, params)
        else:
            raise ValueError(f"Unknown Mimir action: {action}")
