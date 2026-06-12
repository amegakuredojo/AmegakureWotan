import logging
from typing import Any, Dict, List
from karasugakure.graph.db import get_db

logger = logging.getLogger("karasugakure.adapters.graph")

class GraphAdapter:
    def __init__(self):
        self.db = get_db()

    def query_schema(self) -> List[Dict[str, Any]]:
        """Queries the schema or generic metadata of the Neo4j/Memgraph DB."""
        if not self.db.check_connection():
            return []
        try:
            return self.db.execute_query("CALL db.labels()")
        except Exception as e:
            logger.error(f"Failed calling db.labels(): {e}")
            return []
            
    def get_neighbors(self, node_value: str) -> List[Dict[str, Any]]:
        """Retrieves directly connected neighbors for a specific node value."""
        if not self.db.check_connection():
            return []
        query = "MATCH (n {value: $val})-[r]-(m) RETURN labels(m) as labels, m.value as value, type(r) as relationship"
        return self.db.execute_query(query, {"val": node_value})
