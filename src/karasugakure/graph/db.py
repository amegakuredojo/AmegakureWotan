import logging
import json
from typing import Any, Dict, List, Optional
from neo4j import GraphDatabase, Driver
from karasugakure.config import get_config

logger = logging.getLogger("karasugakure.graph.db")

class GraphDB:
    def __init__(self):
        self.config = get_config().neo4j
        self._driver: Optional[Driver] = None

    def connect(self) -> Driver:
        """Establishes connection to the Neo4j/Memgraph database."""
        if self._driver is None:
            try:
                self._driver = GraphDatabase.driver(
                     self.config.uri,
                     auth=(self.config.username, self.config.password)
                )
                self._driver.verify_connectivity()
                logger.info(f"Connected to Neo4j/Memgraph at {self.config.uri}")
                # Run database migrations on successful connect
                self.run_migrations()
            except Exception as e:
                logger.error(f"Failed to connect to Neo4j/Memgraph at {self.config.uri}: {e}")
                self._driver = None
                raise e
        return self._driver

    def execute_query(self, query: str, parameters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Executes a Cypher query and returns the results as a list of dictionaries."""
        driver = self.connect()
        parameters = parameters or {}
        try:
            with driver.session(database=self.config.database) as session:
                result = session.run(query, parameters)
                return [record.data() for record in result]
        except Exception as e:
            logger.error(f"Query execution failed: {e}\nQuery: {query}\nParams: {parameters}")
            if self._driver is not None:
                try:
                    self._driver.close()
                except Exception:
                    pass
                self._driver = None
            raise e

    def check_connection(self) -> bool:
        """Quick check to see if database is reachable."""
        try:
            driver = self.connect()
            driver.verify_connectivity()
            return True
        except Exception:
            if self._driver is not None:
                try:
                    self._driver.close()
                except Exception:
                    pass
                self._driver = None
            return False

    def run_migrations(self):
        """Creates constraints and indexes, auto-detecting Neo4j vs Memgraph syntax."""
        labels = ["Domain", "IP", "Alias", "Email", "Profile"]
        
        # Test Neo4j syntax for constraints
        try:
            # Let's run a test constraint creation
            self.raw_execute("CREATE CONSTRAINT unique_test_node IF NOT EXISTS FOR (t:TestNode) REQUIRE t.value IS UNIQUE")
            self.raw_execute("DROP CONSTRAINT unique_test_node IF NOT EXISTS")
            
            logger.info("Database detected as Neo4j. Applying Neo4j constraint schemas...")
            for label in labels:
                self.raw_execute(f"CREATE CONSTRAINT unique_{label.lower()}_val IF NOT EXISTS FOR (n:{label}) REQUIRE n.value IS UNIQUE")
                self.raw_execute(f"CREATE INDEX {label.lower()}_id_idx IF NOT EXISTS FOR (n:{label}) ON (n.id)")
            self.raw_execute("CREATE CONSTRAINT unique_evidence_hash IF NOT EXISTS FOR (ev:Evidence) REQUIRE ev.hash IS UNIQUE")
            self.raw_execute("CREATE INDEX evidence_id_idx IF NOT EXISTS FOR (ev:Evidence) ON (ev.id)")
            
        except Exception:
            logger.info("Neo4j schema creation failed. Falling back to Memgraph constraint schemas...")
            # Memgraph syntax: CREATE UNIQUE INDEX ON :Label(property)
            for label in labels:
                try:
                    self.raw_execute(f"CREATE UNIQUE INDEX ON :{label}(value)")
                    self.raw_execute(f"CREATE INDEX ON :{label}(id)")
                except Exception as e:
                    logger.debug(f"Memgraph index creation for {label} skipped (already exists?): {e}")
            try:
                self.raw_execute("CREATE UNIQUE INDEX ON :Evidence(hash)")
                self.raw_execute("CREATE INDEX ON :Evidence(id)")
            except Exception as e:
                logger.debug(f"Memgraph index creation for Evidence skipped: {e}")

    def raw_execute(self, query: str):
        """Helper to run schema queries outside of normal transaction sessions."""
        driver = self.connect()
        with driver.session(database=self.config.database) as session:
            session.run(query)

    def import_graph_data(self, data: Dict[str, Any]):
        """Imports nodes and edges from a JSON structure into the active database."""
        nodes = data.get("nodes", [])
        edges = data.get("edges", [])
        
        # Ingest nodes
        for node in nodes:
            labels = node.get("labels", ["Entity"])
            primary_label = labels[0]
            props = node.get("properties", {})
            val = props.get("value")
            if not val:
                continue
                
            # MERGE query
            query = f"MERGE (n:{primary_label} {{value: $value}}) SET n += $props RETURN n"
            self.execute_query(query, {"value": val, "props": props})
            
        # Ingest edges
        for edge in edges:
            src_val = edge.get("source_value")
            tgt_val = edge.get("target_value")
            rel = edge.get("relationship")
            src_lbl = edge.get("source_labels", ["Entity"])[0]
            tgt_lbl = edge.get("target_labels", ["Entity"])[0]
            props = edge.get("properties", {})
            
            if not src_val or not tgt_val or not rel:
                continue
                
            query = f"""
            MATCH (a:{src_lbl} {{value: $src_val}})
            MATCH (b:{tgt_lbl} {{value: $tgt_val}})
            MERGE (a)-[r:{rel}]->(b)
            SET r += $props
            RETURN r
            """
            self.execute_query(query, {
                "src_val": src_val,
                "tgt_val": tgt_val,
                "props": props
            })

    def close(self):
        """Closes the database driver connection."""
        if self._driver is not None:
            self._driver.close()
            self._driver = None
            logger.info("Database connection closed.")

# Singleton helper
_db_instance = None

def get_db() -> GraphDB:
    global _db_instance
    if _db_instance is None:
        _db_instance = GraphDB()
    return _db_instance
