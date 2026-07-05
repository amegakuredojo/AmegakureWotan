import logging
import json
import os
import re
import time
from typing import Any, Dict, List, Optional
import kuzu
from karasugakure.config import get_config

logger = logging.getLogger("karasugakure.graph.db")

class GraphDB:
    def __init__(self):
        self.config = get_config().kuzu
        self._db: Optional[kuzu.Database] = None
        self._conn: Optional[kuzu.Connection] = None
        
        # Diccionario para trackear tablas creadas y evitar excepciones constantes
        self._known_tables = set()
        self._known_properties = set()

    def connect(self) -> kuzu.Connection:
        """Establishes connection to the embedded Kùzu database."""
        if self._db is None or self._conn is None:
            try:
                # Ensure directory exists
                db_path = self.config.database_path
                os.makedirs(os.path.dirname(db_path), exist_ok=True)
                
                self._db = kuzu.Database(db_path)
                self._conn = kuzu.Connection(self._db)
                logger.info(f"Connected to embedded Kùzu at {db_path}")
                
                # Cargar tablas existentes en la caché
                res = self._conn.execute("CALL show_tables() RETURN *")
                while res.has_next():
                    row = res.get_next()
                    if row and len(row) > 0 and isinstance(row[0], str):
                        self._known_tables.add(row[0].upper())
                
                self.run_migrations()
            except Exception as e:
                logger.error(f"Failed to connect to Kùzu at {self.config.database_path}: {e}")
                self._db = None
                self._conn = None
                raise e
        return self._conn

    def _ensure_schema_for_query(self, query: str):
        """Kùzu requires strict schemas. This intercepts MERGE/CREATE and auto-generates tables."""
        if not self._conn:
            return
            
        # Detectar nodos: MATCH (n:Domain), MERGE (a:Email)
        node_matches = re.findall(r'\(.*?:\s*([A-Za-z0-9_]+)', query)
        for node_label in set(node_matches):
            if node_label.upper() not in self._known_tables:
                try:
                    # Detectar si el query busca/crea por 'value' o por 'id'
                    if re.search(r':\s*' + node_label + r'\s*\{\s*value\s*:', query, re.IGNORECASE):
                        self._conn.execute(f"CREATE NODE TABLE {node_label} (value STRING, id STRING, uuid STRING, record_hash STRING, name STRING, run_id STRING, hash_sha512 STRING, PRIMARY KEY (value))")
                    else:
                        self._conn.execute(f"CREATE NODE TABLE {node_label} (id STRING, value STRING, uuid STRING, record_hash STRING, name STRING, run_id STRING, hash_sha512 STRING, PRIMARY KEY (id))")
                    self._known_tables.add(node_label.upper())
                except Exception:
                    pass

        # Detectar relaciones y crear tablas relacionales dinámicamente basadas en orígenes y destinos
        right_rels = re.findall(
            r'\(\s*[A-Za-z0-9_]*\s*:\s*([A-Za-z0-9_]+)\s*\)\s*-\s*\[\s*[A-Za-z0-9_]*\s*:\s*([A-Za-z0-9_]+)[^\]]*\]\s*->\s*\(\s*[A-Za-z0-9_]*\s*:\s*([A-Za-z0-9_]+)\s*\)',
            query
        )
        for src_lbl, rel_label, tgt_lbl in right_rels:
            if rel_label.upper() not in self._known_tables:
                try:
                    self._conn.execute(f"CREATE REL TABLE {rel_label} (FROM {src_lbl} TO {tgt_lbl})")
                    self._known_tables.add(rel_label.upper())
                except Exception:
                    pass

        left_rels = re.findall(
            r'\(\s*[A-Za-z0-9_]*\s*:\s*([A-Za-z0-9_]+)\s*\)\s*<-\s*\[\s*[A-Za-z0-9_]*\s*:\s*([A-Za-z0-9_]+)[^\]]*\]\s*-\s*\(\s*[A-Za-z0-9_]*\s*:\s*([A-Za-z0-9_]+)\s*\)',
            query
        )
        for tgt_lbl, rel_label, src_lbl in left_rels:
            if rel_label.upper() not in self._known_tables:
                try:
                    self._conn.execute(f"CREATE REL TABLE {rel_label} (FROM {src_lbl} TO {tgt_lbl})")
                    self._known_tables.add(rel_label.upper())
                except Exception:
                    pass

        # Detectar otras relaciones más simples
        rel_matches = re.findall(r'\[.*?:\s*([A-Za-z0-9_]+).*?\]', query)
        for rel_label in set(rel_matches):
            if rel_label.upper() not in self._known_tables:
                try:
                    # Fallback simple
                    self._conn.execute(f"CREATE REL TABLE {rel_label} (FROM Entity TO Entity)")
                    self._known_tables.add(rel_label.upper())
                except Exception:
                    pass

    def _find_table_for_var(self, query: str, var_name: str) -> Optional[str]:
        # Node pattern: (var_name:Label)
        node_match = re.search(r'\(\s*' + var_name + r'\s*:\s*([A-Za-z0-9_]+)', query)
        if node_match:
            return node_match.group(1)
            
        # Relationship pattern: -[var_name:Label]-> or <-[var_name:Label]- or -[var_name:Label]-
        rel_match = re.search(r'\[\s*' + var_name + r'\s*:\s*([A-Za-z0-9_]+)', query)
        if rel_match:
            return rel_match.group(1)
            
        return None

    def _ensure_property_exists_for_var(self, query: str, var_name: str, prop_name: str, val: Any):
        table_name = self._find_table_for_var(query, var_name)
        if not table_name:
            return
            
        if isinstance(val, bool):
            kuzu_type = "BOOL"
        elif isinstance(val, int):
            kuzu_type = "INT64"
        elif isinstance(val, float):
            kuzu_type = "DOUBLE"
        else:
            kuzu_type = "STRING"
            
        prop_key = f"{table_name.upper()}.{prop_name.upper()}"
        if prop_key not in self._known_properties:
            try:
                self._conn.execute(f"ALTER TABLE {table_name} ADD {prop_name} {kuzu_type}")
            except Exception:
                pass
            self._known_properties.add(prop_key)

    def _rewrite_query_and_params(self, query: str, parameters: Dict[str, Any]) -> tuple:
        # 1. Map known primary keys to `id` in MERGE/CREATE patterns
        query = re.sub(
            r'MERGE\s*\(\s*([A-Za-z0-9_]+)\s*:\s*AuditRecord\s*\{\s*record_hash\s*:\s*(\$[A-Za-z0-9_]+)\s*\}\s*\)\s*SET\s+',
            r'MERGE (\1:AuditRecord {id: \2}) SET \1.record_hash = \2, ',
            query,
            flags=re.IGNORECASE
        )
        query = re.sub(
            r'MERGE\s*\(\s*([A-Za-z0-9_]+)\s*:\s*Agent\s*\{\s*name\s*:\s*(\$[A-Za-z0-9_]+)\s*\}\s*\)\s*SET\s+',
            r'MERGE (\1:Agent {id: \2}) SET \1.name = \2, ',
            query,
            flags=re.IGNORECASE
        )
        query = re.sub(
            r'MERGE\s*\(\s*([A-Za-z0-9_]+)\s*:\s*Activity\s*\{\s*run_id\s*:\s*(\$[A-Za-z0-9_]+)\s*\}\s*\)\s*SET\s+',
            r'MERGE (\1:Activity {id: \2}) SET \1.run_id = \2, ',
            query,
            flags=re.IGNORECASE
        )
        query = re.sub(
            r'MERGE\s*\(\s*([A-Za-z0-9_]+)\s*:\s*Evidence\s*\{\s*hash_sha512\s*:\s*(\$[A-Za-z0-9_]+)\s*\}\s*\)\s*SET\s+',
            r'MERGE (\1:Evidence {id: \2}) SET \1.hash_sha512 = \2, ',
            query,
            flags=re.IGNORECASE
        )
        query = re.sub(
            r'MERGE\s*\(\s*([A-Za-z0-9_]+)\s*:\s*Hypothesis\s*\{\s*hypothesis_id\s*:\s*(\$[A-Za-z0-9_]+)\s*\}\s*\)\s*SET\s+',
            r'MERGE (\1:Hypothesis {id: \2}) SET \1.hypothesis_id = \2, ',
            query,
            flags=re.IGNORECASE
        )
        
        query = re.sub(
            r'MERGE\s*\(\s*([A-Za-z0-9_]+)\s*:\s*Evidence\s*\{\s*hash\s*:\s*(\$[A-Za-z0-9_]+)\s*\}\s*\)\s*SET\s+',
            r'MERGE (\1:Evidence {id: \2}) SET \1.hash = \2, ',
            query,
            flags=re.IGNORECASE
        )
        
        # Fallbacks for other match/merge patterns (e.g. read-only MATCH)
        query = re.sub(r'\{\s*record_hash\s*:\s*(\$[A-Za-z0-9_]+)\s*\}', r'{id: \1}', query)
        query = re.sub(r'\{\s*hash_sha512\s*:\s*(\$[A-Za-z0-9_]+)\s*\}', r'{id: \1}', query)
        query = re.sub(r'\{\s*hash\s*:\s*(\$[A-Za-z0-9_]+)\s*\}', r'{id: \1}', query)
        query = re.sub(r'\{\s*hypothesis_id\s*:\s*(\$[A-Za-z0-9_]+)\s*\}', r'{id: \1}', query)

        new_params = dict(parameters)
        
        # 2. Replaces += operator: SET x += $y
        matches = re.findall(r'(\b[A-Za-z0-9_]+)\s*\+=\s*\$(\b[A-Za-z0-9_]+)', query)
        for var_name, param_name in matches:
            if param_name in parameters and isinstance(parameters[param_name], dict):
                props_dict = parameters[param_name]
                set_clauses = []
                for prop_key, prop_val in props_dict.items():
                    flat_param_name = f"{param_name}_{prop_key}"
                    new_params[flat_param_name] = prop_val
                    set_clauses.append(f"{var_name}.{prop_key} = ${flat_param_name}")
                    
                    self._ensure_property_exists_for_var(query, var_name, prop_key, prop_val)
                    
                replacement = ", ".join(set_clauses)
                query = re.sub(
                    rf'\b{var_name}\s*\+=\s*\${param_name}\b',
                    replacement,
                    query
                )

        # 3. Alter schemas for other explicitly set properties
        prop_matches = re.findall(r'\b([A-Za-z0-9_]+)\.([A-Za-z0-9_]+)\b', query)
        for var_name, prop_name in prop_matches:
            # We no longer skip 'id' and others here because relationship tables 
            # don't have them by default and need them added dynamically.
            guess_val = parameters.get(prop_name)
            if guess_val is None:
                for p_val in parameters.values():
                    if isinstance(p_val, dict) and prop_name in p_val:
                        guess_val = p_val[prop_name]
                        break
            
            self._ensure_property_exists_for_var(query, var_name, prop_name, guess_val)

        # 4. Handle Kùzu timestamp() function
        if 'timestamp()' in query:
            query = query.replace('timestamp()', '$__sys_timestamp')
            new_params['__sys_timestamp'] = int(time.time() * 1000)

        return query, new_params

    def _serialize_kuzu_result(self, result: kuzu.QueryResult) -> List[Dict[str, Any]]:
        """Convierte el output de Kuzu al formato Kùzu [ { "n": {props...} } ]"""
        columns = result.get_column_names()
        records = []
        while result.has_next():
            row = result.get_next()
            record_dict = {}
            for col_name, val in zip(columns, row):
                # Si es un string/int, se pasa directo. 
                # Si es un nodo de Kuzu (diccionario interno), tratamos de aplanarlo o pasarlo.
                if isinstance(val, dict):
                    # Kuzu devuelve propiedades dict
                    record_dict[col_name] = val
                else:
                    record_dict[col_name] = val
            records.append(record_dict)
        return records

    def execute_query(self, query: str, parameters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Executes a Cypher query on Kùzu imitating Kùzu driver output."""
        parameters = parameters or {}
        
        # Rewrite query and parameters for Kuzu compatibility
        query, parameters = self._rewrite_query_and_params(query, parameters)
        
        self._ensure_schema_for_query(query)
        
        try:
            conn = self.connect()
            result = conn.execute(query, parameters)
            return self._serialize_kuzu_result(result)
        except RuntimeError as e:
            error_str = str(e)
            # Manejo automático de creación de relaciones si Kuzu se queja de que no existe la tabla relacional
            if "Table" in error_str and "does not exist" in error_str:
                match = re.search(r"Table (.*?) does not exist", error_str)
                if match:
                    missing_table = match.group(1)
                    # Hack táctico: si falta una tabla de relación, intentamos crearla asumiendo que 
                    # las entidades involucradas ya están registradas (ej. de Entity a Entity).
                    # Para OSINT rápido, vinculamos Domain a IP, etc. Kuzu necesita saber los endpoints.
                    # Por robustez en este proxy, si falla, loggeamos.
                    logger.warning(f"Auto-schema missing for {missing_table}. Error: {e}")
            logger.error(f"Query execution failed: {e}\nQuery: {query}\nParams: {parameters}")
            raise e
        except Exception as e:
            logger.error(f"Query execution failed: {e}\nQuery: {query}\nParams: {parameters}")
            raise e

    def execute_transaction(self, operations: list) -> List[Any]:
        """Executes multiple Cypher operations (Kuzu no tiene transacciones complejas en python API aún, iteramos)"""
        results = []
        for cypher, params in operations:
            res = self.execute_query(cypher, params)
            results.append(res)
        return results

    def check_connection(self) -> bool:
        """Quick check to see if database is reachable (In-memory always true if obj exists)."""
        try:
            self.connect()
            return True
        except Exception:
            return False

    def run_migrations(self):
        """Creates Node tables if they don't exist in Kùzu (imita constraints de Kùzu)."""
        # Node tables where primary key is 'id'
        id_tables = ["Activity", "Evidence", "Agent", "AuditRecord", "Hypothesis"]
        for table in id_tables:
            if table.upper() not in self._known_tables:
                try:
                    self._conn.execute(f"CREATE NODE TABLE {table} (id STRING, value STRING, uuid STRING, record_hash STRING, name STRING, run_id STRING, hash_sha512 STRING, PRIMARY KEY (id))")
                    self._known_tables.add(table.upper())
                except Exception:
                    pass

        # Node tables where primary key is 'value'
        value_tables = ["Entity", "Domain", "IP", "Alias", "Email", "Profile"]
        for table in value_tables:
            if table.upper() not in self._known_tables:
                try:
                    self._conn.execute(f"CREATE NODE TABLE {table} (value STRING, id STRING, uuid STRING, record_hash STRING, name STRING, run_id STRING, hash_sha512 STRING, PRIMARY KEY (value))")
                    self._known_tables.add(table.upper())
                except Exception:
                    pass

        # Relaciones explícitas con todos sus posibles tipos FROM/TO para evitar BinderException
        relationships = [
            ("PREV_RECORD", "FROM AuditRecord TO AuditRecord"),
            ("WAS_ASSOCIATED_WITH", "FROM Agent TO Activity"),
            ("USED", "FROM Activity TO Entity, FROM Activity TO Domain, FROM Activity TO IP, FROM Activity TO Alias, FROM Activity TO Email, FROM Activity TO Profile, FROM Activity TO Evidence"),
            ("WAS_GENERATED_BY", "FROM Entity TO Activity, FROM Domain TO Activity, FROM IP TO Activity, FROM Alias TO Activity, FROM Email TO Activity, FROM Profile TO Activity, FROM Evidence TO Activity"),
            ("WAS_ATTRIBUTED_TO", "FROM Entity TO Agent, FROM Domain TO Agent, FROM IP TO Agent, FROM Alias TO Agent, FROM Email TO Agent, FROM Profile TO Agent, FROM Evidence TO Agent"),
            ("WAS_DERIVED_FROM", "FROM Entity TO Entity, FROM Domain TO Domain, FROM Domain TO IP, FROM Domain TO Email, FROM Domain TO Alias, FROM Domain TO Profile, FROM IP TO Domain, FROM Email TO Domain, FROM Alias TO Domain, FROM Profile TO Domain, FROM Evidence TO Evidence"),
            ("RESOLVES_TO", "FROM Domain TO IP, FROM Domain TO Domain"),
            ("HAS_SUBDOMAIN", "FROM Domain TO Domain"),
            ("HAS_PROFILE", "FROM Alias TO Profile"),
            ("HAS_EMAIL", "FROM Alias TO Email, FROM Domain TO Email"),
            ("CORRELATED_WITH", "FROM Entity TO Entity, FROM Domain TO Domain, FROM IP TO IP, FROM Alias TO Alias, FROM Email TO Email, FROM Profile TO Profile, FROM Domain TO IP, FROM Domain TO Email, FROM Domain TO Alias, FROM Domain TO Profile, FROM IP TO Domain, FROM Email TO Domain, FROM Alias TO Domain, FROM Profile TO Domain")
        ]
        
        for rel_name, endpoints in relationships:
            if rel_name.upper() not in self._known_tables:
                try:
                    self._conn.execute(f"CREATE REL TABLE {rel_name} ({endpoints})")
                    self._known_tables.add(rel_name.upper())
                except Exception:
                    pass

    def raw_execute(self, query: str):
        """Helper to run schema queries."""
        conn = self.connect()
        conn.execute(query)

    def import_graph_data(self, data: Dict[str, Any]):
        """Imports nodes and edges from a JSON structure into the active database."""
        nodes = data.get("nodes", [])
        edges = data.get("edges", [])
        
        for node in nodes:
            labels = node.get("labels", ["Entity"])
            primary_label = labels[0]
            props = node.get("properties", {})
            val = props.get("value")
            node_id = props.get("id", val) # Fallback to value if id is missing
            if not val: continue
                
            self._ensure_schema_for_query(f"MATCH (n:{primary_label})")
            query = f"MERGE (n:{primary_label} {{id: $id}}) SET n.value = $value RETURN n"
            self.execute_query(query, {"id": node_id, "value": val})
            
        for edge in edges:
            src_val = edge.get("source_value")
            tgt_val = edge.get("target_value")
            rel = edge.get("relationship")
            src_lbl = edge.get("source_labels", ["Entity"])[0]
            tgt_lbl = edge.get("target_labels", ["Entity"])[0]
            
            if not src_val or not tgt_val or not rel: continue
            
            # Kùzu requiere que las tablas relacionales tengan orígenes y destinos explícitos.
            if rel.upper() not in self._known_tables:
                try:
                    self._conn.execute(f"CREATE REL TABLE {rel} (FROM {src_lbl} TO {tgt_lbl})")
                    self._known_tables.add(rel.upper())
                except Exception:
                    pass
                
            query = f"""
            MATCH (a:{src_lbl} {{id: $src_val}})
            MATCH (b:{tgt_lbl} {{id: $tgt_val}})
            MERGE (a)-[r:{rel}]->(b)
            RETURN r
            """
            try:
                self.execute_query(query, {"src_val": src_val, "tgt_val": tgt_val})
            except Exception:
                pass

    def close(self):
        """Closes the database driver connection."""
        self._db = None
        self._conn = None
        logger.info("Database connection closed (Kuzu embedded).")

# Singleton helper
_db_instance = None

def get_db() -> GraphDB:
    global _db_instance
    if _db_instance is None:
        _db_instance = GraphDB()
    return _db_instance
