import re
import json
import time
from datetime import datetime
from typing import Any, Dict, Tuple
from karasugakure.agents import BaseAgent

class NornAgent(BaseAgent):
    def __init__(self):
        super().__init__("Norn", "Language-to-graph translator and normalizer")

    def normalize_value(self, val: str) -> Tuple[str, str]:
        val = val.strip()
        # IP address check
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", val):
            return val, "IP"
        # Email check
        if "@" in val:
            return val.lower(), "Email"
        # Onion check
        if val.endswith(".onion"):
            return val.lower(), "Domain"
        # Domain check
        if "." in val and not val.endswith("."):
            return val.lower(), "Domain"
        # Default Alias
        return val, "Alias"

    def execute(self, natural_language: str, **kwargs) -> str:
        """
        Translates a natural language search query or ingestion instruction into Cypher.
        Uses a rule-based compiler as a fast fallback, and outputs a Cypher string.
        """
        query = natural_language.strip().lower()

        # Reject vague prompts early
        if query in ["hello", "hi", "test", "help", "query", "search", "what is this", "run", "go", "dump", "view"]:
            raise ValueError(
                json.dumps({
                    "status": "failure",
                    "error": "VagueQuery",
                    "message": "Query is too vague. Karasugakure requires deterministic OSINT graph intent specifying nodes or actions.",
                    "original_query": natural_language
                }, indent=2)
            )

        # Reject ambiguous NL queries with structured failure
        if re.search(r"\b(why|how|should|recommend|describe|summarize|analyze|who|help)\b", query):
            raise ValueError(
                json.dumps({
                    "status": "failure",
                    "error": "AmbiguousQuery",
                    "message": "Query is too ambiguous or conversational. Karasugakure requires deterministic OSINT graph intent.",
                    "original_query": natural_language
                }, indent=2)
            )

        cypher = None
        strategy = "Default substring match fallback"
        normalized_inputs = {}

        # Rule 1: Chained traversal with filters
        # e.g., "traverse from testtarget.com depth 2 filter edge RESOLVES_TO source heimdall time 2026-06-11"
        match_traverse = re.match(r"traverse\s+from\s+['\"]?([^'\"]+)['\"]?\s+depth\s+(\d+)(.*)$", query)
        if match_traverse:
            val = match_traverse.group(1)
            depth = int(match_traverse.group(2))
            rest = match_traverse.group(3)
            
            norm_val, norm_type = self.normalize_value(val)
            normalized_inputs[val] = {"value": norm_val, "type": norm_type}
            strategy = f"Chained traversal from {norm_val} with depth {depth}"
            
            edge_type = None
            source_class = None
            time_val = None
            
            edge_match = re.search(r"filter\s+edge\s+(\w+)", rest)
            if edge_match:
                edge_type = edge_match.group(1)
                strategy += f" filtered by edge type {edge_type}"
                
            source_match = re.search(r"source\s+(\w+)", rest)
            if source_match:
                source_class = source_match.group(1)
                strategy += f" filtered by source class {source_class}"
                
            time_match = re.search(r"time\s+([-\w\d]+)", rest)
            if time_match:
                time_val = time_match.group(1)
                strategy += f" filtered by time {time_val}"
                
            # Construct Cypher
            cypher = f'MATCH p = (n {{value: "{norm_val}"}})-[*..{depth}]-(m)'
            wheres = []
            if edge_type:
                wheres.append(f'ALL(rel IN relationships(p) WHERE type(rel) = "{edge_type}")')
            if source_class:
                wheres.append(f'ALL(rel IN relationships(p) WHERE rel.source = "{source_class}")')
            if time_val:
                ts = 0
                if time_val.isdigit():
                    ts = int(time_val)
                else:
                    try:
                        dt = datetime.strptime(time_val, "%Y-%m-%d")
                        ts = int(dt.timestamp() * 1000)
                    except ValueError:
                        raise ValueError(f"Invalid date format: {time_val}. Use YYYY-MM-DD or Unix timestamp.")
                wheres.append(f'ALL(rel IN relationships(p) WHERE rel.created_at > {ts})')
                
            if wheres:
                cypher += " WHERE " + " AND ".join(wheres)
            cypher += " RETURN p LIMIT 50"

        # Rule 2: Reverse-pivot queries
        # e.g., "reverse pivot to identity from leaks777xxxxxxxx.onion"
        if not cypher:
            match_rev_pivot = re.match(r"reverse\s+pivot\s+to\s+(identity|infra|archive)\s+from\s+['\"]?([^'\"]+)['\"]?$", query)
            if match_rev_pivot:
                target_cat = match_rev_pivot.group(1)
                val = match_rev_pivot.group(2)
                norm_val, norm_type = self.normalize_value(val)
                normalized_inputs[val] = {"value": norm_val, "type": norm_type}
                strategy = f"Reverse pivot to category {target_cat} from {norm_val}"
                
                if target_cat == "identity":
                    cypher = f'MATCH (n)-[r]-(m) WHERE n.value = "{norm_val}" AND (m:Alias OR m:Profile OR m:Email) RETURN n, r, m LIMIT 50'
                elif target_cat == "infra":
                    cypher = f'MATCH (n)-[r]-(m) WHERE n.value = "{norm_val}" AND (m:Domain OR m:IP) RETURN n, r, m LIMIT 50'
                elif target_cat == "archive":
                    cypher = f'MATCH (n)-[r]-(m) WHERE n.value = "{norm_val}" AND m:Evidence RETURN n, r, m LIMIT 50'

        # Rule 3: Common neighbors set query
        # e.g., "common neighbors of val1 and val2"
        if not cypher:
            match_common = re.match(r"common\s+neighbors\s+of\s+['\"]?([^'\"]+)['\"]?\s+and\s+['\"]?([^'\"]+)['\"]?$", query)
            if match_common:
                val1 = match_common.group(1)
                val2 = match_common.group(2)
                norm_val1, norm_type1 = self.normalize_value(val1)
                norm_val2, norm_type2 = self.normalize_value(val2)
                normalized_inputs[val1] = {"value": norm_val1, "type": norm_type1}
                normalized_inputs[val2] = {"value": norm_val2, "type": norm_type2}
                strategy = f"Set query: find common neighbors between {norm_val1} and {norm_val2}"
                cypher = f'MATCH (a {{value: "{norm_val1}"}})-[r1]-(c)-[r2]-(b {{value: "{norm_val2}"}}) RETURN c, r1, r2 LIMIT 50'

        # Rule 4: Shared identifiers set query
        # e.g., "shared identifiers of val1 and val2"
        if not cypher:
            match_shared = re.match(r"shared\s+identifiers\s+of\s+['\"]?([^'\"]+)['\"]?\s+and\s+['\"]?([^'\"]+)['\"]?$", query)
            if match_shared:
                val1 = match_shared.group(1)
                val2 = match_shared.group(2)
                norm_val1, norm_type1 = self.normalize_value(val1)
                norm_val2, norm_type2 = self.normalize_value(val2)
                normalized_inputs[val1] = {"value": norm_val1, "type": norm_type1}
                normalized_inputs[val2] = {"value": norm_val2, "type": norm_type2}
                strategy = f"Set query: find shared identifiers (Email, Profile, IP, Alias) between {norm_val1} and {norm_val2}"
                cypher = f'MATCH (a {{value: "{norm_val1}"}})-[r1]-(c)-[r2]-(b {{value: "{norm_val2}"}}) WHERE labels(c)[0] IN ["Email", "Profile", "IP", "Alias"] RETURN c, r1, r2 LIMIT 50'

        # Rule 5: Path intersection set query
        # e.g., "path intersection between val1 and val2"
        if not cypher:
            match_intersect = re.match(r"path\s+intersection\s+between\s+['\"]?([^'\"]+)['\"]?\s+and\s+['\"]?([^'\"]+)['\"]?$", query)
            if match_intersect:
                val1 = match_intersect.group(1)
                val2 = match_intersect.group(2)
                norm_val1, norm_type1 = self.normalize_value(val1)
                norm_val2, norm_type2 = self.normalize_value(val2)
                normalized_inputs[val1] = {"value": norm_val1, "type": norm_type1}
                normalized_inputs[val2] = {"value": norm_val2, "type": norm_type2}
                strategy = f"Set query: path intersections of up to 4 hops between {norm_val1} and {norm_val2}"
                cypher = f'MATCH p1 = (a {{value: "{norm_val1}"}})-[*..4]-(c), p2 = (b {{value: "{norm_val2}"}})-[*..4]-(c) WHERE a <> b AND c <> a AND c <> b RETURN c, p1, p2 LIMIT 50'

        # Rule 6: Temporal queries
        if not cypher:
            match_temporal = re.match(r"(?:find|list|show)\s+(?:nodes|entities)\s+created\s+after\s+([-\w\d]+)$", query)
            if match_temporal:
                param = match_temporal.group(1)
                ts = 0
                if param.isdigit():
                    ts = int(param)
                else:
                    try:
                        dt = datetime.strptime(param, "%Y-%m-%d")
                        ts = int(dt.timestamp() * 1000)
                    except ValueError:
                        raise ValueError(f"Invalid date format: {param}. Use YYYY-MM-DD or Unix timestamp.")
                strategy = f"Find nodes created after timestamp {ts}"
                cypher = f"MATCH (n) WHERE n.created_at > {ts} RETURN n LIMIT 50"

        # Rule 7: Pivot queries
        if not cypher:
            match_pivot = re.match(r"pivot\s+from\s+['\"]?([^'\"]+)['\"]?\s+to\s+(\w+)$", query)
            if match_pivot:
                val = match_pivot.group(1)
                target_type = match_pivot.group(2).capitalize()
                norm_val, norm_type = self.normalize_value(val)
                normalized_inputs[val] = {"value": norm_val, "type": norm_type}
                strategy = f"Pivot from {norm_val} to node label {target_type}"
                cypher = f'MATCH (n {{value: "{norm_val}"}})-[r]-(m:{target_type}) RETURN n, r, m LIMIT 50'

        # Rule 8: Multi-hop queries
        if not cypher:
            match_multihop = re.match(r"(?:find|show|get)\s+paths\s+of\s+(\d+)\s+hops\s+from\s+['\"]?([^'\"]+)['\"]?$", query)
            if match_multihop:
                hops = int(match_multihop.group(1))
                val = match_multihop.group(2)
                norm_val, norm_type = self.normalize_value(val)
                normalized_inputs[val] = {"value": norm_val, "type": norm_type}
                strategy = f"Find paths of up to {hops} hops from {norm_val}"
                cypher = f'MATCH p = (n {{value: "{norm_val}"}})-[*..{hops}]-(m) RETURN p LIMIT 50'

        # Rule 9: Find path between two values up to H hops
        if not cypher:
            match_path_hops = re.match(r"(?:find\s+)?path\s+(?:between\s+)?['\"]?([^'\"]+)['\"]?\s+and\s+['\"]?([^'\"]+)['\"]?\s+up\s+to\s+(\d+)\s+hops$", query)
            if match_path_hops:
                val1 = match_path_hops.group(1)
                val2 = match_path_hops.group(2)
                hops = int(match_path_hops.group(3))
                norm_val1, norm_type1 = self.normalize_value(val1)
                norm_val2, norm_type2 = self.normalize_value(val2)
                normalized_inputs[val1] = {"value": norm_val1, "type": norm_type1}
                normalized_inputs[val2] = {"value": norm_val2, "type": norm_type2}
                strategy = f"Find shortest path up to {hops} hops between {norm_val1} and {norm_val2}"
                cypher = 'MATCH p = shortestPath((a {value: "%s"})-[*..%d]-(b {value: "%s"})) RETURN p' % (norm_val1, hops, norm_val2)

        # Rule 10: Find path between two values (default 5 hops)
        if not cypher:
            match_path = re.match(r"(?:find\s+)?path\s+(?:between\s+)?['\"]?([^'\"]+)['\"]?\s+and\s+['\"]?([^'\"]+)['\"]?$", query)
            if match_path:
                val1 = match_path.group(1)
                val2 = match_path.group(2)
                norm_val1, norm_type1 = self.normalize_value(val1)
                norm_val2, norm_type2 = self.normalize_value(val2)
                normalized_inputs[val1] = {"value": norm_val1, "type": norm_type1}
                normalized_inputs[val2] = {"value": norm_val2, "type": norm_type2}
                strategy = f"Find shortest path up to 5 hops between {norm_val1} and {norm_val2}"
                cypher = 'MATCH p = shortestPath((a {value: "%s"})-[*..5]-(b {value: "%s"})) RETURN p' % (norm_val1, norm_val2)

        # Rule 11: Find everything connected to a value
        if not cypher:
            match_conn = re.match(r"(?:find|show|get)\s+(?:connections to|connected to|about)\s+['\"]?([^'\"]+)['\"]?", query)
            if match_conn:
                val = match_conn.group(1)
                norm_val, norm_type = self.normalize_value(val)
                normalized_inputs[val] = {"value": norm_val, "type": norm_type}
                strategy = f"Find adjacent connections for {norm_val}"
                cypher = f'MATCH (n {{value: "{norm_val}"}})-[r]-(m) RETURN n, r, m LIMIT 50'

        # Rule 12: Find nodes of a specific type
        if not cypher:
            match_type = re.match(r"(?:list|show)\s+(?:all\s+)?(\w+?)s?$", query)
            if match_type:
                label = match_type.group(1).capitalize()
                strategy = f"List all nodes of label {label}"
                cypher = f'MATCH (n:{label}) RETURN n LIMIT 50'

        # Default fallback
        if not cypher:
            search_term = natural_language.replace("'", "\\'").replace('"', '\\"')
            norm_term, norm_type = self.normalize_value(search_term)
            normalized_inputs[search_term] = {"value": norm_term, "type": norm_type}
            strategy = f"Fallback substring matching on {norm_term}"
            cypher = f'MATCH (n) WHERE n.value CONTAINS "{norm_term}" OR labels(n)[0] CONTAINS "{search_term}" RETURN n LIMIT 50'

        # Emit Query Plan for auditability
        query_plan = {
            "query_intent": natural_language,
            "normalization": normalized_inputs,
            "strategy": strategy,
            "execution_cypher": cypher,
            "timestamp": time.time()
        }
        print("\n=== NORN AUDITABLE QUERY PLAN ===")
        print(json.dumps(query_plan, indent=2))
        print("=================================\n")

        return cypher

