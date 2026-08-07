from typing import Any, Dict, List
from amegakurewotan.agents import BaseAgent

class FenrirAgent(BaseAgent):
    def __init__(self):
        super().__init__("Fenrir", "Relational correlation and link analysis")

    def execute(self, graph_data: Dict[str, Any], **kwargs) -> List[Dict[str, Any]]:
        """
        Analyzes graph nodes and relationships to find matching identifiers,
        potential identities sharing emails, IPs or domains, and outputs suggested correlations.
        Supports temporal correlation, multi-hop traversals, ranking, loop prevention,
        and reproducible cluster subgraph exporting.
        """
        import time
        import os
        import json
        from pathlib import Path
        from amegakurewotan.config import get_config

        session_id = kwargs.get("session_id", "default")
        correlations = []
        nodes = graph_data.get("nodes", [])
        edges = graph_data.get("edges", [])

        # Build mapping of node values to their properties and labels
        node_properties = {}
        node_labels = {}
        for node in nodes:
            props = node.get("properties", {})
            val = props.get("value")
            if val:
                node_properties[val] = props
                node_labels[val] = node.get("labels", ["Entity"])

        # Build set of existing relationships to prevent duplicates and cycles
        existing_relations = set()
        for edge in edges:
            src = edge.get("source_value")
            tgt = edge.get("target_value")
            rel = edge.get("relationship")
            if src and tgt and rel:
                existing_relations.add((src, tgt, rel))
                existing_relations.add((tgt, src, rel))

        # Build adjacency maps for multi-hop search:
        # map value -> list of (neighbor_value, edge_properties, rel_type)
        adj = {}
        for edge in edges:
            src = edge.get("source_value")
            tgt = edge.get("target_value")
            rel = edge.get("relationship")
            if src and tgt and rel:
                # Exclude CORRELATED_WITH to prevent cycle propagation
                if rel == "CORRELATED_WITH":
                    continue
                if src not in adj:
                    adj[src] = []
                if tgt not in adj:
                    adj[tgt] = []
                props = edge.get("properties", {})
                adj[src].append((tgt, props, rel))
                adj[tgt].append((src, props, rel))

        # 1. Temporal correlation between events and node creation windows
        # Pairwise compare all nodes. If created_at is within 5 minutes (300,000 ms), and they share
        # at least one common neighbor or same source class, they are temporally correlated.
        for i in range(len(nodes)):
            for j in range(i + 1, len(nodes)):
                n1 = nodes[i]
                n2 = nodes[j]
                val1 = n1.get("properties", {}).get("value")
                val2 = n2.get("properties", {}).get("value")
                if not val1 or not val2 or val1 == val2:
                    continue
                
                t1 = n1.get("properties", {}).get("created_at")
                t2 = n2.get("properties", {}).get("created_at")
                if t1 and t2:
                    delta_ms = abs(t1 - t2)
                    if delta_ms <= 300000: # 5 minutes
                        # Check context: common neighbor
                        n1_neighbors = set(x[0] for x in adj.get(val1, []))
                        n2_neighbors = set(x[0] for x in adj.get(val2, []))
                        shared = n1_neighbors.intersection(n2_neighbors)
                        
                        src1 = n1.get("properties", {}).get("source", "")
                        src2 = n2.get("properties", {}).get("source", "")
                        
                        if shared or (src1 and src2 and src1 == src2):
                            if (val1, val2, "TEMPORALLY_CORRELATED") not in existing_relations and \
                               (val2, val1, "TEMPORALLY_CORRELATED") not in existing_relations:
                                type1 = node_labels.get(val1, ["Entity"])[0]
                                type2 = node_labels.get(val2, ["Entity"])[0]
                                delta_s = delta_ms / 1000.0
                                correlations.append({
                                    "from_value": val1,
                                    "from_type": type1,
                                    "to_value": val2,
                                    "to_type": type2,
                                    "rel_type": "TEMPORALLY_CORRELATED",
                                    "description": f"Temporal correlation window alignment (delta: {delta_s:.1f}s)",
                                    "confidence": 0.70,
                                    "lineage": [val1, val2],
                                    "sources": list(filter(None, set([src1, src2])))
                                })

        # 2. Multi-hop identity correlation across alias, email, domain, profile, and infra
        # Find paths of length 2 or 3 between identity nodes (Alias, Email, Profile) and infra nodes (Domain, IP)
        identity_infra_labels = {"Alias", "Email", "Profile", "Domain", "IP"}
        
        # We perform BFS up to depth 3 from each node
        for start_val in node_properties:
            start_labels = set(node_labels.get(start_val, []))
            if not start_labels.intersection(identity_infra_labels):
                continue
            
            # BFS queue stores: (current_node, path_of_edges)
            # path_of_edges is a list of tuples: (src, dest, edge_props, rel_type)
            queue = [(start_val, [])]
            visited = {start_val}
            
            while queue:
                curr_val, path = queue.pop(0)
                
                # Check path hops
                if len(path) > 3:
                    continue
                
                # If path length is 2 or 3, check correlation candidate
                if 2 <= len(path) <= 3:
                    curr_labels = set(node_labels.get(curr_val, []))
                    if curr_labels.intersection(identity_infra_labels):
                        # Ensure no direct edge already exists
                        if (start_val, curr_val, "CORRELATED_WITH") not in existing_relations and \
                           (curr_val, start_val, "CORRELATED_WITH") not in existing_relations:
                            
                            # Construct Lineage & sources
                            lineage = [start_val]
                            sources_collected = set()
                            for step_src, step_dst, step_props, step_rel in path:
                                lineage.append(step_dst)
                                src_val = step_props.get("source")
                                if src_val:
                                    # Split multi-sources if nested
                                    for s in src_val.split(","):
                                        sources_collected.add(s.strip())
                                        
                            # Base confidence by hops
                            base_confidence = 0.75 if len(path) == 2 else 0.65
                            # Source overlap boost
                            overlap_count = len(sources_collected)
                            boost = 0.05 * max(0, overlap_count - 1)
                            confidence = min(0.95, base_confidence + boost)
                            
                            type1 = node_labels.get(start_val, ["Entity"])[0]
                            type2 = node_labels.get(curr_val, ["Entity"])[0]
                            
                            path_str = " -> ".join(lineage)
                            correlations.append({
                                "from_value": start_val,
                                "from_type": type1,
                                "to_value": curr_val,
                                "to_type": type2,
                                "rel_type": "CORRELATED_WITH",
                                "description": f"Multi-hop identity path: {path_str}",
                                "confidence": confidence,
                                "lineage": lineage,
                                "sources": list(sources_collected)
                            })
                            
                for neighbor, edge_props, rel_type in adj.get(curr_val, []):
                    if neighbor not in visited:
                        visited.add(neighbor)
                        queue.append((neighbor, path + [(curr_val, neighbor, edge_props, rel_type)]))

        # 3. Rule 3: Subdomain Suffix Pattern Matching (from original)
        domain_nodes = [n for n in nodes if "Domain" in n.get("labels", [])]
        for i in range(len(domain_nodes)):
            for j in range(len(domain_nodes)):
                if i != j:
                    val1 = domain_nodes[i].get("properties", {}).get("value", "")
                    val2 = domain_nodes[j].get("properties", {}).get("value", "")
                    if val1 and val2 and val1.endswith("." + val2):
                        if (val2, val1, "HAS_SUBDOMAIN") not in existing_relations and \
                           (val2, val1, "CORRELATED_WITH") not in existing_relations and \
                           (val1, val2, "CORRELATED_WITH") not in existing_relations:
                            correlations.append({
                                "from_value": val2,
                                "from_type": "Domain",
                                "to_value": val1,
                                "to_type": "Domain",
                                "rel_type": "HAS_SUBDOMAIN",
                                "description": "Subdomain suffix matching pattern",
                                "confidence": 0.95,
                                "lineage": [val2, val1],
                                "sources": ["fenrir"]
                            })

        # Deduplicate & rank candidates by confidence (and compute delta relative to 0.50 floor)
        seen = set()
        deduped = []
        for c in correlations:
            key = (c["from_value"], c["to_value"], c["rel_type"])
            rev_key = (c["to_value"], c["from_value"], c["rel_type"])
            if key not in seen and rev_key not in seen:
                seen.add(key)
                # confidence delta from baseline of 0.50
                c["confidence_delta"] = max(0.0, c["confidence"] - 0.50)
                deduped.append(c)

        # Sort candidate links by confidence descending
        deduped.sort(key=lambda x: x["confidence"], reverse=True)

        # Export correlation clusters as reproducible subgraphs
        # Find connected components of correlated nodes
        corr_adj = {}
        for c in deduped:
            v1 = c["from_value"]
            v2 = c["to_value"]
            if v1 not in corr_adj:
                corr_adj[v1] = []
            if v2 not in corr_adj:
                corr_adj[v2] = []
            corr_adj[v1].append(v2)
            corr_adj[v2].append(v1)

        visited_nodes = set()
        clusters = []

        for node_val in corr_adj:
            if node_val not in visited_nodes:
                # BFS to find component
                comp = []
                q = [node_val]
                visited_nodes.add(node_val)
                while q:
                    curr = q.pop(0)
                    comp.append(curr)
                    for neighbor in corr_adj.get(curr, []):
                        if neighbor not in visited_nodes:
                            visited_nodes.add(neighbor)
                            q.append(neighbor)
                
                if len(comp) > 1:
                    # Collect nodes & relationships for this cluster
                    cluster_nodes = []
                    for cv in comp:
                        cluster_nodes.append({
                            "value": cv,
                            "labels": node_labels.get(cv, ["Entity"]),
                            "properties": node_properties.get(cv, {})
                        })
                    cluster_edges = []
                    # Find all correlation edges matching this cluster
                    for c in deduped:
                        if c["from_value"] in comp and c["to_value"] in comp:
                            cluster_edges.append(c)
                    clusters.append({
                        "node_count": len(cluster_nodes),
                        "nodes": cluster_nodes,
                        "edges": cluster_edges
                    })

        # Write components to disk
        config = get_config()
        session_dir = config.base_dir / "sessions"
        session_dir.mkdir(parents=True, exist_ok=True)
        subgraph_filepath = session_dir / f"correlation_subgraph_{session_id}.json"
        
        export_payload = {
            "session_id": session_id,
            "timestamp": time.time(),
            "clusters": clusters
        }
        with open(subgraph_filepath, "w") as f:
            json.dump(export_payload, f, indent=2)
            
        print(f"[FENRIR] Exported reproducible correlation clusters (count: {len(clusters)}) to: {subgraph_filepath}")

        return deduped
