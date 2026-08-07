import logging
import json
import uuid
import time
from typing import Any, Dict
from pydantic import BaseModel, Field, field_validator
from amegakurewotan.graph.db import get_db
from amegakurewotan.agents.skadi import SkadiAgent

logger = logging.getLogger("amegakurewotan.graph.provenance")

class ProvenancePayload(BaseModel):
    run_id: str = Field(..., description="Unique ID for the activity/run")
    source_uri: str = Field(..., description="URI or identity of the source tool/script")
    agent_name: str = Field(..., description="Name of the agent executing this")
    tool_name: str = Field("amegakurewotan-cli", description="Name of the tool")
    tool_version: str = Field("1.0", description="Version of the tool used")
    entity_type: str = Field(..., description="Type of the primary entity")
    seed_canonical: str = Field(..., description="Canonical seed of the entity")
    confidence: float = Field(0.0, description="Confidence score or HES")
    classification: str = Field("UNCLASSIFIED", description="Classification level")
    provenance_level: str = Field("RAW", description="Level of provenance")
    review_state: str = Field("PENDING", description="Review state")
    hypothesis_status: str = Field("HYPOTHESIS", description="Status of the generated hypothesis")
    raw_data: Dict[str, Any] = Field(..., description="Raw execution data")

    @field_validator('run_id', 'source_uri', 'entity_type')
    def must_not_be_empty(cls, v):
        if not v or not v.strip():
            raise ValueError("Field cannot be empty")
        return v

class ProvenanceRouter:
    """
    Enforces the ingestion contract for AmegakureWotan graphs.
    No agent writes directly to Kùzu without passing through this router.
    """
    def __init__(self):
        self.db = get_db()

    def route(self, payload: Dict[str, Any]) -> str:
        """
        Validates payload, hashes raw evidence via Skadi, and commits W3C PROV graph to Kùzu.
        Returns the run_id of the committed graph.
        """
        # 1. Validation (Pydantic will raise exceptions if invalid)
        prov_data = ProvenancePayload(**payload)
        
        # 2. RawEvidence -> EvidenceHash (Skadi)
        skadi = SkadiAgent()
        raw_json = json.dumps(prov_data.raw_data, indent=2).encode('utf-8')
        
        import tempfile
        import os
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(raw_json)
            tmp_path = tmp.name
            
        skadi_res = skadi.execute(raw_json, tmp_path)
        os.unlink(tmp_path)
        evidence_hash = skadi_res.get("sha512")
        
        # 3. Decision Matrix (Doctrina Humana vs Custodia)
        decision = "REVIEW_REQUIRED"
        if prov_data.confidence >= 94.0:
            decision = "ACTIONABLE"
        elif prov_data.confidence < 85.0:
            decision = "HYPOTHESIS"
            
        base_props = {
            "run_id": prov_data.run_id,
            "schema_version": "PROV-1.0",
            "created_at": time.time(),
            "source_uri": prov_data.source_uri,
            "tool_name": prov_data.tool_name,
            "tool_version": prov_data.tool_version,
            "confidence": prov_data.confidence,
            "classification": prov_data.classification,
            "hash_sha512": evidence_hash,
            "provenance_level": prov_data.provenance_level,
            "entity_type": prov_data.entity_type,
            "review_state": prov_data.review_state
        }

        operations = []
        def gen_uuid(): return str(uuid.uuid4())
        h_uuid = gen_uuid()
        
        # Agent Node
        cypher_agent = """
        MERGE (ag:Agent {name: $name})
        SET ag += $base_props, ag.uuid = coalesce(ag.uuid, $ag_uuid)
        """
        operations.append((cypher_agent, {
            "name": prov_data.agent_name,
            "base_props": base_props,
            "ag_uuid": gen_uuid()
        }))
        
        # Activity Node
        cypher_activity = """
        MERGE (act:Activity {run_id: $run_id})
        SET act += $base_props, act.uuid = coalesce(act.uuid, $act_uuid)
        WITH act
        MATCH (ag:Agent {name: $agent_name})
        MERGE (ag)-[r:WAS_ASSOCIATED_WITH]->(act)
        SET r += $base_props, r.uuid = coalesce(r.uuid, $r_uuid)
        """
        operations.append((cypher_activity, {
            "run_id": prov_data.run_id,
            "agent_name": prov_data.agent_name,
            "base_props": base_props,
            "act_uuid": gen_uuid(),
            "r_uuid": gen_uuid()
        }))
        
        # Entity Node (Seed)
        cypher_entity = """
        MERGE (e:Entity {value: $seed})
        SET e += $base_props, e.uuid = coalesce(e.uuid, $e_uuid)
        WITH e
        MATCH (act:Activity {run_id: $run_id})
        MERGE (act)-[r:USED]->(e)
        SET r += $base_props, r.uuid = coalesce(r.uuid, $r_uuid)
        """
        operations.append((cypher_entity, {
            "seed": prov_data.seed_canonical,
            "run_id": prov_data.run_id,
            "base_props": base_props,
            "e_uuid": gen_uuid(),
            "r_uuid": gen_uuid()
        }))
        
        # Evidence Node
        cypher_evidence = """
        MERGE (ev:Evidence:Entity {hash_sha512: $hash})
        SET ev += $base_props, ev.uuid = coalesce(ev.uuid, $ev_uuid), ev.provenance_level = "RAW"
        WITH ev
        MATCH (act:Activity {run_id: $run_id})
        MERGE (act)-[r1:WAS_GENERATED_BY]->(ev)
        SET r1 += $base_props, r1.uuid = coalesce(r1.uuid, $r1_uuid)
        MERGE (act)-[r2:ATTESTED_BY]->(ev)
        SET r2 += $base_props, r2.uuid = coalesce(r2.uuid, $r2_uuid)
        """
        operations.append((cypher_evidence, {
            "hash": evidence_hash,
            "run_id": prov_data.run_id,
            "base_props": base_props,
            "ev_uuid": gen_uuid(),
            "r1_uuid": gen_uuid(),
            "r2_uuid": gen_uuid()
        }))
        
        # Hypothesis Node
        cypher_hypo = """
        MERGE (h:Hypothesis:Entity {uuid: $h_uuid})
        SET h += $base_props, h.status = $status
        WITH h
        MATCH (ev:Evidence {hash_sha512: $ev_hash})
        MATCH (e:Entity {value: $seed})
        MATCH (act:Activity {run_id: $run_id})
        MATCH (ag:Agent {name: $agent_name})
        MERGE (ev)-[r1:SUPPORTS]->(h)
        SET r1 += $base_props, r1.uuid = coalesce(r1.uuid, $r1_uuid)
        MERGE (h)-[r2:WAS_DERIVED_FROM]->(e)
        SET r2 += $base_props, r2.uuid = coalesce(r2.uuid, $r2_uuid)
        MERGE (h)-[r3:SIGNED_BY]->(ag)
        SET r3 += $base_props, r3.uuid = coalesce(r3.uuid, $r3_uuid)
        MERGE (h)-[r4:WAS_GENERATED_BY]->(act)
        SET r4 += $base_props, r4.uuid = coalesce(r4.uuid, $r4_uuid)
        """
        operations.append((cypher_hypo, {
            "h_uuid": h_uuid,
            "status": decision,
            "ev_hash": evidence_hash,
            "seed": prov_data.seed_canonical,
            "run_id": prov_data.run_id,
            "agent_name": prov_data.agent_name,
            "base_props": base_props,
            "r1_uuid": gen_uuid(),
            "r2_uuid": gen_uuid(),
            "r3_uuid": gen_uuid(),
            "r4_uuid": gen_uuid()
        }))

        # Review Node
        cypher_review = """
        MATCH (h:Hypothesis {uuid: $h_uuid})
        MERGE (rev:Review:Activity {uuid: $rev_uuid})
        SET rev += $base_props, rev.review_state = $status
        MERGE (h)-[r1:REVIEWED_BY]->(rev)
        SET r1 += $base_props, r1.uuid = coalesce(r1.uuid, $r1_uuid)
        """
        operations.append((cypher_review, {
            "h_uuid": h_uuid,
            "status": decision,
            "base_props": base_props,
            "rev_uuid": gen_uuid(),
            "r1_uuid": gen_uuid()
        }))

        # Decision Node if applicable
        if decision == "ACTIONABLE":
            cypher_decision = """
            MATCH (h:Hypothesis {uuid: $h_uuid})
            MERGE (dec:Decision:Activity {uuid: $dec_uuid})
            SET dec += $base_props, dec.status = $status
            MERGE (h)-[r1:PROMOTED_TO]->(dec)
            SET r1 += $base_props, r1.uuid = coalesce(r1.uuid, $r1_uuid)
            """
            operations.append((cypher_decision, {
                "h_uuid": h_uuid,
                "status": decision,
                "base_props": base_props,
                "dec_uuid": gen_uuid(),
                "r1_uuid": gen_uuid()
            }))
        
        # Execute Transaction
        if self.db.check_connection():
            self.db.execute_transaction(operations)
            logger.info(f"ProvenanceRouter successfully committed run_id {prov_data.run_id} to graph.")
        else:
            logger.warning("GraphDB is offline. Provenance payload was evaluated but not committed.")
            
        return prov_data.run_id
