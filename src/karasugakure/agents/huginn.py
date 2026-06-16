import json
import logging
import time
from typing import Any, Dict, List
from karasugakure.agents import BaseAgent
from karasugakure.policy.opsec import enforce_opsec_policy, run_isolated_process
from karasugakure.config import get_config
from karasugakure.agents.loki import LokiAgent
from karasugakure.agents.heimdall import HeimdallAgent
from karasugakure.agents.skadi import SkadiAgent
from karasugakure.agents.normalizer import EntitySeedNormalizer, SeedExpander
from karasugakure.graph.provenance import ProvenanceRouter
import uuid

logger = logging.getLogger("karasugakure.agents.huginn")

class HuginnAgent(BaseAgent):
    def __init__(self):
        super().__init__("Huginn", "Human-Centric & Legal Entity Intelligence (Domain 7)")

    def calculate_hes(self, iv: int, ct: int, ce: int, er: int, et: int, ed: int, entity_type: str) -> float:
        """
        Calculate Human Exposure Score (HES). GAP 4: Calibrated for physical vs juridical.
        """
        is_legal = "jurídica" in entity_type.lower()
        if is_legal:
            # GAP 4: Higher weights for domain, footprint, relational; lower for visible/credentials
            w_iv, w_ct, w_ce, w_er, w_et, w_ed = 0.5, 1.5, 0.5, 1.5, 1.0, 2.0
            total_weight = sum([w_iv, w_ct, w_ce, w_er, w_et, w_ed])
            weighted_sum = (iv * w_iv) + (ct * w_ct) + (ce * w_ce) + (er * w_er) + (et * w_et) + (ed * w_ed)
            return weighted_sum / total_weight
        else:
            return (iv + ct + ce + er + et + ed) / 6.0

    def evaluate_certainty(self, certainty: float) -> str:
        """
        Evaluate if the finding meets the certainty threshold for Domain 7.
        """
        if certainty >= 94.0:
            return "ACTIONABLE"
        elif certainty >= 85.0:
            return "HUMAN_REVIEW_REQUIRED"
        else:
            return "HYPOTHESIS"

    def execute(self, target: str, entity_type: str = "Persona física", **kwargs) -> Dict[str, Any]:
        """
        Runs DOMINIO 7 Identity & Entity Intelligence scanning.
        """
        config = get_config()
        enforce_opsec_policy("huginn", config)

        def analyze_entity():
            logger.info(f"Huginn parsing seed: {target}")
            # GAP 1: Normalization
            normalized_seed = EntitySeedNormalizer.normalize(target)
            # GAP 5: Expansion
            expanded_seeds = SeedExpander.expand(normalized_seed)
            
            final_type = entity_type if entity_type != "Persona física" else normalized_seed.entity_type
            is_physical = "física" in final_type.lower() or "mixto" in final_type.lower()
            is_legal = "jurídica" in final_type.lower() or "mixto" in final_type.lower()
            
            logger.info(f"Huginn starting deep analysis. Canonical: {normalized_seed.canonical} ({final_type})")
            
            raw_evidence = {"target": normalized_seed.canonical, "type": final_type, "timestamp": time.time(), "scans": {}}
            iv, ct, ce, er, et, ed = 0, 0, 0, 0, 0, 0
            certainty = 50.0
            
            profiles_found = []
            emails_found = []
            domains_found = []
            
            # GAP 5: Retry loop over expanded seeds
            for current_seed in expanded_seeds:
                logger.info(f"Huginn testing expanded seed: {current_seed}")
                
                if is_physical and not (profiles_found or emails_found):
                    try:
                        loki = LokiAgent()
                        loki_res = loki.execute(current_seed)
                        raw_evidence["scans"][f"loki_{current_seed}"] = loki_res
                        profiles_found.extend(loki_res.get("profiles", []))
                        emails_found.extend(loki_res.get("emails", []))
                    except Exception as e:
                        logger.error(f"Huginn: Loki execution failed on {current_seed} - {e}")
                
                if is_legal and not domains_found:
                    try:
                        heimdall = HeimdallAgent()
                        heim_res = heimdall.execute(current_seed)
                        raw_evidence["scans"][f"heimdall_{current_seed}"] = heim_res
                        domains_found.extend(heim_res.get("subdomains", []))
                    except Exception as e:
                        logger.error(f"Huginn: Heimdall execution failed on {current_seed} - {e}")
                        
                # Break early if we found enough data to stop retrying seeds
                if (is_physical and profiles_found) and (not is_legal or domains_found):
                    break
                if (is_legal and domains_found) and (not is_physical or profiles_found):
                    break
                    
            # Compute IV (Identidad Visible) and CE (Credenciales Expuestas)
            iv = min(100, len(profiles_found) * 25 + (len(domains_found) * 10 if is_legal else 0))
            ce = min(100, len(emails_found) * 35)
            # Compute ER (Exposición Relacional) and ED (Exposición Documental)
            er = min(100, (len(profiles_found) + len(emails_found) + len(domains_found)) * 15)
            ed = min(100, len(domains_found) * 15 + (10 if is_legal else 0))
            
            if profiles_found: certainty += 15.0
            if emails_found: certainty += 20.0
            if domains_found: certainty += 20.0
            if len(domains_found) > 5: certainty += 10.0

            # GAP 3: Base CT with coverage protection
            # CT should measure real correlation + base source coverage
            sources_hit = len(raw_evidence["scans"].keys())
            base_ct = min(40, sources_hit * 10) # 10 points per source successfully invoked
            ct_additive = 0
            
            if (profiles_found and emails_found) or (domains_found and emails_found):
                ct_additive += 40
                certainty += 10.0
            elif is_physical and is_legal and profiles_found and domains_found:
                ct_additive += 50
                certainty += 15.0
                
            ct = min(100, base_ct + ct_additive)
                
            et = min(100, (len(profiles_found) + len(domains_found) + len(emails_found)) * 10)
            certainty = min(100.0, certainty)
            
            # GAP 4: Calibrated HES
            hes_score = self.calculate_hes(iv, ct, ce, er, et, ed, final_type)
            status = self.evaluate_certainty(certainty)

            status = self.evaluate_certainty(certainty)

            # Hypothesis generation
            hypothesis = {
                "title": f"Correlación de Identidad/Entidad: {normalized_seed.canonical}",
                "domain": "DOMINIO 7",
                "entity_type": final_type,
                "context": f"Target {normalized_seed.canonical} (original: {target}) presenta {len(profiles_found)} perfiles, {len(emails_found)} correos, y {len(domains_found)} dominios corporativos vinculados tras expansión de semillas.",
                "vulnerability": "identity linkage, corporate footprint exposure" if ct > 50 else "surface exposure",
                "hes_score": hes_score,
                "certainty": certainty,
                "priority": "Critica" if hes_score >= 75 else "Alta" if hes_score >= 50 else "Media",
                "status": status,
                "validation_steps": [
                    "1. Fuente primaria: Extracción OSINT pasiva (Heimdall/Loki)",
                    "2. Fuente secundaria: Análisis de alias y subdominios cruzados",
                    "3. Validación cruzada: Grafo relacional",
                    "4. Criterio observable: Presencia simultánea en múltiples plataformas",
                    "5. Umbral de certeza requerido: > 94%"
                ]
            }

            # GAP 2 (Capa 2): ProvenanceRouter Contract
            prov_payload = {
                "run_id": str(uuid.uuid4()),
                "source_uri": "karasugakure://agents/huginn/execute",
                "agent_name": "huginn",
                "tool_version": "2.1",
                "entity_type": final_type,
                "seed_canonical": normalized_seed.canonical,
                "confidence": certainty,
                "hypothesis_status": "HYPOTHESIS", # Overridden by router logic based on confidence
                "raw_data": raw_evidence
            }

            router = ProvenanceRouter()
            committed_run_id = router.route(prov_payload)

            return {
                "target": normalized_seed.canonical,
                "entity_type": final_type,
                "hes": hes_score,
                "certainty": certainty,
                "status": status,
                "hypothesis": hypothesis,
                "metrics": {"IV": iv, "CT": ct, "CE": ce, "ER": er, "ET": et, "ED": ed},
                "run_id": committed_run_id,
                "source": "huginn"
            }

        return run_isolated_process(analyze_entity)
