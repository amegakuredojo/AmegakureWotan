from typing import Any, Dict, List, Tuple
from amegakurewotan.agents import BaseAgent

class TyrAgent(BaseAgent):
    def __init__(self):
        super().__init__("Tyr", "Intelligence validation and reliability scoring")
        self.reliability_map = {"A": 1.0, "B": 0.8, "C": 0.6, "D": 0.4, "E": 0.2, "F": 0.0}
        self.credibility_map = {"1": 1.0, "2": 0.8, "3": 0.6, "4": 0.4, "5": 0.2, "6": 0.0}

    def validate_finding(
        self,
        value: str,
        sources: List[Dict[str, Any]],
        strict_threshold: float = 0.60,
        entity_type: str = "Default"
    ) -> Dict[str, Any]:
        """
        Adversarial validation with consensus, freshness, floors, and thresholds.
        `sources` is a list of dicts: [{"agent": "heimdall", "reliability": "B", "credibility": "2", "timestamp": 1234567890}]
        """
        import time
        import re

        if not sources:
            return {
                "value": value,
                "confidence": 0.0,
                "is_trusted": False,
                "status": "tentative",
                "reason": "No sources reporting this entity.",
                "decomposition": {}
            }

        # Source class confidence floors
        floors = {
            "heimdall": 0.60,
            "loki": 0.50,
            "hel": 0.40,
            "operator": 0.70
        }

        # Domain-specific/entity-specific thresholds
        entity_thresholds = {
            "Domain": 0.60,
            "Email": 0.50,
            "IP": 0.60,
            "Profile": 0.50,
            "Alias": 0.50,
            "Default": 0.60
        }

        # Detect entity type if default
        if entity_type == "Default" or not entity_type:
            val_clean = value.strip()
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", val_clean):
                entity_type = "IP"
            elif "@" in val_clean:
                entity_type = "Email"
            elif val_clean.endswith(".onion") or ("." in val_clean and not val_clean.endswith(".")):
                entity_type = "Domain"
            elif val_clean.startswith("http"):
                entity_type = "Profile"
            else:
                entity_type = "Alias"

        target_threshold = entity_thresholds.get(entity_type, entity_thresholds["Default"])

        scores = []
        unique_agents = set()
        freshness_decays = []

        for src in sources:
            agent = src.get("agent", "unknown").lower()
            rel = src.get("reliability", "F").upper()
            cred = str(src.get("credibility", "6"))
            unique_agents.add(agent)
            
            r_score = self.reliability_map.get(rel, 0.0)
            c_score = self.credibility_map.get(cred, 0.0)
            score = (r_score + c_score) / 2.0
            
            # Apply freshness weighting
            src_time = src.get("timestamp", time.time())
            age = max(0.0, time.time() - src_time)
            if age < 60.0:
                decay = 1.0
                days = age / 86400.0
            else:
                # decay: lose 5% confidence per day, cap at 40% decay (min multiplier 0.60)
                days = age / 86400.0
                decay = max(0.60, 1.0 - (0.05 * days))
            freshness_decays.append({"agent": agent, "days_old": days, "decay_multiplier": decay})
            score = score * decay


            # Reject immediately if below source class floor
            floor = floors.get(agent, 0.50)
            if score < floor:
                return {
                    "value": value,
                    "confidence": score,
                    "is_trusted": False,
                    "status": "tentative",
                    "reason": f"CRITICAL VALIDATION FAILURE: Source class '{agent}' score {score:.2f} (with freshness decay) fell below confidence floor threshold of {floor:.2f}.",
                    "num_sources": len(sources),
                    "conflicting": False,
                    "decomposition": {
                        "failed_agent": agent,
                        "score": score,
                        "floor": floor
                    }
                }
            
            scores.append(score)
            
        base_confidence = sum(scores) / len(scores)
        
        # Consensus boost: +10% confidence for each additional corroborating agent source
        num_sources = len(unique_agents)
        boost = 0.10 * (num_sources - 1)
        final_confidence = base_confidence + boost
        
        # Conflict detection & contradiction penalty
        conflicting = False
        contradiction_penalty = 0.0
        if len(scores) > 1:
            max_score = max(scores)
            min_score = min(scores)
            if max_score - min_score >= 0.5:
                conflicting = True
                contradiction_penalty = 0.30
                final_confidence -= contradiction_penalty

        final_confidence = max(0.0, min(final_confidence, 1.0))
        
        # Trust check: meets strict domain/entity threshold
        is_trusted = final_confidence >= target_threshold and num_sources >= 1 and not conflicting
        
        status = "trusted" if is_trusted else "tentative"
        reason = "Passed threshold check."
        if conflicting:
            status = "escalated"
            reason = "Blocked and escalated to operator decision due to adversarial source conflict (deviation >= 0.5)."
        elif final_confidence < target_threshold:
            reason = f"Confidence {final_confidence:.2f} is below domain-specific threshold of {target_threshold} for type {entity_type}."

        decomposition = {
            "base_confidence": base_confidence,
            "consensus_boost": boost,
            "freshness_decays": freshness_decays,
            "contradiction_penalty": contradiction_penalty,
            "final_confidence": final_confidence,
            "target_threshold": target_threshold,
            "entity_type": entity_type
        }

        return {
            "value": value,
            "confidence": final_confidence,
            "is_trusted": is_trusted,
            "status": status,
            "reason": reason,
            "num_sources": num_sources,
            "conflicting": conflicting,
            "decomposition": decomposition
        }

    def execute(self, action: str, **kwargs) -> Dict[str, Any]:
        """
        Executes validation on incoming intelligence nodes/relationships.
        """
        import time
        if action == "validate":
            # Support legacy caller by packing single source
            rel = kwargs.get("reliability", "C")
            cred = kwargs.get("credibility", "3")
            source_agent = kwargs.get("source", "unknown")
            value = kwargs.get("value", "")
            entity_type = kwargs.get("entity_type", "Default")
            
            sources = [{"agent": source_agent, "reliability": rel, "credibility": cred, "timestamp": time.time()}]
            res = self.validate_finding(value, sources, entity_type=entity_type)
            res["nato_rating"] = f"{rel.upper()}{cred}"
            return res
            
        elif action == "validate_consensus":
            value = kwargs.get("value", "")
            sources = kwargs.get("sources", [])
            strict_threshold = kwargs.get("strict_threshold", 0.60)
            entity_type = kwargs.get("entity_type", "Default")
            return self.validate_finding(value, sources, strict_threshold, entity_type=entity_type)
            
        else:
            raise ValueError(f"Unknown Tyr action: {action}")

