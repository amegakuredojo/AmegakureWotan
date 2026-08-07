import pytest
import time
from amegakurewotan.agents.tyr import TyrAgent

def test_tyr_floor_fail():
    """Verify source agent score below floor fails validation."""
    tyr = TyrAgent()
    
    # Heimdall reliability floor is 0.60. A B-2 rating has base score (0.8 + 0.8) / 2.0 = 0.8.
    # But if reliability is F (0.0) and credibility is 6 (0.0), score is 0.0, which is below 0.60 floor.
    sources = [{"agent": "heimdall", "reliability": "F", "credibility": "6", "timestamp": time.time()}]
    res = tyr.validate_finding("test_val", sources)
    
    assert res["is_trusted"] == False
    assert "CRITICAL VALIDATION FAILURE" in res["reason"]
    assert res["status"] == "tentative"

def test_tyr_consensus_boost():
    """Verify consensus boost (+10% for each additional corroborating agent)."""
    tyr = TyrAgent()
    
    # Heimdall and Loki both reporting the same finding.
    sources = [
        {"agent": "heimdall", "reliability": "B", "credibility": "2", "timestamp": time.time()},
        {"agent": "loki", "reliability": "B", "credibility": "2", "timestamp": time.time()}
    ]
    
    res = tyr.validate_finding("test_val", sources)
    # Base score for B-2 is (0.8 + 0.8)/2 = 0.8.
    # With 2 unique agents, consensus boost is +0.10. Total confidence = 0.90.
    assert res["decomposition"]["consensus_boost"] == pytest.approx(0.10)
    assert res["confidence"] == pytest.approx(0.90)
    assert res["is_trusted"] == True

def test_tyr_freshness_decay():
    """Verify score decay over time."""
    tyr = TyrAgent()
    
    # 10 days old source
    old_time = time.time() - (10 * 86400)
    sources = [{"agent": "heimdall", "reliability": "A", "credibility": "1", "timestamp": old_time}]
    
    res = tyr.validate_finding("test_val", sources)
    
    # A-1 base score is 1.0.
    # 10 days decay: 1.0 - (0.05 * 10) = 0.50.
    # Let's check multiplier
    multiplier = res["decomposition"]["freshness_decays"][0]["decay_multiplier"]
    assert multiplier == pytest.approx(0.60) # Capped at 0.60 minimum multiplier

def test_tyr_conflict_escalation():
    """Verify conflict detection when score deviation >= 0.5."""
    tyr = TyrAgent()
    
    # Heimdall reports very high confidence, Hel reports low confidence
    sources = [
        {"agent": "operator", "reliability": "A", "credibility": "1", "timestamp": time.time()}, # score = 1.0
        {"agent": "hel", "reliability": "D", "credibility": "4", "timestamp": time.time()} # score = 0.4
    ]
    
    res = tyr.validate_finding("conflict_val", sources, entity_type="Alias")
    # Deviation is 1.0 - 0.4 = 0.6 >= 0.5.
    # Should flag conflicting and status should be escalated.
    assert res["conflicting"] == True
    assert res["status"] == "escalated"
    assert "escalated to operator decision" in res["reason"]
