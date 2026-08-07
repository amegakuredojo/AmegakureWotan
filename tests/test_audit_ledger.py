import pytest
import json
from pathlib import Path
from amegakurewotan.evidence.audit import ForensicAuditLedger
from amegakurewotan.config import get_config

@pytest.fixture(autouse=True)
def mock_config_base_dir(tmp_path, monkeypatch):
    config = get_config()
    monkeypatch.setattr(config, "base_dir", tmp_path)
    config.init_dirs()
    # Mock GraphDB check_connection to False to isolate tests from the live database
    from amegakurewotan.graph.db import get_db
    db = get_db()
    monkeypatch.setattr(db, "check_connection", lambda: False)

def test_tamper_detection():
    """Si se modifica cualquier byte del ledger, verify_ledger_integrity() debe retornar False."""
    ledger = ForensicAuditLedger()
    # Log an execution entry
    ledger.log_execution("test_agent", "test_action", {"param": "value"}, ["finding1"], ["ev1.txt"])
    
    # Verify initial integrity is OK
    assert ledger.verify_ledger_integrity() == True, "Initial ledger integrity failed!"
    
    # Tamper directly the file
    content = ledger.ledger_path.read_text()
    tampered = content.replace('"agent": "test_agent"', '"agent": "TAMPERED"')
    ledger.ledger_path.write_text(tampered)
    
    assert ledger.verify_ledger_integrity() == False, \
        "Tamper detection FAILED — ledger accepted modified record!"

def test_hmac_verification():
    """Verify that ledger entries are signed with HMAC and validation detects wrong signature."""
    ledger = ForensicAuditLedger()
    # Log execution
    ledger.log_execution("test_agent_2", "action_2", {}, [], [])
    
    # Read the entries
    entries = []
    with open(ledger.ledger_path, "r") as f:
        for line in f:
            if line.strip():
                entries.append(json.loads(line))
                
    assert len(entries) > 0
    last_entry = entries[-1]
    assert "signature" in last_entry
    
    # Tamper signature only
    last_entry["signature"] = "0" * 64
    
    # Write tampered entries back
    with open(ledger.ledger_path, "w") as f:
        for entry in entries[:-1]:
            f.write(json.dumps(entry) + "\n")
        f.write(json.dumps(last_entry) + "\n")
        
    assert ledger.verify_ledger_integrity() == False, "HMAC verification failed to detect invalid signature!"
