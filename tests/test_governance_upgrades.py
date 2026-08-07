import pytest
import os
import tempfile
from pathlib import Path
from amegakurewotan.config import get_config
from amegakurewotan.policy.state import FindingStateMachine, DualApprovalRegistry, StateTransitionError
from amegakurewotan.policy.interfaces import InterfaceFreezePolicy
from amegakurewotan.policy.adr import ADRRegistry
from amegakurewotan.policy.rollback import ReleaseTrainManager

@pytest.fixture(autouse=True)
def mock_config_base_dir(tmp_path, monkeypatch):
    config = get_config()
    monkeypatch.setattr(config, "base_dir", tmp_path)
    config.init_dirs()

def test_state_machine_transitions():
    """Verify that FindingStateMachine enforces strict valid transitions and rejects invalid ones."""
    fsm = FindingStateMachine()
    finding_id = "test_finding_123"

    # Start state is draft
    assert fsm.get_state(finding_id) == "draft"

    # Draft -> Triaged is valid
    fsm.transition_to(finding_id, "triaged", author_id="op1", reason="Triage completed")
    assert fsm.get_state(finding_id) == "triaged"

    # Triaged -> Reproduced is valid
    fsm.transition_to(finding_id, "reproduced", author_id="op1", reason="PoC reproduced")
    assert fsm.get_state(finding_id) == "reproduced"

    # Direct draft/reproduced -> promoted (skipping validated_5_5 and reviewed) is invalid
    with pytest.raises(StateTransitionError) as exc_info:
        fsm.transition_to(finding_id, "promoted", author_id="op1", reason="Direct promotion attempt")
    assert "Invalid state transition" in str(exc_info.value)


def test_dual_approval_for_critical_promotion():
    """Verify that critical findings require dual approvals before promotion to 'promoted'."""
    reg = DualApprovalRegistry()
    fsm = FindingStateMachine(dual_approval_registry=reg)
    finding_id = "critical_finding_001"

    # Move finding to reviewed state following the correct path
    fsm.transition_to(finding_id, "triaged", author_id="op1", reason="ok")
    fsm.transition_to(finding_id, "reproduced", author_id="op1", reason="ok")
    fsm.transition_to(finding_id, "validated_5_5", author_id="op1", reason="ok")
    fsm.transition_to(finding_id, "reviewed", author_id="op1", reason="ok")

    # Attempt to promote critical finding without approvals -> fails
    with pytest.raises(StateTransitionError) as exc_info:
        fsm.transition_to(finding_id, "promoted", author_id="op1", reason="Promote critical", is_critical=True)
    assert "Dual approval required" in str(exc_info.value)

    # Operator 1 approves
    reg.add_approval(finding_id, operator_id="op1", signature="sig_op1", reason="Looks critical and verified")
    assert reg.is_approved(finding_id) == False

    # Attempt to promote with only 1 approval -> fails
    with pytest.raises(StateTransitionError):
        fsm.transition_to(finding_id, "promoted", author_id="op1", reason="Promote critical", is_critical=True)

    # Operator 2 approves (distinct operator)
    reg.add_approval(finding_id, operator_id="op2", signature="sig_op2", reason="Double checked and agreed")
    assert reg.is_approved(finding_id) == True

    # Promotion now succeeds
    fsm.transition_to(finding_id, "promoted", author_id="op1", reason="Promote critical", is_critical=True)
    assert fsm.get_state(finding_id) == "promoted"


def test_interface_freeze_policy():
    """Verify that InterfaceFreezePolicy detects and rejects changed version inputs."""
    # Matches registry version
    assert InterfaceFreezePolicy.validate_interface_version("schema.prov", "PROV-1.0") == True
    
    # Raises error on mismatch
    with pytest.raises(ValueError) as exc_info:
        InterfaceFreezePolicy.validate_interface_version("schema.prov", "PROV-2.0")
    assert "INTERFACE COMPATIBILITY BREAK" in str(exc_info.value)


def test_adr_registry_exceptions():
    """Verify ADR creation, exception logging, and constraint checks."""
    adr_reg = ADRRegistry()
    
    # Attempting to log an exception with a non-existent ADR -> fails
    with pytest.raises(ValueError) as exc_info:
        adr_reg.log_exception("EXC-001", "ADR-999", "Need exception", "op1", "tyr_agent")
    assert "ADR-999" in str(exc_info.value)

    # Create ADR
    adr_reg.create_adr(
        adr_id="ADR-100",
        title="Allow offline DB fallback",
        author="op1",
        context="Database can be offline",
        decision="Allow fallback to mock DB",
        consequences="Audit trail will log mock DB usage",
        reversibility_plan="Ensure bolt endpoint is reachable"
    )

    # Logging exception with valid ADR -> succeeds
    exc = adr_reg.log_exception("EXC-001", "ADR-100", "Fallback database triggered", "op1", "db_connector")
    assert exc["exception_id"] == "EXC-001"
    assert exc["adr_id"] == "ADR-100"
    assert exc["reversibility_plan"] == "Ensure bolt endpoint is reachable"


def test_release_train_rollback():
    """Verify ReleaseTrainManager switches versions and runs rollback self-test."""
    rtm = ReleaseTrainManager()
    
    # Initial version
    assert rtm.get_active_version() == "v1.1"

    # Rollback to v1.0
    rtm.set_active_version("v1.0")
    assert rtm.get_active_version() == "v1.0"
    assert rtm.get_active_resource("rules.nato_scoring")["reliability_map"]["B"] == 0.8

    # Rollforward to v1.1
    rtm.set_active_version("v1.1")
    assert rtm.get_active_resource("rules.nato_scoring")["reliability_map"]["B"] == 0.9

    # Rollback self-test cycle
    assert rtm.test_rollback_cycle() == True
