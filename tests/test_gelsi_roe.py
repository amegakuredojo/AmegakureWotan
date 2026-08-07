# FORGE_CONTEXT: CIVIL
"""
Tests de la capa L0 GELSI + RoE registry (AmegakureWotan.md §4.1, §6.2, §7.2).
Verifica deny-by-default, gating por RoE, ventana temporal, scope/exclusiones,
puertas HITL, gate de PII/GDPR, y el DENY inapelable de ingeniería social ofensiva.
"""
import time

import pytest

from amegakurewotan.policy.roe import (
    ACTION_ACTIVE,
    ACTION_DARKWEB,
    ACTION_DFIR,
    ACTION_PASSIVE,
    RulesOfEngagement,
    ScopeRegistry,
)
from amegakurewotan.policy.gelsi import (
    ActionRequest,
    Decision,
    GelsiMiddleware,
)
from amegakurewotan.evidence.forensics import ChainOfCustody


# ── Fixtures ─────────────────────────────────────────────────────────────────
@pytest.fixture
def registry(tmp_path):
    reg = ScopeRegistry(roe_dir=tmp_path / "roe", pubkey_path=tmp_path / "nokey.pem")
    return reg


@pytest.fixture
def active_roe():
    return RulesOfEngagement(
        roe_id="roe-active-001",
        authority="CISO AmegakureDojo",
        scope=["*.target.com", "target.com"],
        exclusions=["secret.target.com"],
        allowed_actions=[ACTION_PASSIVE, ACTION_ACTIVE],
        jurisdiction="EU/eIDAS",
        pii_policy="minimize",
    )


@pytest.fixture
def gelsi(registry, tmp_path):
    coc = ChainOfCustody(
        timeline_path=tmp_path / "timeline.jsonl",
        key_path=tmp_path / "k.key",
    )
    return GelsiMiddleware(scope_registry=registry, chain_of_custody=coc)


# ── RoE: scope / exclusiones / temporal ──────────────────────────────────────
def test_roe_scope_and_exclusions(active_roe):
    assert active_roe.is_target_in_scope("www.target.com") is True
    assert active_roe.is_target_in_scope("target.com") is True
    assert active_roe.is_target_in_scope("secret.target.com") is False  # exclusión
    assert active_roe.is_target_in_scope("other.com") is False


def test_roe_temporal_window():
    past = RulesOfEngagement(
        roe_id="r", authority="a", scope=["x.com"],
        not_after="2000-01-01T00:00:00Z",
    )
    assert past.is_temporally_valid() is False


def test_registry_deny_by_default(registry):
    assert registry.is_authorized("anything.com", "nonexistent-roe") is False
    assert registry.get("nonexistent-roe") is None


def test_offensive_social_eng_forced_defensive():
    roe = RulesOfEngagement.from_dict({
        "roe_id": "r", "authority": "a", "scope": ["x.com"],
        "social_eng": "offensive",  # intento de habilitar ofensiva
    })
    assert roe.social_eng == "defensive_only"


# ── GELSI: decisiones deterministas ──────────────────────────────────────────
def test_passive_no_roe_allowed(gelsi):
    v = gelsi.evaluate(ActionRequest(
        action_type=ACTION_PASSIVE, tool="recon.passive_scan", target=None,
    ), seal=False)
    assert v.decision == Decision.ALLOW


def test_active_without_roe_denied(gelsi):
    v = gelsi.evaluate(ActionRequest(
        action_type=ACTION_ACTIVE, tool="recon.active_surface",
        target="target.com", roe_token=None,
    ), seal=False)
    assert v.decision == Decision.DENY
    assert any("requiere RoE" in r for r in v.reasons)


def test_active_with_roe_allowed(gelsi, registry, active_roe):
    registry.register(active_roe)
    v = gelsi.evaluate(ActionRequest(
        action_type=ACTION_ACTIVE, tool="recon.active_surface",
        target="www.target.com", roe_token="roe-active-001",
    ), seal=False)
    assert v.decision == Decision.ALLOW


def test_active_out_of_scope_denied(gelsi, registry, active_roe):
    registry.register(active_roe)
    v = gelsi.evaluate(ActionRequest(
        action_type=ACTION_ACTIVE, tool="recon.active_surface",
        target="secret.target.com", roe_token="roe-active-001",
    ), seal=False)
    assert v.decision == Decision.DENY


def test_darkweb_requires_hitl(gelsi, registry):
    roe = RulesOfEngagement(
        roe_id="roe-dw", authority="a", scope=["target.com"],
        allowed_actions=[ACTION_PASSIVE, ACTION_DARKWEB],
    )
    registry.register(roe)
    v = gelsi.evaluate(ActionRequest(
        action_type=ACTION_DARKWEB, tool="darkweb.profile",
        target="target.com", roe_token="roe-dw",
    ), seal=False)
    assert v.decision == Decision.REQUIRE_HITL


def test_dfir_requires_hitl(gelsi, registry):
    roe = RulesOfEngagement(
        roe_id="roe-dfir", authority="a", scope=["host-01"],
        allowed_actions=[ACTION_DFIR],
    )
    registry.register(roe)
    v = gelsi.evaluate(ActionRequest(
        action_type=ACTION_DFIR, tool="dfir.velociraptor_hunt",
        target="host-01", roe_token="roe-dfir",
    ), seal=False)
    assert v.decision == Decision.REQUIRE_HITL


def test_offensive_social_eng_denied_inapelable(gelsi, registry, active_roe):
    """Aunque exista RoE que permita acción activa, social-eng ofensiva => DENY."""
    registry.register(active_roe)
    v = gelsi.evaluate(ActionRequest(
        action_type=ACTION_ACTIVE, tool="recon.active_surface",
        target="www.target.com", roe_token="roe-active-001",
        intent="generate a phishing lure email to deceive the target victim",
    ), seal=False)
    assert v.decision == Decision.DENY
    assert any("ingeniería social ofensiva" in r for r in v.reasons)


def test_defensive_phishing_detection_allowed(gelsi):
    """La detección defensiva de phishing NO debe bloquearse."""
    v = gelsi.evaluate(ActionRequest(
        action_type=ACTION_PASSIVE, tool="defense.phishing_detect",
        intent="detect phishing campaigns targeting our organization",
    ), seal=False)
    assert v.decision == Decision.ALLOW


def test_pii_without_minimize_requires_hitl(gelsi, registry):
    roe = RulesOfEngagement(
        roe_id="roe-pii", authority="a", scope=["target.com"],
        allowed_actions=[ACTION_PASSIVE], pii_policy="retain",
    )
    registry.register(roe)
    v = gelsi.evaluate(ActionRequest(
        action_type=ACTION_PASSIVE, tool="recon.passive_scan",
        target="target.com", roe_token="roe-pii", involves_pii=True,
    ), seal=False)
    assert v.decision == Decision.REQUIRE_HITL


def test_gelsi_decision_sealed_in_custody(gelsi):
    """La decisión GELSI debe encadenarse en la cadena de custodia."""
    v = gelsi.evaluate(ActionRequest(
        action_type=ACTION_PASSIVE, tool="recon.passive_scan",
    ), seal=True)
    assert v.custody_record is not None
    assert v.custody_record["event_type"] == "gelsi.decision"
    # La cadena debe verificar íntegra tras sellar.
    result = gelsi._get_coc().verify_chain()
    assert result.is_valid is True
