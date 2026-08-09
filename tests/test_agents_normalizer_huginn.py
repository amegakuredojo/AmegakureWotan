# FORGE_CONTEXT: CIVIL
"""Tests de normalización de semillas (agents/normalizer) y scoring HES (agents/huginn).

Solo rutas PURAS: no se invoca run_isolated_process ni subagentes, así el test es
hermético, rápido y determinista. La normalización de dominios requiere tldextract
(instalado); si falla la extracción, el comportamiento de fallback debe seguir siendo
coherente (no excepción).
"""
import pytest

from amegakurewotan.agents.normalizer import EntitySeedNormalizer, SeedExpander, NormalizedSeed
from amegakurewotan.agents.huginn import HuginnAgent


# ── Normalizer ───────────────────────────────────────────────────────────────
def test_normalize_handle_strips_at():
    s = EntitySeedNormalizer.normalize("@john_doe")
    assert s.canonical == "john_doe"
    assert s.username == "john_doe"
    assert s.entity_type == "Persona física"


def test_normalize_email_lowercases_and_splits():
    s = EntitySeedNormalizer.normalize("John.Doe@Example.COM")
    assert s.email == "john.doe@example.com"
    assert s.username == "john.doe"
    assert s.base_domain == "example.com"
    assert s.entity_type == "Persona física"


def test_normalize_domain_canonicalizes():
    s = EntitySeedNormalizer.normalize("Sub.Example.COM")
    assert s.canonical == "example.com"
    assert s.base_domain == "example.com"
    assert s.entity_type == "Persona jurídica"


def test_normalize_bareword_adds_dotcom():
    s = EntitySeedNormalizer.normalize("anthropic")
    assert s.canonical == "anthropic.com"
    assert s.base_domain == "anthropic.com"
    assert s.entity_type == "Persona jurídica"


def test_normalize_legal_name_with_corp():
    s = EntitySeedNormalizer.normalize("Acme Corp")
    assert s.entity_type == "Persona jurídica"
    assert s.canonical == "Acme Corp"


def test_normalize_physical_name():
    s = EntitySeedNormalizer.normalize("John Doe")
    assert s.entity_type == "Persona física"


@pytest.mark.parametrize("seed,typ", [
    ("@alice", "Persona física"),
    ("target.com", "Persona jurídica"),
    ("Acme Inc", "Persona jurídica"),
])
def test_normalize_returns_model(seed, typ):
    s = EntitySeedNormalizer.normalize(seed)
    assert isinstance(s, NormalizedSeed)
    assert s.entity_type == typ
    assert s.original == seed


# ── SeedExpander ─────────────────────────────────────────────────────────────
def test_expand_legal_adds_tld_variants():
    s = EntitySeedNormalizer.normalize("target.com")
    expansions = SeedExpander.expand(s)
    assert expansions[0] == "target.com"
    assert "target.net" in expansions
    assert "target.org" in expansions
    assert "target" in expansions  # brand search
    # Sin duplicados
    assert len(expansions) == len(set(expansions))


def test_expand_physical_adds_username_variants():
    s = EntitySeedNormalizer.normalize("@alice")
    expansions = SeedExpander.expand(s)
    assert "alice" in expansions
    assert "alice123" in expansions
    assert "alice_" in expansions


# ── HUGINN: scoring puro ─────────────────────────────────────────────────────
def test_hes_legal_weighted():
    h = HuginnAgent()
    # Jurídica: pesos sesgados a dominio/footprint. Mismos inputs => distinto a física.
    legal = h.calculate_hes(10, 20, 30, 40, 50, 60, "Persona jurídica")
    physical = h.calculate_hes(10, 20, 30, 40, 50, 60, "Persona física")
    # La media simple (física) difiere de la ponderada (jurídica).
    assert legal != physical
    assert 0.0 <= legal <= 100.0


def test_hes_physical_simple_mean():
    h = HuginnAgent()
    # Física: media simple de los 6 componentes.
    val = h.calculate_hes(10, 20, 30, 40, 50, 60, "Persona física")
    assert abs(val - (10 + 20 + 30 + 40 + 50 + 60) / 6.0) < 1e-9


def test_evaluate_certainty_thresholds():
    h = HuginnAgent()
    assert h.evaluate_certainty(95.0) == "ACTIONABLE"
    assert h.evaluate_certainty(90.0) == "HUMAN_REVIEW_REQUIRED"
    assert h.evaluate_certainty(80.0) == "HYPOTHESIS"
    # Borde exacto 94 => ACTIONABLE; 85 => HUMAN_REVIEW_REQUIRED
    assert h.evaluate_certainty(94.0) == "ACTIONABLE"
    assert h.evaluate_certainty(85.0) == "HUMAN_REVIEW_REQUIRED"
