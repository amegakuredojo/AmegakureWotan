import re
import tldextract
from pydantic import BaseModel, field_validator

class NormalizedSeed(BaseModel):
    original: str
    canonical: str
    entity_type: str  # "Persona física", "Persona jurídica", "Mixto"
    base_domain: str | None = None
    username: str | None = None
    email: str | None = None

class EntitySeedNormalizer:
    @staticmethod
    def normalize(seed: str) -> NormalizedSeed:
        """
        Cleans handles, emails, and company names.
        Classifies the seed.
        """
        seed = seed.strip()
        canonical = seed
        entity_type = "Mixto"
        base_domain = None
        username = None
        email = None

        # Clean @ handles
        if seed.startswith("@"):
            canonical = seed[1:]
            username = canonical
            entity_type = "Persona física"
        
        # Is email?
        elif re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", seed):
            canonical = seed.lower()
            email = canonical
            username = canonical.split("@")[0]
            base_domain = canonical.split("@")[1]
            entity_type = "Persona física" # Usually tied to a person, though could be mixed
        
        # Is domain?
        else:
            # Check if it has a valid TLD using tldextract
            ext = tldextract.extract(seed)
            if ext.suffix:
                canonical = f"{ext.domain}.{ext.suffix}".lower()
                base_domain = canonical
                entity_type = "Persona jurídica"
            elif re.match(r"^[a-zA-Z0-9-]+$", seed):
                # Probably a company name or username. If it's short/no spaces, could be both.
                # The user requested: canonize anthropic to anthropic.com
                canonical = f"{seed.lower()}.com"
                base_domain = canonical
                username = seed.lower()
                entity_type = "Persona jurídica"
            else:
                # E.g. "John Doe" or "Acme Corp"
                canonical = seed
                if "corp" in seed.lower() or "inc" in seed.lower() or "llc" in seed.lower():
                    entity_type = "Persona jurídica"
                else:
                    entity_type = "Persona física"
                    
        return NormalizedSeed(
            original=seed,
            canonical=canonical,
            entity_type=entity_type,
            base_domain=base_domain,
            username=username,
            email=email
        )

class SeedExpander:
    @staticmethod
    def expand(seed: NormalizedSeed) -> list[str]:
        """
        Returns a list of alternative seeds to try if the main one fails.
        Order is important (priority first).
        """
        expansions = []
        
        # First try the canonical
        expansions.append(seed.canonical)
        
        if seed.entity_type == "Persona jurídica" and seed.base_domain:
            ext = tldextract.extract(seed.base_domain)
            # Try variations like .net, .org, or without suffix for brand searches
            expansions.append(f"{ext.domain}.net")
            expansions.append(f"{ext.domain}.org")
            expansions.append(ext.domain) # Brand name search
            
        elif seed.entity_type == "Persona física" and seed.username:
            expansions.append(seed.username)
            # Variations of username
            expansions.append(f"{seed.username}123")
            expansions.append(f"{seed.username}_")
            
        # Ensure uniqueness while preserving order
        seen = set()
        unique_expansions = []
        for x in expansions:
            if x and x not in seen:
                seen.add(x)
                unique_expansions.append(x)
                
        return unique_expansions
