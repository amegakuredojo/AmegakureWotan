OPERATIONAL_QUERIES = {
    "cadena_completa_custodia": """
    MATCH p=(ag:Agent)-[:WAS_ASSOCIATED_WITH]->(act:Activity)-[:USED]->(e:Entity)
    MATCH p2=(act)-[:WAS_GENERATED_BY]->(ev:Evidence)-[:SUPPORTS]->(h:Hypothesis)
    MATCH p3=(h)-[:SIGNED_BY]->(ag)
    RETURN p, p2, p3
    """,
    
    "hipotesis_pendientes_revision": """
    MATCH (h:Hypothesis)
    WHERE h.status = 'REVIEW_REQUIRED' OR h.review_state = 'PENDING'
    RETURN h.uuid, h.confidence, h.created_at
    """,

    "evidencia_sin_firma": """
    MATCH (ev:Evidence)-[:SUPPORTS]->(h:Hypothesis)
    WHERE NOT (h)-[:SIGNED_BY]->(:Agent)
    RETURN ev.hash_sha512, h.uuid
    """,

    "entidades_sin_fuente_primaria": """
    MATCH (e:Entity)
    WHERE NOT (:Activity)-[:USED]->(e) AND NOT (:Hypothesis)-[:WAS_DERIVED_FROM]->(e)
    RETURN e.value, e.uuid
    """,

    "decisiones_por_agente": """
    MATCH (ag:Agent)<-[:SIGNED_BY]-(h:Hypothesis)-[:PROMOTED_TO]->(dec:Decision)
    RETURN ag.name, dec.status, count(dec) as total
    GROUP BY ag.name, dec.status
    """,

    "hallazgos_promovidos": """
    MATCH (h:Hypothesis)
    WHERE h.confidence >= 94.0 AND h.status = 'ACTIONABLE'
    RETURN h.uuid, h.confidence, h.classification
    """,

    "inconsistencias_entity_evidence": """
    MATCH (act:Activity)-[:USED]->(e:Entity)
    MATCH (act)-[:WAS_GENERATED_BY]->(ev:Evidence)
    WHERE NOT (ev)-[:SUPPORTS]->(:Hypothesis)-[:WAS_DERIVED_FROM]->(e)
    RETURN e.uuid, ev.hash_sha512
    """
}
