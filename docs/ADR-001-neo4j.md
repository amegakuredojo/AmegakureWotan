# ADR-001 — Graph-RAG: Kùzu embebido como fuente de verdad (NO Neo4j en núcleo TRL-9)

- **Estado:** ACEPTADO
- **Fecha:** 2026-08-08
- **Autor:** lugh (AmegakureDōjō)

## Contexto

AmegakureWotan.md (§3.4, §9.5) menciona Neo4j Graph-RAG como capa de correlación.
El objetivo de despliegue es hardware edge (Intel N100 / 8 GB RAM). Neo4j requiere
JVM + heap considerable (>1 GB solo en reposo) y no es embebido: introduce un
servicio de fondo, superficie de ataque adicional y sobrecarga de memoria
incompatible con el perfil edge. Kùzu (embedded, C++, columnar) ya está integrado
y operativo en el repo.

## Decisión

El núcleo TRL-9 de AmegakureWotan usa **Kùzu embebido** como grafo de correlación
y fuente de verdad. Neo4j queda FUERA del alcance del núcleo y se documenta como
extensión opcional (conector de exportación a Neo4j para despliegues de centro de
operaciones con recursos holgados), nunca como dependencia del runtime edge.

Graph-RAG (§9.5) se implementa sobre Kùzu vía `graph.query` + `NornAgent`
(NL→Cypher) ya presentes; no requiere Neo4j.

## Consecuencias

- Positivas: huella de memoria <300 MB para el grafo; arranque sin JVM; un solo
  proceso; cadena de custodia coherente (ledger de archivo autónomo).
- Negativas: quienes ya operan Neo4j en su SOC deben usar el conector de
  exportación (pendiente, no bloquea TRL-9).
- La matriz de integración (docs/INTEGRATION_MATRIX.md) refleja este estado.

## Confirmación de TRL-9

Este ADR NO bloquea TRL-9: la correlación grafos ya es funcional con Kùzu.
Neo4j es mejora post-TRL-9, no requisito.
