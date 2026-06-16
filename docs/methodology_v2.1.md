# KARASUGAKURE OSINT METHODOLOGY v2.1

## DOMINIO 7: HUMINT OSINT, HUMAN-CENTRIC Y LEGAL ENTITY INTELLIGENCE

### OBJETIVO
Mapear, correlacionar y validar inteligencia sobre activos humanos y personas jurídicas como objetos primarios de análisis.
El enfoque no es tecnológico sino identitario, relacional y organizacional.
Incluye personas físicas, personas jurídicas, grupos, filiales, marcas, dominios corporativos, órganos de gobierno, fundadores, empleados clave, administradores, perfiles públicos, cuentas asociadas y superficies de exposición digital vinculadas.

### ALCANCE
#### PERSONAS FISICAS
Nombre real, alias, usernames, emails, teléfonos, perfiles sociales, historial público, afiliaciones, roles, ubicaciones públicas, hábitos de publicación, patrones horarios, exposición documental, credenciales filtradas, relaciones con activos técnicos.

#### PERSONAS JURIDICAS
Empresa, asociación, fundación, filial, marca, dominio, holding, razón social, estructura societaria, administradores, directivos, empleados clave, proveedores, repositorios, infraestructura pública, marcas registradas, documentos legales, licitaciones, fugas de credenciales, huella digital organizacional.

### SUBDOMINIOS
- 7.1 Identity Resolution
- 7.2 Social Graph Correlation
- 7.3 Credential Exposure and Breach Linking
- 7.4 Behavioral and Temporal Pattern Analysis
- 7.5 Physical-Digital Bridge
- 7.6 Corporate Entity Intelligence
- 7.7 Relationship and Ownership Graphs
- 7.8 Reputation and Trust Surface Mapping

### HERRAMIENTAS
- maigret
- sherlock
- holehe
- h8mail
- socialscan
- spiderfoot
- theHarvester
- recon-ng
- exiftool
- amass
- whois
- crtsh
- maltego (si disponible)
- browser-based OSINT manual
- graph correlation pipeline en Neo4j o Memgraph (Fenrir/Huginn)

### FUENTES
- Perfiles públicos
- Breach corpora autorizados
- CT logs
- WHOIS histórico
- Redes sociales
- Repos públicos
- Documentos legales
- Registro mercantil
- Prensa
- Imágenes públicas y metadatos
- Fuentes de empleo, liderazgo y afiliación
- Dominios y subdominios corporativos
- Direcciones de correo y patrones de naming

### CHECKPOINT NATIVO (Validación Previa)
Antes de iniciar cualquier análisis técnico:
1. ¿El activo primario es una persona física, una persona jurídica, o ambas?
2. ¿Existe un seed inicial: nombre, email, username, dominio corporativo o razón social?
3. ¿Cuál es la relación esperada entre identidad humana y activos técnicos?
4. ¿La inteligencia buscada es de exposición, de relación, de compromiso o de validación?
5. ¿Cuál es el umbral de certeza requerido antes de aceptar un hallazgo?

### SALIDA OBLIGATORIA: HUMINT OSINT BRIEF
- Target Identity or Entity
- Type
- Confidence
- Known Aliases
- Known Affiliations
- Digital Presence
- Credential Exposure
- Relationship Graph
- Technical Tie-Ins
- Primary Risks
- Priority Actions
- Evidence Sources
- Validation Status

---

## REGLAS DE VALIDACION Y CERTEZA (DOMINIO 7)

No se documenta ningún hallazgo como cierto sin una confianza mínima del **94%**.
- **94% - 100%**: Confirmado para inteligencia accionable.
- **85% - 93.99%**: El hallazgo queda en estado de cuasi-confirmado y exige depuración humana obligatoria.
- **< 85%**: El hallazgo permanece como hipótesis y no se eleva a inteligencia accionable.

Toda conclusión debe tener trazabilidad de fuentes, convergencia multifuente y validación cruzada.

---

## SCORING DE EXPOSICION HUMANA (HES)

Se usa **HES (Human Exposure Score)**, en escala 0 a 100.
El score mide exposición, no impacto técnico ni explotabilidad. Proporciona una métrica operativa para personas físicas y jurídicas, mientras que la "certeza" controla si un dato pasa de hipótesis a inteligencia accionable.

Se compone de 6 ejes:
- **IV**: Identidad visible
- **CT**: Correlación transversal
- **CE**: Credenciales expuestas
- **ER**: Exposición relacional
- **ET**: Exposición temporal
- **ED**: Exposición documental

**FÓRMULA**:
`HES = (IV + CT + CE + ER + ET + ED) / 6`

**INTERPRETACIÓN DEL SCORE**:
- **0-24**: Bajo
- **25-49**: Medio
- **50-74**: Alto
- **75-84**: Crítico
- **85-93.99**: Crítico con depuración humana obligatoria
- **94-100**: Confirmado para inteligencia accionable

---

## FORMATO DE HIPOTESIS

Cuando un hallazgo no alcanza el 94% o requiere revisión, se genera bajo este formato:

```markdown
HIPOTESIS N
Titulo descriptivo
DOMINIO 7
TIPO Persona fisica / Persona juridica / Mixto
CONTEXTO TECNICO
Describir el sujeto, sus alias, entidades vinculadas, fuentes y correlaciones observadas.

VULNERABILIDAD O EXPOSICION SOSPECHADA
Ejemplo: credencial exposure, identity linkage, role leakage, corporate relationship exposure, metadata leakage.

SCORING
HES X/100
Certainty X%
Prioridad Critica / Alta / Media / Baja

PASOS DE CONFIRMACION
Paso 1 fuente primaria
Paso 2 fuente secundaria
Paso 3 validacion cruzada
Paso 4 criterio observable
Paso 5 umbral de certeza

COMANDO INICIAL
[Comando o script base para continuar]
```

---

## FASES DEL FLUJO HUMINT (INTEGRACIÓN DOCTRINAL)

### FASE -1 HUMINT PRE-ENGAGEMENT
1. Identificar seed inicial.
2. Resolver identidad o entidad por alias, afiliación y naming.
3. Construir grafo inicial.
4. Correlacionar exposición documental, relacional y técnica.
5. Clasificar el target por tipo: persona física, persona jurídica o híbrido.
6. Derivar vectores hacia dominios 1-6.

### FASE 0 HUMINT THREAT MODEL
1. Definir objetivo humano u organizacional.
2. Definir activos críticos.
3. Definir amenazas más probables.
4. Medir exposición por HES.
5. Priorizar vectores con certeza y trazabilidad.
6. Confirmar qué hallazgos cruzan hacia dominios tecnológicos.

### FASE 2 CORRELACION DINAMICA
1. Unificar entidades duplicadas.
2. Resolver alias y coincidencias ambiguas.
3. Correlacionar brechas, repos, redes, dominios y documentos.
4. Identificar vínculos entre personas y activos técnicos.
5. Extraer hipótesis accionables para Web, Cloud, Source Code o LLM.

### FASE 3 VALIDACION
1. Convergencia mínima de tres fuentes.
2. Validación humana obligatoria si certeza <94%.
3. Depuración si 85-93.99%.
4. No elevar conclusiones no trazables.
5. Adjuntar evidencia reproducible.

### FASE 4 KAISEN
1. Crear patrones reutilizables de identidad.
2. Crear reglas de normalización de nombres y aliases.
3. Crear taxonomía de entidades jurídicas.
4. Añadir fuentes recurrentes al knowledge base.
5. Registrar lecciones de correlación.

### FASE 5 REPORTING
1. Resumen ejecutivo.
2. Tabla de entidades.
3. Tabla de relaciones.
4. Tabla de exposiciones.
5. Hallazgos confirmados con HES y certeza.
6. Remediación operacional.
