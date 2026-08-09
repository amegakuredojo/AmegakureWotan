# AmegakureWotan — Arquitectura consolidada OSINT/DFIR de grado militar‑forense

## 1. Objetivo y alcance

AmegakureWotan es la consolidación doctrinal e industrial de los proyectos AmegakureWotan y SENTINEL‑OSINT en una sola plataforma de inteligencia de fuentes abiertas (OSINT) y respuesta forense de grado militar, diseñada para operar bajo la doctrina y protocolos de AmegakureDojo. El sistema se orienta a hardware edge de bajo consumo (Intel N100, 8GB RAM) y entornos industriales con requisitos de alta trazabilidad, cadena de custodia legalmente defendible y controles estrictos de OPSEC, reduciendo al mínimo el uso de SaaS externos y manteniendo una superficie de ataque compacta.[^1]

La plataforma elimina explícitamente cualquier capacidad de ingeniería social ofensiva: ni generación de pretextos, ni plantillas de phishing, ni contenido persuasivo dirigido a humanos; solo se permite ingeniería social defensiva (detección de phishing, correlación de campañas contra la organización, huella digital expuesta del personal) y operaciones OSINT/DFIR dentro de Reglas de Empeño (RoE) firmadas. A diferencia de frameworks OSINT generalistas, AmegakureWotan prioriza gobernanza (GELSI), cadena de custodia HMAC‑SHA512, OPSEC duro (Tor, proxies, evasión bajo RoE) y acoplamiento con marcos regulatorios como eIDAS y GDPR.[^1]


## 2. Renombrado de proyecto y doctrina Odin en Hermes

El proyecto AmegakureWotan se renombra formalmente a **AmegakureWotan**, manteniendo su núcleo técnico (grafo embebido, contenedores, ledger) pero alineando el branding con la visión consolidada y el rol de Wotan/Odin como autoridad de mando y visión estratégica. Odin deja de ser un orquestador autónomo aislado y pasa a constituir el **perfil doctrinal** de Hermes Agent: las reglas de Odin se implementan como configuración inicial de Hermes (prompt de sistema, restricciones, estilos de planificación, límites operacionales), de forma que cualquier sesión de Hermes en este ecosistema nace ya con la doctrina de AmegakureDojo integrada.[^1]

Esto permite que Hermes funcione como "Wotan externo" (kernel de orquestación) mientras que la lógica de agentes internos de AmegakureWotan (Heimdall, Huginn, Tyr, Hel, Odin, Mimir) se conserva sin cambios semánticos, simplemente re‑anclada a subagentes Hermes con los mismos nombres y misiones. El resultado es que la identidad y protocolos de AmegakureDojo no se diluyen al adoptar Hermes, sino que Hermes se convierte en el vehículo para aplicarlos de forma sistemática a todo motor OSINT/DFIR conectado.


## 3. Modelo de determinismo vs flexibilidad de IA

El comportamiento del sistema se diseña como un **SOC/DFIR impulsado por IA**, no como "IA autónoma arbitraria": la IA actúa como triager, correlador y generador de informes, pero las acciones activas, intrusivas o evasivas se mantienen deterministas y gateadas por RoE + HITL. Las rutas de ejecución hacia herramientas externas (Maltego, Shodan, Nuclei, Velociraptor, etc.) están descritas en contratos MCP y scripts idempotentes; el LLM decide qué combinar y cómo priorizar, pero no puede ejecutar comandos fuera del conjunto permitido ni modificar parámetros críticos sin pasar por GELSI.[^1]

El diseño de AmegakureWotan adopta una **flexibilidad acotada**: para tareas de investigación OSINT y análisis forense donde no existe un único flujo rígido, el LLM puede elegir diferentes combinaciones de herramientas (p. ej. SpiderFoot vs theHarvester vs Amass) siempre dentro de plantillas de playbooks predefinidos, permitiendo creatividad operativa sin sacrificar reproducibilidad. Para tareas SOC/DFIR (detección, respuesta, cazas Velociraptor, análisis de memoria con Volatility), se privilegia pipelines reproducibles, con parámetros versionados y capacidad de re‑ejecución exacta durante auditorías.[^2][^3][^4][^5]


## 4. Arquitectura lógica consolidada

### 4.1 Capas globales

La arquitectura de AmegakureWotan se organiza en seis capas, consolidando AmegakureWotan y SENTINEL‐OSINT en un solo MCP OSINT/DFIR de siguiente generación.

1. **L0 – Gobernanza y Cumplimiento (GELSI global)**  
   Middleware obligatorio entre Hermes y cualquier herramienta/tarea, que evalúa RoE, jurisdicción, categoría de acción (pasiva/activa/evasiva), PII bajo GDPR y presencia de contenido de ingeniería social ofensiva.[^1] Emite decisiones `ALLOW | DENY | REQUIRE_HITL` y las encadena en `timeline.jsonl` mediante `forensics.py`, con referencias a `roe_id` y justificación auditable.[^1]

2. **L1 – Orquestación Agentica (Hermes/Odin)**  
   Hermes Agent actúa como orquestador raíz, con un perfil doctrinal Odin que define: estilo de planificación, límite de delegaciones, reglas de mínima superficie, prohibición de contenido ofensivo y prioridad de evidencias sobre "intuiciones" del modelo. Hermes crea subagentes con los nombres ya usados en AmegakureWotan (Heimdall, Huginn, Tyr, Hel, Mimir, etc.), mapeados a skills y herramientas MCP de AmegakureWotan.[^1]

3. **L2 – MCP único de AmegakureWotan**  
   Un **servidor MCP consolidado** expone las capacidades OSINT/DFIR como herramientas tipadas, combinando el diseño del MCP OSINT de SENTINEL con el motor interno de AmegakureWotan. No se exponen múltiples MCP separados: desde Hermes todo se ve como `amegakurewotan.mcp` con diferentes herramientas (`recon.passive_scan`, `amewotan.graph_query`, `dfir.velociraptor_hunt`, etc.).[^1]

4. **L3 – Motores OSINT/DFIR subyacentes**  
   Contenedores y binarios endurecidos (Docker/K8s) para: BBOT, Axiom‑lite, Kùzu (grafo AmegakureWotan), Neo4j (Graph‑RAG), SpiderFoot CLI, theHarvester, Amass, Recon‑ng, Shodan CLI, Censys CLI, Maltego CE (via scripts/headless), Nuclei, Volatility 3, Velociraptor, Autopsy/Sleuth Kit. Estos no son visibles directamente al LLM: solo se invocan a través del MCP consolidado con parámetros validados.[^3][^6][^2][^1]

5. **L4 – Memoria Cognitiva y Grafos**  
   Neo4j Community como grafo central para Graph‑RAG, Kùzu como grafo embebido de AmegakureWotan para consultas locales y pipelines específicos de análisis de relaciones, y un vector store ligero (SQLite+FAISS) para embeddings cuando sea necesario. Esta capa evita la alucinación de vulnerabilidades o relaciones inexistentes: las respuestas del LLM se basan en consultas explícitas al grafo.[^1]

6. **L5 – Interfaces de Operador e Integración Industrial**  
   TUI de AmegakureWotan (heredada de AmegakureWotan), CLI `amewotan`/`amewotan`, dashboards de SOC/DFIR, integraciones con SIEM/SOAR y QTSP eIDAS para anclaje de cadena de custodia. No se exponen paneles web públicos; cualquier UI web se aloja en redes restringidas.[^1]


### 4.2 Módulos funcionales principales

La plataforma se estructura en módulos cohesivos, cada uno con contratos claros y sin exposición directa al LLM:

- **forensics.py (Cadena de Custodia Criptográfica Encadenada)**: módulo compartido que implementa `ChainOfCustody` con HMAC‑SHA512 encadenado sobre `timeline.jsonl`, usado tanto por SENTINEL como por AmegakureWotan.[^1]
- **amegakurewotan.mcp**: servidor MCP consolidado con esquemas Pydantic para todas las herramientas OSINT/DFIR, validación de RoE y gating OPSEC.[^1]
- **graph.neo4j** y **graph.kuzu**: adaptadores para consulta y sincronización de grafo, con políticas de replicación controlada del grafo interno de AmegakureWotan hacia Neo4j cuando se requiera correlación global.[^1]
- **opsec.tor_proxy** y **opsec.evasive_proxy_pool**: módulos de red que enrutan tráfico OSINT por Tor o pools de proxies según RoE, separando OPSEC "obligatoria" (anonimidad básica) de OPSEC evasiva (rotación agresiva, timing aleatorio), siempre registrada en la cadena de custodia.[^1]
- **dfir.velociraptor_client**: integración con Velociraptor para cazas DFIR en endpoints, usando VQL y artifacts para hunts y monitoreo a gran escala.[^5][^7][^3]
- **dfir.volatility3_adapter** y **dfir.sleuthkit_adapter**: wrappers para Volatility 3 y Sleuth Kit/Autopsy, ejecutados en contenedores aislados para análisis de memoria y discos.[^3]


## 5. Cadena de custodia consolidada (SENTINEL + AmegakureWotan)

### 5.1 Modelo estándar `ChainOfCustody`

El modelo de cadena de custodia definitivo es el de SENTINEL, aplicado a toda acción OSINT/DFIR en el ecosistema. Cada evento forense (captura, escaneo, ejecución de herramienta externa, decisión GELSI, aprobación HITL, resultado de VQL Velociraptor, informe de Volatility o Sleuth Kit) se serializa de forma canónica y se encadena usando HMAC‑SHA512, con la estructura:[^1]

```json
{
  "seq": <int>,
  "ts_utc": "2026-08-07T10:00:00Z",
  "collector_id": "<agente o herramienta>",
  "event_type": "<tipo de evento>",
  "payload_hash": "<sha512 del artefacto crudo>",
  "roe_ref": "<id de RoE o null>",
  "prev_hash": "hain_hash anterior>",
  "chain_hash": "<HMAC-SHA512(key, prev_hash || canonical_json(body))>"
}
```

El archivo `timeline.jsonl` es append‑only, con `fsync` sincrono tras cada escritura, y `ChainOfCustody.verify_chain()` permite verificación completa de integridad sin acceso al sistema vivo, siempre que el auditor posea la clave HMAC correspondiente o una clave de verificación derivada.[^1]


### 5.2 Integración del ledger de AmegakureWotan

El "Forensic Audit Ledger" original de AmegakureWotan se adapta para convertirse en un **frontend** del `timeline.jsonl` global: sus operaciones de hash HMAC‑SHA512 se implementan llamando al módulo `forensics.py`, de forma que no existan dos cadenas paralelas. El CLI `amewotan audit verify` se mapea a `ChainOfCustody.verify_chain`, y los comandos `amewotan orchestrate`, `amewotan export`, `amewotan darkweb` y otros generan eventos con `collector_id="amewotan-agent"` o similares, asegurando trazabilidad cruzada con el resto de la plataforma.[^1]

Para análisis internos rápidos, AmegakureWotan puede mantener índices adicionales del ledger (por ejemplo, en SQLite o Kùzu), pero estos se consideran derivados; el registro probatorio oficial siempre es `timeline.jsonl` bajo `forensics.py` con anclaje opcional a eIDAS/RFC 3161 por lote.[^1]


### 5.3 Alineamiento eIDAS/GDPR y RoE

La cadena de custodia se alinea con eIDAS (sellado de tiempo cualificado, presunción de autenticidad) y GDPR (minimización de datos, retención limitada de PII) tal como define SENTINEL: ciertos lotes de eventos se anclan externamente mediante QTSP o TSA RFC 3161 para obtener valor probatorio reforzado. La RoE se define como documento YAML firmado digitalmente (autoridad que autoriza la misión), cargado en `scope_registry` y citado en todos los eventos relevantes mediante `roe_ref`, incluyendo denegaciones GELSI.[^1]


## 6. MCP consolidado AmegakureWotan

### 6.1 Diseño general

Se implementa un único servidor MCP, por ejemplo `amegakurewotan_mcp_server`, que expone todas las capacidades OSINT/DFIR del ecosistema. Hermes lo ve como un solo endpoint MCP; la separación entre AmegakureWotan/AmegakureWotan, BBOT, Axiom, Velociraptor, etc. está encapsulada detrás de los handlers de herramientas.[^1]

El servidor se organiza por dominios lógicos:

- `recon.*` – OSINT técnico clásico (dominios, IPs, subdominios, certificados, superficies en red).
- `intel.*` – correlación de inteligencia, scoring tipo NATO, consolidación de hallazgos.
- `graph.*` – consultas de grafo Neo4j/Kùzu.
- `darkweb.*` – búsquedas y correlación en entornos Tor/onion.
- `dfir.*` – operaciones forenses/IR (Velociraptor, Volatility, Sleuth Kit, Autopsy).
- `forensic.*` – operaciones sobre cadena de custodia (`append`, `verify`).
- `defense.*` – detección de phishing/ingeniería social defensiva.


### 6.2 Esquema MCP para recon consolidado

Ejemplo de esquemas Pydantic para unificar recon clásico (BBOT, Amass, theHarvester, Recon‑ng, SpiderFoot, Nuclei) con las restricciones de RoE y GELSI:

```python
from pydantic import BaseModel, field_validator
from typing import Literal

class ReconTarget(BaseModel):
    value: str  # dominio, IP, email, org name
    type: Literal["domain", "ip", "email", "org", "username"]

class ReconMode(str):
    # Abstraccion logica; el MCP se encarga de mapear a herramientas concretas
    # segun el modo y la configuracion de AmegakureWotan.

    pass


class ReconRequest(BaseModel):
    target: ReconTarget
    mode: Literal[
        "passive_surface",   # whois, certs, DNS, leaks pasivos
        "active_surface",    # portscan, banner grabbing, Nuclei
        "deep_osint",        # SpiderFoot/Recon-ng/Amass combinados
        "darkweb_profile",   # Tor + busqueda onion
    ]
    roe_token: str

    @field_validator("target")
    def target_in_scope(cls, v, info):
        if not scope_registry.is_authorized(v.value, info.data.get("roe_token")):
            raise ValueError("target fuera de RoE autorizado")
        return v

    @field_validator("mode")
    def mode_requires_roe_clause(cls, v, info):
        roe = scope_registry.get(info.data.get("roe_token"))
        if v in ("active_surface", "darkweb_profile") and not roe.allows_active():
            raise ValueError("RoE no autoriza acciones activas")
        if v == "darkweb_profile" and not roe.allows_darkweb():
            raise ValueError("RoE no autoriza operaciones darkweb")
        return v
```

Los handlers internos de MCP decidirán qué herramientas usar en cada modo:

- `passive_surface`: whois, DNS, certificados, leaks pasivos (p. ej. SecurityTrails, certificate transparency, SpiderFoot en modo pasivo).[^4][^2]
- `active_surface`: Nuclei, portscanning moderado (con límites), BBOT activo.[^1]
- `deep_osint`: combinación SpiderFoot/theHarvester/Amass/Recon‑ng según el tipo de objetivo.[^2]
- `darkweb_profile`: Hel + Tor + scripts específicos para onion, siempre con RoE explícita.[^1]


### 6.3 Integración DFIR (Velociraptor, Volatility, Sleuth Kit/Autopsy)

Para DFIR, el MCP consolida herramientas que operan sobre endpoints y artefactos forenses:

- `dfir.velociraptor_hunt`: lanza hunts VQL definidos (por nombre o contenido) contra etiquetas de clientes en Velociraptor (p. ej. `windows_workstations`, `critical_servers`), y encadena resultados en `timeline.jsonl`.[^8][^5][^3]
- `dfir.velociraptor_collect`: recopila artefactos específicos (logs, registros, MFT) para análisis posterior.[^5][^3]
- `dfir.memory_analyze`: ejecuta Volatility 3 sobre dumps de memoria, devolviendo resumen + ruta de reporte.[^3]
- `dfir.disk_timeline`: usa Sleuth Kit/Autopsy para generar timelines de disco (mactime, etc.) y correlacionarlos.[^3]

Cada una de estas herramientas debe ejecutar binarios en contenedores aislados, con límites de CPU/memoria, volúmenes de solo lectura y output redirigido a directorios de evidencias controlados, cuyo hash se registra en `payload_hash` de `ChainOfCustody`.[^1]


## 7. Conservación de agentes y roles de AmegakureWotan

### 7.1 Mapeo de agentes existentes a Hermes

Los agentes ya definidos en AmegakureWotan se preservan y mapean directamente a subagentes Hermes con el mismo nombre y objetivo.

- **Heimdall — Digital Reconnaissance & Perimeter Mapping**  
  Encargado de reconocimiento técnico: usa las herramientas MCP `recon.*` para mapear superficie de ataque, enumerar dominios/IPs, servicios y certificados. En la práctica, orquesta Amass, theHarvester, Nuclei, SpiderFoot (módulos de DNS/WHOIS) y BBOT/Axiom según recursos y RoE.[^2][^1]

- **Huginn — Corporate Entity & HUMINT Mapping**  
  Responsabilidad sobre correlación de entidades corporativas, personas y relaciones (SOCINT/HUMINT pasivo), usando Maltego CE, Recon‑ng, SpiderFoot y consultas a grafos Neo4j/Kùzu. Este agente nunca genera contenido persuasivo; solo reconstruye redes y expone riesgos de suplantación.[^2][^1]

- **Tyr — Information Verification & NATO Intelligence Scoring**  
  Encargado de validación de fuentes y scoring tipo NATO (A/B/C para fuente, 1‑6 para contenido), cruzando múltiples herramientas y fuentes OSINT/DFIR y utilizando Graph‑RAG para evitar sesgos. Opera sobre datos ya recolectados por Heimdall/Huginn/Hel/DFIR.[^1]

- **Hel — Dark Web / Deep Web Intel Indexing**  
  Responsable de operaciones dark web bajo RoE específica, usando el módulo `darkweb.*` del MCP, Tor y herramientas adicionales compatibles con operaciones onion. Todas sus acciones pasan por doble puerta HITL y son registradas con `event_type="darkweb.op"` en la cadena de custodia.[^1]

- **Odin — Workflow Orchestrator and Central Brain**  
  Configurado como perfil de sistema de Hermes, define doctrina (deny‑by‑default, prioridad de evidencias, separación ofensiva/defensiva) y decide cuándo delegar en los otros agentes, pero no ejecuta comandos de bajo nivel.[^1]

- **Mimir — Memory Retrieval and Contextual Search**  
  Agente de memoria y búsqueda contextual que media el acceso de otros agentes a Neo4j, Kùzu y vector store, proporcionando contextos concisos y verificados al LLM para minimizar alucinaciones.[^1]

Adicionalmente, se mantienen los subagentes definidos en SENTINEL (recon‑agent, correlation‑agent, defense‑socialeng‑agent, forensic‑agent, opsec‑agent) como roles lógicos que pueden coincidir funcionalmente con los anteriores o agruparlos, según convenga a la implementación.[^1]


### 7.2 Conexión con GELSI y RoE

Todos los agentes Hermes/AmegakureWotan llaman a herramientas MCP a través de GELSI, que aplica reglas deny‑by‑default para ingeniería social ofensiva, acciones activas sin RoE y operaciones OPSEC evasivas sin autorización explícita. Cualquier intento de subagente de generar contenido persuasivo (por ejemplo, un prompt adversarial para producir phishing) se traduce en `DENY` con incidente registrado; este comportamiento se valida mediante pruebas negativas descritas en SENTINEL.[^1]


## 8. Integración de herramientas externas (Maltego, Shodan, SpiderFoot, Nuclei, Velociraptor, etc.)

### 8.1 Estrategia general de integración

Las herramientas listadas se integran de forma homogénea siguiendo principios:

- **Encapsulación en contenedores** (donde sea viable): cada herramienta pesada (SpiderFoot, Autopsy/Sleuth Kit, Velociraptor server) se despliega en su propio contenedor con configuración declarativa, límites de recursos y volúmenes controlados.[^6][^2][^3]
- **Interfaces CLI controladas**: se invocan por CLI/SDK a través de wrappers que validan inputs y limitan flags, evitando que el LLM construya comandos arbitrarios.
- **Gestión de API keys fuera del código**: Shodan, VirusTotal, Censys, GreyNoise, Maltego y otros SaaS usan claves almacenadas en secret managers o envvars, nunca en repositorio o logs.[^4][^2]
- **Normalización de outputs**: los resultados se convierten a un esquema común (por ejemplo, JSON con `entity`, `attribute`, `source`, `confidence`) y se ingieren a Neo4j/Kùzu; las rutas a archivos crudos se hashean y registran en `payload_hash` de `ChainOfCustody`.[^1]


### 8.2 Ejemplo de mapeo por herramienta

Tabla de alto nivel para la lista solicitada:

| Herramienta | Tipo | Uso principal en AmegakureWotan |
| --- | --- | --- |
| Maltego CE | GUI/CLI de grafos SOCINT/OSINT | Análisis de relaciones persona/entidad; Huginn, Hel. Integración mediante transforms locales o export/import de grafos. |
| VirusTotal | SaaS/API | Enriquecimiento de hashes, URLs y dominios; se consume vía API desde wrappers, nunca directo desde LLM. |
| Shodan CLI | CLI/API | Búsqueda de servicios y banners en Internet; usado por Heimdall y SpiderFoot/Amass integrados.[^2] |
| Censys CLI | CLI/API | Enumeración y perfilado de servicios TLS/HTTP a escala; complementa Shodan para reconocimiento pasivo/activo. |
| GreyNoise CLI | CLI/API | Clasificación de IPs "Internet noise" vs actividad dirigida; apoya a Tyr en scoring de amenazas. |
| theHarvester | CLI | Recolección de correos, nombres, hosts desde fuentes públicas; input de Huginn y Heimdall.[^2] |
| Amass | CLI | Enumeración avanzada de subdominios y superficies de red; motor clave de Heimdall.[^2] |
| Recon‑ng | Framework CLI | Framework OSINT scriptable; usado por Huginn para SOCINT y huella corporativa. |
| SpiderFoot CLI | CLI | OSINT automatizado: 200+ módulos sobre dominios/IPs/emails; modo CLI sin GUI web para mapping de superficie.[^2][^4] |
| Nuclei | CLI | Escaneo de vulnerabilidades con plantillas; utilizado bajo RoE activa por Heimdall con límites estrictos. |
| Volatility 3 | CLI | Análisis de memoria; `dfir.memory_analyze` mediante contenedores dedicados. |
| Velociraptor | Servidor/agent | DFIR a gran escala: hunts, monitoreo de endpoints con VQL.[^3][^5][^8] |
| Autopsy/Sleuth Kit | GUI/CLI | Análisis de disco/timeline; `dfir.disk_timeline` y extracción de artefactos forenses. |


### 8.3 Scripts de bootstrap en primera instalación

El comportamiento deseado en la primera instalación de AmegakureWotan es ejecutar un bootstrap que:

1. Detecta sistema operativo y hardware (N100/8GB o superior) y configura límites de recursos para contenedores.  
2. Instala dependencias base: `git`, `docker`, `docker compose`, Python 3.13+, etc.  
3. Clona o instala binarios/paquetes de las herramientas listadas (donde las licencias y distribución lo permitan) y genera contenedores de uso interno.  
4. Solicita o carga claves API (Shodan, VirusTotal, Censys, GreyNoise, Maltego) desde un archivo cifrado o secret manager, nunca en texto plano.[^4][^2]
5. Inicializa Neo4j, Kùzu, Velociraptor (opcional) y otros servicios con configuración hardened.[^5][^3][^1]
6. Ejecuta pruebas smoke para verificar que cada herramienta responde correctamente a comandos de ejemplo y que `ChainOfCustody.verify_chain` pasa con éxito tras los primeros eventos de instalación.[^1]

La instalación se expone mediante un wrapper (`install.sh`) similar al existente en AmegakureWotan, pero extendido para cubrir la nueva lista de dependencias y servicios. 


## 9. Diseño de comportamiento determinista vs flexible

### 9.1 Zonas deterministas

Las zonas donde el comportamiento debe ser lo más determinista posible:

- **Ejecución de herramientas externas**: cada herramienta tiene contratos fijos (parámetros permitidos, límites de concurrencia, timeouts), y los wrappers MCP se encargan de construir comandos exactos recuperables desde logs y `timeline.jsonl`.[^1]
- **Playbooks SOC/DFIR**: flujos como "alerta de IOC → hunt Velociraptor → análisis Volatility → timeline Sleuth Kit → informe" se codifican como playbooks versionados que Hermes puede instanciar, pero no modificar estructuralmente sin intervención humana.[^8][^5][^3]
- **Reglas GELSI/RoE**: decisiones de `ALLOW/DENY/REQUIRE_HITL` son función de reglas estáticas y estados de RoE, no del LLM.[^1]


### 9.2 Zonas de flexibilidad controlada

Las zonas donde se permite mayor flexibilidad:

- **Selección de herramienta OSINT dentro de un conjunto**: por ejemplo, para enumerar subdominios, Hermes puede elegir entre Amass, SpiderFoot o combinaciones según la misión y restricciones de OPSEC.[^4][^2]
- **Orden de profundidad de análisis**: el LLM decide si, después del primer pass con SpiderFoot, conviene ampliar con Nuclei, Shodan o Censys, siempre dentro de las acciones permitidas por la RoE.[^2][^1]
- **Redacción y priorización en informes**: la IA resume hallazgos, aplica scoring y presenta conclusiones a analistas humanos, siempre basándose en evidencias del grafo y la cadena de custodia.[^1]

Este modelo mixto convierte a Hermes/Odin en un **triager y planificador experto** dentro de un entorno fuertemente acotado, acorde con prácticas modernas de SOC/DFIR asistidos por IA, evitando tanto el determinismo excesivamente rígido (que limita utilidad en investigación abierta) como el caos no reproducible.[^9][^1]


## 10. Patrones de implementación recomendados para los agentes Amegakure

### 10.1 Separación de capas de IO, lógica y seguridad

Para la implementación:

- Mantener el módulo `forensics.py` libre de lógica de negocio; solo cadena de custodia y verificación.[^1]
- En el MCP consolidado, separar claramente:
  - Esquemas Pydantic (validación de entrada).  
  - Handlers de negocio (deciden qué herramientas internas invocar).  
  - Adaptadores de IO (invocan CLI, SDKs, contenedores).  
  - Hooks GELSI/ChainOfCustody (registro y decisiones de política).  
- Evitar que los adaptadores CLI/SDK manejen lógica de RoE o decisiones de autorización; concentrar esto en GELSI y los handlers.[^1]


### 10.2 Idempotencia e id de operación

Cada operación OSINT/DFIR que pueda re‑intentarse debe tener un `operation_id` único, asociado a entradas en `timeline.jsonl`.  

- Wrappers MCP deben revisar si existe ya un evento con `operation_id` igual y `status=completed` antes de lanzar de nuevo la herramienta, evitando duplicación de escaneos peligrosos (Nuclei, hunts Velociraptor, etc.).[^1]
- En caso de reintento tras fallo parcial, se registra un nuevo evento con el mismo `operation_id` pero diferente `seq`, permitiendo reconstruir el historial completo.[^1]


### 10.3 Pruebas y hardening

El conjunto de pruebas descrito en SENTINEL se extiende para cubrir las nuevas herramientas y el MCP consolidado:[^1]

- **Unitarias**: validación de esquemas MCP (RoE, modos, dominios), comportamiento de GELSI ante inputs adversariales, determinismo de `ChainOfCustody` ante cambios de un bit en payload/prev_hash.[^1]
- **Integración**: aislamiento de contenedores de SpiderFoot, Velociraptor, Autopsy; verificación de que no pueden acceder a la red interna ni a otros volúmenes no autorizados.[^6][^3][^2]
- **E2E**: misiones completas con RoE autorizada y no autorizada, incluyendo operaciones dark web, hunts DFIR y verificación forense posterior desde un entorno externo con solo `timeline.jsonl` y clave de verificación.[^1]
- **Pruebas negativas de ingeniería social**: mismo set de prompts adversariales usado en SENTINEL para garantizar que ninguna ruta de ejecución permite generación de phishing o contenido persuasivo ofensivo.[^1]


## 11. Conclusión operativa

AmegakureWotan consolida AmegakureWotan y SENTINEL‑OSINT en un único ecosistema OSINT/DFIR de grado militar‑forense, manteniendo los nombres y roles de agentes ya definidos, adoptando la cadena de custodia encadenada HMAC‑SHA512 de SENTINEL como estándar global, y usando Hermes Agent como kernel de orquestación bajo la doctrina de Odin/AmegakureDojo. La plataforma integra de forma disciplinada herramientas industriales como Maltego CE, Shodan, SpiderFoot, Nuclei, Velociraptor, Volatility y Sleuth Kit, encapsulándolas tras un MCP consolidado y reforzando tanto la trazabilidad forense como la alineación con marcos legales y de cumplimiento contemporáneos.[^7][^5][^3][^2][^1]

Este documento sirve como contrato de arquitectura para los agentes Amegakure encargados de la implementación: cada sección puede convertirse en un módulo, playbook o test suite, asegurando que el código resultante respete la doctrina, minimice superficie de ataque y maximice el valor probatorio de toda operación de inteligencia y respuesta.

---

## References

1. [SENTINEL-OSINT_walkthrough.md](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/106417013/03e5c3c3-19e2-4ad2-a1e7-0eaddf0bac90/SENTINEL-OSINT_walkthrough.md?AWSAccessKeyId=ASIA2F3EMEYEYILKVNLV&Signature=s5hqLDb8dlae07PV3M5xoPu9rtE%3D&x-amz-security-token=IQoJb3JpZ2luX2VjEJX%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCXVzLWVhc3QtMSJIMEYCIQClyW5y2gLLNwCvCJh3VRzdVdRBjjArz9iXqidRY2D%2FvwIhAObhmmLt90YBfch1DP8bxwL2qiPA7N0aQE1pI2etarp7KvMECF4QARoMNjk5NzUzMzA5NzA1IgxNklo%2B31zWxoK4TCsq0AQdDQUZEqftEAZ2zAMQ14aEDmToARaFFuEzaW8hME0tguVvlW6fHiQgM9IkiH9KjwNRstx9BjfeRtiJsGSCVit7dTn%2BA7OU4Bgbon%2B6a4y5rdXX8SMw%2BOpA9ivPH%2FFPbGJIC1lesmFksPGfJBgX3n1U%2FB%2Fcxv%2FXt0iPkXyPrgQlvc9jq%2FbIsuXYJ6l2SvYUj9SmUkS%2BbqGk15PfkGbp02S%2Bd2kW%2BXDxTdDBXwv89Piathle7MGYO1LVr4EjkL28otubK%2FlLeiIR0O9%2BtxzDx3%2BatlSdY0J5n3WftItYde8%2F0BJKVfjooV73OsQhPxCgrxBbzni4O2qY9hbX10O9PyHMm3sgBuwebk7FNIcWfQYNY8hSf%2Br9yZfycQkA1ejcKsoBg9Hx92FSPtOR0Tq2jXaiMqR2sSpLCrSxEDwaPQhjWwK8sqBYsyCgO%2BjjzxktXonu37ZaNMFW6OeHWVjdKV7BQr%2F1u%2B4pQ73M%2FY9irfP0FpPPzSc27F7%2BkihSxcwQC71CohQvKQME9arf2xz9SI4Hy4Ig7tjjKqwe7MAP4j3vhPuC5FgFwjx88vqXFFaZSu5f3lXxVysoDmV7sIZqjfIah98FVFHh5JgHG%2BlIz1q5MZlul%2BObn5Q82Fh7hPILN2lAaD273q3J4gpb%2BnhtLc9RA3wvTP5oXqcc461ZPA0kqkCLcg85IkXletQY3xOLTCSevR1WIMl3EU6PgKDJwnWbupxYLluWF0zbnWyTY0zx9McHTMt9ZFNsF9rrfIqEL%2BdvLwKHWT5feD4eEwapWZFVMNb92NMGOpcBo85pQWrg9EGAmVFRiR2Y%2BiuHYrKO%2FIl0cz6Q7CrGZHb5J54%2Fi3Vc2GPPYPZK%2BCxL3mRlUVgQ4RVEdTR0eI9rmPMXC%2FpB2uUInmwiYF%2B3dBy1FmlHrC3hBW1RHU1BR7GXqXMHZ1v4nZBoh2z83R9uq%2BZ3SGnFiz9G6%2FrW7Dl%2B07bc6ljUXQrfoy4Mk8R6Gi2IdjlnIilUEA%3D%3D&Expires=1786137769) - # PROYECTO: SENTINEL-OSINT -- Plataforma OSINT/Contra-Ingenieria Social de Grado Militar-Forense
## ...

2. [SpiderFoot Cheat Sheet](https://www.cybercheatsheets.org/en/tools/spiderfoot) - OSINT automation platform correlating IPs, domains, emails, breaches, and social data from 200+ modu...

3. [Velociraptor - Digging deeper - DFRWS](https://dfrws.org/presentation/velociraptor-digging-deeper/) - Velociraptor is an advanced open source digital forensic and incident response tool that enhances yo...

4. [SpiderFoot: Automazione OSINT con 200+ Moduli per ...](https://hackita.it/articoli/spiderfoot/) - SpiderFoot è uno strumento OSINT automatizzato con oltre 200 moduli per la raccolta e correlazione d...

5. [Digital Paleontologist](https://s3.amazonaws.com/resources.osdfcon.org/presentations/2021/Mike_Cohen_Velociraptor_OSDFCon_2021.pdf)

6. [© 2020 Velocidex Enterprises](https://dfrws.org/wp-content/uploads/2021/03/DFRWS-EU-2021-Velociraptor-Digging-Deeper.pdf)

7. [Velociraptor | SIEM Documentation](https://docs.rapid7.com/insightidr/velociraptor-alerts/)

8. [Starting with Velociraptor Incident Response](https://www.youtube.com/watch?v=EA40rztSOd4) - Velociraptor IR (Incident Response) is an open-source endpoint visibility tool. You can monitor many...

9. [CyberThreat-Eval: Can Large Language Models Automate Real-World Threat Research?](https://arxiv.org/abs/2603.09452) - Analyzing Open Source Intelligence (OSINT) from large volumes of data is critical for drafting and p...

