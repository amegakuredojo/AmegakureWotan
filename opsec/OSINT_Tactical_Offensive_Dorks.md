# Dorks OSINT Tácticos y Ofensivos para Validación de Superficie Forense
**Dojo Karasugakure / Amegakure**  
**Clasificación**: CONFIDENCIAL / OPERACIONAL  

---

## 0. Reglas Operacionales de Simulación Adversaria
- Usar exclusivamente en auditorías de seguridad autorizadas, ejercicios de Red Teaming o investigaciones forenses oficiales.
- Enrutar todas las consultas a través de la red Tor mediante el pool de proxies local para evitar telemetría o bloqueos del buscador.
- Reemplazar los marcadores:
  - `<TARGET_DOMAIN>` = Dominio principal del objetivo
  - `<TARGET_ORG>` = Nombre o razón social del objetivo
  - `<TARGET_ALIAS>` = Nickname, alias o usuario del objetivo
  - `<TARGET_EXEC>` = Nombre de directivos o personas clave

---

## 1. Mapeo de Infraestructura y Superficie Expuesta

### Detección de Subdominios y Sub-activos
- `site:*.<TARGET_DOMAIN> -www` (Exclusión del host principal)
- `site:*.dev.<TARGET_DOMAIN>` (Entornos de desarrollo desprotegidos)
- `site:*.staging.<TARGET_DOMAIN>` (Entornos de pruebas de integración)
- `site:*.test.<TARGET_DOMAIN>` (Laboratorios expuestos)
- `site:*.qa.<TARGET_DOMAIN>` (Aseguramiento de calidad)
- `site:*.vpn.<TARGET_DOMAIN>` (Accesos a red privada)
- `site:*.ext.<TARGET_DOMAIN>` (Interfaces para socios externos)

### Paneles de Administración y Gestión
- `site:<TARGET_DOMAIN> inurl:admin`
- `site:<TARGET_DOMAIN> inurl:dashboard`
- `site:<TARGET_DOMAIN> inurl:panel`
- `site:<TARGET_DOMAIN> intitle:"control panel"`
- `site:<TARGET_DOMAIN> intitle:"dashboard"`
- `site:<TARGET_DOMAIN> intitle:"login" OR intitle:"signin"`
- `site:<TARGET_DOMAIN> inurl:wp-admin OR inurl:wp-login`
- `site:<TARGET_DOMAIN> inurl:cpanel OR inurl:webmail`

### Consolas de Desarrollo y Monitoreo
- `site:<TARGET_DOMAIN> inurl:jenkins` (Orquestadores de integración)
- `site:<TARGET_DOMAIN> inurl:git` (Repositorios expuestos)
- `site:<TARGET_DOMAIN> inurl:portainer` (Contenedores)
- `site:<TARGET_DOMAIN> inurl:kibana OR inurl:elasticsearch` (Logs expuestos)
- `site:<TARGET_DOMAIN> inurl:grafana` (Métricas del sistema)
- `site:<TARGET_DOMAIN> inurl:prometheus` (Monitoreo)

---

## 2. Descubrimiento de Fugas de Información y Documentos Sensibles

### Archivos de Configuración y Claves
- `site:<TARGET_DOMAIN> filetype:env` (Variables de entorno con llaves/contraseñas)
- `site:<TARGET_DOMAIN> filetype:ini OR filetype:conf`
- `site:<TARGET_DOMAIN> filetype:sql OR filetype:db OR filetype:sqlite` (Dump de bases de datos)
- `site:<TARGET_DOMAIN> filetype:log` (Registros de errores y stack traces)
- `site:<TARGET_DOMAIN> filetype:json OR filetype:yaml "aws_access_key_id"`
- `site:<TARGET_DOMAIN> filetype:xml "password"`

### Backups y Código Fuente Expuesto
- `site:<TARGET_DOMAIN> filetype:bak OR filetype:old OR filetype:temp`
- `site:<TARGET_DOMAIN> filetype:zip OR filetype:tar.gz OR filetype:rar`
- `site:<TARGET_DOMAIN> filetype:git`
- `site:<TARGET_DOMAIN> inurl:backup OR inurl:dump`

### Documentación Interna y Planos
- `site:<TARGET_DOMAIN> filetype:pdf "confidential" OR "internal use only"`
- `site:<TARGET_DOMAIN> filetype:pdf "architecture" OR "network diagram"`
- `site:<TARGET_DOMAIN> filetype:pdf "deployment" OR "installation guide"`
- `site:<TARGET_DOMAIN> filetype:pdf "security audit" OR "vulnerability assessment"`
- `site:<TARGET_DOMAIN> filetype:xlsx "contacts" OR "employees" OR "salary"`
- `site:<TARGET_DOMAIN> filetype:pptx "roadmap" OR "strategic plan"`

---

## 3. APIs y Endpoints No Documentados

### Mapeo de Swagger y OpenAPI
- `site:<TARGET_DOMAIN> inurl:swagger OR inurl:openapi`
- `site:<TARGET_DOMAIN> inurl:v1 OR inurl:v2 OR inurl:v3`
- `site:<TARGET_DOMAIN> filetype:json "swagger" OR "openapi"`
- `site:<TARGET_DOMAIN> filetype:yaml "swagger" OR "openapi"`
- `site:<TARGET_DOMAIN> inurl:graphql OR inurl:graphiql`

### Fugas en Código JavaScript del Frontend
- `site:<TARGET_DOMAIN> filetype:js "apiKey" OR "token"`
- `site:<TARGET_DOMAIN> filetype:js "eval(" OR "localStorage"`

---

## 4. Ingeniería Social y Perfilamiento de Objetivos (HUMINT)

### Exposición de Credenciales y Cuentas
- `"@<TARGET_DOMAIN>"` (Búsqueda de correos en foros externos)
- `"@<TARGET_DOMAIN>" "password" OR "contraseña"`
- `site:github.com "<TARGET_DOMAIN>" "apiKey"`
- `site:gitlab.com "<TARGET_DOMAIN>" "token"`

### Perfilamiento de Directivos y Personal Clave
- `"<TARGET_EXEC>" "<TARGET_ORG>"`
- `"<TARGET_EXEC>" site:linkedin.com/in`
- `"<TARGET_EXEC>" filetype:pdf OR filetype:docx`
- `"<TARGET_ALIAS>" site:github.com OR site:gitlab.com`
- `"<TARGET_ALIAS>" site:stackoverflow.com`
- `"<TARGET_ALIAS>" site:reddit.com`

---

## 5. Navegación e Identificación en la Red Oscura (Onion Space)

### Sitios Espejo y Leaks
- `site:*.onion "<TARGET_ORG>"`
- `site:*.onion "<TARGET_DOMAIN>"`
- `site:*.onion "leak" OR "database"`
- `site:*.onion "ransomware" OR "hack"`
- `site:*.onion "exploit" OR "zero day"`
