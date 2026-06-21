# Dorks OSINT defensivos para hardening autorizado

## 0. Reglas de uso
- Usar solo sobre activos propios, dominios autorizados, marcas propias, entornos de laboratorio o personas evaluadas con consentimiento documentado.
- Sustituir:
  - `<ORG>` = nombre de organización
  - `<DOMAIN>` = dominio principal
  - `<SUB>` = subdominio
  - `<BRAND>` = marca comercial
  - `<EXEC>` = directivo/persona evaluada con consentimiento
  - `<EMAIL_DOMAIN>` = dominio de correo corporativo
  - `<PRODUCT>` = producto o app
  - `<PHONE>` = número corporativo autorizado
  - `<ADDR>` = dirección corporativa pública
  - `<REPOORG>` = organización en GitHub/GitLab

---

## 1. Operadores base por motor

### Google / Brave / Startpage
- `site:<DOMAIN>`
- `site:<DOMAIN> -www`
- `site:*. <DOMAIN>`
- `filetype:pdf`
- `filetype:docx`
- `filetype:xlsx`
- `filetype:pptx`
- `intitle:"index of"`
- `intitle:"login"`
- `inurl:admin`
- `inurl:portal`
- `inurl:api`
- `inurl:docs`
- `inurl:swagger`
- `inurl:openapi`
- `"exact phrase"`
- `-exclude`
- `(term1 OR term2)`

### Bing
- `site:<DOMAIN> filetype:pdf`
- `site:<DOMAIN> inurl:api`
- `" <ORG> " (security OR privacy OR compliance)`
- `" <BRAND> " (apk OR ipa OR app)`
- `" <ORG> " (vpn OR sso OR okta)`

### DuckDuckGo
- `" <ORG> " site:<DOMAIN>`
- `" <BRAND> " filetype:pdf`
- `" <ORG> " "security.txt"`
- `" <ORG> " "robots.txt"`
- `" <DOMAIN> " "swagger"`

### Yandex
- `site:<DOMAIN> pdf`
- `site:<DOMAIN> xlsx`
- `site:<DOMAIN> api`
- `" <ORG> " "login"`
- `" <BRAND> " "documentation"`

---

## 2. Asset discovery autorizado

### Dominio y subdominios visibles
- `site:<DOMAIN>`
- `site:<DOMAIN> -www`
- `site:dev.<DOMAIN>`
- `site:staging.<DOMAIN>`
- `site:test.<DOMAIN>`
- `site:api.<DOMAIN>`
- `site:docs.<DOMAIN>`
- `site:status.<DOMAIN>`
- `site:support.<DOMAIN>`
- `site:help.<DOMAIN>`
- `site:careers.<DOMAIN>`
- `site:blog.<DOMAIN>`
- `site:cdn.<DOMAIN>`
- `site:m.<DOMAIN>`
- `site:mobile.<DOMAIN>`

### Marca y propiedades relacionadas
- `"<ORG>" "<DOMAIN>"`
- `"<BRAND>" "<DOMAIN>"`
- `"<ORG>" "status page"`
- `"<ORG>" "developer portal"`
- `"<ORG>" "api documentation"`
- `"<ORG>" "open source"`
- `"<ORG>" "GitHub"`
- `"<ORG>" "GitLab"`
- `"<ORG>" "Bitbucket"`
- `"<ORG>" "docker"`
- `"<ORG>" "npm"`
- `"<ORG>" "pypi"`

### Infraestructura pública documentada
- `site:<DOMAIN> ("AWS" OR "Azure" OR "GCP")`
- `site:<DOMAIN> ("CloudFront" OR "S3" OR "Blob Storage")`
- `site:<DOMAIN> ("Fastly" OR "Akamai" OR "Cloudflare")`
- `site:<DOMAIN> ("status" OR "uptime" OR "incident")`
- `site:<DOMAIN> ("vpn" OR "sso" OR "okta" OR "entra")`
- `site:<DOMAIN> ("grafana" OR "kibana" OR "jenkins")`
- `site:<DOMAIN> ("jira" OR "confluence" OR "wiki")`

---

## 3. Documentos expuestos en alcance propio

### PDFs y políticas
- `site:<DOMAIN> filetype:pdf`
- `site:<DOMAIN> filetype:pdf ("internal" OR "confidential" OR "draft")`
- `site:<DOMAIN> filetype:pdf ("architecture" OR "network" OR "runbook")`
- `site:<DOMAIN> filetype:pdf ("playbook" OR "incident response")`
- `site:<DOMAIN> filetype:pdf ("SSO" OR "VPN" OR "MFA")`
- `site:<DOMAIN> filetype:pdf ("onboarding" OR "employee handbook")`
- `site:<DOMAIN> filetype:pdf ("disaster recovery" OR "BCP")`
- `site:<DOMAIN> filetype:pdf ("security assessment" OR "penetration test")`

### Office docs
- `site:<DOMAIN> filetype:docx`
- `site:<DOMAIN> filetype:xlsx`
- `site:<DOMAIN> filetype:pptx`
- `site:<DOMAIN> (filetype:doc OR filetype:docx) ("internal use only")`
- `site:<DOMAIN> (filetype:xls OR filetype:xlsx) ("inventory" OR "contacts")`
- `site:<DOMAIN> (filetype:ppt OR filetype:pptx) ("roadmap" OR "QBR")`
- `site:<DOMAIN> (filetype:csv OR filetype:tsv) ("report" OR "export")`

### Backups y artefactos permitidos para revisión propia
- `site:<DOMAIN> (filetype:bak OR filetype:old OR filetype:zip)`
- `site:<DOMAIN> (filetype:sql OR filetype:db OR filetype:sqlite)`
- `site:<DOMAIN> (filetype:env OR filetype:ini OR filetype:conf)`
- `site:<DOMAIN> (filetype:log OR filetype:txt) ("error" OR "stack trace")`
- `site:<DOMAIN> (filetype:yml OR filetype:yaml OR filetype:json)`

---

## 4. Portales y superficies visibles

### Acceso y autenticación
- `site:<DOMAIN> intitle:"login"`
- `site:<DOMAIN> inurl:login`
- `site:<DOMAIN> inurl:signin`
- `site:<DOMAIN> inurl:sso`
- `site:<DOMAIN> inurl:auth`
- `site:<DOMAIN> inurl:oauth`
- `site:<DOMAIN> inurl:saml`
- `site:<DOMAIN> ("forgot password" OR "reset password")`
- `site:<DOMAIN> ("MFA" OR "2FA")`

### Consolas, paneles, dashboards
- `site:<DOMAIN> (inurl:admin OR inurl:dashboard OR inurl:portal)`
- `site:<DOMAIN> ("control panel" OR "admin console")`
- `site:<DOMAIN> ("grafana" OR "kibana" OR "jenkins")`
- `site:<DOMAIN> ("jira" OR "confluence")`
- `site:<DOMAIN> ("swagger ui" OR "openapi")`
- `site:<DOMAIN> ("api reference" OR "developer docs")`

### Soporte y service desk
- `site:<DOMAIN> ("support" OR "help center" OR "knowledge base")`
- `site:<DOMAIN> ("ticket" OR "service desk")`
- `site:<DOMAIN> ("status" OR "incident history")`
- `site:<DOMAIN> ("maintenance" OR "scheduled downtime")`

---

## 5. APIs y documentación técnica propias

### Descubrimiento de APIs
- `site:<DOMAIN> inurl:api`
- `site:<DOMAIN> inurl:v1`
- `site:<DOMAIN> inurl:v2`
- `site:<DOMAIN> ("api documentation" OR "api reference")`
- `site:<DOMAIN> ("swagger" OR "openapi" OR "postman")`
- `site:<DOMAIN> filetype:json ("openapi" OR "swagger")`
- `site:<DOMAIN> filetype:yaml ("openapi" OR "swagger")`
- `site:<DOMAIN> ("graphql" OR "graphiql")`

### SDKs, repos y paquetes
- `"<ORG>" site:github.com`
- `site:github.com/<REPOORG>`
- `site:gitlab.com "<ORG>"`
- `site:npmjs.com "<ORG>"`
- `site:pypi.org "<ORG>"`
- `site:hub.docker.com "<ORG>"`
- `site:mvnrepository.com "<ORG>"`
- `site:rubygems.org "<ORG>"`

---

## 6. Apps móviles y distribución oficial

### Android / iOS / artefactos
- `"<BRAND>" ("apk" OR "android app")`
- `"<BRAND>" ("ipa" OR "ios app")`
- `site:play.google.com "<BRAND>"`
- `site:apps.apple.com "<BRAND>"`
- `site:<DOMAIN> ("download apk" OR "mobile app")`
- `site:<DOMAIN> ("AndroidManifest" OR "deep link")`
- `site:<DOMAIN> ("universal link" OR "app link")`
- `site:<DOMAIN> ("release notes" OR "changelog")`

### MDM y enterprise mobility visibles
- `site:<DOMAIN> ("intune" OR "workspace one" OR "mobileiron")`
- `site:<DOMAIN> ("mdm" OR "mam")`
- `site:<DOMAIN> ("company portal" OR "device enrollment")`

---

## 7. Correo, identidad y branding

### Huella de correo y dominios
- `"<EMAIL_DOMAIN>"`
- `site:<DOMAIN> ("@<EMAIL_DOMAIN>")`
- `site:<DOMAIN> ("security.txt" OR "contact")`
- `site:<DOMAIN> ("SPF" OR "DKIM" OR "DMARC")`
- `"<ORG>" ("MX" OR "mail server")`
- `"<ORG>" ("support email" OR "abuse" OR "security@")`

### SSO e identidad
- `site:<DOMAIN> ("Okta" OR "Entra ID" OR "Azure AD" OR "Ping")`
- `site:<DOMAIN> ("single sign-on" OR "identity provider")`
- `site:<DOMAIN> ("SAML" OR "OIDC" OR "OAuth")`

### Brand abuse / typosquatting monitoring
- `"<BRAND>" -site:<DOMAIN>`
- `"<BRAND>" ("login" OR "support" OR "account") -site:<DOMAIN>`
- `"<BRAND>" ("coupon" OR "promo" OR "giveaway") -site:<DOMAIN>`
- `"<BRAND>" ("apk" OR "download") -site:<DOMAIN>`
- `"<BRAND>" ("telegram" OR "discord" OR "whatsapp") -site:<DOMAIN>`

---

## 8. Riesgo humano en alcance autorizado

### Presencia profesional
- `"<EXEC>" site:linkedin.com/in`
- `"<EXEC>" site:github.com`
- `"<EXEC>" site:researchgate.net`
- `"<EXEC>" site:scholar.google.com`
- `"<EXEC>" ("speaker" OR "webinar" OR "conference")`
- `"<EXEC>" ("bio" OR "profile")`
- `"<EXEC>" ("email" OR "contact")`

### Exposición corporativa no sensible
- `"<EXEC>" "<ORG>"`
- `"<EXEC>" site:<DOMAIN>`
- `"<EXEC>" ("press release" OR "interview")`
- `"<EXEC>" ("pdf" OR "pptx")`
- `"<EXEC>" ("board" OR "leadership" OR "team")`

### Metadatos y publicaciones propias
- `site:<DOMAIN> filetype:pdf "<EXEC>"`
- `site:<DOMAIN> filetype:pptx "<EXEC>"`
- `site:<DOMAIN> filetype:docx "<EXEC>"`
- `site:<DOMAIN> ("author" OR "prepared by") "<EXEC>"`

### Reclutamiento y estructura interna visible
- `site:<DOMAIN> ("careers" OR "jobs")`
- `site:<DOMAIN> ("SOC analyst" OR "DevSecOps" OR "IAM engineer")`
- `site:<DOMAIN> ("Okta" OR "Kubernetes" OR "AWS") "job"`
- `site:<DOMAIN> ("senior security engineer" OR "red team")`
- `site:<DOMAIN> ("remote" OR "hybrid") "security"`

---

## 9. SOCMINT defensivo no intrusivo

### Marca y comunidad
- `"<BRAND>" site:x.com`
- `"<BRAND>" site:reddit.com`
- `"<BRAND>" site:youtube.com`
- `"<BRAND>" site:tiktok.com`
- `"<BRAND>" site:facebook.com`
- `"<BRAND>" site:instagram.com`
- `"<BRAND>" ("outage" OR "broken" OR "down")`
- `"<BRAND>" ("phishing" OR "scam" OR "fake")`
- `"<BRAND>" ("telegram" OR "discord")`

### Incidentes y abuso de marca
- `"<ORG>" ("breach" OR "leak" OR "incident")`
- `"<BRAND>" ("credential" OR "password reset")`
- `"<BRAND>" ("impersonation" OR "fake support")`
- `"<BRAND>" ("malware" OR "trojanized app")`
- `"<BRAND>" ("spoof" OR "clone site")`

### Narrativas y desinformación
- `"<ORG>" ("rumor" OR "hoax" OR "misinformation")`
- `"<BRAND>" ("deepfake" OR "fake announcement")`
- `"<ORG>" ("telegram" OR "reddit") ("leak" OR "hack")`

---

## 10. Infraestructura documental secundaria

### Portales de terceros legítimos relacionados con la organización
- `"<ORG>" site:statuspage.io`
- `"<ORG>" site:atlassian.net`
- `"<ORG>" site:zendesk.com`
- `"<ORG>" site:freshdesk.com`
- `"<ORG>" site:notion.site`
- `"<ORG>" site:readme.io`
- `"<ORG>" site:postman.com`
- `"<ORG>" site:slack.com`

### Presentaciones y materiales
- `"<ORG>" site:slideshare.net`
- `"<ORG>" filetype:pptx`
- `"<ORG>" filetype:pdf "architecture"`
- `"<ORG>" filetype:pdf "case study"`
- `"<ORG>" filetype:pdf "implementation guide"`

---

## 11. Búsquedas por tipo de fuga documental propia

### Arquitectura / operación
- `site:<DOMAIN> filetype:pdf ("architecture" OR "network diagram")`
- `site:<DOMAIN> filetype:pdf ("runbook" OR "playbook")`
- `site:<DOMAIN> filetype:pdf ("deployment guide" OR "operations guide")`
- `site:<DOMAIN> filetype:pdf ("disaster recovery" OR "BCP")`

### Terceros y cumplimiento
- `site:<DOMAIN> filetype:pdf ("SOC 2" OR "ISO 27001" OR "PCI DSS")`
- `site:<DOMAIN> filetype:pdf ("DPA" OR "subprocessor")`
- `site:<DOMAIN> filetype:pdf ("vendor" OR "supplier")`
- `site:<DOMAIN> filetype:pdf ("privacy impact assessment")`

### Datos de contacto corporativos
- `site:<DOMAIN> ("support@" OR "security@" OR "abuse@")`
- `site:<DOMAIN> ("press@" OR "media@")`
- `site:<DOMAIN> ("office" OR "headquarters")`
- `site:<DOMAIN> ("phone" OR "contact us")`

---

## 12. Hardening de superficie humana

### Evaluación de exposición profesional consentida
- `"<EXEC>" "<ORG>" filetype:pdf`
- `"<EXEC>" ("resume" OR "cv")`
- `"<EXEC>" ("speakerdeck" OR "slideshare")`
- `"<EXEC>" ("github" OR "gitlab")`
- `"<EXEC>" ("patent" OR "publication")`
- `"<EXEC>" ("webinar" OR "conference talk")`

### Correlación de roles y funciones
- `"<EXEC>" ("CISO" OR "CTO" OR "Security Engineer")`
- `"<EXEC>" ("team" OR "leadership" OR "about us")`
- `"<EXEC>" ("incident response" OR "cloud" OR "identity")`

### Higiene de publicaciones
- `site:<DOMAIN> "<EXEC>" ("email" OR "@")`
- `site:<DOMAIN> "<EXEC>" ("phone" OR "mobile")`
- `site:<DOMAIN> "<EXEC>" ("bio" OR "about")`
- `site:<DOMAIN> "<EXEC>" ("calendar" OR "schedule")`

---

## 13. Consultas académicas y doctrinales PDF

### Doctrina OSINT / SOCMINT
- `site:gov filetype:pdf "open source intelligence"`
- `site:mil filetype:pdf OSINT`
- `site:gov filetype:pdf SOCMINT`
- `site:nato.int filetype:pdf OSINT`
- `site:cia.gov filetype:pdf OSINT`
- `site:dni.gov filetype:pdf OSINT`
- `site:gov filetype:pdf "publicly available information" intelligence`

### Revisión sistemática y papers
- `site:springer.com OSINT "systematic review"`
- `site:mdpi.com OSINT SOCMINT review`
- `site:tandfonline.com OSINT artificial intelligence`
- `site:edu filetype:pdf OSINT syllabus`
- `site:edu filetype:pdf "Bellingcat" investigation`
- `site:gov filetype:pdf "analyst note" OSINT`

---

## 14. Plantillas por objetivo

### Objetivo: inventario de activos públicos
- `site:<DOMAIN>`
- `site:<DOMAIN> -www`
- `"<ORG>" "<DOMAIN>"`
- `"<BRAND>" site:<DOMAIN>`
- `"<ORG>" ("developer portal" OR "api reference")`

### Objetivo: exposición documental
- `site:<DOMAIN> filetype:pdf`
- `site:<DOMAIN> filetype:docx`
- `site:<DOMAIN> filetype:xlsx`
- `site:<DOMAIN> ("internal" OR "draft" OR "confidential")`

### Objetivo: hardening humano consentido
- `"<EXEC>" "<ORG>"`
- `"<EXEC>" site:linkedin.com/in`
- `"<EXEC>" ("speaker" OR "conference")`
- `site:<DOMAIN> "<EXEC>"`

### Objetivo: abuso de marca
- `"<BRAND>" -site:<DOMAIN>`
- `"<BRAND>" ("login" OR "support") -site:<DOMAIN>`
- `"<BRAND>" ("scam" OR "phishing" OR "fake")`
- `"<BRAND>" ("apk" OR "app download") -site:<DOMAIN>`

---

## 15. Normalización de resultados

Para cada hallazgo, registrar:
- query exacta
- fecha/hora UTC
- motor de búsqueda
- URL
- título
- tipo de activo
- sensibilidad aparente
- dueño interno
- estado (válido / irrelevante / duplicado)
- acción de hardening
- evidencia archivada

---

## 16. Priorización sugerida

### P1
- documentos con arquitectura
- runbooks
- portales de identidad
- documentación API pública no inventariada
- referencias a MFA/SSO
- datos corporativos publicados fuera de control

### P2
- presentaciones técnicas
- ofertas de empleo que revelan stack
- páginas de soporte no inventariadas
- mirrors, micrositios y dominios de marca

### P3
- perfiles profesionales
- referencias mediáticas
- material académico
- menciones indirectas a proveedores
