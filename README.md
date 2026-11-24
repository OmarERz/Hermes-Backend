# Hermes Backend

Self-hosted, personalized threat intelligence: simulated vulnerability scanning over an iTop CMDB,
correlation with threat news, a deterministic scoring engine plus an LLM judge, iTop tickets and
notification events.

## Requirements

- Python 3.12.16 and [uv](https://docs.astral.sh/uv/)
- Docker (PostgreSQL 18 + pgvector, Semgrep, test services)
- Linux or WSL2

## Development

```bash
uv sync          # install dependencies
make verify      # quality gate
make up          # local stack: writes the Docker secret files from your env file, then docker compose up
```

Copy `.env.example` to `.env` and set at least `POSTGRES_PASSWORD`, `MIGRATOR_DB_PASSWORD`, `APP_DB_PASSWORD` and
`RETENTION_DB_PASSWORD` before `make up`.

### Puerta antes del push (D-086)

Hasta después de la entrega, el CI remoto es mínimo para ahorrar minutos de GitHub Actions: en un PR a `develop` solo
corren `static`, `tests` y `commit-messages`; Schemathesis y SonarQube corren solo en PR y push a `main`; ya no hay
corrida en push a `develop` (su PR ya pasó los checks); el flujo de seguridad (`security-weekly.yml`) solo se lanza a
mano, y Dependabot no abre PR de versiones (las de seguridad siguen). Lo demás corre en tu equipo antes del push:

```bash
make prepush     # con el árbol limpio, sobre el commit que vas a publicar
```

`make prepush` (`scripts/prepush.sh`) reproduce el CI en este orden:

1. `make verify`: formato, tipos, fronteras, pruebas con la puerta de cobertura, Semgrep, KICS, Gitleaks (historia desde
   `origin/develop`, como en un PR) y pip-audit.
2. Una pila de Compose aislada, como la de los jobs de Schemathesis y ZAP: nombre de proyecto y puertos (20000–39999)
   propios de la corrida, contraseñas desechables en un directorio temporal fuera del repositorio, sin archivo de
   entorno (ninguna llave real llega a la pila), el falso de embeddings (`compose.ci.yaml`) y la documentación de la API
   activa.
3. Tokens del emulador para admin, analista y lector; `make dynamic` (Schemathesis y la suite adversarial),
   `make bruno` con los tres tokens y `make zap`.

La pila y los secretos temporales siempre se borran (`down -v`), aunque algo falle. Tarda unos 15 minutos en un equipo
de desarrollo: unos 5 de `make verify`, 7 de Schemathesis, 2 de ZAP y 1 de arrancar la pila. Usa los valores fijados
en el repositorio aunque tu entorno defina otros (imágenes de los escáneres, opciones de `make` o de pytest, carpeta de
Bruno). Si todo pasa, guarda el árbol del commit (`HEAD^{tree}`) en `.review/prepush.json` del checkout donde corrió y
agrega una línea a `.review/prepush.log` del checkout principal, que comparten todos los worktrees (archivos locales,
no versionados).

- En el equipo de desarrollo, un hook local `pre-push` (no versionado; se instala una vez con
  `bash scripts/hooks/pre-push --install`) rechaza el push de una rama `feat/*` si no hay una corrida en verde para el
  árbol de ese commit. No tiene ninguna variable ni opción propia para saltarlo, y aunque un push se salte los hooks de
  git, el merge sigue exigiendo la corrida.
- El merge a `develop` (`scripts/hooks/merge-pr`, D-081) exige esa corrida para la cabeza del PR, y que `static`,
  `tests` y `commit-messages` estén en verde.
- Cualquier commit nuevo, incluido un merge de `develop`, cambia el árbol: hay que volver a correr `make prepush`. Las
  ramas creadas antes de este cambio (por ejemplo, `feat/f15-3-worker-shutdown`) necesitan su propio `make prepush`
  después de integrar `develop`; antes de integrarlo no tienen el target, pero pueden correr
  `bash <checkout que lo tenga>/scripts/prepush.sh` desde su propio checkout.
- Los títulos de los commits los revisan el hook local `commit-msg` y, en el PR, el job `commit-messages`.

## Front de personalización

El front (React) lo construye otro equipo. Todo lo que necesita del backend está en [`FRONTEND.md`](FRONTEND.md).

## Guía de operación (español)

Esta guía es para quien instala y mantiene Hermes en un servidor propio. Todo corre con Docker Compose; los puertos
solo escuchan en `127.0.0.1`.

### 1. Instalar

1. Instala Docker (con Compose v2) y clona el repositorio.
2. Copia `.env.example` a `.env` y llena **al menos**: `POSTGRES_PASSWORD`, `MIGRATOR_DB_PASSWORD`, `APP_DB_PASSWORD`,
   `RETENTION_DB_PASSWORD` y `CURSOR_SIGNING_KEY` (mínimo 32 caracteres; genera una con
   `python -c "import secrets; print(secrets.token_urlsafe(48))"`).
3. `make up`. Escribe las llaves como archivos de Docker secrets (`.compose-secrets/`, nunca se versionan), construye
   las imágenes y levanta el servicio. En cada arranque ocurre, en orden: el aprovisionamiento de la base
   (`provision`), las migraciones (`migrate`) y la carga de los **valores de fábrica** (`bootstrap`: fórmula,
   catálogos, parámetros y fuentes por defecto). `bootstrap` solo carga lo que falta, así que repetir `make up`
   no cambia nada. Después arrancan el servicio de *embeddings* (`embeddings`, modelo local en CPU para deduplicar
   noticias, sin puerto publicado), la API (`http://127.0.0.1:8000`) y los trabajos periódicos (`workers`).
   La primera construcción descarga el modelo dentro de la imagen, fijado a un commit de Hugging Face y con el
   SHA-256 de cada archivo; al arrancar el servicio lo verifica y no arranca si algo cambió. Después no usa la red.

### 2. Llaves y conexiones

Las llaves de terceros son opcionales y van en `.env` (vacío = «no configurado»); ninguna respuesta de la API las
devuelve y los registros las enmascaran.

| Variable | Para qué |
|---|---|
| `ITOP_URL`, `ITOP_TOKEN`, `ITOP_SYSTEM_USER`, `ITOP_WEBHOOK_TOKEN` | Leer el CMDB y crear tickets en iTop; sin ellas no corren los trabajos de iTop |
| `ITOP_CONSOLE_URL` | La consola de iTop que abren las personas desde los enlaces del front y de las notificaciones; vacío = `ITOP_URL`. Hace falta cuando `ITOP_URL` es un nombre que solo resuelven los contenedores (sección 9) |
| `NVD_API_KEY` | Más cuota en NVD y consulta al diccionario CPE (sin llave solo hay candidatos locales). Sin llave, la primera carga de 90 días de NVD al arrancar tarda varios minutos y un escaneo pedido mientras tanto espera en cola |
| `DEEPSEEK_API_KEY`, `LLM_BASE_URL_JUDGE`, `LLM_BASE_URL_ANALYSTS` | Juez y analistas de IA; **la demo nunca las usa** |
| `LLM_PROVIDER`, `CLAUDE_CODE_MODEL_JUDGE`, `CLAUDE_CODE_MODEL_ANALYSTS`, `CLAUDE_CODE_EFFORT`, `CLAUDE_CODE_TIMEOUT_SECONDS` | Proveedor del juez y los analistas: `deepseek` (por defecto) o `claude-code`, la CLI de Claude Code con tu suscripción, solo en tu equipo (ver la sección 8) |
| `ABUSECH_AUTH_KEY`, `RANSOMWARELIVE_API_KEY` | Fuentes de indicadores y víctimas |
| `FIREBASE_PROJECT_ID`, `FIREBASE_CREDENTIALS_FILE` | Inicio de sesión; con `demo-hermes` solo sirve el emulador de Firebase incluido |
| `EMBEDDINGS_URL` | Servicio de *embeddings* del ciclo de noticias; por defecto `http://embeddings:8080` dentro de Compose. Vacío apaga el ciclo de noticias |
| `ITOP_ORG_ID`, `ITOP_CALLER_ID`, `ITOP_SERVICE_ID` | Quién abre los tickets en iTop (ids de la organización, la persona del sistema y el servicio); sin los dos primeros el pipeline puntúa pero no abre tickets |
| `SCAN_INTERVAL_HOURS` | Escaneo simulado programado cada N horas; `0` (por defecto) = solo a pedido (`POST /api/scans`) |
| `ADVISORY_DOMAINS` | Dominios de los que el analista de CVE puede descargar el aviso del fabricante; sin definir = la lista aprobada por defecto, vacía = ninguno |
| `CORS_ALLOWED_ORIGINS` | Orígenes exactos del front si va en otro origen (separados por comas); vacío = mismo origen |
| `API_DOCS_ENABLED` | Documentación interactiva en `/api/docs`; solo desarrollo (apagada por defecto) |

Para la pila local, `API_PORT`, `DB_PORT` y `AUTH_EMULATOR_PORT` cambian los puertos publicados en `127.0.0.1`,
`COMPOSE_SECRETS_DIR` cambia dónde se escriben los archivos de secretos y `MIGRATION_DATABASE_URL` es la conexión del
rol `migrator` para `make seed` fuera de Compose (ver `.env.example`).

El primer administrador se asigna con el rol (*custom claim*) de Firebase; con el emulador local,
`make emulator-token ROLE=admin` imprime un token de prueba. Después, un admin cambia roles con
`PUT /api/admin/users/{uid}/role`.

### 3. Datos de demostración

Con la pila arriba, `make demo` carga el inventario de ejemplo, un par de CVE con su software, noticias ya
analizadas, un indicador y corre **un ciclo completo**: escaneo simulado → correlación → puntuación → reglas de
tickets. Deja evaluaciones, tickets pendientes en el *outbox* de iTop y eventos de notificación, así que todas las
pantallas del front tienen datos. No usa red ni gasta tokens: el juez es un doble que registra un solo motivo
aceptado. Las operaciones de iTop quedan guardadas como `failed` («demo data: never sent to iTop») en la misma
transacción, así que el trabajador del *outbox* nunca las envía aunque iTop esté configurado, y la demo **se niega a
correr** si la base ya tiene activos que no son de la demo. Úsala solo en una instalación de pruebas: los eventos de
notificación sí son filas reales, así que no cambies el consumidor a Slack con datos de demostración. Los tickets llevan ids `DEMO-n`: si iTop está configurado, la sincronización los consultará y solo registrará que no existen. Repetirlo no
duplica datos, tickets ni eventos, y sin cambios no vuelve a evaluar.
Para ver los eventos: `docker compose exec api python -m core.devtools.admin events`.

**Guion de punta a punta (unos 10 minutos).**

1. `make up` y espera a que `docker compose ps` muestre `api` y `workers` en `running` (F-01).
2. `make demo` y lee el resumen (activos, hallazgos, evaluaciones, tickets, eventos) (F-02).
3. Obtén un token de administrador local con `make emulator-token ROLE=admin`.
4. Recorre las vistas con ese token: vulnerabilidades (`/api/vulnerabilities`), recomendaciones y su desglose
   (`/api/recommendations`, `/api/assessments/{id}/breakdown`), tickets (`/api/tickets`), alertas (`/api/alerts`),
   corridas (`/api/runs`), fuentes (`/api/sources`) y configuración (`/api/config`).
5. Cambia un parámetro de la fórmula o la sensibilidad desde `/api/config` y comprueba la nueva versión en
   `/api/config/versions`.
6. Verifica la colección de Bruno de la demo (exige datos en cada lista con `demoMinItems=1`):
   `cd bruno && npx @usebruno/cli run f13-1-demo --env local --env-var token=<token> --env-var demoMinItems=1`.

### 4. Salud y registros

- `curl -s http://127.0.0.1:8000/api/health` responde `{"status":"ok"}` sin autenticación.
- `docker compose ps` muestra el estado; `provision`, `migrate` y `bootstrap` terminan en `exited (0)` por diseño.
- `docker compose logs -f api workers` sigue los registros (JSON, una línea por evento, con las llaves enmascaradas).
- Si el servicio de *embeddings* cae, el ciclo de noticias lo anota («news deduplication skipped») y deja los
  artículos guardados sin agrupar; el siguiente ciclo los agrupa cuando el servicio vuelve.
- Las métricas, las fuentes caídas y la escalera del juez están en `GET /api/metrics` y `GET /api/sources`.

### 5. Respaldo y restauración

Los datos viven en el volumen `hermes_db_data` (PostgreSQL).

```bash
make backup                      # backups/hermes-AAAAMMDD-HHMMSS.dump (formato personalizado de pg_dump)
# restaurar (detén antes lo que escribe en la base):
docker compose stop api workers
docker compose exec -T db pg_restore -U hermes -d hermes --clean --if-exists < backups/hermes-....dump
docker compose start api workers
```

Guarda los respaldos fuera del servidor y prueba la restauración de vez en cuando. `docker compose down -v` **borra el
volumen**: no lo uses en producción.

### 6. Pasar las notificaciones a Slack

Las notificaciones salen como eventos en la tabla `notification_event`; el consumidor por defecto es `log`. Cuando el
módulo de Slack (otro equipo) esté integrado (F11), sus llaves `SLACK_BOT_TOKEN` y `SLACK_APP_TOKEN` se agregarán
a `compose.yaml` junto con el módulo. El cambio de consumidor es entonces un parámetro que un admin edita
(`PUT /api/config` con `{"expected_version": <versión actual>, "changes": {"notifications.consumer": "slack"}}`, o la
pantalla de configuración); los eventos pendientes se entregan sin perderse y volver a `log` es repetir el cambio.
Hasta entonces el único consumidor disponible es `log`.

### 7. Proxy inverso: límites por IP y tamaño de petición

La API no limita la frecuencia de peticiones por sí misma: en producción pon un proxy inverso (nginx o Caddy) delante,
con TLS, un límite de peticiones por IP y un tamaño máximo de petición (la API rechaza cuerpos de más de 1 MiB con
413, pero conviene cortarlos antes). Publica solo el proxy y deja el puerto 8000 de la API en `127.0.0.1`, como ya lo
hace `compose.yaml`.

La API ya envía `Strict-Transport-Security` (un año) y no envía el encabezado `server`; en nginx agrega
`server_tokens off;` para que el proxy tampoco anuncie su versión y **no** agregues otro `Strict-Transport-Security`
(saldría duplicado). `includeSubDomains` está apagado por defecto: actívalo con `HSTS_INCLUDE_SUBDOMAINS=true` solo si
la API tiene su propio nombre de host, porque obliga al navegador a usar HTTPS durante un año en todos los subdominios
del host que la sirve. Los límites de memoria y CPU
de cada servicio no vienen en `compose.yaml` porque dependen del equipo y de la carga: agrégalos (`mem_limit`,
`cpus`) según tu instalación.

Ejemplo mínimo con nginx (ajusta el dominio, los certificados y los límites a tu uso):

```nginx
limit_req_zone $binary_remote_addr zone=hermes_api:10m rate=10r/s;

server {
    listen 443 ssl;
    server_name hermes.ejemplo.local;
    server_tokens off;
    ssl_certificate     /etc/nginx/tls/hermes.crt;
    ssl_certificate_key /etc/nginx/tls/hermes.key;

    client_max_body_size 1m;

    location /api/ {
        limit_req zone=hermes_api burst=20 nodelay;
        limit_req_status 429;
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;  # sobrescribe lo que mande el cliente
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffering off;  # el progreso del escaneo llega por eventos del servidor (SSE)
    }
}
```

Con Caddy, `request_body { max_size 1MB }` y un módulo de límite de frecuencia (p. ej. `caddy-ratelimit`) cumplen lo
mismo.

Cada línea de log de la API que pertenece a una petición lleva `request_id`, `client`, `method`, `path` (sin la cadena
de consulta) y, con un token válido, `user` (el uid de Firebase, nunca el correo); cada respuesta devuelve el mismo id
en `X-Request-ID` (lo genera siempre la API; para cruzarlo con el log del proxy, agrega `$upstream_http_x_request_id`
a su `log_format`). Para que `client` sea la IP real y no la del proxy, pon la dirección con la que el proxy llega a la
API en `FORWARDED_ALLOW_IPS`: una lista explícita de los proxies de confianza, nunca `*`. Con nginx en el mismo equipo
llegando a `127.0.0.1:8000`, es la puerta de enlace de la red de Compose del proyecto (no la de `docker0`): consúltala con
`docker network inspect hermes_default --format '{{(index .IPAM.Config 0).Gateway}}'`. El proxy de entrada debe **sobrescribir** `X-Forwarded-For` con la dirección que
ve (`$remote_addr`, como en el ejemplo), no agregarla a la que mande el cliente: si no, el cliente podría escribir su
propia IP en los logs.

### 8. Pruebas con lotes reales usando Claude (`LLM_PROVIDER=claude-code`)

Por ahora el juez y los analistas pueden usar **Claude con tu suscripción** a través de la CLI de Claude Code en modo no
interactivo (D-084), en lugar de DeepSeek. La CLI y tu sesión viven en tu equipo, no en las imágenes: con
`claude-code`, el trabajador de Compose deja apagados el juez y los analistas (lo anota en el registro). Para probar
con lotes reales, el trabajador corre **en tu equipo**, contra la base de la pila de Compose:

1. Instala Claude Code, inicia sesión con tu cuenta (`claude`, luego `/login`) y comprueba `claude auth status`
   (`"loggedIn": true`). `claude` debe estar en el `PATH`.
2. Levanta la pila (`make up`) y, si quieres datos de ejemplo, `make demo`.
3. `make worker-host`. Detiene el trabajador del contenedor (solo debe correr uno), publica el servicio de
   *embeddings* en `127.0.0.1:${EMBEDDINGS_PORT:-8081}` (`compose.host.yaml`) y corre `python -m workers` en tu equipo
   como el rol `app`, con las llaves de `.compose-secrets/`. Lo demás sale de `.env`, como siempre. Si una URL de
   `.env` solo la resuelven los contenedores (p. ej. `ITOP_URL` con `host.docker.internal`), pásala al llamar:
   `ITOP_URL=http://127.0.0.1:8080 make worker-host`.
4. Pide un escaneo (`POST /api/scans`) y sigue el registro: cada llamada deja una línea `claude-code call` con el modelo,
   la latencia, los tokens y el costo que estima la CLI.
5. Al terminar, `Ctrl+C` (puede tardar hasta que acabe el trabajo en curso) y `docker compose start workers` para
   volver al trabajador del contenedor; `make up` devuelve el servicio de *embeddings* a su red interna.

Ajustes (todos opcionales): `CLAUDE_CODE_MODEL_JUDGE` (por defecto `opus`) y `CLAUDE_CODE_MODEL_ANALYSTS` (por defecto
`sonnet`) aceptan un alias o el nombre completo de un modelo; `CLAUDE_CODE_EFFORT` (`low` … `max`, por defecto
`medium`) y `CLAUDE_CODE_TIMEOUT_SECONDS` (por defecto 300). Con `LLM_PROVIDER=deepseek make worker-host` el mismo
trabajador en tu equipo usa DeepSeek.

Qué conviene saber:

- **Cada llamada consume los límites de uso de tu plan.** Un ciclo con muchos CVE o grupos hace muchas llamadas (el
  juez hace una por turno). Si se alcanza el límite, esas llamadas fallan y el pipeline sigue sin juez (puntuación base)
  y deja los análisis en la cola de errores, como cuando el proveedor no responde.
- El costo que reporta la CLI es un equivalente de la API: la suscripción no lo cobra. El presupuesto diario sigue
  contando los tokens con la tabla de precios configurada, así que sigue limitando cuántas llamadas se hacen al día.
- La CLI corre sin herramientas, sin servidores MCP, sin tus ajustes ni tu `CLAUDE.md`, sin guardar la sesión y en una
  carpeta temporal vacía: el modelo solo puede responder. Recibe un entorno mínimo (`PATH`, `HOME`, idioma, proxy):
  nunca las contraseñas de la base, Firebase, iTop ni DeepSeek, y nunca `ANTHROPIC_API_KEY`, que cobraría a una cuenta
  de la API en lugar de usar tu suscripción.
- La salida pasa por las mismas tres capas de validación que con DeepSeek, y las pruebas automáticas nunca llaman a la
  CLI real.

### 9. iTop persistente con su consola web (D-085)

`compose.itop.yaml` levanta iTop 3.2.2 (proyecto `hermes-itop`) con su base MariaDB, su cron y la extensión de Hermes
(los cinco atributos de seguridad en cada CI y el perfil de mínimo privilegio del backend). Es un proyecto aparte: sus
datos sobreviven a `make up` y a `docker compose down` de Hermes. Ningún contenedor corre como root ni con
capacidades extra; la consola escucha en `127.0.0.1:${ITOP_PORT:-8080}`.

**Primera vez**

1. Si Hermes ya tiene `ITOP_WEBHOOK_TOKEN` en `.env` (un valor largo al azar), corre antes `make compose-secrets` para
   que iTop use el mismo token en su *webhook*.
2. `make itop-up ITOP_LINK=1`. Escribe los secretos de iTop en `.compose-secrets/itop_*` y crea la red compartida con
   Hermes. Las contraseñas de MariaDB y del administrador se generan al azar la primera vez y nunca se reemplazan; la
   del usuario `admin` está en `.compose-secrets/itop_admin_password`. Para elegirla tú, corre
   `ITOP_ADMIN_PASSWORD='…' make itop-secrets` **antes** del primer `make itop-up`.
3. `make itop-install ITOP_LINK=1`: instala iTop, compila el modelo y crea lo que Hermes necesita (organización
   `Demo-Lab`, persona «Hermes System», usuarios y *webhook*). Repetirlo no cambia nada; después de actualizar el
   repositorio vuelve a correrlo: si la extensión cambió, recompila el modelo sin tocar los datos.
4. Entra a `http://127.0.0.1:8080` como `admin` (la consola está en español). Puedes cambiar la contraseña en «Mi
   cuenta»; el archivo de secretos solo se usa en la instalación.
5. Carga el inventario: `make itop-seed` (simulacro) y `make itop-seed APPLY=1` (escribe).

**Conectar Hermes con iTop**

Con la red compartida, los contenedores de Hermes llegan a iTop como `http://itop:8080` y el *webhook* de iTop llega a
la API como `http://api:8000`. En `.env`:

```
COMPOSE_FILE=compose.yaml:compose.itop-link.yaml
ITOP_URL=http://itop:8080
# los enlaces que abren las personas: http://itop:8080 solo lo resuelven los contenedores
ITOP_CONSOLE_URL=http://127.0.0.1:8080
ITOP_WEBHOOK_URL=http://api:8000/api/itop/webhook
ITOP_TOKEN=<lo que imprime make itop-token>
ITOP_WEBHOOK_TOKEN=<un valor largo al azar>
# ids de iTop de la organización, de la persona «Hermes System» y del servicio de los tickets
ITOP_ORG_ID=…
ITOP_CALLER_ID=…
ITOP_SERVICE_ID=…
```

Después `make compose-secrets`, `make itop-install ITOP_LINK=1` (aplica la URL y el token del *webhook* a los objetos
ya creados) y `make up`. Sin la red compartida, usa `ITOP_URL=http://host.docker.internal:8080` y deja
`ITOP_WEBHOOK_URL` sin definir (por defecto apunta a la API publicada en el equipo). Para el trabajador en tu equipo
(sección 8): `ITOP_URL=http://127.0.0.1:8080 make worker-host`.

**Usuarios que crea Hermes en iTop**

| Usuario | Para qué |
|---|---|
| `hermes-rest` | El token del backend (`ITOP_TOKEN`): lee el CMDB, crea y actualiza tickets y solo los **reabre** (`ev_reopen`); asignar, resolver y cerrar lo hacen las personas en la consola. Ojo: la API REST de iTop no revisa los estímulos de un perfil, solo el permiso de modificar; lo que limita al backend a `ev_reopen` es su propio *outbox*. `make itop-rotate-token` le da un token nuevo (luego actualiza `ITOP_TOKEN` y corre `make compose-secrets` y `make up`) |
| `hermes-seed` | Administrador por REST para el cargador de inventario. Está **desactivado** y sin token salvo mientras corre `make itop-seed`, que lo activa con un token nuevo y lo desactiva al terminar, aunque falle |
| `hermes-cron` | Administrador local con el que corre el cron de iTop (notificaciones, SLA, tareas asíncronas, respaldo nocturno). Su contraseña solo está en un archivo del volumen de datos |

**Respaldo y restauración**

- Los datos viven en los volúmenes `hermes-itop_itop_db` (base), `_itop_conf` (configuración), `_itop_data` (datos y
  tokens) e `_itop_env` (modelo compilado). `make itop-down` detiene iTop y **conserva** todo;
  `make itop-destroy CONFIRM=yes` borra los volúmenes.
- `make itop-backup` deja `backups/itop-<fecha>.tar.gz`: el volcado de la base más las carpetas `conf` y `data`. Contiene
  la contraseña de la base, la llave de cifrado de iTop y los tokens: guárdalo como un secreto.
- `make itop-restore BACKUP=backups/itop-<fecha>.tar.gz` reemplaza la base y los archivos por los del respaldo y
  recompila el modelo. En otra máquina, copia también los archivos `.compose-secrets/itop_*` antes de `make itop-up`,
  porque la configuración respaldada guarda la contraseña de la base de esa instalación.
- iTop además hace su propio respaldo cada noche (23:30) dentro de su volumen de datos; `make itop-backup` no lo
  incluye.

**Salud y registros**

- `docker compose -f compose.itop.yaml --profile itop ps` y `… logs -f itop itop-cron`.
- Estado de las tareas del cron: `docker compose -f compose.itop.yaml --profile itop exec itop-cron php
  /var/www/html/webservices/cron.php --param_file=/var/www/html/data/hermes-cron.params --status_only=1`.
- Las contraseñas de MariaDB solo las usan los contenedores (nunca se publican). Cambiarlas después de instalar pide
  pasos a mano: `ALTER USER` en MariaDB y el mismo valor en `db_pwd` de `conf/production/config-itop.php`.

## License

Apache-2.0
