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
   no cambia nada. Después arrancan la API (`http://127.0.0.1:8000`) y los trabajos periódicos (`workers`).

### 2. Llaves y conexiones

Las llaves de terceros son opcionales y van en `.env` (vacío = «no configurado»); ninguna respuesta de la API las
devuelve y los registros las enmascaran.

| Variable | Para qué |
|---|---|
| `ITOP_URL`, `ITOP_TOKEN`, `ITOP_SYSTEM_USER`, `ITOP_WEBHOOK_TOKEN` | Leer el CMDB y crear tickets en iTop; sin ellas no corren los trabajos de iTop |
| `NVD_API_KEY` | Más cuota en NVD y consulta al diccionario CPE (sin llave solo hay candidatos locales) |
| `DEEPSEEK_API_KEY`, `LLM_BASE_URL_JUDGE`, `LLM_BASE_URL_ANALYSTS` | Juez y analistas de IA; **la demo nunca las usa** |
| `ABUSECH_AUTH_KEY`, `RANSOMWARELIVE_API_KEY` | Fuentes de indicadores y víctimas |
| `FIREBASE_PROJECT_ID`, `FIREBASE_CREDENTIALS_FILE` | Inicio de sesión; con `demo-hermes` solo sirve el emulador de Firebase incluido |

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
hace `compose.yaml`. Ejemplo mínimo con nginx (ajusta el dominio, los certificados y los límites a tu uso):

```nginx
limit_req_zone $binary_remote_addr zone=hermes_api:10m rate=10r/s;

server {
    listen 443 ssl;
    server_name hermes.ejemplo.local;
    ssl_certificate     /etc/nginx/tls/hermes.crt;
    ssl_certificate_key /etc/nginx/tls/hermes.key;

    client_max_body_size 1m;

    location /api/ {
        limit_req zone=hermes_api burst=20 nodelay;
        limit_req_status 429;
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffering off;  # el progreso del escaneo llega por eventos del servidor (SSE)
    }
}
```

Con Caddy, `request_body { max_size 1MB }` y un módulo de límite de frecuencia (p. ej. `caddy-ratelimit`) cumplen lo
mismo.

## License

Apache-2.0
