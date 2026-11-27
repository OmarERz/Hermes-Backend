# Guía para el agente del front de Hermes

> Para el equipo (y su agente de código) que construye el **front de personalización en React**. Explica todo lo
> que el front necesita del backend: contrato, autenticación, roles, errores, paginación, tiempo real y qué
> pantalla usa qué ruta. El backend vive en este repositorio; el front, en otro.

**Fuente de verdad del contrato:** `openapi/openapi.json` (OpenAPI 3.1, versionado en este repo). Si algo de esta
guía y el OpenAPI no coinciden, **gana el OpenAPI**. Genera el cliente y los tipos desde ese archivo (por ejemplo
con `openapi-typescript` u `orval`); no escribas tipos a mano.

## 1. Primeros pasos (en orden)

1. **Levanta el backend local** (Docker y Linux/WSL2):
   ```bash
   cp .env.example .env        # llena al menos las 4 contraseñas de PostgreSQL y CURSOR_SIGNING_KEY (≥ 32 caracteres)
   make up                     # API en http://127.0.0.1:8000, emulador de Firebase Auth en 127.0.0.1:9099
   make demo                   # datos de demostración: todas las vistas tienen contenido (sin red ni tokens)
   ```
   Para que tu front corra en otro origen (por ejemplo Vite en `http://localhost:5173`), pon
   `CORS_ALLOWED_ORIGINS=http://localhost:5173` en `.env` antes de `make up`. Para ver la documentación
   interactiva en `http://127.0.0.1:8000/api/docs`, pon `API_DOCS_ENABLED=true` (solo desarrollo).
2. **Obtén un token de prueba** por rol: `make emulator-token ROLE=admin` (o `analyst`, `reader`). Imprime un
   *ID token* del emulador con el claim `role` ya puesto.
3. **Genera el cliente** desde `openapi/openapi.json`. Generador recomendado: `openapi-typescript` (probado con la
   versión 7.9.1; el resultado compila con `tsc --strict`), por ejemplo
   `npx openapi-typescript@7.9.1 openapi/openapi.json -o src/api/schema.d.ts`; con `orval` o `openapi-generator`
   funciona igual. El documento declara `servers` (primero `/`, el mismo origen que lo sirve; después `http://127.0.0.1:8000` para
   desarrollo local), `tags` por pantalla
   y descripciones en español en cada operación, parámetro y campo, con `examples` en los cuerpos principales.
   **Convención de `operationId`:** cada operación tiene uno explícito y estable en `snake_case`, de la forma
   `verbo_sustantivo` (`list_vulnerabilities`, `get_config`, `update_config`, `create_feedback`, `simulate_formula`).
   Los generadores lo usan como nombre de función. Verbos: `list_` (colecciones paginadas), `get_` (uno),
   `create_`, `update_`, `delete_`, `restore_`, `approve_`/`reject_`, `stream_` (SSE). Un `operationId` publicado no
   se renombra sin versionar la ruta. (F10.6 cambió los `operationId` automáticos, como
   `get_config_api_config_get`, por estos nombres: si ya generaste un cliente, vuelve a generarlo; ninguna ruta,
   método, cuerpo ni código de estado cambió.)
4. **Configura Firebase en el front** contra el emulador en desarrollo (`connectAuthEmulator(auth,
   "http://127.0.0.1:9099")`, proyecto `demo-hermes`) y contra el proyecto real en producción.
5. **Prueba el recorrido** con las colecciones de Bruno de `bruno/` (`make bruno` con `TEST_TOKEN` de admin):
   cada carpeta muestra peticiones reales con sus respuestas esperadas.

**Una pantalla está terminada** cuando: usa solo rutas del OpenAPI con el cliente generado; respeta el rol
mínimo de cada acción (oculta o deshabilita lo que el rol no puede hacer, y aun así maneja el 403); maneja la
envoltura de error de §4 (mensaje para la persona + detalle por campo en formularios); pagina con `next_cursor`;
y funciona con los datos de `make demo`.

## 2. Autenticación y roles

- El front inicia sesión con **Firebase Auth** y manda el *ID token* en cada petición:
  `Authorization: Bearer <id token>`. Renueva el token antes de que expire (el SDK lo hace con
  `getIdToken()`); no lo guardes en `localStorage`.
- **Roles** (claim `role`, jerarquía `reader < analyst < admin`). Los asigna **solo el backend**:
  `PUT /api/admin/users/{uid}/role` (admin). El front nunca escribe claims.
- **`GET /api/me`** devuelve el usuario actual y su **rol efectivo**. Úsalo para decidir qué mostrar; no leas el
  rol del token: el efectivo es el menor entre el claim y la copia del backend (una baja de permisos aplica al
  instante).
- Tras un cambio de rol, el backend **revoca las sesiones** de ese usuario: el siguiente request da 401 y el
  front debe pedir un token nuevo (`getIdToken(true)`) o volver a iniciar sesión.
- Respuestas: **401** sin token o token inválido/expirado/revocado (`WWW-Authenticate: Bearer`); **403**
  `forbidden` si el rol no alcanza, `user_inactive` si el usuario está desactivado; **503** `auth_unavailable`
  si Firebase no responde (reintenta más tarde).
- El primer admin se asigna fuera del front (consola de Firebase o el emulador). Un admin no puede cambiar su
  propio rol (409 `own_role`).

## 3. Mapa de pantallas → rutas → rol mínimo

Los requisitos de cada pantalla (FRO-xx) están en la especificación del producto; aquí va lo que el front llama.

| Pantalla | Rutas | Rol mínimo |
|---|---|---|
| Sesión / perfil propio | `GET /api/me` | reader |
| Usuarios y roles | `GET /api/admin/users`, `PUT /api/admin/users/{uid}/role` | admin |
| Parámetros (sensibilidad del juez, motivos del juez, fórmula, niveles) | `GET /api/config/schema`, `GET /api/config`, `PUT /api/config` (cada parámetro trae su `min_role`; los motivos son `reasons.<code>.enabled`), `GET /api/config/versions`, `POST /api/config/versions/{v}/restore` | reader para ver; editar según el parámetro; restaurar: admin |
| Simulación antes de guardar la fórmula o la sensibilidad | `POST /api/formula/simulate` | admin |
| Perfil de la empresa y empresas pares | `GET/PUT /api/profile`, `GET/POST /api/peer-companies`, `PUT/DELETE /api/peer-companies/{id}` | reader para ver; admin para editar |
| Fuentes | `GET /api/sources`, `POST /api/sources`, `PATCH /api/sources/{id}` | reader ver; admin alta y nivel; analyst activar/desactivar |
| Pendientes de inventario y mapeo CPE | `GET /api/pending/inventory`, `GET /api/cpe/candidates?q=`, `PUT /api/mappings/{software}` | reader ver; analyst buscar y mapear |
| Vistas agrupadas (por vulnerabilidad, criticidad, activo) | `GET /api/vulnerabilities?view=vulnerability\|criticality\|asset` + filtros | reader |
| Detalle de vulnerabilidad / de activo | `GET /api/vulnerabilities/{group_id}`, `GET /api/assets/{ci_id}` | reader |
| Historial de puntuación | `GET /api/findings/{id}/history`, con el `finding_id` de cada activo de `GET /api/vulnerabilities/{group_id}` | reader |
| Comparación crudo vs. procesado y cascada del Δ | `GET /api/comparison/summary`, `GET /api/comparison/table`, `GET /api/assessments/{id}/breakdown` | reader |
| Historial de recomendaciones y feedback | `GET /api/recommendations` (filtros `group_id`, `ci_id`, `ticket_itop_id`, `level`, `verdict`, `without_feedback`), `GET /api/recommendations/{assessment_id}`, `GET /api/recommendations/{assessment_id}/judge`, `GET /api/recommendations/{id}/feedback`, `POST /api/feedback` | reader ver; analyst dar feedback |
| Tickets y alertas | `GET /api/tickets` (cada ticket trae `itop_id` para mostrar y `ticket_itop_id` para filtrar), `GET /api/tickets/summary`, `GET /api/tickets/updates` (filtros `ticket_itop_id`, `action`), `GET /api/alerts` | reader |
| Corridas (lanzar escaneo y ver progreso en vivo) | `POST /api/scans`, `GET /api/runs` (filtros `kind`, `status`, `date_from`, `date_to`), `GET /api/runs/{id}` (una corrida), `GET /api/runs/{id}/events` (SSE) | analyst lanzar; reader ver |
| Historial (línea de tiempo de corridas, revisiones LLM y cambios de configuración) | `GET /api/history` (filtros `type`, `status`, `date_from`, `date_to`) | reader |
| Telemetría de agentes (analistas y juez) | `GET /api/telemetry/summary?window=24h\|7d\|30d`, `GET /api/telemetry/daily?days=1..90`, `GET /api/telemetry/reviews` (filtros `agent`, `status`, `date_from`, `date_to`) | reader |
| Inventario de activos y software (solo lectura; iTop es el inventario) | `GET /api/inventory/assets` (filtros `q`, `itop_class`, `criticality`, `exposed`, `classification`, `owner`, `custodian`, `with_findings`), `GET /api/inventory/summary`, `GET /api/inventory/software` (filtros `q`, `has_cpe`, `worst_level`, `with_vulnerabilities`, `category`), `GET /api/inventory/assets/{ci_id}/software` | reader |
| Exportación STIX | `POST /api/stix/export` | analyst |
| Propuestas de calibración (modo supervisado) | `GET /api/calibration/proposals`, `POST .../{id}/approve`, `POST .../{id}/reject` | reader ver; admin decidir |
| Métricas | `GET /api/metrics` | reader |
| Cola de errores (notificaciones, escrituras en iTop y validación LLM) | `GET /api/error-queue` (filtro `kind`), `POST /api/notifications/events/{id}/retry` para los `retryable` | admin |
| Eventos de notificación en error | `GET /api/notifications/events`, `POST /api/notifications/events/{id}/retry` | admin |
| Conexiones (estado de llaves y servicios) | `GET /api/connections/status`, `POST /api/connections/test` | admin |
| Asistente de primera configuración | `GET /api/setup/status`, `PUT /api/setup/steps/{n}` | admin |
| Auditoría | `GET /api/audit` | admin |
| Salud del servicio | `GET /api/health` (sin token) | — |

La tabla de roles exacta está en `src/api/routes/_auth.py` (`ROUTE_ROLES`); es la que hace cumplir el backend.

## 4. Errores (una sola envoltura)

Todo error responde con:

```json
{"error": {"code": "validation_error", "message": "Los datos enviados no son válidos.",
           "details": [{"field": "body.weights.S", "issue": "less_than_equal"}]}}
```

- `code`: estable, en inglés, en `snake_case`; úsalo para decidir qué hacer. `message`: para la persona, en el
  idioma de salida (español por defecto); muéstralo tal cual. `details`: en formularios, marca cada `field` con su
  `issue` (nunca trae el valor enviado).
- Códigos que el front debe manejar: `bad_request`, `invalid_cursor` (400) · `unauthorized` (401) · `forbidden`,
  `user_inactive` (403) · `not_found`, `user_not_found` (404) · `conflict`, `version_conflict`, `own_role`,
  `structural_source`, `not_in_error`, `stale_proposal`, `already_decided` (409) · `validation_error` (422) · `too_many_requests` (429, puede venir
  del proxy) · `auth_unavailable` (503) · 500 con mensaje genérico.
- El cuerpo de una petición tiene un límite de **1 MiB**: la API responde 413 en la envoltura de error si se
  excede, y el proxy inverso de producción aplica el mismo tope.
- Los ids de la ruta (`/api/vulnerabilities/{group_id}`, `/api/recommendations/{assessment_id}`, `/api/sources/{id}`,
  `/api/runs/{id}/events`…) son UUID: uno mal formado responde **422** (`validation_error`, con `details[].field` =
  `path.<nombre>`) antes de buscar nada; un UUID bien formado que no existe sigue respondiendo 404. `{ci_id}` acepta
  hasta 100 caracteres imprimibles. El OpenAPI publica el patrón de cada uno.
- `PUT /api/mappings/{software}`: un CPE que el mapeo no puede guardar (fabricante y producto con letras, números y
  `. _ ~ + -`) responde 422 con `details[].field = body.cpe` e `issue = string_pattern_mismatch` y el mensaje genérico
  de validación; el front muestra su propio texto para ese caso.

## 5. Reglas del contrato que afectan al front

- **Paginación por cursor** solo en las rutas cuyo esquema de respuesta es una página (`items` +
  `next_cursor`) y que aceptan `?limit=` (por defecto 50, máximo 200) y `?cursor=`: revisa el OpenAPI de cada
  ruta. Algunas devuelven un arreglo directo sin paginar (por ejemplo `GET /api/config/schema` y
  `GET /api/connections/status`). `next_cursor` es `null` en la última página. El cursor es **opaco y firmado**:
  pásalo tal cual solo a la misma ruta y con los mismos filtros; no lo construyas ni lo modifiques. Uno alterado
  da 400 `invalid_cursor` (vuelve a la primera página).
- **Concurrencia optimista (versión esperada):** las escrituras de configuración llevan la versión que el front
  leyó (`expected_version`); si alguien cambió algo entretanto, responde **409 `version_conflict`**. Muestra el
  cambio y ofrece recargar. Aplica hoy a `PUT /api/config`, `POST /api/config/versions/{v}/restore` y
  `PUT /api/profile`. Las decisiones de calibración responden 409 `stale_proposal` si la base cambió desde la
  propuesta y `already_decided` si otro admin ya decidió.
- **Edición por rol:** `GET /api/config/schema` trae, por parámetro, su tipo, rango, opciones y `min_role`. El
  front construye el formulario desde ese esquema y deshabilita lo que el rol no puede editar. Validaciones que
  el servidor repite (y tú adelantas): los pesos suman exactamente 1.0 y cada uno está entre 0 y 1; los niveles
  de cada factor son monótonos; el piso KEV + expuesto entre 80 y 100.
- **Lo bloqueado no se ofrece:** citas textuales del juez, asimetría de fuentes, esquema cerrado del juez, juez
  sin acciones, respaldo `final = base`, estructura de la fórmula y entrega inmediata de lo crítico **no tienen
  ruta para cambiarse**; no muestres controles para ellos.
- **Fuentes estructurales** (🔒): no se pueden apagar (409 `structural_source`). Un feed nuevo entra como N4 e
  inactivo.
- **Simulación antes de guardar** la fórmula o la sensibilidad: llama a `POST /api/formula/simulate` y muestra el
  impacto; guardar recalcula sin llamar al juez. Simula los parámetros de la fórmula, `dead_zone`,
  `sensitivity_profile` y los motivos `reasons.<code>.enabled` (FRO-04): para el perfil y los motivos **estima** el
  ajuste del juez a partir de los motivos que ya aceptó, reescalados al perfil propuesto (sin llamar al juez; un
  motivo que el juez no propuso nunca aparece; si hubo doble revisión ciega, combina las dos con su regla). La zona
  muerta se resuelve como al guardar: la que mandes o la actual (guardar solo el perfil no la cambia). Cada perfil
  trae su zona muerta (mínima 6, normal 4, amplia 2): **al cambiar de perfil, manda también su `dead_zone`, igual en
  la simulación y al guardar**, para que la vista previa sea lo que se guarda. Cualquier otro parámetro conocido (por
  ejemplo `judge_model`) se
  ignora y vuelve en `not_simulable`: avisa a la persona que ese cambio no tiene vista previa. Una clave desconocida
  o un valor inválido siguen dando 422. Compara cada hallazgo abierto con su última evaluación
  usando la fórmula propuesta y devuelve `changed_findings` (los que cambian de nivel),
  `level_matrix` (nivel antes -> nivel después -> cuántos, incluidos los que se quedan en su nivel), `top_movers`
  (hasta 5, por mayor cambio de puntaje) y `last_30_days_effect` (un resumen del impacto sobre los hallazgos
  abiertos de hoy; el motor no reproduce los últimos 30 días). Guardar o restaurar una fórmula encola una corrida
  `recalculation` (estado `queued`, visible en `GET /api/runs`) que el worker toma en segundos; cada guardado
  encola la suya.
- **Feedback:** un feedback activo por usuario y evaluación (editable); `wrong_priority` exige el nivel
  propuesto. El usuario sale del token, nunca del cuerpo. Si la evaluación tiene tickets de varios custodios, manda
  `ticket_itop_id` (el ticket que el usuario tiene a la vista) para que «no sugerir más» y «falso positivo» solo
  afecten a ese ticket; sin él se aplican a todos los tickets de la evaluación. Errores: 404 si la evaluación no
  existe, 403 si el usuario no es analista o admin activo, 422 si el ticket no es de esa evaluación.
- **Id de un ticket (F18.4):** `ticket_itop_id` es siempre el id **numérico** de iTop, en los filtros
  (`GET /api/tickets/updates`, `GET /api/recommendations`), en `POST /api/feedback` y en las respuestas que lo
  traen. En `GET /api/tickets`, `itop_id` es para mostrar (la referencia `R-000123` cuando ya existe, si no el id
  numérico) y `ticket_itop_id` es el valor que pasas a esos filtros; nunca mandes la referencia a un filtro (422).
  `ticket_itop_id` llega nulo si el ticket no tiene un id numérico de iTop (los tickets de `make demo`, `DEMO-n`):
  no ofrezcas filtrar por ese ticket.
- **Motivos del juez y su cita (FRO-13):** cada recomendación trae `accepted_reasons` (`code`, `label`, `points`,
  `quote`, `ci_id`), `judge_summary`, `judge_status` y `ticket_itop_id`; `accepted_reasons` llega vacío sin juez, con
  respaldo (`no_judge_review`) o con desacuerdo. El detalle completo (motivos rechazados con su regla, ajuste
  propuesto contra aplicado, zona muerta y doble revisión ciega) está en
  `GET /api/recommendations/{assessment_id}/judge`. **Toda cita es texto externo** (noticias, CVE, iTop):
  muéstrala como dato, escapada, nunca como HTML.
- **Telemetría e historial:** solo metadatos (agente, modelo, estado, latencia, tokens, costo, nivel de la
  escalera); ninguna ruta devuelve prompts, paquetes ni llamadas crudas. Las series diarias vienen rellenas con
  cero. Costos y porcentajes llegan como texto decimal: no los conviertas a `float` para sumarlos.
- **Motivos del juez (FRO-03):** cada motivo es un interruptor booleano `reasons.<code>.enabled` del grupo `judge`
  (solo admin). Activar o desactivar uno guarda una versión nueva de la configuración (como un cambio de fórmula, con
  la misma `expected_version`) y aplica desde la siguiente revisión del juez; **no** recalcula puntajes guardados ni
  encola una corrida.
- **Usuarios:** `GET /api/admin/users` lista todas las cuentas de Firebase, hayan iniciado sesión o no, ordenadas
  por correo y paginadas. Cada una trae `role` (el guardado: mándalo como `expected_role` al cambiarlo; nulo si
  nunca inició sesión), `claim_role`, `effective_role` (el que tendría una petición suya ahora; nulo si se
  rechazaría), `active`, `signed_in` y `last_login_at`. Responde 503 `auth_unavailable` si Firebase no responde.
- **Cola de errores (FRO-18):** `GET /api/error-queue` junta, de lo más reciente a lo más antiguo, los eventos de
  notificación y las escrituras en iTop que agotaron sus reintentos y los elementos que un analista o el juez no
  pudieron validar (`kind`: `notification`, `itop`, `llm_validation`). Solo los que traen `retryable: true` (hoy, los
  eventos de notificación) se reintentan, con `POST /api/notifications/events/{id}/retry`. `error` es un texto corto
  (máximo 500 caracteres): muéstralo como dato.
- **Inventario:** es de solo lectura; un activo, su dueño o su software se registran o cambian en iTop. Los totales
  y porcentajes del resumen ya vienen calculados.
- **Historial de un hallazgo:** abre el detalle `GET /api/vulnerabilities/{group_id}`; cada activo trae su
  `finding_id`, que es el `{id}` de `GET /api/findings/{id}/history` (puntaje de ese CI en cada evaluación del
  grupo, del más antiguo al más reciente). En las recomendaciones `asset.finding_id` llega nulo: su CI puede ser
  el de una alerta, sin hallazgo de escaneo.
- **Niveles por nombre:** la comparación muestra el nivel CVSS (Crítica/Alta/Media/Baja) contra la urgencia
  final por su nombre, cada uno con su escala; no compares números entre escalas.
- **Cascada del Δ:** `GET /api/assessments/{id}/breakdown` devuelve las barras (factores, juez, piso, límites,
  redondeo); `raw` + todas las barras = la final. Píntalas tal cual, sin recalcular.
- **Sin sumas de riesgo:** el riesgo de un activo nunca es la suma de sus puntuaciones (diez bajas no son una
  crítica); el backend ya entrega la agregación correcta.
- **Datos de inventario de iTop (D-088):** `GET /api/assets/{ci_id}` trae además `itop_class`, `description`,
  `cpu` y `ram` del CI y `software`: cada instalación viva con `category` (la clase de iTop: `DBServer`,
  `WebServer`, `Middleware`, `OtherSoftware`, `PCSoftware`), `status` (`active`/`inactive`, solo informativo: una
  instalación inactiva se sigue escaneando), `description` y `licence` (nombre, límite de uso, fechas,
  perpetua). CPU y RAM son texto libre de iTop: muéstralos tal cual, sin convertir. Cualquiera puede llegar nulo
  (sin dato en iTop o aún no sincronizado); la descripción es texto de iTop: muéstrala como texto, nunca como
  HTML. GPU y almacenamiento no existen en iTop. Editar cualquiera de estos datos es un enlace a iTop.
  **Desde F18.6** el detalle trae también los datos del CI que ya tenía la lista del inventario, con los mismos
  valores: `criticality`, `exposed` (expuesto a internet; nulo sin dato), `personal_data`, `os`, `service`,
  `synced_at` e `itop_url` (enlace al CI en iTop para editarlo; vacío si el backend no tiene la URL de iTop). El
  detalle ya no necesita una segunda lectura de `GET /api/inventory/assets`.
  Las rutas de inventario traen lo mismo (F18.4): cada CI de `GET /api/inventory/assets` trae `description`,
  `cpu` y `ram` (además de `itop_class`); cada instalación de `GET /api/inventory/assets/{ci_id}/software` trae
  `category`, `status`, `description` y `licence`; cada producto de `GET /api/inventory/software` trae, sobre
  sus instalaciones vivas, `categories` (las categorías distintas, en orden alfabético; vacía si ninguna está
  sincronizada), `by_category` (instalaciones por categoría), `by_status` (instalaciones `active`, `inactive` y
  `unknown`, siempre las tres claves), `licences` (las licencias vivas del producto, asignadas o no, por nombre,
  cada una con `instances`: cuántas de sus instalaciones la tienen) y `licensed_instances` (instalaciones con
  alguna licencia asignada). La lista acepta `?category=` (incluye el producto si **alguna** de sus instalaciones
  la tiene). Las gráficas «por categoría», «por estado» y «por licencia» cuentan instalaciones: suma esos conteos.
- **Privacidad:** el backend no devuelve correos de otros usuarios en vistas de lectura; usa el nombre que venga.
- **Secretos:** ninguna respuesta trae una llave. El asistente y la pantalla de conexiones solo **verifican**; las
  llaves se configuran en el servidor (`.env` / Docker secrets), nunca desde el front.

## 6. Tiempo real (SSE)

`GET /api/runs/{id}/events` es un *Server-Sent Events* (`text/event-stream`) con eventos `progress` mientras la
corrida avanza, leídos de la tabla de corridas: uno cada vez que cambia el estado o el avance. El `data` de cada
evento es un texto JSON con `run_id`, `progress` (0 a 100), `status` (`queued`, `running`, `succeeded` o `failed`,
el mismo de `GET /api/runs`) y `message` (el estado en español); el flujo termina después del evento con estado
final (`succeeded` o `failed`), o a los 15 minutos aunque la corrida siga (reconecta). `POST /api/scans` deja la
corrida en cola y el worker la toma; el stream refleja su avance real. `EventSource` del navegador no permite cabecera `Authorization`:
usa un cliente SSE que acepte cabeceras (por ejemplo `@microsoft/fetch-event-source`) y manda el Bearer.

**Una corrida por su id (F18.6):** `GET /api/runs/{id}` (rol `reader`, como la lista) devuelve esa corrida con el
mismo modelo que cada elemento de `GET /api/runs` (incluidos `trigger_reason` y `triggered_by`), con su estado
actual: el final cuando ya terminó. 404 `not_found` si no existe. Úsala para el detalle y, si la conexión del
stream se corta, para leer el estado final (o reconecta el stream), en lugar de buscar la corrida en la lista por
tipo y fecha de inicio.

## 7. Idioma, formato y despliegue

- Textos para personas en español (los mensajes del backend ya vienen así). Fechas en ISO 8601 UTC; muéstralas
  en la zona del usuario. Puntuaciones enteras 0–100; factores decimales 0–1.
- **Despliegue:** lo más simple es servir el front y la API **en el mismo origen** detrás del proxy inverso (sin
  CORS). Si van en orígenes distintos, el operador lista el origen exacto del front en `CORS_ALLOWED_ORIGINS`
  (sin comodines). El proxy aplica el límite de peticiones (429).
- **Cambios de contrato:** el backend solo agrega campos opcionales sin versionar; un cambio incompatible saldrá
  en una ruta versionada. Vuelve a generar el cliente cuando cambie `openapi/openapi.json`.
