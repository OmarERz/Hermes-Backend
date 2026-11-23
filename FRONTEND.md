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
3. **Genera el cliente** desde `openapi/openapi.json`.
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
| Usuarios y roles | `PUT /api/admin/users/{uid}/role` | admin |
| Parámetros (sensibilidad del juez, fórmula, niveles) | `GET /api/config/schema`, `GET /api/config`, `PUT /api/config` (cada parámetro trae su `min_role`), `GET /api/config/versions`, `POST /api/config/versions/{v}/restore` | reader para ver; editar según el parámetro; restaurar: admin |
| Simulación antes de guardar la fórmula | `POST /api/formula/simulate` | admin |
| Perfil de la empresa y empresas pares | `GET/PUT /api/profile`, `GET/POST /api/peer-companies`, `PUT/DELETE /api/peer-companies/{id}` | reader para ver; admin para editar |
| Fuentes | `GET /api/sources`, `POST /api/sources`, `PATCH /api/sources/{id}` | reader ver; admin alta y nivel; analyst activar/desactivar |
| Pendientes de inventario y mapeo CPE | `GET /api/pending/inventory`, `GET /api/cpe/candidates?q=`, `PUT /api/mappings/{software}` | reader ver; analyst buscar y mapear |
| Vistas agrupadas (por vulnerabilidad, criticidad, activo) | `GET /api/vulnerabilities?view=vulnerability\|criticality\|asset` + filtros | reader |
| Detalle de vulnerabilidad / de activo | `GET /api/vulnerabilities/{group_id}`, `GET /api/assets/{ci_id}` | reader |
| Historial de puntuación | `GET /api/findings/{id}/history` | reader |
| Comparación crudo vs. procesado y cascada del Δ | `GET /api/comparison/summary`, `GET /api/comparison/table`, `GET /api/assessments/{id}/breakdown` | reader |
| Historial de recomendaciones y feedback | `GET /api/recommendations`, `GET /api/recommendations/{assessment_id}`, `GET /api/recommendations/{id}/feedback`, `POST /api/feedback` | reader ver; analyst dar feedback |
| Tickets y alertas | `GET /api/tickets`, `GET /api/alerts` | reader |
| Corridas (lanzar escaneo y ver progreso en vivo) | `POST /api/scans`, `GET /api/runs`, `GET /api/runs/{id}/events` (SSE) | analyst lanzar; reader ver |
| Exportación STIX | `POST /api/stix/export` | analyst |
| Propuestas de calibración (modo supervisado) | `GET /api/calibration/proposals`, `POST .../{id}/approve`, `POST .../{id}/reject` | reader ver; admin decidir |
| Métricas | `GET /api/metrics` | reader |
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
- **Simulación antes de guardar** la fórmula: llama a `POST /api/formula/simulate` y muestra el impacto; guardar
  recalcula sin llamar al juez. La simulación es real y solo acepta parámetros de la fórmula (los demás, como la
  sensibilidad del juez, dan 422: no tienen vista previa). Compara cada hallazgo abierto con su última evaluación
  usando la fórmula propuesta (sin llamar al juez) y devuelve `changed_findings` (los que cambian de nivel),
  `level_matrix` (nivel antes -> nivel después -> cuántos, incluidos los que se quedan en su nivel), `top_movers`
  (hasta 5, por mayor cambio de puntaje) y `last_30_days_effect` (un resumen del impacto sobre los hallazgos
  abiertos de hoy; el motor no reproduce los últimos 30 días). Guardar o restaurar una fórmula encola una corrida
  `recalculation` (estado `queued`, visible en `GET /api/runs`) que el worker toma en segundos; cada guardado
  encola la suya.
- **Feedback:** un feedback activo por usuario y evaluación (editable); `wrong_priority` exige el nivel
  propuesto. El usuario sale del token, nunca del cuerpo.
- **Niveles por nombre:** la comparación muestra el nivel CVSS (Crítica/Alta/Media/Baja) contra la urgencia
  final por su nombre, cada uno con su escala; no compares números entre escalas.
- **Cascada del Δ:** `GET /api/assessments/{id}/breakdown` devuelve las barras (factores, juez, piso, límites,
  redondeo); `raw` + todas las barras = la final. Píntalas tal cual, sin recalcular.
- **Sin sumas de riesgo:** el riesgo de un activo nunca es la suma de sus puntuaciones (diez bajas no son una
  crítica); el backend ya entrega la agregación correcta.
- **Privacidad:** el backend no devuelve correos de otros usuarios en vistas de lectura; usa el nombre que venga.
- **Secretos:** ninguna respuesta trae una llave. El asistente y la pantalla de conexiones solo **verifican**; las
  llaves se configuran en el servidor (`.env` / Docker secrets), nunca desde el front.

## 6. Tiempo real (SSE)

`GET /api/runs/{id}/events` es un *Server-Sent Events* (`text/event-stream`) con eventos `progress` mientras la
corrida avanza, leídos de la tabla de corridas. `POST /api/scans` deja la corrida en cola y el worker la toma;
el stream refleja su avance real y `GET /api/runs` su estado final. `EventSource` del navegador no permite cabecera `Authorization`: usa un cliente SSE que acepte
cabeceras (por ejemplo `@microsoft/fetch-event-source`) y manda el Bearer. Si la conexión se corta, reconecta y
consulta `GET /api/runs` para el estado final.

## 7. Idioma, formato y despliegue

- Textos para personas en español (los mensajes del backend ya vienen así). Fechas en ISO 8601 UTC; muéstralas
  en la zona del usuario. Puntuaciones enteras 0–100; factores decimales 0–1.
- **Despliegue:** lo más simple es servir el front y la API **en el mismo origen** detrás del proxy inverso (sin
  CORS). Si van en orígenes distintos, el operador lista el origen exacto del front en `CORS_ALLOWED_ORIGINS`
  (sin comodines). El proxy aplica el límite de peticiones (429).
- **Cambios de contrato:** el backend solo agrega campos opcionales sin versionar; un cambio incompatible saldrá
  en una ruta versionada. Vuelve a generar el cliente cuando cambie `openapi/openapi.json`.
