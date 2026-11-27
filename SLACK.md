# Módulo de Slack · Guía de instalación

Hermes avisa en Slack de los tickets y alertas que decide notificar y recibe el feedback de los analistas con botones. El módulo (`notifications_slack`) corre como el servicio `slack` de Docker Compose, con Bolt para Python en **Socket Mode**: abre una conexión de salida hacia Slack, así que no hay que exponer ninguna URL a internet.

Esta guía arma un **workspace de pruebas** desde cero. Toma unos 15 minutos.

## 1. Crear el workspace de pruebas

1. Entra a <https://slack.com/get-started#/createnew> con el correo con el que vas a administrar las pruebas.
2. Crea un workspace nuevo (por ejemplo, `hermes-pruebas`). Puedes saltarte la invitación de compañeros; los agregas después.

## 2. Crear la app desde el manifiesto

1. Abre <https://api.slack.com/apps> → **Create New App** → **From a manifest**.
2. Elige el workspace de pruebas.
3. Pega el contenido de [`slack/manifest.yaml`](slack/manifest.yaml) (pestaña YAML) → **Next** → **Create**.

El manifiesto pide solo lo mínimo:

| Permiso | Para qué |
|---|---|
| `chat:write` | Publicar los avisos y las respuestas efímeras al feedback |
| `users:read`, `users:read.email` | Saber el correo de quien da clic en un botón (Hermes valida su rol) |
| Socket Mode + interactividad | Recibir los clics sin exponer una URL pública |

## 3. Generar los dos tokens

| Token | Dónde se genera | Variable |
|---|---|---|
| **Token de app** (`xapp-…`) | **Basic Information** → **App-Level Tokens** → **Generate Token and Scopes**: nombre `socket-mode`, permiso `connections:write` → **Generate** | `SLACK_APP_TOKEN` |
| **Token del bot** (`xoxb-…`) | **Install App** → **Install to Workspace** → **Permitir**; copia el **Bot User OAuth Token** | `SLACK_BOT_TOKEN` |

Los dos son **secretos**: nunca los pegues en un chat, un ticket ni el repositorio. Si alguno se expone, regéneralo en la misma pantalla (Slack invalida el anterior) y actualiza la variable.

## 4. Crear los canales e invitar al bot

| Canal (nombre sugerido) | Uso | Variable |
|---|---|---|
| `#hermes-general` | Equipos sin canal propio y alertas de amenaza | `SLACK_DEFAULT_CHANNEL` (obligatoria) |
| `#hermes-urgente` | Eventos `immediate` (final ≥ 90): salen solos y al momento | `SLACK_URGENT_CHANNEL` (opcional; sin ella van al canal del equipo) |
| `#hermes-restringido` (**privado**) | Detalle completo de los activos ultra clasificados (NOT-08); en los demás canales sus nombres salen ocultos | `SLACK_RESTRICTED_CHANNEL` (recomendada) |
| `#hermes-infra`, `#hermes-apps`, … | Uno por equipo custodio de iTop | `SLACK_CHANNEL_MAP` |

En **cada** canal escribe `/invite @Hermes` (sin invitarlo, Slack responde `not_in_channel`).

Hermes usa el **ID** del canal, no su nombre: abre el canal → clic en su nombre arriba → al final del panel aparece **ID del canal** (empieza con `C`, por ejemplo `C08ABCD1234`).

## 5. Configurar Hermes

Agrega a tu archivo de variables local (el mismo `.env` del resto del stack; `.env.example` trae la lista comentada):

```dotenv
SLACK_BOT_TOKEN=xoxb-...
SLACK_APP_TOKEN=xapp-...
# Contraseña del rol slack_module de PostgreSQL (cualquier texto largo y aleatorio). Sin ella el módulo no arranca.
SLACK_DB_PASSWORD=...
SLACK_DEFAULT_CHANNEL=C0XXXXXXXXX
SLACK_URGENT_CHANNEL=C0XXXXXXXXX
SLACK_RESTRICTED_CHANNEL=C0XXXXXXXXX
# Nombre del equipo custodio tal como está en iTop → ID del canal (sin distinguir mayúsculas)
SLACK_CHANNEL_MAP={"Infraestructura": "C0XXXXXXXXX", "Aplicaciones": "C0YYYYYYYYY"}
# Opcional: cuánto junta un resumen antes de publicarlo (10 a 3600 s, 120 por defecto)
SLACK_DIGEST_WINDOW_SECONDS=120
```

Los tokens y la contraseña viajan como **secretos de Docker**, nunca como variables del contenedor:

```bash
make compose-secrets                 # escribe .compose-secrets/slack_bot_token, slack_app_token, slack_db_password
COMPOSE_PROFILES=slack make up       # el servicio slack está en el perfil "slack"
docker compose logs -f slack         # debe decir "slack service started (socket mode)"
```

Al arrancar, el servicio `provision` da permiso de inicio de sesión al rol `slack_module` y `migrate` crea sus tablas (`slack_thread`, `slack_delivery`, `slack_digest_item`). Si falta algo, el servicio no se conecta a nada y el log dice qué variable falta.

## 6. Encender las notificaciones por Slack

Hasta aquí los eventos siguen saliendo por el log (`notifications.consumer = log`). Para pasarlos a Slack, un administrador cambia el parámetro **`notifications.consumer`** a **`slack`** en la configuración del front (o con `PUT /api/config`). Desde ese momento el worker deja los eventos y los entrega el servicio `slack`; para volver al log, regresa el parámetro a `log`.

## 7. Usuarios que dan feedback

Al dar clic en un botón, Hermes toma el **correo del perfil de Slack** de esa persona y lo busca entre los usuarios de Hermes (Firebase):

- Debe ser **el mismo correo** con el que entra al front.
- Su rol debe ser **analista** o **administrador** y estar activo. Un lector recibe un mensaje de rechazo y no se guarda nada.

Invita al workspace de pruebas a cada analista con ese mismo correo.

## 8. Qué se ve en Slack

- **Ticket nuevo, sube de nivel o reabierto:** un mensaje con nivel y puntuación (`Base 74 · Juez +12 · Final 86`), CVE y producto, CIs, custodio y dueños, liga al ticket de iTop, justificación, mitigación, pasos sugeridos con la etiqueta `IA`, todas las noticias con fecha y los botones **Relevante · Falso positivo · Prioridad incorrecta · Investigando · No sugerir más**.
- **Un hilo por ticket:** "corrección parcial" y "corregido" llegan como respuesta en el hilo; "sube de nivel" y "reabierto" abren un mensaje nuevo, que pasa a ser el hilo del ticket.
- **Resúmenes:** los eventos `normal` y `digest` de un canal se juntan durante la ventana (120 s) y salen como un resumen con los 10 de mayor puntuación y el conteo del resto; el detalle y los botones de cada uno están en el hilo del resumen. Los `immediate` nunca esperan.
- **Prioridad incorrecta** abre un formulario: nivel propuesto, puntuación opcional y comentario.
- Las respuestas al feedback son efímeras: solo las ve quien dio clic.

## 9. Probarlo

```bash
COMPOSE_PROFILES=slack make up
make demo          # solo en el workspace de pruebas: carga el inventario de prueba y genera tickets y eventos
```

Con `notifications.consumer = slack`, los avisos llegan en segundos a los canales. Da clic en **Relevante** en uno: debe aparecer "Gracias: registramos tu feedback «Relevante»." y el feedback se ve en el front (historial de la recomendación, canal `slack`).

## 10. Problemas comunes

| Síntoma en `docker compose logs slack` | Causa y arreglo |
|---|---|
| `the Slack service is not configured; missing: …` | Falta esa variable; agrégala y corre `make compose-secrets` |
| `the Slack service cannot start: OperationalError` | El rol `slack_module` no entra a PostgreSQL: falta o cambió `SLACK_DB_PASSWORD`. Corre `make compose-secrets` y reinicia el stack para que `provision` le ponga la contraseña |
| `slack not_in_channel` | El bot no está en el canal: `/invite @Hermes` |
| `slack channel_not_found` | El ID del canal está mal (usa el ID, no el nombre). Un canal de equipo que falla cae al canal general; el restringido nunca cae a otro canal |
| `slack invalid_auth` / `BoltError` al arrancar | Token equivocado o regenerado: actualízalo y reinicia |
| El botón responde que el correo no corresponde a un analista | El correo de Slack no es el de Hermes, o el usuario es lector o está inactivo |
| Los avisos no llegan y el worker dice `delivered by the slack service` | El servicio `slack` no está corriendo: `COMPOSE_PROFILES=slack make up` |

Los eventos nunca se pierden: si Slack falla, el outbox los reintenta (1, 2, 4… minutos, hasta 1 hora, 10 intentos) y los que agotan los intentos quedan visibles en los pendientes del front. Los resúmenes tienen sus propios reintentos.

## 11. Una sola instancia

Corre **un solo** servicio `slack`: el publicador de resúmenes no está pensado para varias réplicas.
