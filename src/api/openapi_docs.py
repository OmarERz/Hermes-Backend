"""Documentation layer of the OpenAPI document (F10.6): operation ids, tags, summaries, descriptions, field and
parameter descriptions, enum value descriptions and examples.

It only edits the generated document (`apply`); it never changes a path, a method, a request or response shape or a
status code, so it is compatible with every client already generated. Text for people is in Spanish (D-060); the
identifiers and the operation ids are English, `snake_case`, in the form `verb_noun` (`list_vulnerabilities`).
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Final

INFO_DESCRIPTION: Final = (
    "API del backend de Hermes: inteligencia de amenazas personalizada. Cruza las vulnerabilidades de los activos "
    "de la empresa con noticias de amenazas, las prioriza con un motor determinista y un juez de IA, y las lleva a "
    "tickets de iTop.\n\n"
    "**Autenticación:** todas las rutas (salvo `GET /api/health` y el webhook de iTop) exigen "
    "`Authorization: Bearer <ID token de Firebase>`. Tres roles: `reader` < `analyst` < `admin`.\n\n"
    '**Errores:** toda respuesta que no sea 2xx usa el sobre `{ "error": { "code", "message", "details" } }`.\n\n'
    '**Paginación:** las listas devuelven `{ "items": [...], "next_cursor": "..." }`; manda `cursor` y `limit` '
    "para pedir la siguiente página.\n\n"
    "**Fechas:** ISO 8601 en UTC.\n\n"
    "**Nombres de operación:** cada operación tiene un `operationId` estable en `snake_case` (`verbo_sustantivo`) "
    "que los generadores de clientes usan como nombre de función."
)
CONTACT: Final = {"name": "Equipo Hermes", "email": "hermes@example.test"}  # placeholder until the team publishes one
SERVERS: Final = [
    {"url": "/", "description": "El mismo origen que sirve este documento (producción detrás del proxy)"},
    {"url": "http://127.0.0.1:8000", "description": "Desarrollo local (Docker Compose)"},
]

TAGS: Final = (
    ("system", "Sistema", "Salud del servicio y usuario actual."),
    (
        "vulnerabilities",
        "Vulnerabilidades",
        "Vistas agrupadas por vulnerabilidad, criticidad o activo, detalle e historial.",
    ),
    ("comparison", "Comparación", "Valor crudo (CVSS) frente al valor procesado por Hermes."),
    ("recommendations", "Recomendaciones", "Historial de recomendaciones, su desglose y el feedback de las personas."),
    ("tickets", "Tickets y alertas", "Tickets creados en iTop y alertas de amenazas."),
    (
        "configuration",
        "Configuración",
        "Parámetros, versiones, simulación de la fórmula, perfil de empresa y empresas pares.",
    ),
    ("sources", "Fuentes e inventario", "Fuentes de noticias, pendientes de inventario y mapeo a CPE."),
    ("runs", "Corridas y escaneos", "Escaneos, corridas del pipeline y su progreso en vivo."),
    ("stix", "Exportación STIX", "Exportación de hallazgos como bundle STIX 2.1."),
    ("calibration", "Calibración", "Propuestas de ajuste supervisadas por un administrador."),
    ("operations", "Operación", "Métricas, eventos de notificación, conexiones, instalación y auditoría."),
    (
        "telemetry",
        "Telemetría de agentes",
        "Corridas y revisiones de los agentes de IA (analistas y juez): resúmenes, series diarias y bitácora. "
        "Solo metadatos; nunca prompts, llamadas crudas ni texto de noticias.",
    ),
    ("admin", "Administración", "Gestión de roles de usuario."),
    ("itop", "iTop", "Webhook que iTop llama cuando cambia un ticket."),
)


@dataclass(frozen=True)
class Op:
    operation_id: str
    tag: str
    summary: str
    description: str


OPERATIONS: Final[dict[tuple[str, str], Op]] = {
    ("GET", "/api/health"): Op(
        "get_health", "system", "Estado del servicio", "Comprobación de vida. Es la única ruta sin autenticación."
    ),
    ("GET", "/api/me"): Op(
        "get_current_user", "system", "Usuario actual", "Devuelve el correo, el nombre y el rol del usuario del token."
    ),
    ("PUT", "/api/admin/users/{uid}/role"): Op(
        "assign_user_role", "admin", "Asignar rol", "Asigna un rol a un usuario y revoca sus sesiones. Solo `admin`."
    ),
    ("GET", "/api/vulnerabilities"): Op(
        "list_vulnerabilities",
        "vulnerabilities",
        "Listar vulnerabilidades",
        "Vista agrupada por `vulnerability`, `criticality` o `asset` con los filtros de FRO-10. "
        "Pagina por cursor. Rol mínimo: `reader`.",
    ),
    ("GET", "/api/vulnerabilities/{group_id}"): Op(
        "get_vulnerability",
        "vulnerabilities",
        "Detalle de una vulnerabilidad",
        "Un grupo CVE por producto con todos sus activos afectados.",
    ),
    ("GET", "/api/assets/{ci_id}"): Op(
        "get_asset",
        "vulnerabilities",
        "Detalle de un activo",
        "Un activo (CI de iTop) con sus hallazgos; su riesgo es el mayor de sus hallazgos, nunca una suma.",
    ),
    ("GET", "/api/findings/{id}/history"): Op(
        "get_finding_history",
        "vulnerabilities",
        "Historial de un hallazgo",
        "Evolución del puntaje (base, ajuste del juez y final) de un hallazgo.",
    ),
    ("GET", "/api/comparison/summary"): Op(
        "get_comparison_summary",
        "comparison",
        "Resumen de la comparación",
        "Matriz de reclasificación, embudo y métricas de ruido evitado y críticos ocultos.",
    ),
    ("GET", "/api/comparison/table"): Op(
        "list_comparison_rows",
        "comparison",
        "Tabla de la comparación",
        "Una fila por CVE y activo: valor crudo, base, ajuste del juez, final y la causa principal.",
    ),
    ("GET", "/api/assessments/{id}/breakdown"): Op(
        "get_assessment_breakdown",
        "recommendations",
        "Desglose de una evaluación",
        "Cascada de barras desde el valor crudo hasta el final (EVA-12).",
    ),
    ("GET", "/api/recommendations"): Op(
        "list_recommendations",
        "recommendations",
        "Listar recomendaciones",
        "Historial de evaluaciones, de la más reciente a la más antigua. Se puede acotar a un grupo o a un activo.",
    ),
    ("GET", "/api/recommendations/{assessment_id}"): Op(
        "get_recommendation",
        "recommendations",
        "Detalle de una recomendación",
        "Una evaluación con su justificación y su mitigación.",
    ),
    ("GET", "/api/recommendations/{id}/feedback"): Op(
        "list_recommendation_feedback",
        "recommendations",
        "Feedback de una recomendación",
        "Los feedbacks dados a una evaluación, con el activo de cada uno.",
    ),
    ("POST", "/api/feedback"): Op(
        "create_feedback",
        "recommendations",
        "Dar feedback",
        "Registra el feedback del usuario del token sobre una evaluación; es el mismo servicio que "
        "usa Slack. Nunca cambia el puntaje por sí mismo. Rol mínimo: `analyst`.",
    ),
    ("GET", "/api/tickets"): Op(
        "list_tickets", "tickets", "Listar tickets", "Tickets ya creados en iTop, los más urgentes primero."
    ),
    ("GET", "/api/alerts"): Op(
        "list_alerts",
        "tickets",
        "Listar alertas",
        "Alertas de amenazas (R2, R3 o inferidas) con actor, víctima y vector.",
    ),
    ("GET", "/api/config/schema"): Op(
        "get_config_schema",
        "configuration",
        "Esquema de parámetros",
        "Lista de parámetros con su tipo, rango y rol mínimo; con ella el front arma sus formularios.",
    ),
    ("GET", "/api/config"): Op(
        "get_config", "configuration", "Configuración vigente", "Valores actuales y número de versión."
    ),
    ("PUT", "/api/config"): Op(
        "update_config",
        "configuration",
        "Guardar configuración",
        "Aplica un cambio como una versión nueva. Exige la versión que el cliente leyó "
        "(`expected_version`): 409 si cambió. Un cambio de fórmula encola un recálculo sin llamar al juez.",
    ),
    ("GET", "/api/config/versions"): Op(
        "list_config_versions",
        "configuration",
        "Historial de versiones",
        "Versiones de la configuración con quién y cuándo.",
    ),
    ("POST", "/api/config/versions/{v}/restore"): Op(
        "restore_config_version",
        "configuration",
        "Restaurar una versión",
        "Hace vigente una versión anterior como una nueva. Solo `admin`.",
    ),
    ("POST", "/api/formula/simulate"): Op(
        "simulate_formula",
        "configuration",
        "Simular la fórmula",
        "Vista previa sin guardar nada: cuántos hallazgos abiertos cambiarían de nivel con la "
        "fórmula propuesta. Solo `admin`.",
    ),
    ("GET", "/api/profile"): Op(
        "get_profile", "configuration", "Perfil de la empresa", "Sector, subsectores, países e idioma de salida."
    ),
    ("PUT", "/api/profile"): Op(
        "update_profile",
        "configuration",
        "Guardar el perfil de la empresa",
        "Reemplaza el perfil; exige `expected_version`. Solo `admin`.",
    ),
    ("GET", "/api/peer-companies"): Op(
        "list_peer_companies",
        "configuration",
        "Listar empresas pares",
        "Empresas del mismo sector que Hermes vigila en las noticias.",
    ),
    ("POST", "/api/peer-companies"): Op(
        "create_peer_company", "configuration", "Crear empresa par", "Agrega una empresa par. Solo `admin`."
    ),
    ("PUT", "/api/peer-companies/{id}"): Op(
        "update_peer_company",
        "configuration",
        "Actualizar empresa par",
        "Reemplaza los datos de una empresa par. Solo `admin`.",
    ),
    ("DELETE", "/api/peer-companies/{id}"): Op(
        "delete_peer_company", "configuration", "Eliminar empresa par", "Quita una empresa par. Solo `admin`."
    ),
    ("GET", "/api/sources"): Op(
        "list_sources",
        "sources",
        "Listar fuentes",
        "Fuentes de noticias con su nivel de confianza (N1 a N4), estado y salud.",
    ),
    ("POST", "/api/sources"): Op(
        "create_source",
        "sources",
        "Agregar una fuente",
        "Agrega un feed propio; entra como N4 e inactivo. Debe usar HTTPS. Solo `admin`.",
    ),
    ("PATCH", "/api/sources/{id}"): Op(
        "update_source",
        "sources",
        "Editar una fuente",
        "Enciende o apaga una fuente o cambia su nivel (el nivel, solo `admin`). Las fuentes "
        "estructurales no se apagan.",
    ),
    ("GET", "/api/pending/inventory"): Op(
        "get_pending_inventory",
        "sources",
        "Pendientes de inventario",
        "Activos y software con datos faltantes: sin CPE, sin clasificación, sin exposición o sin responsable.",
    ),
    ("GET", "/api/cpe/candidates"): Op(
        "list_cpe_candidates",
        "sources",
        "Candidatos de CPE",
        "Candidatos de CPE para un software, con su puntaje de coincidencia. Rol mínimo: `analyst`.",
    ),
    ("PUT", "/api/mappings/{software}"): Op(
        "set_cpe_mapping",
        "sources",
        "Mapear software a CPE",
        "Fija el CPE de un software del inventario. Rol mínimo: `analyst`.",
    ),
    ("POST", "/api/scans"): Op(
        "create_scan",
        "runs",
        "Lanzar un escaneo",
        "Encola un escaneo; el worker lo toma en segundos. Devuelve la corrida en estado `queued`. "
        "Rol mínimo: `analyst`.",
    ),
    ("GET", "/api/runs"): Op(
        "list_runs",
        "runs",
        "Listar corridas",
        "Corridas de escaneo, ingesta, recálculo y nocturnas, las más recientes primero. Filtros opcionales por "
        "tipo, estado y fecha de inicio; cada corrida dice por qué se lanzó y quién la lanzó.",
    ),
    ("GET", "/api/runs/{id}/events"): Op(
        "stream_run_events",
        "runs",
        "Progreso de una corrida (SSE)",
        "Flujo `text/event-stream` con el progreso hasta que la corrida termina. Si se corta, "
        "reconecta con `Last-Event-ID`.",
    ),
    ("POST", "/api/stix/export"): Op(
        "export_stix",
        "stix",
        "Exportar STIX",
        "Bundle STIX 2.1 de una vulnerabilidad, una corrida o un rango de fechas, respetando el TLP. "
        "Rol mínimo: `analyst`.",
    ),
    ("GET", "/api/calibration/proposals"): Op(
        "list_calibration_proposals",
        "calibration",
        "Listar propuestas de calibración",
        "Propuestas semanales de ajuste, con su evidencia y la repetición de 30 días.",
    ),
    ("POST", "/api/calibration/proposals/{id}/approve"): Op(
        "approve_calibration_proposal",
        "calibration",
        "Aprobar una propuesta",
        "Aplica la propuesta por el servicio de configuración. Solo `admin`.",
    ),
    ("POST", "/api/calibration/proposals/{id}/reject"): Op(
        "reject_calibration_proposal", "calibration", "Rechazar una propuesta", "Descarta la propuesta. Solo `admin`."
    ),
    ("GET", "/api/metrics"): Op("get_metrics", "operations", "Métricas", "Tablero de métricas del sistema."),
    ("GET", "/api/notifications/events"): Op(
        "list_notification_events",
        "operations",
        "Eventos de notificación",
        "Eventos que el módulo de Slack entrega, con su estado e intentos. Solo `admin`.",
    ),
    ("POST", "/api/notifications/events/{id}/retry"): Op(
        "retry_notification_event",
        "operations",
        "Reintentar un evento",
        "Vuelve a poner un evento con error en `pending`. Solo `admin`.",
    ),
    ("GET", "/api/connections/status"): Op(
        "get_connections_status",
        "operations",
        "Estado de las conexiones",
        "Último resultado de cada conexión externa (iTop, DeepSeek, NVD, abuse.ch, ransomware.live, "
        "Firebase). Nunca devuelve llaves. Solo `admin`.",
    ),
    ("POST", "/api/connections/test"): Op(
        "test_connections",
        "operations",
        "Probar conexiones",
        "Comprueba las conexiones pedidas (o todas) y devuelve el resultado. Solo `admin`.",
    ),
    ("GET", "/api/setup/status"): Op(
        "get_setup_status",
        "operations",
        "Estado de la instalación",
        "Pasos del asistente de instalación y cuáles están hechos. Solo `admin`.",
    ),
    ("PUT", "/api/setup/steps/{n}"): Op(
        "update_setup_step",
        "operations",
        "Marcar un paso de instalación",
        "Marca un paso del asistente como hecho u omitido. Solo `admin`.",
    ),
    ("GET", "/api/audit"): Op(
        "list_audit_entries",
        "operations",
        "Bitácora de auditoría",
        "Cambios hechos por personas y por el sistema, con filtros opcionales. Solo `admin`.",
    ),
    ("POST", "/api/itop/webhook"): Op(
        "receive_itop_webhook",
        "itop",
        "Webhook de iTop",
        "iTop avisa que un ticket cambió. Usa su propio token Bearer (no el de Firebase); responde 202.",
    ),
    ("GET", "/api/telemetry/summary"): Op(
        "get_telemetry_summary",
        "telemetry",
        "Resumen de telemetría",
        "Corridas por estado y tipo, una tarjeta por agente (revisiones, éxito, latencia promedio y p95, tokens, "
        "costo, proveedor y modelo, gasto del día contra el presupuesto, nivel de la escalera del juez) y los "
        "motivos del juez más usados, en la ventana pedida. Rol mínimo: `reader`.",
    ),
    ("GET", "/api/telemetry/daily"): Op(
        "get_telemetry_daily",
        "telemetry",
        "Series diarias de telemetría",
        "Un punto por día UTC, del más antiguo a hoy, con ceros en los días sin actividad: corridas terminadas "
        "bien y con error, y por agente revisiones, % de éxito, latencia promedio y costo. Rol mínimo: `reader`.",
    ),
    ("GET", "/api/telemetry/reviews"): Op(
        "list_llm_reviews",
        "telemetry",
        "Bitácora de revisiones de IA",
        "Cada interacción con un LLM, de la más reciente a la más antigua: agente, modo, modelo, estado, intentos, "
        "latencia, tokens, costo y la evaluación ligada. Solo metadatos (X-2). Pagina por cursor. "
        "Rol mínimo: `reader`.",
    ),
    ("GET", "/api/history"): Op(
        "list_history",
        "runs",
        "Historial de eventos",
        "Una sola línea de tiempo con las corridas, las revisiones de IA y los cambios de configuración, del más "
        "reciente al más antiguo. Cada revisión trae la evaluación que alimentó (para ligar su feedback) y cada "
        "cambio de configuración su versión y su autor. La auditoría completa sigue siendo solo de `admin` "
        "(`GET /api/audit`). Filtros por tipo, estado y fechas. Pagina por cursor. Rol mínimo: `reader`.",
    ),
}

PARAMS: Final[dict[str, str]] = {
    "authorization": "Token de Firebase: `Bearer <ID token>`.",
    "assessment_id": "Id (UUID) de la evaluación.",
    "ci_id": "Id del CI en iTop (por ejemplo `CI-0001`).",
    "group_id": "Id (UUID) del grupo de vulnerabilidad (CVE por producto).",
    "id": "Identificador del recurso (UUID).",
    "n": "Número del paso del asistente de instalación.",
    "software": "Id (UUID) del producto de software del inventario.",
    "uid": "Identificador del usuario en Firebase.",
    "v": "Número de versión de la configuración.",
    "band": "Nivel de la vulnerabilidad: filtra por banda.",
    "classification": "Clasificación de los activos afectados.",
    "custodian": "Equipo custodio del activo (texto exacto).",
    "exposed": "Solo activos expuestos a internet (`true`) o no (`false`).",
    "in_kev": "Solo vulnerabilidades del catálogo KEV de CISA (`true`) o no.",
    "owner": "Responsable del activo (texto exacto).",
    "q": "Texto a buscar (por ejemplo el nombre del software).",
    "status": "Estado del hallazgo.",
    "urgency": "Urgencia del ticket: 1 (crítica) a 4 (baja).",
    "view": "Vista agrupada: `vulnerability`, `criticality` o `asset`.",
    "window": "Ventana del resumen: últimas 24 horas, 7 días o 30 días.",
    "days": "Cuántos días hacia atrás, hoy incluido (1 a 90).",
    "agent": "Agente de IA.",
    "type": "Tipo de evento.",
}

ENUMS: Final[dict[tuple[str, ...], dict[str, str]]] = {
    ("critical", "high", "medium", "low"): {
        "critical": "Crítica (urgencia 1)",
        "high": "Alta (urgencia 2)",
        "medium": "Media (urgencia 3)",
        "low": "Baja (urgencia 4)",
    },
    ("public", "classified", "highly_classified", "unclassified"): {
        "public": "Información pública",
        "classified": "Clasificada",
        "highly_classified": "Altamente clasificada (se puede excluir de las exportaciones)",
        "unclassified": "Sin clasificación asignada en iTop",
    },
    ("new", "persistent", "reopened", "fixed", "no_data"): {
        "new": "Apareció en el último escaneo",
        "persistent": "Sigue presente desde un escaneo anterior",
        "reopened": "Estaba corregido y volvió a aparecer",
        "fixed": "Ya no aparece",
        "no_data": "No hay datos suficientes para decidir",
    },
    ("vulnerability", "criticality", "asset"): {
        "vulnerability": "Una fila por vulnerabilidad (CVE por producto)",
        "criticality": "Agrupada por nivel de criticidad",
        "asset": "Una fila por activo, con su mayor riesgo",
    },
    ("relevant", "false_positive", "wrong_priority", "investigating", "stop_suggestions"): {
        "relevant": "La recomendación es útil",
        "false_positive": "No aplica: suprime los hallazgos evaluados hasta que cambien",
        "wrong_priority": "Prioridad incorrecta; exige `proposed_level`",
        "investigating": "Se está investigando",
        "stop_suggestions": "No sugerir más en el ticket",
    },
    ("frontend", "slack"): {"frontend": "Dado desde el front", "slack": "Dado desde Slack"},
    ("R2", "R3", "inferred"): {
        "R2": "La noticia menciona un producto del inventario",
        "R3": "Una empresa par, del mismo sector o con el mismo vector, fue atacada",
        "inferred": "Relación inferida por la IA; verificar su presencia",
    },
    ("scan", "ingestion", "recalculation", "nightly"): {
        "scan": "Escaneo simulado de vulnerabilidades",
        "ingestion": "Ingesta y análisis de noticias",
        "recalculation": "Recálculo por un cambio de fórmula, sin juez",
        "nightly": "Recálculo nocturno por el paso del tiempo",
    },
    ("queued", "running", "succeeded", "failed"): {
        "queued": "En cola; el worker aún no la toma",
        "running": "En ejecución",
        "succeeded": "Terminó bien",
        "failed": "Terminó con error",
    },
    ("N1", "N2", "N3", "N4"): {
        "N1": "Oficial (máxima confianza)",
        "N2": "Investigación o proveedor reconocido",
        "N3": "Medios especializados",
        "N4": "Feed propio o sin verificar (mínima confianza)",
    },
    ("official", "research", "media", "feed"): {
        "official": "Fuente oficial",
        "research": "Investigación",
        "media": "Medio",
        "feed": "Feed propio",
    },
    ("ok", "degraded", "failing"): {"ok": "Responde bien", "degraded": "Responde con fallas", "failing": "No responde"},
    ("rss", "atom", "json", "csv", "api"): {
        "rss": "Feed RSS",
        "atom": "Feed Atom",
        "json": "Documento JSON",
        "csv": "Archivo CSV",
        "api": "API",
    },
    ("vulnerability", "run", "date_range"): {
        "vulnerability": "Una vulnerabilidad (`vulnerability_id`)",
        "run": "Lo que produjo una corrida (`run_id`)",
        "date_range": "Un rango de fechas (`date_from` y `date_to`)",
    },
    ("source_level", "reason_threshold", "formula_weight"): {
        "source_level": "Cambiar el nivel de confianza de una fuente",
        "reason_threshold": "Ajustar el umbral de un motivo del juez",
        "formula_weight": "Cambiar el peso de un factor de la fórmula",
    },
    ("pending", "approved", "rejected"): {
        "pending": "Espera la decisión de un administrador",
        "approved": "Aprobada y aplicada",
        "rejected": "Rechazada",
    },
    ("immediate", "normal", "digest"): {
        "immediate": "Se entrega al momento",
        "normal": "Se entrega en el siguiente ciclo",
        "digest": "Va en el resumen periódico",
    },
    ("pending", "delivered", "error"): {
        "pending": "Aún no se entrega",
        "delivered": "Entregado",
        "error": "Falló; se puede reintentar",
    },
    ("itop", "deepseek", "nvd", "abusech", "ransomwarelive", "firebase"): {
        "itop": "CMDB y tickets de iTop",
        "deepseek": "Juez y analistas de IA",
        "nvd": "Base de vulnerabilidades NVD",
        "abusech": "Indicadores de abuse.ch",
        "ransomwarelive": "Víctimas de ransomware.live",
        "firebase": "Inicio de sesión",
    },
    ("reader", "analyst", "admin"): {
        "reader": "Solo lectura",
        "analyst": "Lee, da feedback, lanza escaneos y exporta",
        "admin": "Además configura el sistema y administra usuarios",
    },
    ("news_analyst", "cve_analyst", "judge"): {
        "news_analyst": "Analista de noticias",
        "cve_analyst": "Analista de CVE",
        "judge": "Juez",
    },
    ("24h", "7d", "30d"): {"24h": "Últimas 24 horas", "7d": "Últimos 7 días", "30d": "Últimos 30 días"},
    ("scan", "ingestion", "recalculation", "nightly", "inventory_sync", "calibration"): {
        "scan": "Escaneo simulado de vulnerabilidades",
        "ingestion": "Ingesta y análisis de noticias",
        "recalculation": "Recálculo por un cambio de fórmula, sin juez",
        "nightly": "Recálculo nocturno por el paso del tiempo",
        "inventory_sync": "Sincronización del inventario con iTop",
        "calibration": "Calibración semanal (modo 4)",
    },
    (
        "applied",
        "suggestion",
        "partial_review",
        "judge_disagreement",
        "no_judge_review",
        "rejected",
        "queued",
    ): {
        "applied": "Aplicada: su ajuste llegó a la puntuación",
        "suggestion": "Solo sugerencia (ticket que cambió una persona)",
        "partial_review": "Revisión parcial: se aplicó lo validado",
        "judge_disagreement": "Desacuerdo en la doble revisión: final = base",
        "no_judge_review": "Sin juez (respaldo): final = base",
        "rejected": "Rechazada por la validación",
        "queued": "En cola para la siguiente corrida",
    },
    ("run", "llm_review", "config_change"): {
        "run": "Corrida (escaneo, noticias, recálculo, sincronización o calibración)",
        "llm_review": "Revisión de un agente de IA",
        "config_change": "Cambio de configuración",
    },
    ("schedule", "manual", "after_scan", "formula_change"): {
        "schedule": "Por la agenda",
        "manual": "Lanzada por una persona",
        "after_scan": "Después de un escaneo",
        "formula_change": "Por un cambio de fórmula",
    },
    ("deepseek", "claude-code"): {"deepseek": "API de DeepSeek", "claude-code": "Claude por la CLI de Claude Code"},
    ("decimal", "integer", "boolean", "string", "enum"): {
        "decimal": "Número decimal (como texto)",
        "integer": "Número entero",
        "boolean": "`true` o `false`",
        "string": "Texto",
        "enum": "Uno de `options`",
    },
    ("free", "validated", "blocked"): {
        "free": "Se cambia libremente",
        "validated": "Se cambia con validaciones",
        "blocked": "No se puede cambiar",
    },
}

# Field descriptions by field name (the same meaning in every schema), with `Schema.field` overrides below.
FIELDS: Final[dict[str, str]] = {
    "action": "Acción registrada, por ejemplo `source.enable`.",
    "active": "Si está activo.",
    "actor": "Actor de amenazas mencionado, o quien hizo la acción (`sistema` si fue automática).",
    "aliases": "Otros nombres con los que aparece la empresa en las noticias.",
    "assessment_id": "Id de la evaluación.",
    "asset": "Activo que impulsa la recomendación.",
    "assets": "Activos afectados.",
    "attempts": "Intentos de entrega hechos.",
    "author": "Quién hizo el cambio.",
    "avoided_noise": "Hallazgos de CVSS alto que Hermes bajó de prioridad.",
    "bands": "Una banda por nivel con su conteo y los grupos de la página.",
    "base": "Puntaje base (0 a 100) calculado por la fórmula, antes del juez.",
    "changed_findings": "Cuántos hallazgos abiertos cambiarían de nivel.",
    "changes": "Parámetros a cambiar: clave -> valor nuevo, como texto.",
    "channel": "Canal por el que llegó: `frontend` o `slack`.",
    "ci_count": "Cantidad de activos afectados.",
    "ci_id": "Id del CI en iTop.",
    "class": "Clase del objeto de iTop; hoy solo `UserRequest`.",
    "classification": "Clasificación del activo (la más restrictiva si son varios).",
    "classification_at_evaluation": "Clasificación que tenía el activo cuando se hizo la evaluación.",
    "comment": "Comentario libre (hasta 2000 caracteres); se guarda como dato, nunca se interpreta.",
    "count": "Cantidad de grupos de la banda en todo el resultado filtrado.",
    "countries": "Países de operación (códigos ISO de dos letras).",
    "country": "País (código ISO de dos letras).",
    "cpe": "Identificador CPE 2.3 del software.",
    "created_at": "Fecha y hora de creación (UTC).",
    "criticality": "Criticidad del activo en iTop.",
    "custodian": "Equipo custodio del activo.",
    "custodians": "Equipos custodios de los activos afectados.",
    "cve": "Identificador CVE.",
    "cvss": "Puntaje CVSS del CVE, como texto.",
    "date": "Fecha de la evaluación (UTC).",
    "date_from": "Inicio del rango (UTC).",
    "date_to": "Fin del rango (UTC).",
    "decided_at": "Cuándo decidió un administrador.",
    "default": "Valor de fábrica, como texto.",
    "delta": "Final menos crudo: cuánto movió Hermes la prioridad.",
    "description": "Descripción para personas.",
    "detail": "Dato que ayuda a identificar el pendiente.",
    "details": "Problemas concretos: campo y regla que falló.",
    "display_name": "Nombre para mostrar, si existe.",
    "domain": "Dominio web de la empresa.",
    "done": "Si el paso está hecho.",
    "email": "Correo del usuario.",
    "error": "Detalle del error.",
    "evidence": "Evidencia que sustenta la propuesta.",
    "exclude_ultra_classified": "Deja fuera los activos altamente clasificados del bundle y de su TLP.",
    "expected_version": "Versión que el cliente leyó; 409 si cambió desde entonces (API-03).",
    "exposed": "Si está expuesto a internet.",
    "feedback_count": "Cantidad de feedbacks activos de la evaluación.",
    "feedback_id": "Id del feedback guardado.",
    "final": "Puntaje final (0 a 100) tras el juez y el piso KEV.",
    "finding_status": "Estado del hallazgo en ese activo.",
    "findings": "Hallazgos del activo.",
    "findings_by_level": "Cantidad de hallazgos por nivel.",
    "finished_at": "Cuándo terminó (UTC); nulo si sigue en curso.",
    "fixed_cis": "Activos ya corregidos.",
    "funnel": "Embudo: cuántos hallazgos quedan en cada etapa.",
    "generated_at": "Cuándo se generó el tablero (UTC).",
    "group": "Grupo del parámetro, por ejemplo `formula` o `judge`.",
    "group_id": "Id (UUID) del grupo de vulnerabilidad (CVE por producto).",
    "groups": "Grupos de vulnerabilidad.",
    "health": "Salud de la fuente.",
    "hidden_criticals": "Hallazgos críticos que un escáner con solo CVSS no habría marcado.",
    "id": "Identificador.",
    "in_kev": "Si está en el catálogo KEV de CISA (explotación conocida).",
    "inferred": "Si la relación la infirió la IA.",
    "items": "Elementos de la página.",
    "items_per_run": "Elementos que trae la fuente por corrida.",
    "itop_id": "Id del ticket en iTop.",
    "itop_url": "Enlace al activo en iTop.",
    "judge_adjustment": "Ajuste del juez en puntos (puede ser negativo).",
    "justification": "Por qué tiene esta prioridad, en español.",
    "key": "Clave estable.",
    "kind": "Tipo.",
    "known_user": "Si el usuario ya existía en Hermes.",
    "label": "Nombre para mostrar.",
    "language": "Idioma de salida (por ejemplo `es`).",
    "last_30_days_effect": "Resumen del efecto del cambio, en español.",
    "last_capture": "Última captura de la fuente (UTC).",
    "last_error": "Último error de entrega, sin datos sensibles.",
    "last_seen": "Última vez que se vio el hallazgo (UTC).",
    "latency_ms": "Latencia de la comprobación en milisegundos.",
    "level": "Nivel.",
    "main_cause": "Qué factor movió más el puntaje.",
    "max": "Valor máximo permitido, como texto.",
    "metrics": "Métricas del tablero.",
    "min": "Valor mínimo permitido, como texto.",
    "min_role": "Rol mínimo para cambiar el parámetro.",
    "mitigation": "Mitigación redactada, si existe.",
    "mitigation_draft": "Pasos de mitigación sugeridos, si existen.",
    "n": "Número del paso.",
    "name": "Nombre.",
    "names": "Conexiones a probar; todas si se omite.",
    "next_cursor": "Cursor de la página siguiente; nulo en la última.",
    "objects": "Objetos STIX del bundle.",
    "ok": "Si la conexión funciona.",
    "on_older_version": "Si el feedback se dio sobre una versión anterior de la evaluación.",
    "outside_delivery_model": "Activos fuera del modelo de entrega de Hermes.",
    "owner": "Responsable del activo.",
    "owners": "Responsables de los activos afectados.",
    "previous_final": "Puntaje final de la evaluación anterior, si hubo.",
    "previous_value": "Valor actual antes del cambio propuesto.",
    "priority": "Prioridad de entrega.",
    "product": "Producto de software afectado.",
    "progress": "Avance de 0 a 100.",
    "proposed_level": "Nivel que propone la persona; obligatorio si el veredicto es `wrong_priority`.",
    "proposed_score": "Puntaje que propone la persona (0 a 100), opcional.",
    "proposed_value": "Valor propuesto.",
    "rank_correlation": "Correlación de rangos entre el orden crudo y el final, como texto.",
    "raw": "Valor crudo: 100 x S, lo que diría un escáner con solo CVSS.",
    "reclassification_matrix": "Nivel por CVSS -> nivel de Hermes -> cantidad.",
    "reclassified_percent": "Porcentaje de hallazgos que cambiaron de nivel, como texto.",
    "ref": "Referencia del ticket en iTop.",
    "relevance": "Por qué es relevante la alerta.",
    "risk": "Riesgo del activo: el mayor final de sus hallazgos.",
    "role": "Rol del usuario.",
    "run_id": "Id de la corrida cuyo resultado se exporta.",
    "scope": "Qué se exporta.",
    "score": "Puntaje.",
    "sector": "Sector de la empresa (código del catálogo).",
    "sessions_revoked": "Si se revocaron las sesiones activas del usuario.",
    "skipped": "Si el paso se omitió.",
    "software": "Nombre del software en el inventario.",
    "software_without_cpe": "Software que aún no tiene CPE.",
    "started_at": "Cuándo empezó (UTC).",
    "status": "Estado.",
    "structural": "Si es una fuente estructural: no se puede apagar.",
    "subsectors": "Subsectores (códigos del catálogo).",
    "summary": "Resumen para personas.",
    "target": "Qué se cambió.",
    "ticket_url": "Enlace al ticket de iTop, si existe.",
    "tickets": "Tickets de iTop del grupo.",
    "title": "Título.",
    "top_movers": "Hasta 5 hallazgos que más cambian de puntaje.",
    "total_cis": "Activos totales del ticket.",
    "type": "Tipo.",
    "uid": "Identificador del usuario en Firebase.",
    "unit": "Unidad de la métrica.",
    "urgency": "Urgencia de iTop: 1 (crítica) a 4 (baja).",
    "url": "Enlace.",
    "user": "Correo o nombre de quien dio el feedback.",
    "validations": "Reglas de validación del parámetro, en texto.",
    "value": "Valor de la métrica, como texto.",
    "values": "Valores vigentes: clave -> valor, como texto.",
    "vector": "Vector de ataque mencionado.",
    "verdict": "Veredicto de la persona.",
    "version": "Número de versión.",
    "victim": "Víctima mencionada.",
    "view": "Vista que se devuelve.",
    "vulnerability_id": "Id del grupo de vulnerabilidad a exportar.",
    "without_classification": "Activos sin clasificación.",
    "without_custodian": "Activos sin equipo custodio.",
    "without_exposure": "Activos sin dato de exposición.",
    "without_owner": "Activos sin responsable.",
    # F18.1 (D-088): telemetry, inventory, tickets, history, judge detail, users and the error queue.
    "accepted": "Veces que se aceptó.",
    "agent": "Agente de IA: analista de noticias, analista de CVE o juez.",
    "agents": "Una entrada por agente de IA.",
    "by_status": "Cantidad por estado: estado -> cantidad.",
    "cost_usd": "Costo en dólares (USD), como texto.",
    "days": "Días de la serie.",
    "last_model": "Modelo de la última revisión guardada de ese agente, si hubo.",
    "latency_avg_ms": "Latencia promedio de una llamada al LLM, en milisegundos.",
    "latency_p95_ms": "Latencia p95 de una llamada al LLM, en milisegundos.",
    "ladder_label": "Nombre del nivel de la escalera del juez.",
    "ladder_level": "Nivel de la escalera del juez: 0 normal, 1 vigilado, 2 cauteloso, 3 apagado.",
    "mode": "Modo del agente (por ejemplo `scoring` o `dismissals`).",
    "model": "Modelo de IA.",
    "provider": "Proveedor del LLM.",
    "reasons_accepted": "Motivos del juez aceptados en esta revisión.",
    "reasons_rejected": "Motivos del juez rechazados en esta revisión.",
    "rejected": "Veces que se rechazó.",
    "reviews": "Revisiones de IA.",
    "runs": "Corridas por tipo y estado.",
    "runs_failed": "Corridas que terminaron con error.",
    "runs_queued": "Corridas en cola.",
    "runs_running": "Corridas en ejecución.",
    "runs_succeeded": "Corridas que terminaron bien.",
    "run_success_percent": "Corridas terminadas bien sobre las terminadas, en %, como texto; nulo sin corridas.",
    "second_review": "Si es la segunda revisión ciega de una doble revisión.",
    "series": "Un punto por día, del más antiguo al más reciente.",
    "since": "Inicio de la ventana (UTC).",
    "spend_today_usd": "Gasto de LLM de hoy (UTC) en dólares, como texto.",
    "daily_budget_usd": "Presupuesto diario de LLM en dólares, como texto.",
    "success_percent": "Revisiones válidas sobre las terminadas, en %, como texto; nulo sin revisiones.",
    "tokens_cached": "Tokens de entrada leídos de la caché.",
    "tokens_input": "Tokens de entrada.",
    "tokens_output": "Tokens de salida.",
    "tokens_reasoning": "Tokens de razonamiento.",
    "top_reasons": "Motivos del juez más usados en la ventana, con cuántas veces se aceptaron y rechazaron.",
    "window": "Ventana del resumen.",
    "at": "Cuándo ocurrió (UTC).",
    "config_version": "Versión de la configuración que creó el cambio.",
    "duration_seconds": "Duración en segundos; nula si no terminó.",
    "run_kind": "Tipo de corrida, si el evento es una corrida.",
    "trigger": "Por qué se lanzó la corrida.",
}
OVERRIDES: Final[dict[str, str]] = {
    "Alert.id": "Id de la alerta.",
    "Alert.created_at": "Cuándo se creó la alerta (UTC).",
    "Alert.summary": "Resumen de la noticia, en español.",
    "AssetDetail.risk": "Riesgo del activo: el mayor final de sus hallazgos.",
    "AuditEntry.id": "Id del registro.",
    "AuditEntry.target": "Qué se cambió, por ejemplo `source:cisa_kev`.",
    "CalibrationProposal.id": "Id de la propuesta.",
    "CalibrationProposal.kind": "Qué clase de ajuste propone.",
    "CalibrationProposal.status": "Estado de la decisión.",
    "CalibrationProposal.created_at": "Cuándo se generó (UTC).",
    "CalibrationProposal.summary": "Resumen de la propuesta, en español.",
    "ConfigParameter.key": "Clave del parámetro, por ejemplo `weights.S` o `dead_zone`.",
    "ConfigParameter.type": "Tipo del valor.",
    "ConfigParameter.level": "Qué tan libremente se cambia.",
    "ConfigVersion.version": "Número de la versión.",
    "ConfigVersion.created_at": "Cuándo se guardó (UTC).",
    "ConfigVersion.summary": "Qué cambió, en español.",
    "ConfigDocument.version": "Versión vigente de la configuración.",
    "CompanyProfile.version": "Versión del perfil; mándala como `expected_version` al guardar.",
    "ComparisonRow.product": "Producto de software afectado.",
    "ComparisonRow.final": "Puntaje final de Hermes.",
    "ComparisonRow.base": "Puntaje base antes del juez.",
    "ComparisonRow.ci_id": "Id del CI en iTop.",
    "CpeCandidate.score": "Qué tan bien coincide (0 a 1).",
    "CpeCandidate.title": "Nombre del producto en el diccionario CPE.",
    "FeedbackEntry.active": "Si es el feedback vigente de la persona (uno por evaluación).",
    "FeedbackEntry.verdict": "Veredicto dado.",
    "FeedbackEntry.created_at": "Cuándo se dio (UTC).",
    "FeedbackEntry.proposed_level": "Nivel propuesto por la persona.",
    "FeedbackEntry.proposed_score": "Puntaje propuesto por la persona.",
    "FeedbackEntry.comment": "Comentario de la persona.",
    "InventoryItem.name": "Nombre del activo o del software.",
    "Metric.key": "Clave estable de la métrica.",
    "Metric.label": "Nombre de la métrica, en español.",
    "NotificationEventRow.id": "Id del evento.",
    "NotificationEventRow.type": "Tipo de evento, por ejemplo `new_ticket` o `level_up`.",
    "NotificationEventRow.status": "Estado de la entrega.",
    "NotificationEventRow.created_at": "Cuándo se generó (UTC).",
    "PeerCompany.id": "Id de la empresa par.",
    "ProfileUpdate.expected_version": "Versión del perfil que el cliente leyó; 409 si cambió.",
    "Recommendation.created_at": "Cuándo se hizo la evaluación (UTC).",
    "Recommendation.level": "Nivel de la evaluación.",
    "Recommendation.cve": "CVE; nulo en alertas inferidas por la IA.",
    "Recommendation.product": "Producto afectado; nulo en alertas inferidas.",
    "Run.id": "Id de la corrida.",
    "Run.kind": "Qué clase de corrida es.",
    "Run.status": "Estado de la corrida.",
    "ScanRequest.kind": "Siempre `scan`.",
    "ScoreHistoryPoint.base": "Puntaje base ese día.",
    "SetupStep.name": "Nombre del paso.",
    "Source.id": "Id de la fuente.",
    "Source.name": "Nombre de la fuente.",
    "Source.type": "Clase de fuente.",
    "Source.level": "Nivel de confianza.",
    "StixBundle.id": "Id del bundle (`bundle--` y un UUID).",
    "StixBundle.type": "Siempre `bundle`.",
    "Ticket.status": "Estado del ticket en iTop.",
    "Ticket.cve": "CVE del ticket.",
    "Ticket.custodian": "Equipo custodio del ticket.",
    "VulnerabilityBand.level": "Nivel de la banda.",
    "VulnerabilityDetail.description": "Descripción del CVE.",
    "VulnerabilityGroup.status": "Estado del hallazgo.",
    "VulnerabilityGroup.final": "Puntaje final más alto entre sus activos.",
    "VulnerabilityGroup.level": "Nivel del puntaje final.",
    "VulnerabilityList.groups": "Grupos de la página (vistas `vulnerability`).",
    "VulnerabilityList.assets": "Activos de la página (vista `asset`).",
    "AffectedAsset.score": "Puntaje final del activo (0 a 100).",
    "AffectedAsset.name": "Nombre del activo.",
    "AssetRisk.name": "Nombre del activo.",
    "AssetRisk.status": "Estado.",
    "AssetRisk.last_seen": "Última vez que se vio un hallazgo en el activo (UTC).",
    "AssetRisk.in_kev": "Cantidad de hallazgos del activo en el catálogo KEV.",
    "ConnectionStatus.name": "Conexión comprobada.",
    "ErrorResponse.error": "Detalle del error.",
    "ErrorBody.details": "Problemas concretos: campo y regla que falló.",
    "ItopWebhookCall.class": "Clase del objeto de iTop; hoy solo `UserRequest`.",
    "ItopWebhookCall.ref": "Referencia del ticket en iTop.",
    "FeedbackResult.feedback_id": "Id del feedback guardado.",
    "RoleAssignment.role": "Rol que se asigna.",
    "RoleAssigned.role": "Rol asignado.",
    "WebhookAccepted.status": "Siempre `accepted`.",
    "Run.trigger_reason": "Por qué se lanzó la corrida.",
    "Run.triggered_by": "Nombre de quien la lanzó; nulo si la lanzó la agenda.",
    "HistoryEvent.id": "Id del evento (el de la corrida, la revisión o el registro del cambio).",
    "HistoryEvent.type": "Tipo de evento.",
    "HistoryEvent.status": "Estado final: el de la corrida, el de la revisión o `applied` en un cambio.",
    "HistoryEvent.actor": "Quién: la persona que lanzó o cambió, el agente de IA o `sistema`.",
    "HistoryEvent.assessment_id": "Evaluación que alimentó la revisión; con ella se lee su feedback.",
    "HistoryEvent.title": "Título del evento, en español.",
    "SimulationResult.last_30_days_effect": "Resumen del impacto sobre los hallazgos abiertos de hoy, en español.",
    "AgentTelemetry.active": "Si el agente puede trabajar: queda presupuesto hoy y, para el juez, la escalera no "
    "lo apagó.",
    "AgentTelemetry.model": "Modelo configurado para el agente con el proveedor vigente.",
    "AgentTelemetry.reviews": "Revisiones del agente en la ventana.",
    "AgentDay.reviews": "Revisiones del agente ese día.",
    "LlmReviewEntry.id": "Id de la revisión.",
    "LlmReviewEntry.status": "Resultado de la revisión.",
    "LlmReviewEntry.attempts": "Intentos (reintentos de formato incluidos).",
    "LlmReviewEntry.latency_ms": "Latencia total de la revisión, en milisegundos.",
    "LlmReviewEntry.ladder_level": "Nivel de la escalera del juez cuando se hizo la revisión.",
    "LlmReviewEntry.assessment_id": "Evaluación que usó esta revisión, si la hay.",
    "ReasonUsage.code": "Código del motivo, por ejemplo `mass_exploitation`.",
    "ReasonUsage.label": "Descripción del motivo, en español.",
    "RunCounts.kind": "Tipo de corrida.",
    "RunCounts.queued": "En cola.",
    "RunCounts.running": "En ejecución.",
    "RunCounts.succeeded": "Terminadas bien.",
    "RunCounts.failed": "Terminadas con error (o canceladas).",
    "TelemetryDay.date": "Día (UTC), `AAAA-MM-DD`.",
    "TelemetryDay.agents": "Revisiones del día por agente.",
    "TelemetrySummary.generated_at": "Cuándo se calculó el resumen (UTC).",
    "TelemetrySummary.ladder_level": "Nivel vigente de la escalera del juez (0 a 3).",
}

EXAMPLES: Final[dict[str, list[dict[str, Any]]]] = {
    "ConfigUpdate": [{"expected_version": 3, "changes": {"weights.S": "0.30", "weights.P": "0.25"}}],
    "ConfigDocument": [
        {"version": 4, "values": {"weights.S": "0.30", "dead_zone": "4", "notifications.consumer": "log"}}
    ],
    "SimulationRequest": [{"changes": {"weights.S": "0.30", "weights.P": "0.25"}}],
    "SimulationResult": [
        {
            "changed_findings": 2,
            "level_matrix": {"high": {"high": 5, "critical": 1}, "medium": {"medium": 8, "high": 1}},
            "last_30_days_effect": "2 de 15 hallazgos abiertos cambiarían de nivel con la fórmula propuesta.",
            "top_movers": ["CVE-2026-10001 en srv-pagos-01: 70 a 82"],
        }
    ],
    "FeedbackRequest": [
        {
            "assessment_id": "0192f3a4-7b1e-7c2d-8a5f-3e4d5c6b7a89",
            "verdict": "wrong_priority",
            "proposed_level": "high",
            "comment": "El servidor no está expuesto a internet.",
            "ticket_itop_id": "1234",
        }
    ],
    "FeedbackResult": [{"feedback_id": "0192f3a5-1c2d-7e3f-9a4b-5c6d7e8f9a0b", "replaced_previous": False}],
    "SourceCreate": [
        {"name": "Boletín de seguridad de ejemplo", "url": "https://feeds.example.test/seguridad.xml", "kind": "rss"}
    ],
    "SourcePatch": [{"active": True}],
    "StixExportRequest": [
        {
            "scope": "vulnerability",
            "vulnerability_id": "0192f3a4-7b1e-7c2d-8a5f-3e4d5c6b7a89",
            "exclude_ultra_classified": True,
        }
    ],
    "ScanRequest": [{"kind": "scan"}],
    "Run": [
        {
            "id": "0192f3a6-2d3e-7f40-8b5c-6d7e8f9a0b1c",
            "kind": "scan",
            "status": "running",
            "started_at": "2026-11-23T10:30:00Z",
            "finished_at": None,
            "progress": 40,
        }
    ],
    "Ticket": [
        {
            "itop_id": "1234",
            "url": "https://itop.example.test/pages/UI.php?operation=details&class=UserRequest&id=1234",
            "cve": "CVE-2026-10001",
            "custodian": "Infraestructura Linux",
            "urgency": 1,
            "status": "En atención",
            "fixed_cis": 1,
            "total_cis": 3,
        }
    ],
    "Alert": [
        {
            "id": "0192f3a7-3e4f-7051-9c6d-7e8f9a0b1c2d",
            "created_at": "2026-11-22T08:00:00Z",
            "relevance": "R2",
            "inferred": False,
            "actor": "Grupo Ejemplo",
            "victim": None,
            "vector": "Credenciales expuestas",
            "summary": "Campaña contra servidores Redis expuestos; la empresa usa Redis 7.0.",
            "ci_id": "CI-0003",
        }
    ],
    "CompanyProfile": [
        {"sector": "fintech", "subsectors": ["payments"], "countries": ["MX"], "language": "es", "version": 2}
    ],
    "ProfileUpdate": [
        {"expected_version": 2, "sector": "fintech", "subsectors": ["payments"], "countries": ["MX"], "language": "es"}
    ],
    "PeerCompanyInput": [
        {
            "name": "Pagos Ejemplo",
            "aliases": ["PagosEj"],
            "domain": "pagos-ejemplo.example.test",
            "sector": "fintech",
            "country": "MX",
        }
    ],
    "Source": [
        {
            "id": "cisa_kev",
            "name": "CISA KEV",
            "type": "official",
            "level": "N1",
            "structural": True,
            "active": True,
            "last_capture": "2026-11-23T06:00:00Z",
            "items_per_run": 12,
            "health": "ok",
        }
    ],
    "Recommendation": [
        {
            "assessment_id": "0192f3a4-7b1e-7c2d-8a5f-3e4d5c6b7a89",
            "created_at": "2026-11-23T10:35:00Z",
            "cve": "CVE-2026-10001",
            "product": "OpenSSL 3.0.7",
            "base": 82,
            "judge_adjustment": 8,
            "final": 90,
            "level": "critical",
            "previous_final": None,
            "justification": "Vulnerabilidad explotada activamente en un servidor expuesto, "
            "impulsada por srv-pagos-01.",
            "mitigation": "Actualizar OpenSSL a la versión 3.0.8 o superior.",
            "mitigation_draft": ["Aislar el servidor de la red pública.", "Aplicar el parche del fabricante."],
            "asset": None,
            "ticket_url": None,
            "feedback_count": 1,
        }
    ],
    "ErrorResponse": [
        {
            "error": {
                "code": "validation_error",
                "message": "La solicitud no es válida.",
                "details": [{"field": "body.changes", "issue": "missing"}],
            }
        }
    ],
    "ConnectionTestRequest": [{"names": ["itop", "nvd"]}],
    "SetupStepUpdate": [{"done": True, "skipped": False}],
    "RoleAssignment": [{"role": "analyst"}],
    "LlmReviewEntry": [
        {
            "id": "0192f3a8-4f50-7162-8d7e-8f9a0b1c2d3e",
            "created_at": "2026-11-23T10:34:12Z",
            "agent": "judge",
            "mode": "scoring",
            "model": "deepseek-v4-pro",
            "status": "applied",
            "attempts": 1,
            "latency_ms": 9800,
            "tokens_input": 14200,
            "tokens_cached": 9000,
            "tokens_output": 820,
            "tokens_reasoning": 0,
            "cost_usd": "0.004120",
            "ladder_level": 0,
            "second_review": False,
            "assessment_id": "0192f3a4-7b1e-7c2d-8a5f-3e4d5c6b7a89",
            "reasons_accepted": 2,
            "reasons_rejected": 1,
        }
    ],
    "HistoryEvent": [
        {
            "id": "0192f3a6-2d3e-7f40-8b5c-6d7e8f9a0b1c",
            "type": "run",
            "at": "2026-11-23T10:30:00Z",
            "title": "Escaneo simulado",
            "status": "succeeded",
            "actor": "Ana Analista",
            "trigger": "manual",
            "run_kind": "scan",
            "agent": None,
            "assessment_id": None,
            "config_version": None,
            "duration_seconds": 412,
        }
    ],
}


def _described(schema: dict[str, Any]) -> bool:
    return "description" in schema or any("description" in part for part in schema.get("anyOf", []))


def _enum_values(schema: dict[str, Any]) -> tuple[str, ...] | None:
    if "enum" in schema:
        return tuple(str(v) for v in schema["enum"])
    for part in schema.get("anyOf", []):
        if "enum" in part:
            return tuple(str(v) for v in part["enum"])
    return None


def _with_values(text: str, values: tuple[str, ...]) -> str:
    meanings = ENUMS.get(values)
    if meanings is None:
        return text
    listing = "; ".join(f"`{value}`: {meanings[value]}" for value in values)
    return f"{text} Valores: {listing}."


def _document_schema(name: str, schema: dict[str, Any]) -> None:
    for prop, body in schema.get("properties", {}).items():
        text = OVERRIDES.get(f"{name}.{prop}") or FIELDS.get(prop)
        if not _described(body) and text is not None:
            body["description"] = text
        values = _enum_values(body)
        if values is not None:
            base = body.get("description") or next(
                (p["description"] for p in body.get("anyOf", []) if "description" in p), None
            )
            if base is not None:
                body["description"] = _with_values(base, values)
                for part in body.get("anyOf", []):
                    part.pop("description", None)
    if name in EXAMPLES:
        schema["examples"] = deepcopy(EXAMPLES[name])


def _document_parameter(parameter: dict[str, Any]) -> None:
    text = parameter.get("description") or PARAMS.get(parameter["name"])
    if text is None:
        return
    values = _enum_values(parameter.get("schema", {}))
    parameter["description"] = _with_values(text, values) if values is not None else text


def apply(document: dict[str, Any]) -> dict[str, Any]:
    """Edit the generated OpenAPI document in place and return it."""
    document["info"].update(
        description=INFO_DESCRIPTION, contact=CONTACT, license={"name": "Apache-2.0", "identifier": "Apache-2.0"}
    )
    document["servers"] = deepcopy(SERVERS)
    document["tags"] = [{"name": tag, "description": f"{title}. {about}"} for tag, title, about in TAGS]
    for path, methods in document["paths"].items():
        for method, operation in methods.items():
            op = OPERATIONS.get((method.upper(), path))
            if op is None:
                continue
            operation["operationId"] = op.operation_id
            operation["tags"] = [op.tag]
            operation["summary"] = op.summary
            operation["description"] = op.description
            for parameter in operation.get("parameters", []):
                _document_parameter(parameter)
    for name, schema in document.get("components", {}).get("schemas", {}).items():
        _document_schema(name, schema)
    return document
