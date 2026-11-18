use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        DefaultBodyLimit, Path, Query, Request, State,
    },
    http::{header, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use omni_core::{DataPayload, FeatureStatus, OperationCategory};
use omni_pipeline::{PipelineDefinition, PipelineExecutionReport, PipelineValidator};
use omni_registry::{OperationRegistry, RegistryFilter};
use omni_security::sanitize_error_message;
use omni_storage::DatabaseManager;
use omni_workers::JobManager;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::Semaphore;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::services::ServeDir;

#[derive(Debug, Clone)]
pub struct ApiConfig {
    /// Allowed browser origins for CORS (never wildcard with credentials).
    pub allowed_origins: Vec<String>,
    /// Optional bearer token required for protected API and WebSocket access.
    pub auth_token: Option<String>,
    /// Maximum allowed HTTP request body size in bytes.
    pub max_body_bytes: usize,
    /// Upper bound on client-supplied execution timeouts.
    pub max_timeout_seconds: u64,
    /// Maximum concurrent WebSocket connections.
    pub max_ws_connections: usize,
    /// Optional directory containing the frontend web assets to serve at `/`.
    pub frontend_dir: Option<PathBuf>,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self::for_loopback_port(8080)
    }
}

impl ApiConfig {
    pub fn for_loopback_port(port: u16) -> Self {
        Self {
            allowed_origins: vec![
                format!("http://127.0.0.1:{port}"),
                format!("http://localhost:{port}"),
                "http://127.0.0.1".to_string(),
                "http://localhost".to_string(),
                "wry://localhost".to_string(),
                "tauri://localhost".to_string(),
            ],
            auth_token: None,
            max_body_bytes: 16 * 1024 * 1024, // 16 MB
            max_timeout_seconds: 120,
            max_ws_connections: 32,
            frontend_dir: detect_default_frontend_dir(),
        }
    }

    pub fn with_auth_token(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(token.into());
        self
    }

    pub fn with_frontend_dir(mut self, dir: PathBuf) -> Self {
        self.frontend_dir = Some(dir);
        self
    }

    pub fn with_allowed_origins(mut self, origins: Vec<String>) -> Self {
        self.allowed_origins = origins;
        self
    }

    pub fn with_max_body_bytes(mut self, max_bytes: usize) -> Self {
        self.max_body_bytes = max_bytes.max(1024);
        self
    }
}

/// Attempts to locate the local `frontend/` directory relative to the current working directory or executable.
pub fn detect_default_frontend_dir() -> Option<PathBuf> {
    let cwd_candidate = PathBuf::from("frontend");
    if cwd_candidate.join("index.html").is_file() {
        return Some(cwd_candidate);
    }
    if let Ok(exe) = std::env::current_exe() {
        for ancestor in exe.ancestors().take(4) {
            let candidate = ancestor.join("frontend");
            if candidate.join("index.html").is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

#[derive(Clone)]
pub struct AppState {
    pub registry: Arc<RwLock<OperationRegistry>>,
    pub db: Arc<DatabaseManager>,
    pub job_manager: JobManager,
    pub config: ApiConfig,
    pub ws_semaphore: Arc<Semaphore>,
}

impl AppState {
    pub fn new(
        registry: Arc<RwLock<OperationRegistry>>,
        db: Arc<DatabaseManager>,
        job_manager: JobManager,
        config: ApiConfig,
    ) -> Self {
        let ws_limit = config.max_ws_connections.max(1);
        Self {
            registry,
            db,
            job_manager,
            config,
            ws_semaphore: Arc::new(Semaphore::new(ws_limit)),
        }
    }
}

/// Constant-time token equality check to avoid timing side channels.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn check_auth_header(req: &Request, expected_token: &str) -> bool {
    if let Some(auth_val) = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(token) = auth_val.strip_prefix("Bearer ") {
            if constant_time_eq(token.as_bytes(), expected_token.as_bytes()) {
                return true;
            }
        }
    }
    if let Some(header_tok) = req
        .headers()
        .get("x-omni-token")
        .and_then(|v| v.to_str().ok())
    {
        if constant_time_eq(header_tok.as_bytes(), expected_token.as_bytes()) {
            return true;
        }
    }
    false
}

async fn auth_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let Some(ref expected) = state.config.auth_token else {
        return next.run(req).await;
    };

    let path = req.uri().path();
    if path == "/api/v1/health" {
        return next.run(req).await;
    }

    if check_auth_header(&req, expected) {
        return next.run(req).await;
    }

    // For WebSocket endpoints, also allow `?token=<secret>` query parameter
    if path == "/api/v1/ws/jobs" {
        if let Some(query_str) = req.uri().query() {
            for pair in query_str.split('&') {
                if let Some((k, v)) = pair.split_once('=') {
                    if k == "token" && constant_time_eq(v.as_bytes(), expected.as_bytes()) {
                        return next.run(req).await;
                    }
                }
            }
        }
    }

    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({
            "success": false,
            "error": "Unauthorized: valid Bearer token or X-Omni-Token header required"
        })),
    )
        .into_response()
}

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub version: &'static str,
    pub operations_count: usize,
    pub active_jobs: usize,
    pub auth_enabled: bool,
    pub frontend_available: bool,
}

#[derive(Deserialize)]
pub struct ExecuteRequest {
    pub operation_id: String,
    pub input: DataPayload,
    #[serde(default)]
    pub config: serde_json::Value,
    #[serde(default = "default_timeout_secs")]
    pub timeout_seconds: u64,
}

fn default_timeout_secs() -> u64 {
    30
}

#[derive(Serialize)]
pub struct ExecuteResponse {
    pub job_id: Option<String>,
    pub success: bool,
    pub output: Option<DataPayload>,
    pub error: Option<String>,
}

#[derive(Deserialize)]
pub struct OperationsQuery {
    pub category: Option<String>,
    pub q: Option<String>,
    pub status: Option<String>,
    pub tag: Option<String>,
}

#[derive(Deserialize)]
pub struct SearchQuery {
    pub q: Option<String>,
}

#[derive(Deserialize)]
pub struct JobsListQuery {
    pub limit: Option<usize>,
}

#[derive(Deserialize)]
pub struct WsSubscribeQuery {
    pub job_id: Option<String>,
    pub token: Option<String>,
}

fn build_cors_layer(config: &ApiConfig) -> CorsLayer {
    let parsed_origins: Vec<HeaderValue> = config
        .allowed_origins
        .iter()
        .filter(|o| o.as_str() != "*")
        .filter_map(|o| HeaderValue::from_str(o).ok())
        .collect();

    CorsLayer::new()
        .allow_origin(AllowOrigin::list(parsed_origins))
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
        .allow_headers([
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            header::HeaderName::from_static("x-omni-token"),
        ])
}

pub fn create_router(state: AppState) -> Router {
    let cors = build_cors_layer(&state.config);
    let max_body = state.config.max_body_bytes;
    let frontend_dir = state.config.frontend_dir.clone();

    let api_routes = Router::new()
        .route("/api/v1/health", get(health_handler))
        .route("/api/v1/inventory", get(inventory_handler))
        .route("/api/v1/operations", get(list_operations_handler))
        .route("/api/v1/operations/search", get(search_operations_handler))
        .route("/api/v1/operations/{id}", get(get_operation_handler))
        .route("/api/v1/execute", post(execute_handler))
        .route("/api/v1/pipelines", get(list_pipelines_handler))
        .route("/api/v1/pipelines", post(save_pipeline_handler))
        .route("/api/v1/pipelines/{id}", get(get_pipeline_handler))
        .route("/api/v1/pipelines/{id}", delete(delete_pipeline_handler))
        .route("/api/v1/pipelines/validate", post(validate_pipeline_handler))
        .route("/api/v1/pipelines/execute", post(execute_pipeline_handler))
        .route("/api/v1/jobs", get(list_jobs_handler))
        .route("/api/v1/jobs/{id}", get(get_job_handler))
        .route("/api/v1/jobs/{id}", delete(cancel_job_handler))
        .route("/api/v1/ws/jobs", get(ws_handler))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .layer(DefaultBodyLimit::max(max_body))
        .layer(cors)
        .with_state(state);

    if let Some(dir) = frontend_dir {
        if dir.exists() {
            return api_routes.fallback_service(ServeDir::new(dir));
        }
    }

    api_routes
}

async fn health_handler(State(state): State<AppState>) -> impl IntoResponse {
    let count = match state.registry.read() {
        Ok(reg) => reg.len(),
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "status": "error", "error": "Registry unavailable" })),
            )
                .into_response()
        }
    };
    let frontend_available = state
        .config
        .frontend_dir
        .as_ref()
        .map(|d| d.join("index.html").is_file())
        .unwrap_or(false);

    (
        StatusCode::OK,
        Json(HealthResponse {
            status: "ok",
            version: "0.1.0",
            operations_count: count,
            active_jobs: state.job_manager.active_job_count(),
            auth_enabled: state.config.auth_token.is_some(),
            frontend_available,
        }),
    )
        .into_response()
}

async fn inventory_handler(State(state): State<AppState>) -> impl IntoResponse {
    match state.registry.read() {
        Ok(reg) => (StatusCode::OK, Json(reg.export_inventory())).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn list_operations_handler(
    State(state): State<AppState>,
    Query(query): Query<OperationsQuery>,
) -> impl IntoResponse {
    let category = match query.category.as_deref() {
        Some(c) if !c.trim().is_empty() => match OperationCategory::from_str_loose(c) {
            Some(parsed) => Some(parsed),
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": format!("Unknown category '{}'", c)
                    })),
                )
                    .into_response();
            }
        },
        _ => None,
    };

    let status = match query.status.as_deref() {
        Some(s) if !s.trim().is_empty() => match FeatureStatus::from_str_loose(s) {
            Some(parsed) => Some(parsed),
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": format!("Unknown feature status '{}'", s)
                    })),
                )
                    .into_response();
            }
        },
        _ => None,
    };

    match state.registry.read() {
        Ok(reg) => {
            let manifests = reg.filter(&RegistryFilter {
                category,
                query: query.q.as_deref(),
                tag: query.tag.as_deref(),
                status,
                ..Default::default()
            });
            (StatusCode::OK, Json(manifests)).into_response()
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn get_operation_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let Ok(reg) = state.registry.read() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    if let Some(op) = reg.get(&id) {
        match serde_json::to_value(op.manifest()) {
            Ok(val) => (StatusCode::OK, Json(val)).into_response(),
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

async fn search_operations_handler(
    State(state): State<AppState>,
    Query(query): Query<SearchQuery>,
) -> impl IntoResponse {
    let Ok(reg) = state.registry.read() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let q = query.q.unwrap_or_default();
    (StatusCode::OK, Json(reg.search(&q))).into_response()
}

async fn execute_handler(
    State(state): State<AppState>,
    Json(req): Json<ExecuteRequest>,
) -> impl IntoResponse {
    if req.operation_id.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ExecuteResponse {
                job_id: None,
                success: false,
                output: None,
                error: Some("operation_id must not be empty".into()),
            }),
        )
            .into_response();
    }

    let capped_timeout = req
        .timeout_seconds
        .clamp(1, state.config.max_timeout_seconds);
    let timeout = Duration::from_secs(capped_timeout);

    match state
        .job_manager
        .run_operation_with_id(&req.operation_id, req.input, req.config, timeout)
        .await
    {
        Ok((job_id, output)) => (
            StatusCode::OK,
            Json(ExecuteResponse {
                job_id: Some(job_id),
                success: true,
                output: Some(output),
                error: None,
            }),
        )
            .into_response(),
        Err(e) => {
            let status = match &e {
                omni_core::OmniError::NotFound(_) => StatusCode::NOT_FOUND,
                omni_core::OmniError::Security(_) => StatusCode::FORBIDDEN,
                omni_core::OmniError::Timeout(_) => StatusCode::REQUEST_TIMEOUT,
                omni_core::OmniError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
                _ => StatusCode::BAD_REQUEST,
            };
            (
                status,
                Json(ExecuteResponse {
                    job_id: None,
                    success: false,
                    output: None,
                    error: Some(sanitize_error_message(&e.to_string())),
                }),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct PipelineExecuteRequest {
    pub pipeline: PipelineDefinition,
    pub input: DataPayload,
    #[serde(default = "default_timeout_secs")]
    pub timeout_seconds: u64,
}

#[derive(Serialize)]
pub struct PipelineExecuteResponse {
    pub success: bool,
    pub outputs: Option<HashMap<String, DataPayload>>,
    pub report: Option<PipelineExecutionReport>,
    pub error: Option<String>,
}

async fn validate_pipeline_handler(
    State(state): State<AppState>,
    Json(pipeline): Json<PipelineDefinition>,
) -> impl IntoResponse {
    let Ok(reg) = state.registry.read() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    match PipelineValidator::validate(&pipeline, &reg) {
        Ok(order) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "valid": true,
                "execution_order": order
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "valid": false,
                "error": sanitize_error_message(&e.to_string())
            })),
        )
            .into_response(),
    }
}

async fn execute_pipeline_handler(
    State(state): State<AppState>,
    Json(req): Json<PipelineExecuteRequest>,
) -> impl IntoResponse {
    let capped_timeout = req
        .timeout_seconds
        .clamp(1, state.config.max_timeout_seconds);
    let timeout = Duration::from_secs(capped_timeout);

    match state
        .job_manager
        .run_pipeline_with_report(&req.pipeline, req.input, timeout)
        .await
    {
        Ok(report) => (
            StatusCode::OK,
            Json(PipelineExecuteResponse {
                success: true,
                outputs: Some(report.outputs.clone()),
                report: Some(report),
                error: None,
            }),
        )
            .into_response(),
        Err(e) => {
            let status = match &e {
                omni_core::OmniError::NotFound(_) => StatusCode::NOT_FOUND,
                omni_core::OmniError::Security(_) => StatusCode::FORBIDDEN,
                omni_core::OmniError::Timeout(_) => StatusCode::REQUEST_TIMEOUT,
                omni_core::OmniError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
                _ => StatusCode::BAD_REQUEST,
            };
            (
                status,
                Json(PipelineExecuteResponse {
                    success: false,
                    outputs: None,
                    report: None,
                    error: Some(sanitize_error_message(&e.to_string())),
                }),
            )
                .into_response()
        }
    }
}

async fn list_pipelines_handler(State(state): State<AppState>) -> impl IntoResponse {
    match state.db.list_pipelines() {
        Ok(list) => (StatusCode::OK, Json(list)).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn save_pipeline_handler(
    State(state): State<AppState>,
    Json(pipeline): Json<PipelineDefinition>,
) -> impl IntoResponse {
    if pipeline.id.trim().is_empty() || pipeline.name.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Pipeline id and name must not be empty" })),
        )
            .into_response();
    }
    match state.db.save_pipeline(&pipeline) {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({ "saved": true, "id": pipeline.id })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": sanitize_error_message(&e.to_string()) })),
        )
            .into_response(),
    }
}

async fn get_pipeline_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.db.get_pipeline(&id) {
        Ok(Some(pipe)) => (StatusCode::OK, Json(pipe)).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn delete_pipeline_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.db.delete_pipeline(&id) {
        Ok(true) => StatusCode::OK.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn list_jobs_handler(
    State(state): State<AppState>,
    Query(query): Query<JobsListQuery>,
) -> impl IntoResponse {
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    match state.db.list_jobs(limit) {
        Ok(jobs) => (StatusCode::OK, Json(jobs)).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn get_job_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.db.get_job(&id) {
        Ok(Some(job)) => (StatusCode::OK, Json(job)).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn cancel_job_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if state.job_manager.cancel_job(&id) {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    }
}

async fn ws_handler(
    ws: Result<WebSocketUpgrade, axum::extract::ws::rejection::WebSocketUpgradeRejection>,
    State(state): State<AppState>,
    Query(query): Query<WsSubscribeQuery>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    // 1. Enforce authentication if configured (defense in depth)
    if let Some(ref expected) = state.config.auth_token {
        let header_ok = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .map(|t| constant_time_eq(t.as_bytes(), expected.as_bytes()))
            .unwrap_or(false)
            || headers
                .get("x-omni-token")
                .and_then(|v| v.to_str().ok())
                .map(|t| constant_time_eq(t.as_bytes(), expected.as_bytes()))
                .unwrap_or(false);
        let query_ok = query
            .token
            .as_deref()
            .map(|t| constant_time_eq(t.as_bytes(), expected.as_bytes()))
            .unwrap_or(false);

        if !header_ok && !query_ok {
            return (
                StatusCode::UNAUTHORIZED,
                "Unauthorized WebSocket connection",
            )
                .into_response();
        }
    }

    // 2. Validate job-specific subscription BEFORE accepting upgrade
    let job_filter = query.job_id.filter(|id| !id.trim().is_empty());
    if let Some(ref target_id) = job_filter {
        if target_id.len() > 128
            || !target_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return (StatusCode::BAD_REQUEST, "Invalid job_id format").into_response();
        }
    }

    // 3. Enforce WebSocket connection resource limit
    let Ok(permit) = state.ws_semaphore.clone().try_acquire_owned() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "Maximum concurrent WebSocket connections reached",
        )
            .into_response();
    };

    let Ok(ws_upgrade) = ws else {
        return (
            StatusCode::UPGRADE_REQUIRED,
            "WebSocket upgrade headers required",
        )
            .into_response();
    };

    ws_upgrade.on_upgrade(move |socket| handle_socket(socket, state, job_filter, permit))
}

async fn handle_socket(
    mut socket: WebSocket,
    state: AppState,
    job_filter: Option<String>,
    _permit: tokio::sync::OwnedSemaphorePermit,
) {
    // Prefer strictly isolated per-job channel when subscribing to an active job ID
    let mut rx = match &job_filter {
        Some(target_id) => match state.job_manager.subscribe_job(target_id) {
            Some(job_rx) => job_rx,
            None => state.job_manager.subscribe(),
        },
        None => state.job_manager.subscribe(),
    };

    loop {
        tokio::select! {
            // Monitor client disconnects or incoming control frames
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    Some(Ok(Message::Ping(payload))) => {
                        if socket.send(Message::Pong(payload)).await.is_err() {
                            break;
                        }
                    }
                    _ => {}
                }
            }
            evt_res = rx.recv() => {
                match evt_res {
                    Ok(event) => {
                        // Strict event isolation: if a job_id filter is active, NEVER leak other jobs' events
                        if let Some(ref target_id) = job_filter {
                            if event.job_id() != target_id {
                                continue;
                            }
                        }
                        if let Ok(json) = serde_json::to_string(&event) {
                            // Bound send duration so a stalled consumer cannot hold resources indefinitely
                            let send_res = tokio::time::timeout(
                                Duration::from_secs(5),
                                socket.send(Message::Text(json.into())),
                            ).await;
                            if !matches!(send_res, Ok(Ok(()))) {
                                break;
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        let notice = serde_json::json!({
                            "warning": "lagged",
                            "skipped_events": skipped
                        })
                        .to_string();
                        if socket.send(Message::Text(notice.into())).await.is_err() {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use omni_core::{
        async_trait, DataPayload, ExecutionContext, OmniResult, Operation, OperationCategory,
        OperationManifest,
    };
    use tower::ServiceExt;

    struct EchoOp;
    #[async_trait]
    impl Operation for EchoOp {
        fn manifest(&self) -> OperationManifest {
            OperationManifest::new(
                "api.echo",
                "Echo",
                "Echo input",
                OperationCategory::TextAndCode,
            )
        }
        async fn execute(
            &self,
            input: DataPayload,
            _config: serde_json::Value,
            _ctx: &ExecutionContext,
        ) -> OmniResult<DataPayload> {
            Ok(input)
        }
    }

    fn make_state(config: ApiConfig) -> AppState {
        let mut reg = OperationRegistry::new();
        reg.register(Arc::new(EchoOp)).unwrap();
        let reg = Arc::new(RwLock::new(reg));
        let db = Arc::new(DatabaseManager::open_in_memory().unwrap());
        let job_mgr = JobManager::new(reg.clone(), db.clone());
        AppState::new(reg, db, job_mgr, config)
    }

    #[tokio::test]
    async fn test_api_health_and_execute() {
        let state = make_state(ApiConfig::default());
        let app = create_router(state);

        // Health
        let req = Request::builder()
            .uri("/api/v1/health")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Execute
        let exec_body = serde_json::json!({
            "operation_id": "api.echo",
            "input": { "type": "Text", "data": "Hello Axum" }
        });
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/execute")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(exec_body.to_string()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_api_auth_token_enforcement() {
        let cfg = ApiConfig::default().with_auth_token("secret-test-token");
        let app = create_router(make_state(cfg));

        // Unauthenticated request to protected endpoint must return 401
        let req = Request::builder()
            .uri("/api/v1/operations")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Wrong token must return 401
        let req = Request::builder()
            .uri("/api/v1/operations")
            .header("authorization", "Bearer wrong-token")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Valid Bearer token must return 200
        let req = Request::builder()
            .uri("/api/v1/operations")
            .header("authorization", "Bearer secret-test-token")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_api_cors_restricts_untrusted_origins() {
        let cfg = ApiConfig::default().with_allowed_origins(vec!["http://127.0.0.1:8080".into()]);
        let app = create_router(make_state(cfg));

        // Trusted origin gets Allow-Origin echoed
        let ok_req = Request::builder()
            .uri("/api/v1/health")
            .header("origin", "http://127.0.0.1:8080")
            .body(axum::body::Body::empty())
            .unwrap();
        let ok_resp = app.clone().oneshot(ok_req).await.unwrap();
        assert_eq!(
            ok_resp
                .headers()
                .get("access-control-allow-origin")
                .and_then(|v| v.to_str().ok()),
            Some("http://127.0.0.1:8080")
        );

        // Untrusted origin does NOT receive Allow-Origin header
        let bad_req = Request::builder()
            .uri("/api/v1/health")
            .header("origin", "https://evil.example.com")
            .body(axum::body::Body::empty())
            .unwrap();
        let bad_resp = app.oneshot(bad_req).await.unwrap();
        assert!(bad_resp.headers().get("access-control-allow-origin").is_none());
    }

    #[tokio::test]
    async fn test_api_body_limit_rejects_oversized_payload() {
        let cfg = ApiConfig::default().with_max_body_bytes(1024);
        let app = create_router(make_state(cfg));

        let big_body = "x".repeat(4096);
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/execute")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(big_body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn test_api_category_filter_and_pipeline_crud() {
        let app = create_router(make_state(ApiConfig::default()));

        // Valid category filter
        let req = Request::builder()
            .uri("/api/v1/operations?category=TextAndCode")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Invalid category returns 400
        let req = Request::builder()
            .uri("/api/v1/operations?category=NonExistentCategory")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // Save pipeline & list pipelines
        let pipe = serde_json::json!({
            "id": "p_test",
            "name": "Test Pipe",
            "nodes": [{ "id": "n1", "operation_id": "api.echo", "config": {} }],
            "edges": []
        });
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/pipelines")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(pipe.to_string()))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let req = Request::builder()
            .uri("/api/v1/pipelines/p_test")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_api_serves_frontend_and_rejects_unauthorized_ws() {
        let dir = std::env::temp_dir().join(format!("omni_api_fe_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("index.html"), b"<!doctype html><title>OMNI</title>").unwrap();

        let cfg = ApiConfig::default()
            .with_auth_token("ws-secret")
            .with_frontend_dir(dir.clone());
        let app = create_router(make_state(cfg));

        // 1. Root serves index.html cleanly
        let req = Request::builder()
            .uri("/")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // 2. WebSocket endpoint without token returns 401
        let ws_req = Request::builder()
            .uri("/api/v1/ws/jobs")
            .header("connection", "upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .body(axum::body::Body::empty())
            .unwrap();
        let ws_resp = app.clone().oneshot(ws_req).await.unwrap();
        assert_eq!(ws_resp.status(), StatusCode::UNAUTHORIZED);

        // 3. WebSocket with valid token but invalid job_id returns 400
        let bad_job_req = Request::builder()
            .uri("/api/v1/ws/jobs?token=ws-secret&job_id=../evil")
            .header("connection", "upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .body(axum::body::Body::empty())
            .unwrap();
        let bad_job_resp = app.oneshot(bad_job_req).await.unwrap();
        assert_eq!(bad_job_resp.status(), StatusCode::BAD_REQUEST);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
