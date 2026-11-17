use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, Query, State,
    },
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use omni_core::DataPayload;
use omni_pipeline::PipelineDefinition;
use omni_registry::OperationRegistry;
use omni_storage::DatabaseManager;
use omni_workers::JobManager;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tower_http::cors::CorsLayer;

#[derive(Clone)]
pub struct AppState {
    pub registry: Arc<RwLock<OperationRegistry>>,
    pub db: Arc<DatabaseManager>,
    pub job_manager: JobManager,
}

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub version: &'static str,
    pub operations_count: usize,
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
    pub success: bool,
    pub output: Option<DataPayload>,
    pub error: Option<String>,
}

#[derive(Deserialize)]
pub struct SearchQuery {
    pub q: Option<String>,
}

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/health", get(health_handler))
        .route("/api/v1/operations", get(list_operations_handler))
        .route("/api/v1/operations/{id}", get(get_operation_handler))
        .route("/api/v1/operations/search", get(search_operations_handler))
        .route("/api/v1/execute", post(execute_handler))
        .route("/api/v1/pipelines/execute", post(execute_pipeline_handler))
        .route("/api/v1/jobs/{id}", get(get_job_handler))
        .route("/api/v1/jobs/{id}", delete(cancel_job_handler))
        .route("/api/v1/ws/jobs", get(ws_handler))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

async fn health_handler(State(state): State<AppState>) -> impl IntoResponse {
    let count = state.registry.read().unwrap().len();
    Json(HealthResponse {
        status: "ok",
        version: "0.1.0",
        operations_count: count,
    })
}

async fn list_operations_handler(State(state): State<AppState>) -> impl IntoResponse {
    let reg = state.registry.read().unwrap();
    Json(reg.list_manifests())
}

async fn get_operation_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let reg = state.registry.read().unwrap();
    if let Some(op) = reg.get(&id) {
        (StatusCode::OK, Json(serde_json::to_value(op.manifest()).unwrap())).into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

async fn search_operations_handler(
    State(state): State<AppState>,
    Query(query): Query<SearchQuery>,
) -> impl IntoResponse {
    let reg = state.registry.read().unwrap();
    let q = query.q.unwrap_or_default();
    Json(reg.search(&q))
}

async fn execute_handler(
    State(state): State<AppState>,
    Json(req): Json<ExecuteRequest>,
) -> impl IntoResponse {
    let timeout = Duration::from_secs(req.timeout_seconds);
    match state
        .job_manager
        .run_operation(&req.operation_id, req.input, req.config, timeout)
        .await
    {
        Ok(output) => (
            StatusCode::OK,
            Json(ExecuteResponse {
                success: true,
                output: Some(output),
                error: None,
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ExecuteResponse {
                success: false,
                output: None,
                error: Some(e.to_string()),
            }),
        )
            .into_response(),
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
    pub error: Option<String>,
}

async fn execute_pipeline_handler(
    State(state): State<AppState>,
    Json(req): Json<PipelineExecuteRequest>,
) -> impl IntoResponse {
    let timeout = Duration::from_secs(req.timeout_seconds);
    match state
        .job_manager
        .run_pipeline(&req.pipeline, req.input, timeout)
        .await
    {
        Ok(outputs) => (
            StatusCode::OK,
            Json(PipelineExecuteResponse {
                success: true,
                outputs: Some(outputs),
                error: None,
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(PipelineExecuteResponse {
                success: false,
                outputs: None,
                error: Some(e.to_string()),
            }),
        )
            .into_response(),
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

async fn cancel_job_handler(State(state): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    if state.job_manager.cancel_job(&id) {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    }
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(mut socket: WebSocket, state: AppState) {
    let mut rx = state.job_manager.subscribe();
    while let Ok(event) = rx.recv().await {
        if let Ok(json) = serde_json::to_string(&event) {
            if socket.send(Message::Text(json.into())).await.is_err() {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omni_core::{async_trait, DataPayload, ExecutionContext, OmniResult, Operation, OperationCategory, OperationManifest};
    use tower::ServiceExt;
    use axum::http::Request;

    struct EchoOp;
    #[async_trait]
    impl Operation for EchoOp {
        fn manifest(&self) -> OperationManifest {
            OperationManifest::new("api.echo", "Echo", "Echo input", OperationCategory::TextAndCode)
        }
        async fn execute(&self, input: DataPayload, _config: serde_json::Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
            Ok(input)
        }
    }

    #[tokio::test]
    async fn test_api_health_and_execute() {
        let mut reg = OperationRegistry::new();
        reg.register(Arc::new(EchoOp)).unwrap();
        let reg = Arc::new(RwLock::new(reg));
        let db = Arc::new(DatabaseManager::open_in_memory().unwrap());
        let job_mgr = JobManager::new(reg.clone(), db.clone());

        let state = AppState {
            registry: reg,
            db,
            job_manager: job_mgr,
        };

        let app = create_router(state);

        // Test Health
        let req = Request::builder().uri("/api/v1/health").body(axum::body::Body::empty()).unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Test Execute
        let exec_body = serde_json::json!({
            "operation_id": "api.echo",
            "input": {
                "type": "Text",
                "data": "Hello Axum"
            }
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
}
