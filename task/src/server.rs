use axum::{routing::get, Router};
use tracing::{info, error};
use tokio::task::JoinHandle;
use crate::store::{ExecutionStorage, get_all_executions, get_executions_by_pid};

pub fn create_app(storage: ExecutionStorage) -> Router {
    Router::new()
        .route("/executions", get(get_all_executions))
        .route("/executions/:pid", get(get_executions_by_pid))
        .with_state(storage)
}

pub async fn start_http_server(storage: ExecutionStorage) -> anyhow::Result<JoinHandle<()>> {
    let app = create_app(storage);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    info!("HTTP server starting on http://0.0.0.0:3000");
    
    // Spawn the server in a separate task
    let server_handle = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            error!("Server error: {}", e);
        }
    });

    info!("System ready - monitoring process executions");
    info!("API endpoints:");
    info!("  GET /executions - get all executions (max 500)");
    info!("  GET /executions/:pid - get executions for specific PID");

    Ok(server_handle)
}
