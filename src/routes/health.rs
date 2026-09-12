//! 健康检查。

use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};

use crate::state::SharedState;

/// 存活检查：进程可响应即通过。
pub async fn healthz() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

/// 就绪检查：探测数据库连接。
pub async fn readyz(State(state): State<SharedState>) -> Json<Value> {
    match state.db.ping().await {
        Ok(_) => Json(json!({ "status": "ready", "database": "ok" })),
        Err(err) => {
            tracing::error!(error = %err, "数据库就绪检查失败");
            Json(json!({ "status": "degraded", "database": "error" }))
        }
    }
}
