use axum::{
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tower_service::Service;
use worker::*;

fn router() -> Router {
    Router::new().route("/healthcheck", get(healthcheck))
}

#[event(fetch)]
async fn fetch(
    req: HttpRequest,
    _env: Env,
    _ctx: Context,
) -> Result<axum::http::Response<axum::body::Body>> {
    console_error_panic_hook::set_once();
    Ok(router().call(req).await?)
}

pub async fn healthcheck() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}
