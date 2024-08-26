use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::str;
use tower_service::Service;
use worker::*;

#[derive(Deserialize, Serialize)]
struct DBUser {
    id: u32,
    name: String,
    password: String,
}

enum Error {
    NoDatabase,
    Internal,
    Unauthorized,
    UserExists
}

impl Error {
    fn into_response(&self) -> (StatusCode, Json<Value>) {
        let code = match self {
            Self::NoDatabase => 1000,
            Self::Internal => 2000,
            Self::Unauthorized => 2001,
            Self::UserExists => 2002,
        };
        (StatusCode::BAD_REQUEST, Json(json!({"code": code})))
    }
}

fn router(env: Env) -> Router {
    Router::new()
        .route("/healthcheck", get(healthcheck))
        .route("/users/create", post(create_user))
        .route("/users/auth", get(auth_user))
        .with_state(env)
}

#[event(fetch)]
async fn fetch(
    req: HttpRequest,
    env: Env,
    _ctx: Context,
) -> Result<axum::http::Response<axum::body::Body>> {
    console_error_panic_hook::set_once();
    Ok(router(env).call(req).await?)
}

async fn authenticate(d1: &D1Database, user: &str, pwd: &str) -> Result<bool> {
    let statement = d1.prepare("SELECT password FROM users WHERE name = ?1");
    let query = statement.bind(&[user.trim().to_lowercase().into()])?;
    if let Some(password) = query.first::<String>(Some("password")).await? {
        Ok(password == pwd)
    } else {
        Ok(false)
    }
}

async fn auth_header(d1: &D1Database, headers: &HeaderMap) -> Result<bool> {
    let user = headers.get("x-auth-user");
    let pwd = headers.get("x-auth-key");
    if let (Some(user), Some(pwd)) = (user, pwd) {
        let user = str::from_utf8(user.as_bytes())?;
        let pwd = str::from_utf8(pwd.as_bytes())?;
        authenticate(d1, user, pwd).await
    } else {
        Ok(false)
    }
}

fn d1_from_env(env: Env) -> Result<D1Database> {
    env.d1("DB_PROD_KOSYNC")
}

pub async fn healthcheck() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

#[derive(Deserialize)]
pub struct CreateUserPayload {
    username: String,
    password: String,
}

pub async fn create_user(
    State(env): State<Env>,
    Json(payload): Json<CreateUserPayload>,
) -> (StatusCode, Json<Value>) {
    #[worker::send]
    async fn do_create_user(
        env: Env,
        payload: CreateUserPayload,
    ) -> Result<(StatusCode, Json<Value>)> {
        let Ok(d1) = d1_from_env(env) else {
            return Ok(Error::NoDatabase.into_response());
        };
        let statement = d1.prepare(concat!(
            "INSERT INTO users (name, password) VALUES(?1, ?2) ",
            "ON CONFLICT DO NOTHING RETURNING id"
        ));
        let username = payload.username.trim().to_lowercase();
        let query = statement.bind(&[username.as_str().into(), payload.password.into()])?;
        if let Some(_id) = query.first::<u32>(Some("id")).await? {
            Ok((StatusCode::CREATED, Json(json!({ "username": username }))))
        } else {
            Ok(Error::UserExists.into_response())
        }
    }
    do_create_user(env, payload)
        .await
        .unwrap_or(Error::Internal.into_response())
}

pub async fn auth_user(State(env): State<Env>, headers: HeaderMap) -> (StatusCode, Json<Value>) {
    #[worker::send]
    async fn do_auth_user(env: Env, headers: HeaderMap) -> Result<(StatusCode, Json<Value>)> {
        let Ok(d1) = d1_from_env(env) else {
            return Ok(Error::NoDatabase.into_response());
        };
        if auth_header(&d1, &headers).await? {
            Ok((StatusCode::OK, Json(json!({ "authorized": "OK" }))))
        } else {
            Ok(Error::Unauthorized.into_response())
        }
    }
    do_auth_user(env, headers)
        .await
        .unwrap_or(Error::Internal.into_response())
}
