use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post, put},
    Json, Router,
};
use chrono;
use rand::rngs::OsRng;
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

#[derive(Deserialize, Serialize)]
struct DBProgress {
    id: u32,
    document: String,
    user_id: u32,
    device_id: String,
    device: String,
    progress: String,
    percentage: f64,
    timestamp: f64,
}

enum Error {
    NoDatabase,
    Internal,
    Unauthorized,
    UserExists,
}

impl Error {
    fn code(&self) -> u32 {
        match self {
            Self::NoDatabase => 1000,
            Self::Internal => 2000,
            Self::Unauthorized => 2001,
            Self::UserExists => 2002,
        }
    }

    fn into_response(&self) -> (StatusCode, Json<Value>) {
        (StatusCode::BAD_REQUEST, Json(json!({"code": self.code()})))
    }

    fn with_message(&self, message: String) -> (StatusCode, Json<Value>) {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"code": self.code(), "message": message})),
        )
    }
}

fn router(env: Env) -> Router {
    Router::new()
        .route("/healthcheck", get(healthcheck))
        .route("/users/create", post(create_user))
        .route("/users/auth", get(auth_user))
        .route("/syncs/progress", put(update_progress))
        .route("/syncs/progress/:document", get(get_progress))
        .route("/manage/users", get(mgm_get_users))
        .route("/manage/users", post(mgm_create_user))
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

fn hash_password(pwd: &str) -> std::result::Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    Ok(argon2.hash_password(pwd.as_bytes(), &salt)?.to_string())
}

fn verify_password(pwd: &str, hash: &str) -> bool {
    let parsed_hash = PasswordHash::new(hash).expect("Failed to parse hashed password");
    Argon2::default()
        .verify_password(pwd.as_bytes(), &parsed_hash)
        .is_ok()
}

async fn authenticate(d1: &D1Database, user: &str, pwd: &str) -> Result<Option<u32>> {
    let statement = d1.prepare("SELECT * FROM users WHERE name = ?1");
    let query = statement.bind(&[user.into()])?;
    if let Some(user) = query.first::<DBUser>(None).await? {
        if verify_password(pwd, &user.password) {
            Ok(Some(user.id))
        } else {
            Ok(None)
        }
    } else {
        Ok(None)
    }
}

async fn auth_header(d1: &D1Database, headers: &HeaderMap) -> Result<Option<u32>> {
    let user = headers.get("x-auth-user");
    let pwd = headers.get("x-auth-key");
    if let (Some(user), Some(pwd)) = (user, pwd) {
        let user = normalize_username(str::from_utf8(user.as_bytes())?);
        let pwd = str::from_utf8(pwd.as_bytes())?;
        authenticate(d1, user.as_str(), pwd).await
    } else {
        Ok(None)
    }
}

async fn auth_management(env: &Env, headers: &HeaderMap) -> Result<bool> {
    let Some(header_secret) = headers.get("x-auth-mgm-token") else {
        return Ok(false);
    };
    let Ok(header_secret) = str::from_utf8(header_secret.as_bytes()) else {
        return Ok(false);
    };
    let secret = env.secret("MGM_TOKEN")?.to_string();
    Ok(secret.len() > 0 && secret == header_secret)
}

async fn insert_user(d1: &D1Database, username: &str, password: &str) -> Result<Option<u32>> {
    let password =
        hash_password(password).map_err(|err| worker::Error::RustError(err.to_string()))?;
    let statement = d1.prepare(concat!(
        "INSERT INTO users (name, password) VALUES(?1, ?2) ",
        "ON CONFLICT DO NOTHING RETURNING id"
    ));
    let query = statement.bind(&[username.into(), password.into()])?;
    query.first::<u32>(Some("id")).await
}

fn d1_from_env(env: Env) -> Result<D1Database> {
    env.d1("DB_PROD_KOSYNC")
}

fn normalize_username(username: &str) -> String {
    username.trim().to_lowercase()
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
        let username = normalize_username(payload.username.as_str());
        let result = insert_user(&d1, username.as_str(), payload.password.as_str()).await?;
        if let Some(_id) = result {
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
        if let Some(_) = auth_header(&d1, &headers).await? {
            Ok((StatusCode::OK, Json(json!({ "authorized": "OK" }))))
        } else {
            Ok(Error::Unauthorized.into_response())
        }
    }
    do_auth_user(env, headers)
        .await
        .unwrap_or(Error::Internal.into_response())
}

#[derive(Deserialize)]
pub struct UpdateProgressPayload {
    document: String,
    percentage: f64,
    progress: String,
    device: String,
    device_id: String,
}

#[derive(Serialize)]
struct UpdateProgressResponse {
    document: String,
    timestamp: f64,
}

pub async fn update_progress(
    State(env): State<Env>,
    header: HeaderMap,
    Json(payload): Json<UpdateProgressPayload>,
) -> (StatusCode, Json<Value>) {
    #[worker::send]
    async fn do_update_progress(
        env: Env,
        header: HeaderMap,
        payload: UpdateProgressPayload,
    ) -> Result<(StatusCode, Json<Value>)> {
        let Ok(d1) = d1_from_env(env) else {
            return Ok(Error::NoDatabase.into_response());
        };

        let Some(user_id) = auth_header(&d1, &header).await? else {
            return Ok(Error::Unauthorized.into_response());
        };

        let timestamp = chrono::Utc::now().timestamp_millis() as f64;
        let timestamp = timestamp / 1000.0;

        let statement = d1.prepare(concat!(
            "INSERT INTO progress ",
            "(document, user_id, device_id, device, progress, percentage, timestamp) ",
            "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) ",
            "ON CONFLICT DO UPDATE SET ",
            "device_id = ?3, ",
            "device = ?4, ",
            "progress = ?5, ",
            "percentage = ?6, ",
            "timestamp = ?7"
        ));

        let query = statement.bind(&[
            payload.document.as_str().into(),
            user_id.into(),
            payload.device_id.into(),
            payload.device.into(),
            payload.progress.into(),
            payload.percentage.into(),
            timestamp.into(),
        ])?;

        let result = query.run().await?;

        if result.success() {
            Ok((
                StatusCode::OK,
                Json(
                    serde_json::to_value(UpdateProgressResponse {
                        document: payload.document,
                        timestamp,
                    })
                    .unwrap(),
                ),
            ))
        } else {
            Ok(Error::Internal.into_response())
        }
    }
    do_update_progress(env, header, payload)
        .await
        .unwrap_or_else(|err| Error::Internal.with_message(err.to_string()))
}

#[derive(Serialize)]
struct GetProgressBody {
    document: String,
    percentage: f64,
    progress: String,
    device: String,
    device_id: String,
    timestamp: f64,
}

impl From<DBProgress> for GetProgressBody {
    fn from(prog: DBProgress) -> Self {
        Self {
            document: prog.document,
            percentage: prog.percentage,
            progress: prog.progress,
            device: prog.device,
            device_id: prog.device_id,
            timestamp: prog.timestamp,
        }
    }
}

pub async fn get_progress(
    State(env): State<Env>,
    Path(document): Path<String>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    #[worker::send]
    async fn do_get_progress(
        env: Env,
        document: String,
        headers: HeaderMap,
    ) -> Result<(StatusCode, Json<Value>)> {
        let Ok(d1) = d1_from_env(env) else {
            return Ok(Error::NoDatabase.into_response());
        };

        let Some(user_id) = auth_header(&d1, &headers).await? else {
            return Ok(Error::Unauthorized.into_response());
        };

        let statement = d1.prepare(concat!(
            "SELECT * FROM progress ",
            "WHERE document = ?1 AND user_id = ?2"
        ));
        let query = statement.bind(&[document.into(), user_id.into()])?;

        if let Some(result) = query.first::<DBProgress>(None).await? {
            Ok((
                StatusCode::OK,
                Json(serde_json::to_value(GetProgressBody::from(result)).unwrap()),
            ))
        } else {
            Ok((StatusCode::OK, Json(json!({}))))
        }
    }
    do_get_progress(env, document, headers)
        .await
        .unwrap_or(Error::Internal.into_response())
}

fn default_offset() -> u32 {
    0
}

fn default_limit() -> u32 {
    50
}

#[derive(Deserialize)]
pub struct PaginationQueryParams {
    #[serde(default = "default_offset")]
    offset: u32,
    #[serde(default = "default_limit")]
    limit: u32,
}

#[derive(Serialize)]
struct MgmGetUserResponseEntry {
    id: u32,
    username: String,
}

impl From<DBUser> for MgmGetUserResponseEntry {
    fn from(user: DBUser) -> MgmGetUserResponseEntry {
        MgmGetUserResponseEntry {
            id: user.id,
            username: user.name,
        }
    }
}

pub async fn mgm_get_users(
    State(env): State<Env>,
    pagination: Query<PaginationQueryParams>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    #[worker::send]
    async fn do_mgm_get_users(
        env: Env,
        pagination: PaginationQueryParams,
        headers: HeaderMap,
    ) -> Result<(StatusCode, Json<Value>)> {
        if !auth_management(&env, &headers).await? {
            return Ok((
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "unauthorized"})),
            ));
        }
        let d1 = d1_from_env(env)?;
        let statement = d1.prepare("SELECT * FROM users LIMIT ?1 OFFSET ?2");
        let query = statement
            .bind(&[pagination.limit.into(), pagination.offset.into()])?
            .all()
            .await?;
        let results: Vec<MgmGetUserResponseEntry> = query
            .results::<DBUser>()?
            .into_iter()
            .map(|user| MgmGetUserResponseEntry::from(user))
            .collect();
        let value = serde_json::to_value(results)?;
        return Ok((StatusCode::OK, Json(value)));
    }
    let ret = do_mgm_get_users(env, pagination.0, headers).await;
    ret.unwrap_or_else(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": err.to_string()})),
        )
    })
}

#[derive(Deserialize)]
pub struct MgmCreateUserPayload {
    username: String,
    password: String,
}

pub async fn mgm_create_user(
    State(env): State<Env>,
    headers: HeaderMap,
    Json(payload): Json<MgmCreateUserPayload>,
) -> (StatusCode, Json<Value>) {
    #[worker::send]
    async fn do_mgm_create_user(
        env: Env,
        headers: HeaderMap,
        payload: MgmCreateUserPayload,
    ) -> Result<(StatusCode, Json<Value>)> {
        if !auth_management(&env, &headers).await? {
            return Ok((
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "unauthorized"})),
            ));
        }
        let d1 = d1_from_env(env)?;
        let username = normalize_username(payload.username.as_str());
        let result = insert_user(&d1, username.as_str(), &payload.password).await?;
        match result {
            Some(id) => Ok((
                StatusCode::CREATED,
                Json(json!({ "id": id, "username": username})),
            )),
            None => Ok((
                StatusCode::CONFLICT,
                Json(json!({"error": "user already exists"})),
            )),
        }
    }
    do_mgm_create_user(env, headers, payload)
        .await
        .unwrap_or_else(|err| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": err.to_string()})),
            )
        })
}
