use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use askama::Template;
use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{Path as RoutePath, Query, State},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{
            CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, ETAG, IF_MODIFIED_SINCE,
            IF_NONE_MATCH, LAST_MODIFIED, LOCATION, SET_COOKIE,
        },
    },
    response::{Html, IntoResponse, Redirect, Response},
    routing::{any, delete, get, post, put},
};
use chrono::{FixedOffset, NaiveDateTime, TimeZone};
use jsonwebtoken::{Algorithm, Header, encode};
use md5::{Digest, Md5};
use pulldown_cmark::{Options, Parser, html as markdown_html};
use regex::RegexBuilder;
use serde::{Deserialize, Serialize};

use crate::{
    AppState,
    auth::{audience_matches, bearer_token, decode_access_token, decode_web_session},
    database::{
        DatabasePool, NotificationRecord, PlayerProfile, PlayerRecord, PlayerRenameOutcome,
        PlayerTextureOutcome, UserProfile,
    },
};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health/live", any(live))
        .route("/health/ready", any(ready))
        .route("/api", any(api_root))
        .route("/api/", any(api_root))
        .route("/", get(home))
        .route("/auth/login", get(login_page).post(handle_login))
        .route("/auth/logout", post(logout))
        .route("/user", get(web_dashboard))
        .route("/api/user", get(api_user))
        .route("/api/closet", get(api_closet).post(api_add_closet_item))
        .route(
            "/api/closet/{tid}",
            put(api_rename_closet_item).delete(api_remove_closet_item),
        )
        .route("/api/user/notifications", get(api_user_notifications))
        .route("/api/admin/notifications", post(api_send_notification))
        .route("/api/user/notifications/{id}", post(api_read_notification))
        .route("/api/players", get(api_players).post(api_add_player))
        .route("/api/players/{pid}", delete(api_delete_player))
        .route("/api/players/{pid}/name", put(api_rename_player))
        .route(
            "/api/players/{pid}/textures",
            put(api_set_player_textures).delete(api_clear_player_textures),
        )
        .route("/{profile}", get(player_json))
        .route("/csl/{profile}", get(player_json))
        .route("/textures/{hash}", get(texture))
        .route("/csl/textures/{hash}", get(texture))
        .route("/raw/{tid}", get(raw_texture))
        .with_state(state)
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginPage {
    site_name: String,
    locale: String,
    title: String,
    prompt: String,
    identification_label: String,
    password_label: String,
    remember_label: String,
    submit_label: String,
}

async fn login_page(State(state): State<AppState>) -> Response {
    let site_name = match &state.database {
        Some(database) => database
            .option(&state.config.database.table_prefix, "site_name")
            .await
            .ok()
            .flatten()
            .unwrap_or_else(|| "Blessing Skin".to_owned()),
        None => "Blessing Skin".to_owned(),
    };
    let chinese = state.config.locale.starts_with("zh");
    let page = LoginPage {
        site_name,
        locale: state.config.locale.clone(),
        title: if chinese { "登录" } else { "Log In" }.to_owned(),
        prompt: if chinese {
            "登录以管理您的角色与皮肤"
        } else {
            "Log in to manage your skin and players"
        }
        .to_owned(),
        identification_label: if chinese {
            "邮箱或角色名"
        } else {
            "Email or player name"
        }
        .to_owned(),
        password_label: if chinese { "密码" } else { "Password" }.to_owned(),
        remember_label: if chinese {
            "保持登录"
        } else {
            "Remember me"
        }
        .to_owned(),
        submit_label: if chinese { "登录" } else { "Log In" }.to_owned(),
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to render login page");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Deserialize)]
struct LoginRequest {
    identification: Option<String>,
    password: Option<String>,
    keep: Option<bool>,
}

async fn handle_login(State(state): State<AppState>, body: Bytes) -> Response {
    let request: LoginRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return validation_error("identification", &state.config.locale),
    };
    let Some(identification) = request
        .identification
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.trim().to_owned())
    else {
        return validation_error("identification", &state.config.locale);
    };
    let Some(password) = request.password.filter(|value| !value.is_empty()) else {
        return validation_error("password", &state.config.locale);
    };
    if !(6..=32).contains(&password.chars().count()) {
        return validation_error("password", &state.config.locale);
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    let credential = if looks_like_email(&identification) {
        database
            .credentials_by_email(&state.config.database.table_prefix, &identification)
            .await
    } else {
        database
            .credentials_by_player_name(&state.config.database.table_prefix, &identification)
            .await
    };
    let credential = match credential {
        Ok(Some(credential)) => credential,
        Ok(None) => {
            let message = if state.config.locale.starts_with("zh") {
                "用户不存在"
            } else {
                "No such user."
            };
            return login_result(2, message, None);
        }
        Err(error) => {
            tracing::error!(%error, "failed to look up login account");
            return unavailable();
        }
    };
    if !crate::auth::verify_legacy_password(
        &password,
        &credential.password,
        &state.config.password_method,
        &state.config.password_salt,
    ) {
        let failures = {
            let now = Instant::now();
            let mut attempts = state
                .login_failures
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if attempts.len() > 4096 {
                attempts.retain(|_, (_, updated)| {
                    now.duration_since(*updated) < Duration::from_secs(3600)
                });
            }
            let entry = attempts.entry(identification.clone()).or_insert((0, now));
            if now.duration_since(entry.1) >= Duration::from_secs(3600) {
                entry.0 = 0;
            }
            entry.0 = entry.0.saturating_add(1);
            entry.1 = now;
            entry.0
        };
        let message = if state.config.locale.starts_with("zh") {
            "密码错误"
        } else {
            "Wrong password."
        };
        return login_result(
            1,
            message,
            Some(serde_json::json!({ "login_fails": failures })),
        );
    }

    let Some(key) = &state.session_key else {
        tracing::error!("APP_KEY is required to create a web login session");
        return unavailable();
    };
    let now = jsonwebtoken::get_current_timestamp();
    let max_age = if request.keep.unwrap_or(false) {
        60 * 60 * 24 * 30
    } else {
        60 * 60 * 12
    };
    let claims = crate::auth::WebSessionClaims {
        sub: credential.uid.to_string(),
        iat: now,
        exp: now + max_age,
    };
    let session = match encode(&Header::new(Algorithm::HS256), &claims, key) {
        Ok(session) => session,
        Err(error) => {
            tracing::error!(%error, "failed to issue web login session");
            return unavailable();
        }
    };
    state
        .login_failures
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(&identification);

    let message = if state.config.locale.starts_with("zh") {
        "登录成功，欢迎回来"
    } else {
        "Logged in successfully."
    };
    let mut response = login_result(
        0,
        message,
        Some(serde_json::json!({ "redirectTo": "/user" })),
    );
    let secure = if state.config.app_url.starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    let cookie = format!(
        "blessing_skin_session={session}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{secure}"
    );
    match HeaderValue::from_str(&cookie) {
        Ok(value) => {
            response.headers_mut().insert(SET_COOKIE, value);
            response
        }
        Err(error) => {
            tracing::error!(%error, "failed to create web session cookie");
            unavailable()
        }
    }
}

#[derive(Template)]
#[template(path = "home.html")]
struct HomePage {
    site_name: String,
    locale: String,
    title: String,
    login: String,
}

async fn home(State(state): State<AppState>) -> Response {
    let site_name = site_name(&state).await;
    let chinese = state.config.locale.starts_with("zh");
    let page = HomePage {
        site_name,
        locale: state.config.locale.clone(),
        title: if chinese { "皮肤站" } else { "Skin Server" }.to_owned(),
        login: if chinese { "登录" } else { "Log in" }.to_owned(),
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to render home page");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardPage {
    site_name: String,
    user: UserProfile,
    players: Vec<PlayerRecord>,
    locale: String,
}

async fn web_dashboard(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(user_id) = session_user_id(&state, &headers) else {
        return Redirect::to("/auth/login").into_response();
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let user = match database
        .user_profile(&state.config.database.table_prefix, user_id)
        .await
    {
        Ok(Some(user)) if user.permission != -1 => user,
        Ok(Some(_)) => return StatusCode::FORBIDDEN.into_response(),
        Ok(None) => return Redirect::to("/auth/login").into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to load web session user");
            return unavailable();
        }
    };
    let players = match database
        .players_for_user(&state.config.database.table_prefix, user_id)
        .await
    {
        Ok(players) => players,
        Err(error) => {
            tracing::error!(%error, "failed to load web session players");
            return unavailable();
        }
    };
    let page = DashboardPage {
        site_name: site_name(&state).await,
        user,
        players,
        locale: state.config.locale.clone(),
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to render user dashboard");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn site_name(state: &AppState) -> String {
    match &state.database {
        Some(database) => database
            .option(&state.config.database.table_prefix, "site_name")
            .await
            .ok()
            .flatten()
            .unwrap_or_else(|| "Blessing Skin".to_owned()),
        None => "Blessing Skin".to_owned(),
    }
}

async fn logout(State(state): State<AppState>) -> Response {
    let mut response = login_result(
        0,
        if state.config.locale.starts_with("zh") {
            "已退出登录"
        } else {
            "Logged out successfully."
        },
        None,
    );
    let secure = if state.config.app_url.starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    let cookie =
        format!("blessing_skin_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{secure}");
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().insert(SET_COOKIE, value);
    }
    response
}

fn session_user_id(state: &AppState, headers: &HeaderMap) -> Option<i64> {
    let cookie_header = headers.get(COOKIE)?.to_str().ok()?;
    let token = cookie_header.split(';').find_map(|cookie| {
        let (name, value) = cookie.trim().split_once('=')?;
        (name == "blessing_skin_session" && !value.is_empty()).then_some(value)
    })?;
    decode_web_session(token, state.config.app_key.as_deref()?)
}

fn looks_like_email(value: &str) -> bool {
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !value.chars().any(char::is_whitespace)
        && !domain.contains('@')
}

fn validation_error(field: &str, locale: &str) -> Response {
    let chinese = locale.starts_with("zh");
    let message = if chinese {
        "给定数据无效。"
    } else {
        "The given data was invalid."
    };
    let field_error = match (field, chinese) {
        ("identification", true) => "此项为必填项。",
        ("identification", false) => "The identification field is required.",
        ("name", true) => "角色名格式或长度无效。",
        ("name", false) => "The player name format or length is invalid.",
        (_, true) => "密码为必填项且长度必须为 6 至 32 个字符。",
        (_, false) => "The password field is required or has an invalid length.",
    };
    let mut errors = serde_json::Map::new();
    errors.insert(field.to_owned(), serde_json::json!([field_error]));
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(serde_json::json!({ "message": message, "errors": errors })),
    )
        .into_response()
}

fn duplicate_player_name_error(locale: &str) -> Response {
    let chinese = locale.starts_with("zh");
    let message = if chinese {
        "给定数据无效。"
    } else {
        "The given data was invalid."
    };
    let field_error = if chinese {
        "名称已经被占用。"
    } else {
        "The name has already been taken."
    };
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(serde_json::json!({
            "message": message,
            "errors": { "name": [field_error] }
        })),
    )
        .into_response()
}
fn login_result(code: i32, message: &str, data: Option<serde_json::Value>) -> Response {
    let mut body = serde_json::json!({ "code": code, "message": message });
    if let Some(data) = data {
        body["data"] = data;
    }
    Json(body).into_response()
}
#[derive(Serialize)]
struct Health {
    status: &'static str,
}

async fn live() -> Json<Health> {
    Json(Health { status: "ok" })
}

async fn ready(State(state): State<AppState>) -> Response {
    match &state.database {
        Some(database) if database.ping().await.is_ok() => {
            (StatusCode::OK, Json(Health { status: "ready" })).into_response()
        }
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(Health {
                status: "not_ready",
            }),
        )
            .into_response(),
    }
}

#[derive(Serialize)]
struct ApiRoot {
    blessing_skin: &'static str,
    spec: u8,
    copyright: &'static str,
    site_name: String,
}

async fn api_user(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_scope("User.Read") {
        return missing_scope();
    }
    let Some(database) = &state.database else {
        return unavailable();
    };

    match database
        .user_profile(&state.config.database.table_prefix, identity.user_id)
        .await
    {
        Ok(Some(user)) => Json(user).into_response(),
        Ok(None) => unauthenticated(),
        Err(error) => {
            tracing::error!(%error, "failed to load authenticated user");
            unavailable()
        }
    }
}

static NOTIFICATION_ID_SEQUENCE: AtomicU64 = AtomicU64::new(0);

async fn api_send_notification(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let prefix = &state.config.database.table_prefix;
    let user = match database.user_profile(prefix, identity.user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => return unauthenticated(),
        Err(error) => {
            tracing::error!(%error, "failed to load notification sender");
            return unavailable();
        }
    };
    if user.permission < 1 {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "message": "This action is unauthorized." })),
        )
            .into_response();
    }
    if !identity.has_scope("Notification.ReadWrite") {
        return missing_scope();
    }

    let request = match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(request) => request,
        Err(_) => return notification_validation_error("receiver", &state.config.locale),
    };
    let Some(receiver) = request.get("receiver").and_then(serde_json::Value::as_str) else {
        return notification_validation_error("receiver", &state.config.locale);
    };
    let receiver = receiver.trim();
    let audience = match receiver {
        "all" => crate::database::NotificationAudience::All,
        "normal" => crate::database::NotificationAudience::Normal,
        "uid" => {
            let Some(uid) = request_i64(request.get("uid")) else {
                return notification_validation_error("uid", &state.config.locale);
            };
            crate::database::NotificationAudience::User(uid)
        }
        "email" => {
            let Some(email) = request.get("email").and_then(serde_json::Value::as_str) else {
                return notification_validation_error("email", &state.config.locale);
            };
            let email = email.trim();
            if !valid_email_address(email) {
                return notification_validation_error("email", &state.config.locale);
            }
            crate::database::NotificationAudience::Email(email.to_owned())
        }
        _ => return notification_validation_error("receiver", &state.config.locale),
    };
    let Some(title) = request.get("title").and_then(serde_json::Value::as_str) else {
        return notification_validation_error("title", &state.config.locale);
    };
    let title = title.trim();
    if title.is_empty() || title.chars().count() > 20 {
        return notification_validation_error("title", &state.config.locale);
    }
    let content = match request.get("content") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(content)) => Some(content.trim()),
        _ => return notification_validation_error("content", &state.config.locale),
    };

    let recipients = match database.notification_recipients(prefix, &audience).await {
        Ok(Some(recipients)) => recipients,
        Ok(None) => {
            return notification_validation_error(
                match audience {
                    crate::database::NotificationAudience::User(_) => "uid",
                    crate::database::NotificationAudience::Email(_) => "email",
                    _ => "receiver",
                },
                &state.config.locale,
            );
        }
        Err(error) => {
            tracing::error!(%error, "failed to select notification recipients");
            return unavailable();
        }
    };
    let data = serde_json::json!({ "title": title, "content": content }).to_string();
    for recipient in recipients {
        if let Err(error) = database
            .create_site_notification(prefix, &new_notification_id(), recipient, &data)
            .await
        {
            tracing::error!(%error, recipient, "failed to store notification");
            return unavailable();
        }
    }
    let mut response = StatusCode::FOUND.into_response();
    response
        .headers_mut()
        .insert(LOCATION, HeaderValue::from_static("/admin"));
    response
}

fn request_i64(value: Option<&serde_json::Value>) -> Option<i64> {
    let value = value?;
    value.as_i64().or_else(|| {
        value
            .as_str()
            .and_then(|number| number.trim().parse::<i64>().ok())
    })
}
fn notification_validation_error(field: &str, locale: &str) -> Response {
    let chinese = locale.starts_with("zh");
    let message = if chinese {
        "给定数据无效。"
    } else {
        "The given data was invalid."
    };
    let field_error = match (field, chinese) {
        ("receiver", true) => "接收对象必须是 all、normal、uid 或 email。",
        ("receiver", false) => "The receiver must be all, normal, uid, or email.",
        ("uid", true) => "用户编号为必填整数且必须存在。",
        ("uid", false) => "The uid must be an integer identifying an existing user.",
        ("email", true) => "邮箱地址无效或不存在。",
        ("email", false) => "The email must be valid and belong to an existing user.",
        ("title", true) => "标题为必填项且不能超过 20 个字符。",
        ("title", false) => "The title is required and may not exceed 20 characters.",
        ("content", true) => "内容必须是字符串。",
        ("content", false) => "The content must be a string.",
        _ => "The given field is invalid.",
    };
    let mut errors = serde_json::Map::new();
    errors.insert(field.to_owned(), serde_json::json!([field_error]));
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(serde_json::json!({ "message": message, "errors": errors })),
    )
        .into_response()
}

fn valid_email_address(value: &str) -> bool {
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !value.chars().any(char::is_whitespace)
}

fn new_notification_id() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let sequence = NOTIFICATION_ID_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let source = format!("{timestamp}:{}:{sequence}", std::process::id());
    let digest = Md5::digest(source.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}
async fn api_user_notifications(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_scope("Notification.Read") {
        return missing_scope();
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    match database
        .unread_notifications(&state.config.database.table_prefix, identity.user_id)
        .await
    {
        Ok(notifications) => Json(notification_summaries(notifications)).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to list unread notifications");
            unavailable()
        }
    }
}

async fn api_read_notification(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(id): RoutePath<String>,
) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_scope("Notification.Read") {
        return missing_scope();
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    match database
        .read_notification(&state.config.database.table_prefix, identity.user_id, &id)
        .await
    {
        Ok(Some(notification)) => notification_detail(notification),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "message": "Notification not found." })),
        )
            .into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to read notification");
            unavailable()
        }
    }
}

fn notification_summaries(notifications: Vec<NotificationRecord>) -> Vec<serde_json::Value> {
    notifications
        .into_iter()
        .map(|notification| {
            let data = serde_json::from_str::<serde_json::Value>(&notification.data)
                .unwrap_or(serde_json::Value::Null);
            serde_json::json!({
                "id": notification.id,
                "title": data.get("title").cloned().unwrap_or(serde_json::Value::Null),
            })
        })
        .collect()
}

fn notification_detail(notification: NotificationRecord) -> Response {
    let data = serde_json::from_str::<serde_json::Value>(&notification.data)
        .unwrap_or(serde_json::Value::Null);
    let title = data
        .get("title")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let content = data
        .get("content")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    Json(serde_json::json!({
        "title": title,
        "content": render_notification_markdown(content),
        "time": notification.created_at,
    }))
    .into_response()
}

fn render_notification_markdown(markdown: &str) -> String {
    let parser = Parser::new_ext(
        markdown,
        Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH | Options::ENABLE_TASKLISTS,
    );
    let mut html = String::with_capacity(markdown.len().saturating_mul(2));
    markdown_html::push_html(&mut html, parser);
    ammonia::clean(&html)
}

#[derive(Deserialize)]
struct RenamePlayerRequest {
    name: Option<String>,
}

async fn api_rename_player(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(raw_id): RoutePath<String>,
    body: Bytes,
) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_scope("Player.ReadWrite") {
        return missing_scope();
    }
    let Ok(player_id) = raw_id.parse::<i64>() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let request: RenamePlayerRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return validation_error("name", &state.config.locale),
    };
    let Some(name) = request.name.filter(|name| !name.is_empty()) else {
        return validation_error("name", &state.config.locale);
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let options = &state.config.database.table_prefix;
    let min_length = database
        .option(options, "player_name_length_min")
        .await
        .ok()
        .flatten()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(3);
    let max_length = database
        .option(options, "player_name_length_max")
        .await
        .ok()
        .flatten()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(16);
    let name_rule = database
        .option(options, "player_name_rule")
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| "official".to_owned());
    let custom_rule = database
        .option(options, "custom_player_name_regexp")
        .await
        .ok()
        .flatten()
        .unwrap_or_default();
    if !valid_player_name(&name, &name_rule, &custom_rule, min_length, max_length) {
        return validation_error("name", &state.config.locale);
    }

    match database
        .rename_player(options, identity.user_id, player_id, &name)
        .await
    {
        Ok(PlayerRenameOutcome::Renamed {
            previous_name,
            player,
        }) => {
            let message = if state.config.locale.starts_with("zh") {
                format!("角色名已从 {previous_name} 更新为 {name}")
            } else {
                format!("Player renamed from {previous_name} to {name}.")
            };
            login_result(
                0,
                &message,
                Some(serde_json::to_value(player).unwrap_or(serde_json::Value::Null)),
            )
        }
        Ok(PlayerRenameOutcome::NameExists) => login_result(
            1,
            if state.config.locale.starts_with("zh") {
                "该角色名已被使用"
            } else {
                "That player name is already in use."
            },
            None,
        ),
        Ok(PlayerRenameOutcome::Forbidden) => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "code": 1,
                "message": if state.config.locale.starts_with("zh") {
                    "无权操作此角色"
                } else {
                    "You are not allowed to modify this player."
                }
            })),
        )
            .into_response(),
        Ok(PlayerRenameOutcome::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to rename player");
            unavailable()
        }
    }
}

async fn api_set_player_textures(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(raw_id): RoutePath<String>,
    body: Bytes,
) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_scope("Player.ReadWrite") {
        return missing_scope();
    }
    let Ok(player_id) = raw_id.parse::<i64>() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let request =
        serde_json::from_slice::<serde_json::Value>(&body).unwrap_or(serde_json::Value::Null);
    let skin = texture_request_id(request.get("skin"));
    let cape = texture_request_id(request.get("cape"));
    let Some(database) = &state.database else {
        return unavailable();
    };
    let result = database
        .set_player_textures(
            &state.config.database.table_prefix,
            identity.user_id,
            player_id,
            skin,
            cape,
        )
        .await;
    player_texture_response(result, &state.config.locale, false)
}

async fn api_clear_player_textures(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(raw_id): RoutePath<String>,
    body: Bytes,
) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_scope("Player.ReadWrite") {
        return missing_scope();
    }
    let Ok(player_id) = raw_id.parse::<i64>() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let request =
        serde_json::from_slice::<serde_json::Value>(&body).unwrap_or(serde_json::Value::Null);
    let clear_type = |kind: &str| {
        request.get(kind).is_some()
            || request
                .get("type")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|types| types.iter().any(|value| value.as_str() == Some(kind)))
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let result = database
        .clear_player_textures(
            &state.config.database.table_prefix,
            identity.user_id,
            player_id,
            clear_type("skin"),
            clear_type("cape"),
        )
        .await;
    player_texture_response(result, &state.config.locale, true)
}

fn texture_request_id(value: Option<&serde_json::Value>) -> Option<i64> {
    match value? {
        serde_json::Value::Null => None,
        serde_json::Value::Bool(false) => None,
        serde_json::Value::Bool(true) => Some(-1),
        serde_json::Value::Number(number) => Some(number.as_i64().unwrap_or(-1)),
        serde_json::Value::String(value) if value.is_empty() => None,
        serde_json::Value::String(value) => Some(value.parse::<i64>().unwrap_or(-1)),
        _ => Some(-1),
    }
}

fn player_texture_response(
    result: Result<PlayerTextureOutcome, sqlx::Error>,
    locale: &str,
    clear: bool,
) -> Response {
    let chinese = locale.starts_with("zh");
    match result {
        Ok(PlayerTextureOutcome::Updated(player)) => {
            let message = match (chinese, clear) {
                (true, true) => format!("角色 {} 的材质已被成功重置", player.name),
                (true, false) => format!("材质已成功应用至角色 {}", player.name),
                (false, true) => format!(
                    "The textures of player {} was resetted successfully.",
                    player.name
                ),
                (false, false) => format!(
                    "The texture was applied to player {} successfully.",
                    player.name
                ),
            };
            login_result(
                0,
                &message,
                Some(serde_json::to_value(player).unwrap_or(serde_json::Value::Null)),
            )
        }
        Ok(PlayerTextureOutcome::TextureNotFound) => login_result(
            1,
            if chinese {
                "材质不存在"
            } else {
                "No such texture."
            },
            None,
        ),
        Ok(PlayerTextureOutcome::TextureNotInCloset) => login_result(
            1,
            if chinese {
                "衣柜中不存在此材质"
            } else {
                "The texture does not exist in your closet."
            },
            None,
        ),
        Ok(PlayerTextureOutcome::Forbidden) => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "code": 1,
                "message": if chinese { "无权操作此角色" } else { "You are not allowed to modify this player." }
            })),
        )
            .into_response(),
        Ok(PlayerTextureOutcome::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to update player textures");
            unavailable()
        }
    }
}
fn valid_player_name(
    name: &str,
    rule: &str,
    custom_rule: &str,
    min_length: usize,
    max_length: usize,
) -> bool {
    let length = name.chars().count();
    if length < min_length || length > max_length {
        return false;
    }
    match rule {
        "official" => name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_'),
        "cjk" => name.chars().all(|ch| {
            ch.is_ascii_alphanumeric()
                || ch == '_'
                || ch == '§'
                || ('\u{4e00}'..='\u{9fff}').contains(&ch)
        }),
        "utf8" => !name.chars().any(char::is_whitespace),
        "custom" => custom_player_name_matches(name, custom_rule),
        _ => false,
    }
}

fn custom_player_name_matches(name: &str, pattern: &str) -> bool {
    if pattern.is_empty() {
        return true;
    }
    let (pattern, flags) = if let Some(inner) = pattern.strip_prefix('/') {
        let Some(end) = inner.rfind('/') else {
            return false;
        };
        (&inner[..end], &inner[end + 1..])
    } else {
        (pattern, "")
    };
    if pattern.len() > 512 {
        return false;
    }
    let mut builder = RegexBuilder::new(pattern);
    builder
        .case_insensitive(flags.contains('i'))
        .multi_line(flags.contains('m'))
        .dot_matches_new_line(flags.contains('s'))
        .ignore_whitespace(flags.contains('x'));
    builder.build().is_ok_and(|regex| regex.is_match(name))
}

async fn api_add_player(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_scope("Player.ReadWrite") {
        return missing_scope();
    }
    let request = match serde_json::from_slice::<RenamePlayerRequest>(&body) {
        Ok(request) => request,
        Err(_) => return validation_error("name", &state.config.locale),
    };
    let Some(name) = request.name.filter(|name| !name.is_empty()) else {
        return validation_error("name", &state.config.locale);
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let prefix = &state.config.database.table_prefix;
    let min_length = database
        .option(prefix, "player_name_length_min")
        .await
        .ok()
        .flatten()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(3);
    let max_length = database
        .option(prefix, "player_name_length_max")
        .await
        .ok()
        .flatten()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(16);
    let rule = database
        .option(prefix, "player_name_rule")
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| "official".to_owned());
    let custom_rule = database
        .option(prefix, "custom_player_name_regexp")
        .await
        .ok()
        .flatten()
        .unwrap_or_default();
    if !valid_player_name(&name, &rule, &custom_rule, min_length, max_length) {
        return validation_error("name", &state.config.locale);
    }
    let score_cost = match database.option(prefix, "score_per_player").await {
        Ok(value) => value
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or_default(),
        Err(error) => {
            tracing::error!(%error, "failed to load player score cost");
            return unavailable();
        }
    };
    match database
        .add_player(prefix, identity.user_id, &name, score_cost)
        .await
    {
        Ok(crate::database::PlayerAddOutcome::Added(player)) => {
            let message = if state.config.locale.starts_with("zh") {
                format!("成功添加了角色 {}", player.name)
            } else {
                format!("Player {} was added successfully.", player.name)
            };
            login_result(
                0,
                &message,
                Some(serde_json::to_value(player).unwrap_or(serde_json::Value::Null)),
            )
        }
        Ok(crate::database::PlayerAddOutcome::NameExists) => {
            duplicate_player_name_error(&state.config.locale)
        }
        Ok(crate::database::PlayerAddOutcome::InsufficientScore) => login_result(
            7,
            if state.config.locale.starts_with("zh") {
                "添加角色失败，积分不足"
            } else {
                "You don't have enough score to add a player."
            },
            None,
        ),
        Err(error) => {
            tracing::error!(%error, "failed to add player");
            unavailable()
        }
    }
}

async fn api_delete_player(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(raw_id): RoutePath<String>,
) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_scope("Player.ReadWrite") {
        return missing_scope();
    }
    let Ok(player_id) = raw_id.parse::<i64>() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let prefix = &state.config.database.table_prefix;
    let return_score = match database.option(prefix, "return_score").await {
        Ok(value) => legacy_option_bool(value.as_deref()),
        Err(error) => {
            tracing::error!(%error, "failed to load player score refund option");
            return unavailable();
        }
    };
    let score_reward = if return_score {
        match database.option(prefix, "score_per_player").await {
            Ok(value) => value
                .and_then(|value| value.parse::<i64>().ok())
                .unwrap_or_default(),
            Err(error) => {
                tracing::error!(%error, "failed to load player score reward");
                return unavailable();
            }
        }
    } else {
        0
    };
    match database
        .delete_player(
            prefix,
            identity.user_id,
            player_id,
            return_score,
            score_reward,
        )
        .await
    {
        Ok(crate::database::PlayerDeleteOutcome::Deleted(name)) => login_result(
            0,
            &if state.config.locale.starts_with("zh") {
                format!("角色 {name} 已被删除")
            } else {
                format!("Player {name} was deleted successfully.")
            },
            None,
        ),
        Ok(crate::database::PlayerDeleteOutcome::Forbidden) => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "code": 1,
                "message": if state.config.locale.starts_with("zh") { "无权操作此角色" } else { "You are not allowed to modify this player." }
            })),
        )
            .into_response(),
        Ok(crate::database::PlayerDeleteOutcome::NotFound) => {
            StatusCode::NOT_FOUND.into_response()
        }
        Err(error) => {
            tracing::error!(%error, "failed to delete player");
            unavailable()
        }
    }
}

fn legacy_option_bool(value: Option<&str>) -> bool {
    match value.map(str::to_ascii_lowercase).as_deref() {
        Some("true" | "(true)") => true,
        Some("" | "0" | "false" | "(false)" | "null" | "(null)") | None => false,
        Some(_) => true,
    }
}
fn closet_validation_error(field: &str, locale: &str) -> Response {
    let chinese = locale.starts_with("zh");
    let message = if chinese {
        "给定数据无效。"
    } else {
        "The given data was invalid."
    };
    let field_error = match (field, chinese) {
        ("tid", true) => "材质编号必须是整数。",
        ("tid", false) => "The tid field must be an integer.",
        ("name", true) => "名称为必填项。",
        ("name", false) => "The name field is required.",
        _ => "The given field is invalid.",
    };
    let mut errors = serde_json::Map::new();
    errors.insert(field.to_owned(), serde_json::json!([field_error]));
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(serde_json::json!({ "message": message, "errors": errors })),
    )
        .into_response()
}

fn texture_id_from_request(value: Option<&serde_json::Value>) -> Option<i64> {
    match value? {
        serde_json::Value::Number(value) => value.as_i64(),
        serde_json::Value::String(value) => value.trim().parse().ok(),
        _ => None,
    }
}

async fn api_add_closet_item(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_scope("Closet.ReadWrite") {
        return missing_scope();
    }
    let request = match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(request) => request,
        Err(_) => return closet_validation_error("tid", &state.config.locale),
    };
    let Some(tid) = texture_id_from_request(request.get("tid")) else {
        return closet_validation_error("tid", &state.config.locale);
    };
    let Some(name) = request.get("name").and_then(serde_json::Value::as_str) else {
        return closet_validation_error("name", &state.config.locale);
    };
    let name = name.trim();
    if name.is_empty() {
        return closet_validation_error("name", &state.config.locale);
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    let prefix = &state.config.database.table_prefix;
    let user = match database.user_profile(prefix, identity.user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => return unauthenticated(),
        Err(error) => {
            tracing::error!(%error, "failed to load closet owner");
            return unavailable();
        }
    };
    let score_cost = match database.option(prefix, "score_per_closet_item").await {
        Ok(value) => value
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or_default(),
        Err(error) => {
            tracing::error!(%error, "failed to load closet score cost");
            return unavailable();
        }
    };
    let like_award = match database.option(prefix, "score_award_per_like").await {
        Ok(value) => value
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or_default(),
        Err(error) => {
            tracing::error!(%error, "failed to load texture like award");
            return unavailable();
        }
    };
    match database
        .add_closet_item(
            prefix,
            identity.user_id,
            tid,
            name,
            score_cost,
            user.permission >= 1,
            like_award,
        )
        .await
    {
        Ok(crate::database::ClosetAddOutcome::Added) => login_result(
            0,
            &if state.config.locale.starts_with("zh") {
                format!("材质 {name} 收藏成功")
            } else {
                format!("Added {name} to closet successfully.")
            },
            None,
        ),
        Ok(crate::database::ClosetAddOutcome::NameExists) => login_result(
            1,
            if state.config.locale.starts_with("zh") {
                "你已经收藏过这个材质啦"
            } else {
                "You have already added this texture."
            },
            None,
        ),
        Ok(crate::database::ClosetAddOutcome::InsufficientScore) => login_result(
            1,
            if state.config.locale.starts_with("zh") {
                "收藏失败，积分不足"
            } else {
                "You don't have enough score to add it to closet."
            },
            None,
        ),
        Ok(crate::database::ClosetAddOutcome::TextureNotFound) => login_result(
            1,
            if state.config.locale.starts_with("zh") {
                "该材质不存在"
            } else {
                "We cannot find this texture."
            },
            None,
        ),
        Ok(crate::database::ClosetAddOutcome::PrivateTexture) => login_result(
            1,
            if state.config.locale.starts_with("zh") {
                "请求的材质已经设为私密，仅上传者和管理员可查看"
            } else {
                "The requested texture is private and only visible to the uploader and admins."
            },
            None,
        ),
        Err(error) => {
            tracing::error!(%error, "failed to add a texture to the closet");
            unavailable()
        }
    }
}

async fn api_rename_closet_item(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(raw_tid): RoutePath<String>,
    body: Bytes,
) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_scope("Closet.ReadWrite") {
        return missing_scope();
    }
    let Ok(tid) = raw_tid.parse::<i64>() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let request = match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(request) => request,
        Err(_) => return closet_validation_error("name", &state.config.locale),
    };
    let Some(name) = request.get("name").and_then(serde_json::Value::as_str) else {
        return closet_validation_error("name", &state.config.locale);
    };
    let name = name.trim();
    if name.is_empty() {
        return closet_validation_error("name", &state.config.locale);
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    match database
        .rename_closet_item(
            &state.config.database.table_prefix,
            identity.user_id,
            tid,
            name,
        )
        .await
    {
        Ok(crate::database::ClosetRenameOutcome::Renamed) => login_result(
            0,
            &if state.config.locale.starts_with("zh") {
                format!("衣柜物品成功重命名至 {name}")
            } else {
                format!("The item is successfully renamed to {name}")
            },
            None,
        ),
        Ok(crate::database::ClosetRenameOutcome::NotInCloset) => closet_item_missing(&state),
        Err(error) => {
            tracing::error!(%error, "failed to rename a closet item");
            unavailable()
        }
    }
}

async fn api_remove_closet_item(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(raw_tid): RoutePath<String>,
) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_scope("Closet.ReadWrite") {
        return missing_scope();
    }
    let Ok(tid) = raw_tid.parse::<i64>() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let prefix = &state.config.database.table_prefix;
    let return_score = match database.option(prefix, "return_score").await {
        Ok(value) => legacy_option_bool(value.as_deref()),
        Err(error) => {
            tracing::error!(%error, "failed to load closet score refund option");
            return unavailable();
        }
    };
    let score_refund = if return_score {
        match database.option(prefix, "score_per_closet_item").await {
            Ok(value) => value
                .and_then(|value| value.parse::<i64>().ok())
                .unwrap_or_default(),
            Err(error) => {
                tracing::error!(%error, "failed to load closet score refund");
                return unavailable();
            }
        }
    } else {
        0
    };
    let like_award = match database.option(prefix, "score_award_per_like").await {
        Ok(value) => value
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or_default(),
        Err(error) => {
            tracing::error!(%error, "failed to load texture like award");
            return unavailable();
        }
    };
    match database
        .remove_closet_item(
            prefix,
            identity.user_id,
            tid,
            return_score,
            score_refund,
            like_award,
        )
        .await
    {
        Ok(crate::database::ClosetRemoveOutcome::Removed) => login_result(
            0,
            if state.config.locale.starts_with("zh") {
                "材质已从衣柜中移除"
            } else {
                "The texture was removed from closet successfully."
            },
            None,
        ),
        Ok(crate::database::ClosetRemoveOutcome::NotInCloset) => closet_item_missing(&state),
        Err(error) => {
            tracing::error!(%error, "failed to remove a texture from the closet");
            unavailable()
        }
    }
}

fn closet_item_missing(state: &AppState) -> Response {
    login_result(
        1,
        if state.config.locale.starts_with("zh") {
            "衣柜中不存在此材质"
        } else {
            "The texture does not exist in your closet."
        },
        None,
    )
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClosetListQuery {
    category: Option<String>,
    q: Option<String>,
    page: Option<i64>,
    per_page: Option<i64>,
}

async fn api_closet(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ClosetListQuery>,
) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_any_scope(&["Closet.Read", "Closet.ReadWrite"]) {
        return missing_scope();
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(6).max(1);
    let category = query.category.as_deref().unwrap_or("skin");
    let search = query
        .q
        .as_deref()
        .filter(|value| !value.is_empty() && *value != "0");
    match database
        .closet_items(
            &state.config.database.table_prefix,
            identity.user_id,
            category,
            search,
            page,
            per_page,
        )
        .await
    {
        Ok((items, total)) => {
            let data = items.into_iter().map(closet_item_json).collect::<Vec<_>>();
            let last_page = total.saturating_add(per_page - 1) / per_page;
            let offset = page.saturating_sub(1).saturating_mul(per_page);
            let from = (!data.is_empty()).then_some(offset + 1);
            let to = (!data.is_empty()).then_some(offset + data.len() as i64);
            Json(serde_json::json!({
                "current_page": page,
                "data": data,
                "last_page": last_page.max(1),
                "per_page": per_page,
                "from": from,
                "to": to,
                "total": total
            }))
            .into_response()
        }
        Err(error) => {
            tracing::error!(%error, "failed to load user's texture closet");
            unavailable()
        }
    }
}

fn closet_item_json(item: crate::database::ClosetTextureRecord) -> serde_json::Value {
    serde_json::json!({
        "tid": item.tid,
        "name": item.name,
        "type": item.texture_type,
        "hash": item.hash,
        "size": item.size,
        "uploader": item.uploader,
        "public": item.is_public,
        "upload_at": item.upload_at,
        "likes": item.likes,
        "pivot": {
            "user_uid": item.user_uid,
            "texture_tid": item.texture_tid,
            "item_name": item.item_name
        }
    })
}
async fn api_players(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_any_scope(&["Player.Read", "Player.ReadWrite"]) {
        return missing_scope();
    }
    let Some(database) = &state.database else {
        return unavailable();
    };

    match database
        .players_for_user(&state.config.database.table_prefix, identity.user_id)
        .await
    {
        Ok(players) => Json(players).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to load authenticated player's list");
            unavailable()
        }
    }
}

struct AuthenticatedToken {
    user_id: i64,
    scopes: Vec<String>,
}

impl AuthenticatedToken {
    fn has_scope(&self, required: &str) -> bool {
        self.scopes.iter().any(|scope| scope == required)
    }

    fn has_any_scope(&self, required: &[&str]) -> bool {
        required.iter().any(|scope| self.has_scope(scope))
    }
}

async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthenticatedToken, Response> {
    let Some(key) = &state.passport_key else {
        return Err(unauthenticated());
    };
    let Some(token) = bearer_token(headers) else {
        return Err(unauthenticated());
    };
    let Some(database) = &state.database else {
        return Err(unavailable());
    };
    let Some(claims) = decode_access_token(token, key) else {
        return Err(unauthenticated());
    };
    if claims.exp <= jsonwebtoken::get_current_timestamp() {
        return Err(unauthenticated());
    }
    let token_record = match database
        .access_token(&state.config.database.table_prefix, &claims.jti)
        .await
    {
        Ok(Some(record)) => record,
        Ok(None) => return Err(unauthenticated()),
        Err(error) => {
            tracing::error!(%error, "failed to load Passport access token");
            return Err(unavailable());
        }
    };
    let user_id = match claims.sub.parse::<i64>() {
        Ok(user_id) => user_id,
        Err(_) => return Err(unauthenticated()),
    };
    if token_record.revoked
        || token_record.user_id != Some(user_id)
        || !audience_matches(claims.aud.as_ref(), token_record.client_id)
    {
        return Err(unauthenticated());
    }

    Ok(AuthenticatedToken {
        user_id,
        scopes: claims.scopes,
    })
}

fn missing_scope() -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "code": 403,
            "message": "Invalid scope(s) provided."
        })),
    )
        .into_response()
}
fn unauthenticated() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({ "message": "Unauthenticated." })),
    )
        .into_response()
}
async fn api_root(State(state): State<AppState>) -> Response {
    let Some(database) = &state.database else {
        return unavailable();
    };
    match build_api_root(database, &state).await {
        Ok(root) => Json(root).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to load public API metadata");
            unavailable()
        }
    }
}

async fn build_api_root(database: &DatabasePool, state: &AppState) -> Result<ApiRoot, sqlx::Error> {
    let locale_key = format!("copyright_prefer_{}", state.config.locale);
    let preference = database
        .option(&state.config.database.table_prefix, &locale_key)
        .await?
        .or(database
            .option(&state.config.database.table_prefix, "copyright_prefer")
            .await?);
    let copyright_index = preference
        .as_deref()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or_default();
    let copyright = COPYRIGHTS
        .get(copyright_index)
        .copied()
        .unwrap_or(COPYRIGHTS[0]);
    let site_name = database
        .option(&state.config.database.table_prefix, "site_name")
        .await?
        .unwrap_or_else(|| "Blessing Skin".to_owned());

    Ok(ApiRoot {
        blessing_skin: state.config.version,
        spec: 0,
        copyright,
        site_name,
    })
}

#[derive(Serialize)]
struct SkinProfile {
    username: String,
    skins: BTreeMap<String, Option<String>>,
    cape: Option<String>,
}

async fn player_json(
    State(state): State<AppState>,
    RoutePath(profile_path): RoutePath<String>,
    request_headers: HeaderMap,
) -> Response {
    let Some(player_name) = profile_path.strip_suffix(".json") else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let profile = match database
        .player_profile(&state.config.database.table_prefix, &player_name)
        .await
    {
        Ok(Some(profile)) => profile,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to load player profile");
            return unavailable();
        }
    };

    if profile.permission == -1 {
        let message = if state.config.locale.starts_with("zh") {
            "该角色拥有者已被本站封禁"
        } else {
            "The owner of this player has been banned."
        };
        return (StatusCode::FORBIDDEN, message).into_response();
    }

    let last_modified = profile
        .last_modified
        .as_deref()
        .and_then(parse_legacy_datetime);
    let ttl = cache_ttl(&state).await;
    let mut response = Json(to_skin_profile(profile)).into_response();
    response.headers_mut().insert(
        CACHE_CONTROL,
        HeaderValue::from_str(&format!("public, max-age={ttl}")).unwrap(),
    );
    if let Some(last_modified) = last_modified {
        response.headers_mut().insert(
            LAST_MODIFIED,
            HeaderValue::from_str(&httpdate::fmt_http_date(last_modified)).unwrap(),
        );
        if !request_headers.contains_key(IF_NONE_MATCH)
            && not_modified_since(&request_headers, last_modified)
        {
            *response.status_mut() = StatusCode::NOT_MODIFIED;
            *response.body_mut() = Body::empty();
            response.headers_mut().remove(CONTENT_TYPE);
            response.headers_mut().remove(CONTENT_LENGTH);
        }
    }
    response
}

fn to_skin_profile(profile: PlayerProfile) -> SkinProfile {
    let model = if profile.skin_type.as_deref() == Some("alex") {
        "slim"
    } else {
        "default"
    };
    let mut skins = BTreeMap::new();
    skins.insert(model.to_owned(), profile.skin_hash);
    SkinProfile {
        username: profile.name,
        skins,
        cape: profile.cape_hash,
    }
}

async fn texture(
    State(state): State<AppState>,
    RoutePath(hash): RoutePath<String>,
    request_headers: HeaderMap,
) -> Response {
    if !valid_texture_hash(&hash) {
        return StatusCode::NOT_FOUND.into_response();
    }
    serve_texture(&state, &hash, &request_headers).await
}

async fn raw_texture(
    State(state): State<AppState>,
    RoutePath(tid): RoutePath<i64>,
    request_headers: HeaderMap,
) -> Response {
    let Some(database) = &state.database else {
        return unavailable();
    };
    let allowed = database
        .option(
            &state.config.database.table_prefix,
            "allow_downloading_texture",
        )
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| "true".to_owned());
    if matches!(
        allowed.to_ascii_lowercase().as_str(),
        "false" | "0" | "off" | "no"
    ) {
        return StatusCode::FORBIDDEN.into_response();
    }

    let hash = match database
        .texture_hash(&state.config.database.table_prefix, tid)
        .await
    {
        Ok(Some(hash)) if valid_texture_hash(&hash) => hash,
        Ok(_) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to load texture metadata");
            return unavailable();
        }
    };
    serve_texture(&state, &hash, &request_headers).await
}

async fn serve_texture(state: &AppState, hash: &str, request_headers: &HeaderMap) -> Response {
    let file_path = state.config.textures_dir.join(hash);
    let metadata = match tokio::fs::metadata(&file_path).await {
        Ok(metadata) if metadata.is_file() => metadata,
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    let bytes = match tokio::fs::read(&file_path).await {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::warn!(%error, hash, "texture file could not be read");
            return StatusCode::NOT_FOUND.into_response();
        }
    };
    let modified = metadata.modified().ok();
    let etag = content_etag(&bytes);
    let ttl = cache_ttl(state).await;
    let mut response_headers = HeaderMap::new();
    response_headers.insert(CONTENT_TYPE, HeaderValue::from_static("image/png"));
    response_headers.insert(ETAG, HeaderValue::from_str(&etag).unwrap());
    response_headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_str(&format!("public, max-age={ttl}")).unwrap(),
    );
    response_headers.insert(
        CONTENT_LENGTH,
        HeaderValue::from_str(&metadata.len().to_string()).unwrap(),
    );
    if let Some(modified) = modified {
        response_headers.insert(
            LAST_MODIFIED,
            HeaderValue::from_str(&httpdate::fmt_http_date(modified)).unwrap(),
        );
    }

    let has_if_none_match = request_headers.contains_key(IF_NONE_MATCH);
    if (has_if_none_match && header_has_etag(request_headers, &etag))
        || (!has_if_none_match
            && modified.is_some_and(|time| not_modified_since(request_headers, time)))
    {
        let mut response = StatusCode::NOT_MODIFIED.into_response();
        *response.headers_mut() = response_headers;
        response.headers_mut().remove(CONTENT_TYPE);
        response.headers_mut().remove(CONTENT_LENGTH);
        return response;
    }

    let mut response = Response::new(Body::from(bytes));
    *response.headers_mut() = response_headers;
    response
}

fn content_etag(bytes: &[u8]) -> String {
    format!("\"{:x}\"", Md5::digest(bytes))
}
async fn cache_ttl(state: &AppState) -> u64 {
    let Some(database) = &state.database else {
        return 31_536_000;
    };
    database
        .option(&state.config.database.table_prefix, "cache_expire_time")
        .await
        .ok()
        .flatten()
        .and_then(|value| value.parse().ok())
        .unwrap_or(31_536_000)
}

fn header_has_etag(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get(IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|item| item.trim() == "*" || item.trim() == etag)
        })
}

fn not_modified_since(headers: &HeaderMap, modified: SystemTime) -> bool {
    headers
        .get(IF_MODIFIED_SINCE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| httpdate::parse_http_date(value).ok())
        .is_some_and(|since| {
            modified
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                <= since
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
        })
}

fn valid_texture_hash(hash: &str) -> bool {
    hash.len() == 64 && hash.chars().all(|character| character.is_ascii_hexdigit())
}

fn parse_legacy_datetime(value: &str) -> Option<SystemTime> {
    let naive = NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S").ok()?;
    let offset = FixedOffset::east_opt(8 * 60 * 60)?;
    let datetime = offset.from_local_datetime(&naive).single()?;
    let timestamp = datetime.timestamp();
    if timestamp >= 0 {
        Some(SystemTime::UNIX_EPOCH + Duration::from_secs(timestamp as u64))
    } else {
        SystemTime::UNIX_EPOCH.checked_sub(Duration::from_secs(timestamp.unsigned_abs()))
    }
}

fn unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(Health {
            status: "not_ready",
        }),
    )
        .into_response()
}

const COPYRIGHTS: [&str; 7] = [
    "Powered with ❤ by Blessing Skin Server.",
    "Powered by Blessing Skin Server.",
    "Proudly powered by Blessing Skin Server.",
    "由 Blessing Skin Server 强力驱动。",
    "采用 Blessing Skin Server 搭建。",
    "使用 Blessing Skin Server 稳定运行。",
    "自豪地采用 Blessing Skin Server。",
];

#[cfg(test)]
mod tests {
    use super::{content_etag, parse_legacy_datetime, router, valid_texture_hash};

    #[tokio::test]
    async fn closet_validation_errors_use_the_requested_field_name() {
        use axum::body::to_bytes;

        let response = super::closet_validation_error("tid", "en");
        assert_eq!(
            response.status(),
            axum::http::StatusCode::UNPROCESSABLE_ENTITY
        );
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(value["errors"]["tid"][0].as_str().is_some());
        assert!(value["errors"]["field"].is_null());
    }
    #[test]
    fn creates_unique_legacy_notification_ids() {
        let first = super::new_notification_id();
        let second = super::new_notification_id();
        assert_eq!(first.len(), 36);
        assert_eq!(second.len(), 36);
        assert_eq!(first.as_bytes()[14], b'4');
        assert_ne!(first, second);
    }
    #[test]
    fn parses_legacy_boolean_options() {
        assert!(super::legacy_option_bool(Some("true")));
        assert!(super::legacy_option_bool(Some("(true)")));
        assert!(!super::legacy_option_bool(Some("false")));
        assert!(!super::legacy_option_bool(Some("0")));
        assert!(!super::legacy_option_bool(None));
    }
    #[test]
    fn parses_legacy_texture_ids_and_clear_request_shapes() {
        use serde_json::json;

        assert_eq!(super::texture_request_id(Some(&json!(0))), Some(0));
        assert_eq!(super::texture_request_id(Some(&json!("12"))), Some(12));
        assert_eq!(super::texture_request_id(Some(&json!(""))), None);
        assert_eq!(super::texture_request_id(Some(&json!(null))), None);

        let by_field = json!({"skin": null});
        assert!(by_field.get("skin").is_some());
        let by_type = json!({"type": ["cape"]});
        assert!(
            by_type["type"]
                .as_array()
                .is_some_and(|types| types.iter().any(|value| value.as_str() == Some("cape")))
        );
    }
    #[test]
    fn serializes_legacy_closet_item_texture_and_pivot_fields() {
        let item = super::closet_item_json(crate::database::ClosetTextureRecord {
            tid: 13,
            name: "Other skin".to_owned(),
            texture_type: "alex".to_owned(),
            hash: "skin-hash".to_owned(),
            size: 10,
            uploader: 8,
            is_public: true,
            upload_at: "2026-10-01 10:02:00".to_owned(),
            likes: 2,
            user_uid: 7,
            texture_tid: 13,
            item_name: Some("Saved name".to_owned()),
        });
        assert_eq!(item["tid"], 13);
        assert_eq!(item["type"], "alex");
        assert_eq!(item["public"], true);
        assert_eq!(item["pivot"]["user_uid"], 7);
        assert_eq!(item["pivot"]["texture_tid"], 13);
        assert_eq!(item["pivot"]["item_name"], "Saved name");
    }
    #[test]
    fn validates_texture_hashes_before_joining_them_to_storage_paths() {
        assert!(valid_texture_hash(&"a".repeat(64)));
        assert!(!valid_texture_hash("../textures"));
        assert!(!valid_texture_hash(&"a".repeat(63)));
    }

    #[test]
    fn parses_legacy_local_datetime_as_shanghai_time() {
        let parsed = parse_legacy_datetime("2026-10-02 12:00:00").unwrap();
        assert_eq!(
            httpdate::fmt_http_date(parsed),
            "Fri, 02 Oct 2026 04:00:00 GMT"
        );
    }

    #[test]
    fn uses_content_md5_for_legacy_texture_etags() {
        assert_eq!(content_etag(b"abc"), "\"900150983cd24fb0d6963f7d28e17f72\"");
    }

    #[tokio::test]
    async fn api_user_rejects_requests_without_a_bearer_token() {
        use axum::{
            body::Body,
            http::{Request, StatusCode},
        };
        use sqlx::sqlite::SqliteConnectOptions;
        use std::{path::PathBuf, sync::Arc};
        use tower::ServiceExt;

        let config = crate::config::Config {
            bind: "127.0.0.1:3000".parse().unwrap(),
            version: "test",
            locale: "en".to_owned(),
            database: crate::config::DatabaseConfig {
                connection: crate::config::DatabaseConnection::Sqlite(SqliteConnectOptions::new()),
                table_prefix: String::new(),
            },
            textures_dir: PathBuf::new(),
            plugins_dir: PathBuf::new(),
            app_url: "http://localhost".to_owned(),
            passport_public_key: None,
            password_method: "BCRYPT".to_owned(),
            password_salt: String::new(),
            app_key: None,
        };
        let app = router(crate::AppState {
            config: Arc::new(config),
            database: None,
            passport_key: None,
            session_key: None,
            login_failures: Default::default(),
        });
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/user")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn login_issues_a_session_that_opens_the_user_dashboard() {
        use axum::{
            body::{Body, to_bytes},
            http::{Request, StatusCode, header::SET_COOKIE},
        };
        use bcrypt;
        use sqlx::sqlite::SqlitePoolOptions;
        use std::{path::PathBuf, sync::Arc};
        use tower::ServiceExt;

        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query("CREATE TABLE users (uid INTEGER PRIMARY KEY, email TEXT NOT NULL, nickname TEXT NOT NULL, locale TEXT, score INTEGER NOT NULL, avatar INTEGER NOT NULL, password TEXT NOT NULL, permission INTEGER NOT NULL, last_sign_at TEXT NOT NULL, register_at TEXT NOT NULL, verified BOOLEAN NOT NULL, is_dark_mode BOOLEAN NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE players (pid INTEGER PRIMARY KEY, uid INTEGER NOT NULL, name TEXT NOT NULL, tid_skin INTEGER NOT NULL, tid_cape INTEGER NOT NULL, last_modified TEXT NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        let password_hash = bcrypt::hash("correct horse", 4).unwrap();
        sqlx::query("INSERT INTO users (uid,email,nickname,locale,score,avatar,password,permission,last_sign_at,register_at,verified,is_dark_mode) VALUES (7,'alex@example.test','Alex User','en',5,0,?,0,'','',1,0)")
            .bind(password_hash)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO players (pid,uid,name,tid_skin,tid_cape,last_modified) VALUES (3,7,'Alex',0,0,'2026-10-02 12:00:00')")
            .execute(&pool)
            .await
            .unwrap();

        let secret = "a test APP_KEY with enough entropy".to_owned();
        let config = crate::config::Config {
            bind: "127.0.0.1:3000".parse().unwrap(),
            version: "test",
            locale: "en".to_owned(),
            database: crate::config::DatabaseConfig {
                connection: crate::config::DatabaseConnection::Sqlite(
                    sqlx::sqlite::SqliteConnectOptions::new(),
                ),
                table_prefix: String::new(),
            },
            textures_dir: PathBuf::new(),
            plugins_dir: PathBuf::new(),
            app_url: "http://localhost".to_owned(),
            passport_public_key: None,
            password_method: "BCRYPT".to_owned(),
            password_salt: String::new(),
            app_key: Some(secret.clone()),
        };
        let app = router(crate::AppState {
            config: Arc::new(config),
            database: Some(crate::database::DatabasePool::Sqlite(pool)),
            passport_key: None,
            session_key: Some(jsonwebtoken::EncodingKey::from_secret(secret.as_bytes())),
            login_failures: Default::default(),
        });
        let homepage = app
            .clone()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(homepage.status(), StatusCode::OK);
        let homepage_html = to_bytes(homepage.into_body(), usize::MAX).await.unwrap();
        assert!(
            String::from_utf8(homepage_html.to_vec())
                .unwrap()
                .contains("Skin Server")
        );

        let login_page = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/auth/login")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login_page.status(), StatusCode::OK);
        let login_html = to_bytes(login_page.into_body(), usize::MAX).await.unwrap();
        assert!(
            String::from_utf8(login_html.to_vec())
                .unwrap()
                .contains("Email or player name")
        );

        let login = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"identification":"alex@example.test","password":"correct horse","keep":true}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login.status(), StatusCode::OK);
        let cookie = login
            .headers()
            .get(SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        assert!(
            login
                .headers()
                .get(SET_COOKIE)
                .unwrap()
                .to_str()
                .unwrap()
                .contains("Max-Age=2592000")
        );
        let body = to_bytes(login.into_body(), usize::MAX).await.unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["code"], 0);
        assert_eq!(result["data"]["redirectTo"], "/user");

        let dashboard = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/user")
                    .header("cookie", cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(dashboard.status(), StatusCode::OK);
        let dashboard_html = to_bytes(dashboard.into_body(), usize::MAX).await.unwrap();
        let dashboard_html = String::from_utf8(dashboard_html.to_vec()).unwrap();
        assert!(dashboard_html.contains("alex@example.test"));
        assert!(dashboard_html.contains("Alex"));

        let logout = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/logout")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(logout.status(), StatusCode::OK);
        assert!(
            logout
                .headers()
                .get(SET_COOKIE)
                .unwrap()
                .to_str()
                .unwrap()
                .contains("Max-Age=0")
        );
    }

    #[test]
    fn renders_github_flavored_notification_markdown_without_unsafe_html() {
        use super::render_notification_markdown;

        let html = render_notification_markdown(
            "## Notice

~~old~~ **new**

|a|b|
|-|-|
|1|2|

<script>alert(1)</script>

[bad](javascript:alert(1))",
        );
        assert!(html.contains("<h2>Notice</h2>"));
        assert!(html.contains("<del>old</del>"));
        assert!(html.contains("<strong>new</strong>"));
        assert!(html.contains("<table>"));
        assert!(!html.contains("<script"));
        assert!(!html.contains("alert(1)"));
    }

    #[tokio::test]
    async fn notification_detail_keeps_the_legacy_json_fields() {
        use axum::body::to_bytes;

        let response = super::notification_detail(crate::database::NotificationRecord {
            id: "notice-id".to_owned(),
            data: r#"{"title":"Site notice","content":"Hello **skin**"}"#.to_owned(),
            created_at: "2026-10-01 10:00:00".to_owned(),
        });
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["title"], "Site notice");
        assert_eq!(value["time"], "2026-10-01 10:00:00");
        assert!(
            value["content"]
                .as_str()
                .unwrap()
                .contains("<strong>skin</strong>")
        );
    }

    #[test]
    fn applies_the_legacy_player_name_rules() {
        use super::valid_player_name;

        assert!(valid_player_name("Alex_2", "official", "", 3, 16));
        assert!(!valid_player_name("Alex!", "official", "", 3, 16));
        assert!(valid_player_name("玩家§2", "cjk", "", 3, 16));
        assert!(!valid_player_name("bad name", "utf8", "", 3, 16));
        assert!(valid_player_name("ABC", "custom", "/^[a-z]+$/i", 3, 16));
        assert!(!valid_player_name("ABC1", "custom", "/^[a-z]+$/i", 3, 16));
    }
}
