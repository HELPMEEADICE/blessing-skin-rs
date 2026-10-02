use std::{
    collections::BTreeMap,
    io::Cursor,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use askama::Template;
use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, Multipart, Path as RoutePath, Query, State},
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
use image::{ImageFormat, ImageReader};
use jsonwebtoken::{Algorithm, Header, encode};
use md5::{Digest, Md5};
use pulldown_cmark::{Options, Parser, html as markdown_html};
use regex::RegexBuilder;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::{
    AppState,
    auth::{audience_matches, bearer_token, decode_access_token, decode_web_session},
    database::{
        DatabasePool, NotificationRecord, PlayerProfile, PlayerRecord, PlayerRenameOutcome,
        PlayerTextureOutcome, ReportManagementRecord, ReportSearchFilters, TextureInfoRecord,
        UserProfile,
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
        .route(
            "/oauth/clients",
            get(oauth_clients_list).post(oauth_client_create),
        )
        .route(
            "/oauth/clients/{id}",
            put(oauth_client_update).delete(oauth_client_delete),
        )
        .route("/user", get(web_dashboard))
        .route("/admin/reports/list", get(admin_report_list))
        .route("/admin/reports/{id}", put(web_review_report))
        .route("/skinlib/list", get(skinlib_list))
        .route("/skinlib/report", post(submit_skinlib_report))
        .route("/skinlib/info/{tid}", get(skinlib_info))
        .route(
            "/texture",
            post(upload_texture).layer(DefaultBodyLimit::max(64 * 1024 * 1024)),
        )
        .route("/texture/{tid}", get(skinlib_info).delete(delete_texture))
        .route("/texture/{tid}/name", put(rename_texture))
        .route("/texture/{tid}/type", put(update_texture_type))
        .route("/texture/{tid}/privacy", put(toggle_texture_privacy))
        .route("/api/user", get(api_user))
        .route("/api/closet", get(api_closet).post(api_add_closet_item))
        .route(
            "/api/closet/{tid}",
            put(api_rename_closet_item).delete(api_remove_closet_item),
        )
        .route("/api/user/notifications", get(api_user_notifications))
        .route("/api/admin/notifications", post(api_send_notification))
        .route("/api/admin/reports", get(api_admin_report_list))
        .route("/api/admin/reports/{id}", put(api_review_report))
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

#[derive(Deserialize)]
struct OAuthClientRequest {
    name: Option<String>,
    redirect: Option<String>,
}

async fn oauth_clients_list(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    match database
        .oauth_clients_for_user(&state.config.database.table_prefix, user.uid)
        .await
    {
        Ok(clients) => Json(clients).into_response(),
        Err(error) => {
            tracing::error!(%error, user_id = user.uid, "failed to list Passport clients");
            unavailable()
        }
    }
}

async fn oauth_client_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let request = match serde_json::from_slice::<OAuthClientRequest>(&body) {
        Ok(request) => request,
        Err(_) => return oauth_client_validation_error("name", &state.config.locale),
    };
    let Some(name) = request
        .name
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty() && name.chars().count() <= 255)
    else {
        return oauth_client_validation_error("name", &state.config.locale);
    };
    let Some(redirect) = request
        .redirect
        .map(|redirect| redirect.trim().to_owned())
        .filter(|redirect| valid_oauth_redirect(redirect))
    else {
        return oauth_client_validation_error("redirect", &state.config.locale);
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    use rand::distributions::{Alphanumeric, DistString};
    let secret = Alphanumeric.sample_string(&mut rand::thread_rng(), 40);
    match database
        .create_oauth_client(
            &state.config.database.table_prefix,
            user.uid,
            &name,
            &secret,
            &redirect,
        )
        .await
    {
        Ok(client) => Json(client).into_response(),
        Err(error) => {
            tracing::error!(%error, user_id = user.uid, "failed to create Passport client");
            unavailable()
        }
    }
}

async fn oauth_client_update(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(id): RoutePath<i64>,
    body: Bytes,
) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let request = match serde_json::from_slice::<OAuthClientRequest>(&body) {
        Ok(request) => request,
        Err(_) => return oauth_client_validation_error("name", &state.config.locale),
    };
    let Some(name) = request
        .name
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty() && name.chars().count() <= 255)
    else {
        return oauth_client_validation_error("name", &state.config.locale);
    };
    let Some(redirect) = request
        .redirect
        .map(|redirect| redirect.trim().to_owned())
        .filter(|redirect| valid_oauth_redirect(redirect))
    else {
        return oauth_client_validation_error("redirect", &state.config.locale);
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    match database
        .update_oauth_client(
            &state.config.database.table_prefix,
            user.uid,
            id,
            &name,
            &redirect,
        )
        .await
    {
        Ok(true) => match database
            .oauth_clients_for_user(&state.config.database.table_prefix, user.uid)
            .await
        {
            Ok(clients) => clients
                .into_iter()
                .find(|client| client.id == id)
                .map(|client| Json(client).into_response())
                .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response()),
            Err(error) => {
                tracing::error!(%error, client_id = id, "failed to reload updated Passport client");
                unavailable()
            }
        },
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, client_id = id, "failed to update Passport client");
            unavailable()
        }
    }
}

async fn oauth_client_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(id): RoutePath<i64>,
) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    match database
        .revoke_oauth_client(&state.config.database.table_prefix, user.uid, id)
        .await
    {
        Ok(crate::database::OAuthClientDeleteOutcome::Revoked) => {
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(crate::database::OAuthClientDeleteOutcome::NotFound) => {
            StatusCode::NOT_FOUND.into_response()
        }
        Err(error) => {
            tracing::error!(%error, client_id = id, "failed to revoke Passport client");
            unavailable()
        }
    }
}

fn valid_oauth_redirect(redirect: &str) -> bool {
    let Ok(uri) = redirect.parse::<axum::http::Uri>() else {
        return false;
    };
    matches!(uri.scheme_str(), Some("http" | "https")) && uri.host().is_some()
}

fn oauth_client_validation_error(field: &str, locale: &str) -> Response {
    let chinese = locale.starts_with("zh");
    let message = if chinese {
        "给定数据无效。"
    } else {
        "The given data was invalid."
    };
    let field_error = match (field, chinese) {
        ("name", true) => "应用名称为必填项且不能超过 255 个字符。",
        ("name", false) => "The name field is required and may not exceed 255 characters.",
        ("redirect", true) => "重定向地址必须是有效的 HTTP 或 HTTPS URL。",
        ("redirect", false) => "The redirect field must be a valid HTTP or HTTPS URL.",
        _ => "The given field is invalid.",
    };
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(serde_json::json!({
            "message": message,
            "errors": { field: [field_error] }
        })),
    )
        .into_response()
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

async fn skinlib_info(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(tid): RoutePath<String>,
) -> Response {
    let Some(database) = &state.database else {
        return unavailable();
    };
    let Ok(tid) = tid.parse::<i64>() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let texture = match database
        .texture_info(&state.config.database.table_prefix, tid)
        .await
    {
        Ok(Some(texture)) => texture,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, tid, "failed to load legacy texture details");
            return unavailable();
        }
    };
    let session_user_id = session_user_id(&state, &headers);
    let (user_id, is_admin) = match session_user_id {
        Some(user_id) => match database
            .user_profile(&state.config.database.table_prefix, user_id)
            .await
        {
            Ok(Some(user)) => (Some(user_id), user.permission >= 1),
            Ok(None) => (None, false),
            Err(error) => {
                tracing::error!(%error, "failed to load texture viewer");
                return unavailable();
            }
        },
        None => (None, false),
    };
    if !texture.is_public && user_id != Some(texture.uploader) && !is_admin {
        let status_code = match database
            .option(
                &state.config.database.table_prefix,
                "status_code_for_private",
            )
            .await
        {
            Ok(value) => value.and_then(|value| value.parse::<u16>().ok()),
            Err(error) => {
                tracing::error!(%error, "failed to read private texture status option");
                return unavailable();
            }
        };
        let status = status_code
            .and_then(|code| StatusCode::from_u16(code).ok())
            .unwrap_or(StatusCode::FORBIDDEN);
        let message = if state.config.locale.starts_with("zh") {
            if status == StatusCode::NOT_FOUND {
                "请求的材质文件已经被删除"
            } else {
                "请求的材质已经设为私密，仅上传者和管理员可查看"
            }
        } else if status == StatusCode::NOT_FOUND {
            "The requested texture was already deleted."
        } else {
            "The requested texture is private and only visible to the uploader and admins."
        };
        return (status, message).into_response();
    }
    Json(texture_info_json(texture)).into_response()
}

fn texture_info_json(texture: TextureInfoRecord) -> serde_json::Value {
    serde_json::json!({
        "tid": texture.tid,
        "name": texture.name,
        "type": texture.texture_type,
        "hash": texture.hash,
        "size": texture.size,
        "uploader": texture.uploader,
        "public": texture.is_public,
        "upload_at": texture.upload_at,
        "likes": texture.likes,
    })
}

async fn authenticated_web_user(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<UserProfile, Response> {
    let database = state.database.as_ref().ok_or_else(unavailable)?;
    let user_id = session_user_id(state, headers).ok_or_else(unauthenticated)?;
    let user = match database
        .user_profile(&state.config.database.table_prefix, user_id)
        .await
    {
        Ok(Some(user)) => user,
        Ok(None) => return Err(unauthenticated()),
        Err(error) => {
            tracing::error!(%error, "failed to load authenticated web user");
            return Err(unavailable());
        }
    };
    if user.permission == -1 {
        let message = if state.config.locale.starts_with("zh") {
            "你已被本站封禁，详情请联系站点管理员"
        } else {
            "You are banned on this site. Please contact the admin."
        };
        let mut response = login_result(-1, message, None);
        *response.status_mut() = StatusCode::FORBIDDEN;
        return Err(response);
    }
    if user.email.is_empty() {
        return Err(Redirect::to("/auth/bind").into_response());
    }
    match database
        .option(&state.config.database.table_prefix, "require_verification")
        .await
    {
        Ok(value) if legacy_option_bool(value.as_deref()) && !user.verified => {
            let message = if state.config.locale.starts_with("zh") {
                "你必须验证邮箱后才能访问此页面"
            } else {
                "To access this page, you should verify your email address first."
            };
            return Err((
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({ "message": message })),
            )
                .into_response());
        }
        Ok(_) => {}
        Err(error) => {
            tracing::error!(%error, "failed to read email verification option");
            return Err(unavailable());
        }
    }
    Ok(user)
}

fn parse_legacy_form_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "(true)" => Some(true),
        "0" | "false" | "(false)" => Some(false),
        _ => None,
    }
}

fn upload_validation_error(field: &str, locale: &str) -> Response {
    let chinese = locale.starts_with("zh");
    let message = if chinese {
        "给定数据无效。"
    } else {
        "The given data was invalid."
    };
    let field_error = match (field, chinese) {
        ("name", true) => "材质名称为必填项且必须符合本站规则。",
        ("name", false) => "The name field is required or does not match the configured rule.",
        ("file", true) => "必须上传有效的 PNG 文件，且不能超过大小限制。",
        ("file", false) => "The file must be a valid PNG and within the size limit.",
        ("type", true) => "type 字段必须为 steve、alex 或 cape。",
        ("type", false) => "The type field must be steve, alex, or cape.",
        ("public", true) => "public 字段必须是布尔值。",
        ("public", false) => "The public field must be true or false.",
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

fn png_dimensions(bytes: &[u8]) -> Option<(u32, u32)> {
    let reader = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .ok()?;
    if reader.format() != Some(ImageFormat::Png) {
        return None;
    }
    reader.into_dimensions().ok()
}

fn sanitize_png(bytes: &[u8]) -> Result<Vec<u8>, image::ImageError> {
    let image = image::load_from_memory_with_format(bytes, ImageFormat::Png)?;
    let mut sanitized = Vec::new();
    image.write_to(&mut Cursor::new(&mut sanitized), ImageFormat::Png)?;
    Ok(sanitized)
}

fn valid_texture_dimensions(texture_type: &str, width: u32, height: u32) -> bool {
    width > 0
        && height > 0
        && width % 64 == 0
        && height % 32 == 0
        && match texture_type {
            "steve" => width == height || width == height.saturating_mul(2),
            "alex" => width == height,
            "cape" => width == height.saturating_mul(2),
            _ => false,
        }
}

fn upload_size_error(locale: &str, texture_type: &str, width: u32, height: u32) -> Response {
    let message = if locale.starts_with("zh") {
        let label = if texture_type == "cape" {
            "披风"
        } else {
            "皮肤"
        };
        format!("不是有效的 {label} 文件（宽 {width}，高 {height}）")
    } else {
        let label = if texture_type == "cape" {
            "cape"
        } else {
            "skin"
        };
        format!("Invalid {label} file (width {width}, height {height}).")
    };
    login_result(1, &message, None)
}
async fn upload_texture(
    State(state): State<AppState>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    let Some(database) = &state.database else {
        return unavailable();
    };
    let reporter = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let mut name = None;
    let mut texture_type = None;
    let mut public = None;
    let mut file_bytes = None;
    loop {
        let field = match multipart.next_field().await {
            Ok(Some(field)) => field,
            Ok(None) => break,
            Err(error) => {
                tracing::warn!(%error, "invalid texture upload multipart body");
                return upload_validation_error("file", &state.config.locale);
            }
        };
        let Some(field_name) = field.name().map(str::to_owned) else {
            continue;
        };
        let bytes = match field.bytes().await {
            Ok(bytes) => bytes,
            Err(error) => {
                tracing::warn!(%error, field = field_name, "failed to read texture upload field");
                return upload_validation_error(&field_name, &state.config.locale);
            }
        };
        if field_name == "file" {
            file_bytes = Some(bytes.to_vec());
            continue;
        }
        let Ok(value) = String::from_utf8(bytes.to_vec()) else {
            return upload_validation_error(&field_name, &state.config.locale);
        };
        match field_name.as_str() {
            "name" => name = Some(value),
            "type" => texture_type = Some(value),
            "public" => public = Some(value),
            _ => {}
        }
    }
    let Some(name) = name
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
    else {
        return upload_validation_error("name", &state.config.locale);
    };
    let Some(file_bytes) = file_bytes.filter(|bytes: &Vec<u8>| !bytes.is_empty()) else {
        return upload_validation_error("file", &state.config.locale);
    };
    let Some(texture_type) = texture_type else {
        return upload_validation_error("type", &state.config.locale);
    };
    if !valid_texture_type(&texture_type) {
        return upload_validation_error("type", &state.config.locale);
    }
    let Some(is_public) = public.as_deref().and_then(parse_legacy_form_bool) else {
        return upload_validation_error("public", &state.config.locale);
    };
    let name_rule = match database
        .option(&state.config.database.table_prefix, "texture_name_regexp")
        .await
    {
        Ok(value) => value.unwrap_or_default(),
        Err(error) => {
            tracing::error!(%error, "failed to read texture name validation rule");
            return unavailable();
        }
    };
    if !name_rule.is_empty() {
        if RegexBuilder::new(&name_rule).build().is_err() {
            tracing::error!("invalid legacy texture name validation regex");
            return unavailable();
        }
        if !valid_texture_name(&name, &name_rule) {
            return upload_validation_error("name", &state.config.locale);
        }
    }
    let max_upload_kb = match database
        .option(&state.config.database.table_prefix, "max_upload_file_size")
        .await
    {
        Ok(value) => value
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(1024)
            .max(0),
        Err(error) => {
            tracing::error!(%error, "failed to read maximum texture upload size");
            return unavailable();
        }
    };
    if file_bytes.len() as u64 > max_upload_kb.saturating_mul(1024) as u64 {
        return upload_validation_error("file", &state.config.locale);
    }
    let Some((width, height)) = png_dimensions(&file_bytes) else {
        return upload_validation_error("file", &state.config.locale);
    };
    let max_width = match database
        .option(&state.config.database.table_prefix, "max_texture_width")
        .await
    {
        Ok(value) => value
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(8192),
        Err(error) => {
            tracing::error!(%error, "failed to read maximum texture width");
            return unavailable();
        }
    };
    if width > max_width {
        let message = if state.config.locale.starts_with("zh") {
            format!("材质过宽（{width}px），本站允许的最大宽度为 {max_width}px")
        } else {
            format!("The texture is too wide ({width}px). Maximum width allowed is {max_width}px")
        };
        return login_result(1, &message, None);
    }
    if !valid_texture_dimensions(&texture_type, width, height) {
        return upload_size_error(&state.config.locale, &texture_type, width, height);
    }
    let sanitized = match sanitize_png(&file_bytes) {
        Ok(sanitized) => sanitized,
        Err(error) => {
            tracing::warn!(%error, "failed to decode uploaded PNG texture");
            return upload_validation_error("file", &state.config.locale);
        }
    };
    let hash = Sha256::digest(&sanitized)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let size_kb = ((sanitized.len() as i64).saturating_add(1023) / 1024).max(1);
    let public_cost_per_kb = match database
        .option(&state.config.database.table_prefix, "score_per_storage")
        .await
    {
        Ok(value) => value
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(0),
        Err(error) => {
            tracing::error!(%error, "failed to read public texture storage score");
            return unavailable();
        }
    };
    let private_cost_per_kb = match database
        .option(
            &state.config.database.table_prefix,
            "private_score_per_storage",
        )
        .await
    {
        Ok(value) => value
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(10),
        Err(error) => {
            tracing::error!(%error, "failed to read private texture storage score");
            return unavailable();
        }
    };
    let closet_cost = match database
        .option(&state.config.database.table_prefix, "score_per_closet_item")
        .await
    {
        Ok(value) => value
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(0),
        Err(error) => {
            tracing::error!(%error, "failed to read closet item score");
            return unavailable();
        }
    };
    let award = match database
        .option(
            &state.config.database.table_prefix,
            "score_award_per_texture",
        )
        .await
    {
        Ok(value) => value
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(0),
        Err(error) => {
            tracing::error!(%error, "failed to read texture upload award");
            return unavailable();
        }
    };
    let storage_cost = if is_public {
        public_cost_per_kb
    } else {
        private_cost_per_kb
    };
    let score_cost = size_kb
        .saturating_mul(storage_cost)
        .saturating_add(closet_cost)
        .saturating_sub(award);
    if reporter.score < score_cost {
        return login_result(
            1,
            if state.config.locale.starts_with("zh") {
                "积分不足"
            } else {
                "You don't have enough score to upload this texture."
            },
            None,
        );
    }
    let file_path = state.config.textures_dir.join(&hash);
    let file_was_missing = match tokio::fs::metadata(&file_path).await {
        Ok(_) => false,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
        Err(error) => {
            tracing::error!(%error, hash, "failed to inspect texture file");
            return unavailable();
        }
    };
    if file_was_missing {
        if let Err(error) = tokio::fs::create_dir_all(&state.config.textures_dir).await {
            tracing::error!(%error, "failed to create texture storage directory");
            return unavailable();
        }
        if let Err(error) = tokio::fs::write(&file_path, &sanitized).await {
            tracing::error!(%error, hash, "failed to store sanitized texture file");
            return unavailable();
        }
    }
    match database
        .upload_texture(
            &state.config.database.table_prefix,
            &name,
            &texture_type,
            &hash,
            size_kb,
            reporter.uid,
            is_public,
            score_cost,
        )
        .await
    {
        Ok(crate::database::TextureUploadOutcome::Uploaded(tid)) => {
            let message = if state.config.locale.starts_with("zh") {
                format!("材质 {name} 上传成功")
            } else {
                format!("Texture {name} was uploaded successfully.")
            };
            login_result(0, &message, Some(serde_json::json!({ "tid": tid })))
        }
        Ok(crate::database::TextureUploadOutcome::AlreadyUploaded(tid)) => login_result(
            2,
            if state.config.locale.starts_with("zh") {
                "已经有人上传过这个材质了，直接添加到衣柜使用吧~"
            } else {
                "The texture is already uploaded by someone else. You can add it to your closet directly."
            },
            Some(serde_json::json!({ "tid": tid })),
        ),
        Ok(crate::database::TextureUploadOutcome::InsufficientScore) => {
            cleanup_unreferenced_upload(&state, database, &hash, file_was_missing).await;
            login_result(
                1,
                if state.config.locale.starts_with("zh") {
                    "积分不足"
                } else {
                    "You don't have enough score to upload this texture."
                },
                None,
            )
        }
        Err(error) => {
            tracing::error!(%error, hash, "failed to create uploaded texture record");
            cleanup_unreferenced_upload(&state, database, &hash, file_was_missing).await;
            unavailable()
        }
    }
}

async fn cleanup_unreferenced_upload(
    state: &AppState,
    database: &DatabasePool,
    hash: &str,
    file_was_missing: bool,
) {
    if !file_was_missing {
        return;
    }
    match database
        .texture_hash_reference_count(&state.config.database.table_prefix, hash)
        .await
    {
        Ok(0) => {
            if let Err(error) = tokio::fs::remove_file(state.config.textures_dir.join(hash)).await {
                if error.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(%error, hash, "failed to clean an unreferenced upload file");
                }
            }
        }
        Ok(_) => {}
        Err(error) => tracing::warn!(%error, hash, "failed to check uploaded texture references"),
    }
}

async fn texture_mutation_context(
    state: &AppState,
    headers: &HeaderMap,
    tid_path: &str,
) -> Result<(i64, TextureInfoRecord), Response> {
    let database = state.database.as_ref().ok_or_else(unavailable)?;
    let user = authenticated_web_user(state, headers).await?;
    let tid = tid_path
        .parse::<i64>()
        .map_err(|_| StatusCode::NOT_FOUND.into_response())?;
    let texture = match database
        .texture_info(&state.config.database.table_prefix, tid)
        .await
    {
        Ok(Some(texture)) => texture,
        Ok(None) => return Err(StatusCode::NOT_FOUND.into_response()),
        Err(error) => {
            tracing::error!(%error, tid, "failed to load texture for mutation");
            return Err(unavailable());
        }
    };
    if texture.uploader != user.uid && user.permission < 1 {
        let message = if state.config.locale.starts_with("zh") {
            "你没有权限修改此材质"
        } else {
            "You have no permission to moderate this texture."
        };
        let mut response = login_result(1, message, None);
        *response.status_mut() = StatusCode::FORBIDDEN;
        return Err(response);
    }
    Ok((tid, texture))
}
async fn submit_skinlib_report(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<serde_json::Value>,
) -> Response {
    let Some(database) = &state.database else {
        return unavailable();
    };
    let reporter = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Some(tid) = texture_id_from_request(request.get("tid")) else {
        return report_validation_error("tid", &state.config.locale);
    };
    let Some(reason) = request.get("reason").and_then(serde_json::Value::as_str) else {
        return report_validation_error("reason", &state.config.locale);
    };
    let reason = reason.trim();
    if reason.is_empty() {
        return report_validation_error("reason", &state.config.locale);
    }
    let texture = match database
        .texture_info(&state.config.database.table_prefix, tid)
        .await
    {
        Ok(Some(texture)) => texture,
        Ok(None) => return report_validation_error("tid", &state.config.locale),
        Err(error) => {
            tracing::error!(%error, tid, "failed to load reported texture");
            return unavailable();
        }
    };
    let score_modification = match database
        .option(
            &state.config.database.table_prefix,
            "reporter_score_modification",
        )
        .await
    {
        Ok(value) => value
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(0),
        Err(error) => {
            tracing::error!(%error, "failed to read report score option");
            return unavailable();
        }
    };
    match database
        .submit_report(
            &state.config.database.table_prefix,
            tid,
            texture.uploader,
            reporter.uid,
            reason,
            score_modification,
        )
        .await
    {
        Ok(crate::database::ReportSubmissionOutcome::Submitted) => login_result(
            0,
            if state.config.locale.starts_with("zh") {
                "举报已提交，请等待管理员处理"
            } else {
                "Thanks for reporting! The administrators will review it as soon as possible."
            },
            None,
        ),
        Ok(crate::database::ReportSubmissionOutcome::AlreadyReported) => login_result(
            1,
            if state.config.locale.starts_with("zh") {
                "您已经举报过该材质了，请耐心等待管理员处理。您可以在用户中心查看举报的处理进度。"
            } else {
                "You have already reported this texture. The administrators will review it as soon as possible. You can also track the status of your report at User Center."
            },
            None,
        ),
        Ok(crate::database::ReportSubmissionOutcome::InsufficientScore) => login_result(
            1,
            if state.config.locale.starts_with("zh") {
                "积分不足"
            } else {
                "You don't have enough score to upload this texture."
            },
            None,
        ),
        Err(error) => {
            tracing::error!(%error, tid, "failed to submit skin library report");
            unavailable()
        }
    }
}

fn report_validation_error(field: &str, locale: &str) -> Response {
    let chinese = locale.starts_with("zh");
    let message = if chinese {
        "给定数据无效。"
    } else {
        "The given data was invalid."
    };
    let field_error = match (field, chinese) {
        ("tid", true) => "材质编号必须是存在的整数。",
        ("tid", false) => "The tid field must reference an existing texture.",
        ("reason", true) => "举报理由为必填项。",
        ("reason", false) => "The reason field is required.",
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

fn valid_texture_name(name: &str, rule: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    rule.is_empty()
        || RegexBuilder::new(rule)
            .build()
            .is_ok_and(|regex| regex.is_match(name))
}

fn valid_texture_type(texture_type: &str) -> bool {
    matches!(texture_type, "steve" | "alex" | "cape")
}

async fn rename_texture(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(tid_path): RoutePath<String>,
    Json(request): Json<serde_json::Value>,
) -> Response {
    let (tid, _texture) = match texture_mutation_context(&state, &headers, &tid_path).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let Some(name) = request.get("name").and_then(serde_json::Value::as_str) else {
        return texture_name_validation_error(&state.config.locale);
    };
    let name = name.trim();
    if name.is_empty() {
        return texture_name_validation_error(&state.config.locale);
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    let name_rule = match database
        .option(&state.config.database.table_prefix, "texture_name_regexp")
        .await
    {
        Ok(value) => value.unwrap_or_default(),
        Err(error) => {
            tracing::error!(%error, "failed to read texture name validation rule");
            return unavailable();
        }
    };
    if !name_rule.is_empty() {
        if RegexBuilder::new(&name_rule).build().is_err() {
            tracing::error!("invalid legacy texture name validation regex");
            return unavailable();
        }
        if !valid_texture_name(name, &name_rule) {
            return texture_name_validation_error(&state.config.locale);
        }
    }
    if let Err(error) = database
        .rename_texture(&state.config.database.table_prefix, tid, name)
        .await
    {
        tracing::error!(%error, tid, "failed to rename texture");
        return unavailable();
    }
    let message = if state.config.locale.starts_with("zh") {
        format!("材质名称已被成功设置为 {name}")
    } else {
        format!("The texture was renamed to {name} successfully.")
    };
    login_result(0, &message, None)
}

fn texture_delete_score_refund(
    texture: &TextureInfoRecord,
    return_score: bool,
    public_cost_per_kb: i64,
    private_cost_per_kb: i64,
    public_award: i64,
    take_back_public_award: bool,
) -> i64 {
    let mut refund = if return_score {
        texture.size.saturating_mul(if texture.is_public {
            public_cost_per_kb
        } else {
            private_cost_per_kb
        })
    } else {
        0
    };
    if texture.is_public && take_back_public_award {
        refund = refund.saturating_sub(public_award);
    }
    refund
}

async fn delete_texture(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(tid_path): RoutePath<String>,
) -> Response {
    let (tid, texture) = match texture_mutation_context(&state, &headers, &tid_path).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let return_score = match database
        .option(&state.config.database.table_prefix, "return_score")
        .await
    {
        Ok(value) => value
            .as_deref()
            .map(|value| legacy_option_bool(Some(value)))
            .unwrap_or(true),
        Err(error) => {
            tracing::error!(%error, "failed to read texture deletion score option");
            return unavailable();
        }
    };
    let public_cost_per_kb = match database
        .option(&state.config.database.table_prefix, "score_per_storage")
        .await
    {
        Ok(value) => value
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(0),
        Err(error) => {
            tracing::error!(%error, "failed to read public texture storage score");
            return unavailable();
        }
    };
    let private_cost_per_kb = match database
        .option(
            &state.config.database.table_prefix,
            "private_score_per_storage",
        )
        .await
    {
        Ok(value) => value
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(10),
        Err(error) => {
            tracing::error!(%error, "failed to read private texture storage score");
            return unavailable();
        }
    };
    let public_award = match database
        .option(
            &state.config.database.table_prefix,
            "score_award_per_texture",
        )
        .await
    {
        Ok(value) => value
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(0),
        Err(error) => {
            tracing::error!(%error, "failed to read texture score award");
            return unavailable();
        }
    };
    let take_back_award = match database
        .option(
            &state.config.database.table_prefix,
            "take_back_scores_after_deletion",
        )
        .await
    {
        Ok(value) => value
            .as_deref()
            .map(|value| legacy_option_bool(Some(value)))
            .unwrap_or(true),
        Err(error) => {
            tracing::error!(%error, "failed to read texture score return option");
            return unavailable();
        }
    };
    let closet_score_refund = if return_score {
        match database
            .option(&state.config.database.table_prefix, "score_per_closet_item")
            .await
        {
            Ok(value) => value
                .and_then(|value| value.parse::<i64>().ok())
                .unwrap_or(0),
            Err(error) => {
                tracing::error!(%error, "failed to read closet item score");
                return unavailable();
            }
        }
    } else {
        0
    };
    let uploader_score_refund = texture_delete_score_refund(
        &texture,
        return_score,
        public_cost_per_kb,
        private_cost_per_kb,
        public_award,
        take_back_award,
    );
    let remove_texture_file = match database
        .delete_texture(
            &state.config.database.table_prefix,
            &texture,
            uploader_score_refund,
            closet_score_refund,
        )
        .await
    {
        Ok(remove_texture_file) => remove_texture_file,
        Err(error) => {
            tracing::error!(%error, tid, "failed to delete legacy texture row");
            return unavailable();
        }
    };
    if remove_texture_file && valid_texture_hash(&texture.hash) {
        let path = state.config.textures_dir.join(&texture.hash);
        if let Err(error) = tokio::fs::remove_file(path).await {
            if error.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(%error, hash = texture.hash, "failed to remove texture file");
            }
        }
    }
    login_result(
        0,
        if state.config.locale.starts_with("zh") {
            "材质已被成功删除"
        } else {
            "The texture was deleted successfully."
        },
        None,
    )
}

fn texture_privacy_score_diff(
    texture: &TextureInfoRecord,
    public_cost_per_kb: i64,
    private_cost_per_kb: i64,
    public_award: i64,
    take_back_public_award: bool,
) -> i64 {
    let cost_difference = texture
        .size
        .saturating_mul(private_cost_per_kb.saturating_sub(public_cost_per_kb));
    let mut score_diff = if texture.is_public {
        cost_difference.saturating_neg()
    } else {
        cost_difference
    };
    if texture.is_public && take_back_public_award {
        score_diff = score_diff.saturating_sub(public_award);
    }
    score_diff
}

async fn toggle_texture_privacy(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(tid_path): RoutePath<String>,
) -> Response {
    let (tid, texture) = match texture_mutation_context(&state, &headers, &tid_path).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let public_cost_per_kb = match database
        .option(&state.config.database.table_prefix, "score_per_storage")
        .await
    {
        Ok(value) => value
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(0),
        Err(error) => {
            tracing::error!(%error, "failed to read public texture storage score");
            return unavailable();
        }
    };
    let private_cost_per_kb = match database
        .option(
            &state.config.database.table_prefix,
            "private_score_per_storage",
        )
        .await
    {
        Ok(value) => value
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(10),
        Err(error) => {
            tracing::error!(%error, "failed to read private texture storage score");
            return unavailable();
        }
    };
    let public_award = match database
        .option(
            &state.config.database.table_prefix,
            "score_award_per_texture",
        )
        .await
    {
        Ok(value) => value
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(0),
        Err(error) => {
            tracing::error!(%error, "failed to read texture score award");
            return unavailable();
        }
    };
    let take_back_award = match database
        .option(
            &state.config.database.table_prefix,
            "take_back_scores_after_deletion",
        )
        .await
    {
        Ok(value) => value
            .as_deref()
            .map(|value| legacy_option_bool(Some(value)))
            .unwrap_or(true),
        Err(error) => {
            tracing::error!(%error, "failed to read texture score return option");
            return unavailable();
        }
    };
    let score_diff = texture_privacy_score_diff(
        &texture,
        public_cost_per_kb,
        private_cost_per_kb,
        public_award,
        take_back_award,
    );
    match database
        .toggle_texture_privacy(
            &state.config.database.table_prefix,
            tid,
            texture.uploader,
            &texture.hash,
            texture.is_public,
            score_diff,
        )
        .await
    {
        Ok(crate::database::TexturePrivacyOutcome::Updated { is_public }) => {
            let privacy = if state.config.locale.starts_with("zh") {
                if is_public { "公开" } else { "私密" }
            } else if is_public {
                "Public"
            } else {
                "Private"
            };
            let message = if state.config.locale.starts_with("zh") {
                format!("材质已被设为 {privacy}")
            } else {
                format!("The texture was set to {privacy} successfully.")
            };
            login_result(0, &message, None)
        }
        Ok(crate::database::TexturePrivacyOutcome::DuplicatePublicTexture(duplicate_tid)) => {
            let message = if state.config.locale.starts_with("zh") {
                "已经有人上传过这个材质了，直接添加到衣柜使用吧~"
            } else {
                "The texture is already uploaded by someone else. You can add it to your closet directly."
            };
            login_result(
                2,
                message,
                Some(serde_json::json!({ "tid": duplicate_tid })),
            )
        }
        Ok(crate::database::TexturePrivacyOutcome::InsufficientScore) => login_result(
            1,
            if state.config.locale.starts_with("zh") {
                "积分不足"
            } else {
                "You don't have enough score to upload this texture."
            },
            None,
        ),
        Err(error) => {
            tracing::error!(%error, tid, "failed to update texture privacy");
            unavailable()
        }
    }
}

async fn update_texture_type(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(tid_path): RoutePath<String>,
    Json(request): Json<serde_json::Value>,
) -> Response {
    let (tid, _texture) = match texture_mutation_context(&state, &headers, &tid_path).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let Some(texture_type) = request.get("type").and_then(serde_json::Value::as_str) else {
        return texture_type_validation_error(&state.config.locale);
    };
    if !valid_texture_type(texture_type) {
        return texture_type_validation_error(&state.config.locale);
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    if let Err(error) = database
        .set_texture_type(&state.config.database.table_prefix, tid, texture_type)
        .await
    {
        tracing::error!(%error, tid, "failed to update texture type");
        return unavailable();
    }
    let message = if state.config.locale.starts_with("zh") {
        format!("材质的适用模型已被修改为 {texture_type}")
    } else {
        format!("The texture's model was changed to {texture_type} successfully.")
    };
    login_result(0, &message, None)
}

fn texture_name_validation_error(locale: &str) -> Response {
    let (message, field_error) = if locale.starts_with("zh") {
        ("给定数据无效。", "材质名称为必填项或不符合本站规则。")
    } else {
        (
            "The given data was invalid.",
            "The name field is required or does not match the configured rule.",
        )
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

fn texture_type_validation_error(locale: &str) -> Response {
    let (message, field_error) = if locale.starts_with("zh") {
        ("给定数据无效。", "type 字段必须为 steve、alex 或 cape。")
    } else {
        (
            "The given data was invalid.",
            "The type field must be steve, alex, or cape.",
        )
    };
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(serde_json::json!({
            "message": message,
            "errors": { "type": [field_error] }
        })),
    )
        .into_response()
}
#[derive(Deserialize)]
struct SkinLibraryQuery {
    filter: Option<String>,
    keyword: Option<String>,
    uploader: Option<String>,
    sort: Option<String>,
    page: Option<i64>,
}

async fn skinlib_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SkinLibraryQuery>,
) -> Response {
    let Some(database) = &state.database else {
        return unavailable();
    };
    let session_user_id = session_user_id(&state, &headers);
    let (user_id, is_admin) = match session_user_id {
        Some(user_id) => match database
            .user_profile(&state.config.database.table_prefix, user_id)
            .await
        {
            Ok(Some(user)) => (Some(user_id), user.permission >= 1),
            Ok(None) => (None, false),
            Err(error) => {
                tracing::error!(%error, "failed to load skin library viewer");
                return unavailable();
            }
        },
        None => (None, false),
    };
    let filter = query.filter.as_deref().unwrap_or("skin");
    let keyword = query
        .keyword
        .as_deref()
        .filter(|value| !value.is_empty() && *value != "0");
    let uploader = query
        .uploader
        .as_deref()
        .filter(|value| !value.is_empty() && *value != "0")
        .and_then(|value| value.parse::<i64>().ok());
    let sort = query.sort.as_deref().unwrap_or("time");
    let page = query.page.unwrap_or(1).max(1);
    let per_page = 20_i64;
    match database
        .skinlib_items(
            &state.config.database.table_prefix,
            user_id,
            is_admin,
            filter,
            keyword,
            uploader,
            sort,
            page,
            per_page,
        )
        .await
    {
        Ok((items, total)) => {
            let data = items
                .into_iter()
                .map(skin_library_item_json)
                .collect::<Vec<_>>();
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
            tracing::error!(%error, "failed to query the skin library");
            unavailable()
        }
    }
}

fn skin_library_item_json(item: crate::database::SkinLibraryRecord) -> serde_json::Value {
    serde_json::json!({
        "tid": item.tid,
        "name": item.name,
        "type": item.texture_type,
        "uploader": item.uploader,
        "public": item.is_public,
        "likes": item.likes,
        "nickname": item.nickname,
    })
}

#[derive(Deserialize)]
struct AdminReportListQuery {
    q: Option<String>,
    page: Option<i64>,
}

struct ParsedReportSearch {
    filters: ReportSearchFilters,
    sort_field: String,
    descending: bool,
}

fn parse_report_search(query: Option<&str>) -> ParsedReportSearch {
    let mut parsed = ParsedReportSearch {
        filters: ReportSearchFilters::default(),
        sort_field: "report_at".to_owned(),
        descending: true,
    };
    let mut free_text = Vec::new();
    for token in query.unwrap_or_default().split_whitespace() {
        let Some((field, value)) = token.split_once(':') else {
            free_text.push(token);
            continue;
        };
        match field {
            "sort" => {
                let (descending, field) = value
                    .strip_prefix('-')
                    .map_or((false, value), |field| (true, field));
                if matches!(
                    field,
                    "id" | "tid" | "uploader" | "reporter" | "reason" | "status" | "report_at"
                ) {
                    parsed.sort_field = field.to_owned();
                    parsed.descending = descending;
                }
            }
            "status" => parsed.filters.status = value.parse().ok(),
            "id" => parsed.filters.id = value.parse().ok(),
            "tid" => parsed.filters.tid = value.parse().ok(),
            "uploader" => parsed.filters.uploader = value.parse().ok(),
            "reporter" => parsed.filters.reporter = value.parse().ok(),
            "reason" if !value.is_empty() => free_text.push(value),
            _ => {}
        }
    }
    if !free_text.is_empty() {
        parsed.filters.reason = Some(free_text.join(" "));
    }
    parsed
}

async fn admin_report_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AdminReportListQuery>,
) -> Response {
    let Some(user_id) = session_user_id(&state, &headers) else {
        return Redirect::to("/auth/login").into_response();
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    match database
        .user_profile(&state.config.database.table_prefix, user_id)
        .await
    {
        Ok(Some(user)) if user.permission >= 1 => admin_reports_response(&state, query).await,
        Ok(Some(_)) => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "message": "This action is unauthorized." })),
        )
            .into_response(),
        Ok(None) => Redirect::to("/auth/login").into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to load report administrator");
            unavailable()
        }
    }
}

async fn api_admin_report_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AdminReportListQuery>,
) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_any_scope(&["ReportsManagement.Read", "ReportsManagement.ReadWrite"]) {
        return missing_scope();
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    match database
        .user_profile(&state.config.database.table_prefix, identity.user_id)
        .await
    {
        Ok(Some(user)) if user.permission >= 1 => admin_reports_response(&state, query).await,
        Ok(Some(_)) | Ok(None) => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "message": "This action is unauthorized." })),
        )
            .into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to load API report administrator");
            unavailable()
        }
    }
}

async fn web_review_report(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(id): RoutePath<i64>,
    body: Bytes,
) -> Response {
    let Some(user_id) = session_user_id(&state, &headers) else {
        return Redirect::to("/auth/login").into_response();
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    match database
        .user_profile(&state.config.database.table_prefix, user_id)
        .await
    {
        Ok(Some(user)) if user.permission >= 1 => {
            return review_report_action(&state, id, &body, user.permission).await;
        }
        Ok(Some(_)) => {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({ "message": "This action is unauthorized." })),
            )
                .into_response();
        }
        Ok(None) => return Redirect::to("/auth/login").into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to load report administrator");
            return unavailable();
        }
    }
}

async fn api_review_report(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(id): RoutePath<i64>,
    body: Bytes,
) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_scope("ReportsManagement.ReadWrite") {
        return missing_scope();
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    match database
        .user_profile(&state.config.database.table_prefix, identity.user_id)
        .await
    {
        Ok(Some(user)) if user.permission >= 1 => {
            return review_report_action(&state, id, &body, user.permission).await;
        }
        Ok(Some(_)) | Ok(None) => {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({ "message": "This action is unauthorized." })),
            )
                .into_response();
        }
        Err(error) => {
            tracing::error!(%error, "failed to load API report administrator");
            return unavailable();
        }
    }
}

async fn review_report_action(
    state: &AppState,
    id: i64,
    body: &[u8],
    admin_permission: i32,
) -> Response {
    let request = serde_json::from_slice::<serde_json::Value>(body).ok();
    let Some(action) = request
        .as_ref()
        .and_then(|request| request.get("action"))
        .and_then(serde_json::Value::as_str)
        .filter(|action| matches!(*action, "reject" | "ban" | "delete"))
    else {
        return report_review_validation_error(&state.config.locale);
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let reporter_score_modification = match read_score_option(
        database,
        &state.config.database.table_prefix,
        "reporter_score_modification",
        0,
    )
    .await
    {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(%error, "failed to read report score modifier");
            return unavailable();
        }
    };
    if action == "delete" {
        return delete_reported_texture(state, id, reporter_score_modification).await;
    }
    let outcome = if action == "reject" {
        database
            .reject_report(
                &state.config.database.table_prefix,
                id,
                reporter_score_modification,
            )
            .await
    } else {
        let reporter_reward_score = match database
            .option(&state.config.database.table_prefix, "reporter_reward_score")
            .await
        {
            Ok(value) => value
                .as_deref()
                .and_then(|value| value.parse::<i64>().ok())
                .unwrap_or_default(),
            Err(error) => {
                tracing::error!(%error, "failed to read reporter reward score");
                return unavailable();
            }
        };
        database
            .ban_report_uploader(
                &state.config.database.table_prefix,
                id,
                admin_permission,
                reporter_score_modification,
                reporter_reward_score,
            )
            .await
    };
    match outcome {
        Ok(crate::database::ReportReviewOutcome::Rejected) => report_review_success(state, 2),
        Ok(crate::database::ReportReviewOutcome::Resolved) => report_review_success(state, 1),
        Ok(crate::database::ReportReviewOutcome::UploaderNotFound) => {
            let message = if state.config.locale.starts_with("zh") {
                "用户不存在"
            } else {
                "No such user."
            };
            login_result(1, message, None)
        }
        Ok(crate::database::ReportReviewOutcome::UploaderPermissionDenied) => {
            let message = if state.config.locale.starts_with("zh") {
                "你无权操作此用户"
            } else {
                "You have no permission to operate this user."
            };
            login_result(1, message, None)
        }
        Ok(crate::database::ReportReviewOutcome::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, report_id = id, "failed to review report");
            unavailable()
        }
    }
}

fn report_review_success(state: &AppState, status: i32) -> Response {
    let message = if state.config.locale.starts_with("zh") {
        "操作成功"
    } else {
        "Operated successfully."
    };
    login_result(0, message, Some(serde_json::json!({ "status": status })))
}

fn report_review_validation_error(locale: &str) -> Response {
    let chinese = locale.starts_with("zh");
    let message = if chinese {
        "给定数据无效。"
    } else {
        "The given data was invalid."
    };
    let field_error = if chinese {
        "所选操作无效。"
    } else {
        "The selected action is invalid."
    };
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(serde_json::json!({
            "message": message,
            "errors": { "action": [field_error] }
        })),
    )
        .into_response()
}

async fn delete_reported_texture(
    state: &AppState,
    report_id: i64,
    reporter_score_modification: i64,
) -> Response {
    let Some(database) = &state.database else {
        return unavailable();
    };
    let filters = ReportSearchFilters {
        id: Some(report_id),
        ..Default::default()
    };
    let mut reports = match database
        .report_management_items(
            &state.config.database.table_prefix,
            &filters,
            "report_at",
            true,
            1,
            1,
        )
        .await
    {
        Ok((reports, _)) => reports,
        Err(error) => {
            tracing::error!(%error, report_id, "failed to load report for texture deletion");
            return unavailable();
        }
    };
    let Some(report) = reports.pop() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let texture = if let Some(tid) = report.texture_tid {
        match database
            .texture_info(&state.config.database.table_prefix, tid)
            .await
        {
            Ok(texture) => texture,
            Err(error) => {
                tracing::error!(%error, tid, "failed to load texture reported for deletion");
                return unavailable();
            }
        }
    } else {
        None
    };
    let Some(texture) = texture else {
        return match database
            .resolve_report_without_texture(
                &state.config.database.table_prefix,
                report_id,
                reporter_score_modification,
            )
            .await
        {
            Ok(crate::database::ReportReviewOutcome::Resolved) => login_result(
                0,
                if state.config.locale.starts_with("zh") {
                    "请求的材质已被删除"
                } else {
                    "The requested texture has been deleted."
                },
                Some(serde_json::json!({ "status": 1 })),
            ),
            Ok(crate::database::ReportReviewOutcome::NotFound) => {
                StatusCode::NOT_FOUND.into_response()
            }
            Ok(_) => unreachable!("missing texture resolution has no other outcome"),
            Err(error) => {
                tracing::error!(%error, report_id, "failed to resolve report with deleted texture");
                unavailable()
            }
        };
    };
    let prefix = &state.config.database.table_prefix;
    let return_score = match read_bool_option(database, prefix, "return_score", true).await {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(%error, "failed to read texture score return option");
            return unavailable();
        }
    };
    let public_cost = match read_score_option(database, prefix, "score_per_storage", 0).await {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(%error, "failed to read public texture storage score");
            return unavailable();
        }
    };
    let private_cost =
        match read_score_option(database, prefix, "private_score_per_storage", 10).await {
            Ok(value) => value,
            Err(error) => {
                tracing::error!(%error, "failed to read private texture storage score");
                return unavailable();
            }
        };
    let public_award = match read_score_option(database, prefix, "score_award_per_texture", 0).await
    {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(%error, "failed to read texture score award");
            return unavailable();
        }
    };
    let take_back_award =
        match read_bool_option(database, prefix, "take_back_scores_after_deletion", true).await {
            Ok(value) => value,
            Err(error) => {
                tracing::error!(%error, "failed to read texture award return option");
                return unavailable();
            }
        };
    let closet_refund = if return_score {
        match read_score_option(database, prefix, "score_per_closet_item", 0).await {
            Ok(value) => value,
            Err(error) => {
                tracing::error!(%error, "failed to read closet item score");
                return unavailable();
            }
        }
    } else {
        0
    };
    let reporter_reward = if report.status == 0 {
        match read_score_option(database, prefix, "reporter_reward_score", 0).await {
            Ok(value) => value,
            Err(error) => {
                tracing::error!(%error, "failed to read reporter reward score");
                return unavailable();
            }
        }
    } else {
        0
    };
    let reporter_adjustment = if report.status == 0 {
        reporter_score_modification
            .min(0)
            .saturating_neg()
            .saturating_add(reporter_reward)
    } else {
        0
    };
    let uploader_refund = texture_delete_score_refund(
        &texture,
        return_score,
        public_cost,
        private_cost,
        public_award,
        take_back_award,
    );
    let remove_texture_file = match database
        .delete_reported_texture(
            prefix,
            &texture,
            report_id,
            reporter_adjustment,
            uploader_refund,
            closet_refund,
        )
        .await
    {
        Ok(crate::database::TextureDeleteOutcome::Deleted(remove_file)) => remove_file,
        Ok(crate::database::TextureDeleteOutcome::ReportNotFound) => {
            return StatusCode::NOT_FOUND.into_response();
        }
        Err(error) => {
            tracing::error!(%error, tid = texture.tid, report_id, "failed to delete reported texture");
            return unavailable();
        }
    };
    if remove_texture_file && valid_texture_hash(&texture.hash) {
        let file_path = state.config.textures_dir.join(&texture.hash);
        if let Err(error) = tokio::fs::remove_file(file_path).await {
            if error.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(%error, hash = texture.hash, "failed to remove reported texture file");
            }
        }
    }
    report_review_success(state, 1)
}

async fn read_score_option(
    database: &DatabasePool,
    prefix: &str,
    name: &str,
    default: i64,
) -> Result<i64, sqlx::Error> {
    Ok(database
        .option(prefix, name)
        .await?
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(default))
}

async fn read_bool_option(
    database: &DatabasePool,
    prefix: &str,
    name: &str,
    default: bool,
) -> Result<bool, sqlx::Error> {
    Ok(database
        .option(prefix, name)
        .await?
        .as_deref()
        .map(|value| parse_legacy_form_bool(value).unwrap_or(false))
        .unwrap_or(default))
}

async fn admin_reports_response(state: &AppState, query: AdminReportListQuery) -> Response {
    let Some(database) = &state.database else {
        return unavailable();
    };
    let parsed = parse_report_search(query.q.as_deref());
    let page = query.page.unwrap_or(1).max(1);
    const PER_PAGE: i64 = 9;
    match database
        .report_management_items(
            &state.config.database.table_prefix,
            &parsed.filters,
            &parsed.sort_field,
            parsed.descending,
            page,
            PER_PAGE,
        )
        .await
    {
        Ok((reports, total)) => {
            let data = reports
                .into_iter()
                .map(report_management_json)
                .collect::<Vec<_>>();
            let last_page = total.saturating_add(PER_PAGE - 1) / PER_PAGE;
            let offset = page.saturating_sub(1).saturating_mul(PER_PAGE);
            let from = (!data.is_empty()).then_some(offset + 1);
            let to = (!data.is_empty()).then_some(offset + data.len() as i64);
            Json(serde_json::json!({
                "current_page": page,
                "data": data,
                "last_page": last_page.max(1),
                "per_page": PER_PAGE,
                "from": from,
                "to": to,
                "total": total
            }))
            .into_response()
        }
        Err(error) => {
            tracing::error!(%error, "failed to query admin reports");
            unavailable()
        }
    }
}

fn report_management_json(report: ReportManagementRecord) -> serde_json::Value {
    let texture = report.texture_tid.map(|tid| {
        serde_json::json!({
            "tid": tid,
            "name": report.texture_name,
            "type": report.texture_type,
            "hash": report.texture_hash,
            "size": report.texture_size,
            "uploader": report.texture_uploader,
            "public": report.texture_public,
            "upload_at": report.texture_upload_at,
            "likes": report.texture_likes,
        })
    });
    let texture_uploader = report.texture_uploader_uid.map(|uid| {
        serde_json::json!({
            "uid": uid,
            "email": report.texture_uploader_email,
            "nickname": report.texture_uploader_nickname,
            "locale": report.texture_uploader_locale,
            "score": report.texture_uploader_score,
            "avatar": report.texture_uploader_avatar,
            "permission": report.texture_uploader_permission,
            "ip": report.texture_uploader_ip,
            "last_sign_at": report.texture_uploader_last_sign_at,
            "register_at": report.texture_uploader_register_at,
            "verified": report.texture_uploader_verified,
            "is_dark_mode": report.texture_uploader_is_dark_mode,
        })
    });
    let informer = report.informer_uid.map(|uid| {
        serde_json::json!({
            "uid": uid,
            "email": report.informer_email,
            "nickname": report.informer_nickname,
            "locale": report.informer_locale,
            "score": report.informer_score,
            "avatar": report.informer_avatar,
            "permission": report.informer_permission,
            "ip": report.informer_ip,
            "last_sign_at": report.informer_last_sign_at,
            "register_at": report.informer_register_at,
            "verified": report.informer_verified,
            "is_dark_mode": report.informer_is_dark_mode,
        })
    });
    serde_json::json!({
        "id": report.id,
        "tid": report.tid,
        "texture": texture,
        "uploader": report.uploader,
        "texture_uploader": texture_uploader,
        "reporter": report.reporter,
        "informer": informer,
        "reason": report.reason,
        "status": report.status,
        "report_at": report.report_at,
    })
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
    fn validates_legacy_texture_name_rules() {
        assert!(super::valid_texture_name("skin_01", ""));
        assert!(!super::valid_texture_name("", ""));
        assert!(super::valid_texture_name("skin_01", "^[a-z0-9_]+$"));
        assert!(!super::valid_texture_name("Skin 01", "^[a-z0-9_]+$"));
        assert!(!super::valid_texture_name("anything", "["));
    }

    #[test]
    fn parses_legacy_admin_report_search_tokens() {
        let parsed =
            super::parse_report_search(Some("status:0 sort:-report_at tid:41 stolen skin"));
        assert_eq!(parsed.filters.status, Some(0));
        assert_eq!(parsed.filters.tid, Some(41));
        assert_eq!(parsed.filters.reason.as_deref(), Some("stolen skin"));
        assert_eq!(parsed.sort_field, "report_at");
        assert!(parsed.descending);

        let parsed = super::parse_report_search(None);
        assert_eq!(parsed.sort_field, "report_at");
        assert!(parsed.descending);
        assert!(parsed.filters.status.is_none());
    }

    #[test]
    fn serializes_legacy_admin_report_list_fields() {
        let report = super::report_management_json(crate::database::ReportManagementRecord {
            id: 5,
            tid: 41,
            uploader: 7,
            reporter: 8,
            reason: "stolen skin".to_owned(),
            status: 0,
            report_at: "2026-10-02 14:00:00".to_owned(),
            texture_tid: Some(41),
            texture_name: Some("Skin".to_owned()),
            texture_type: Some("alex".to_owned()),
            texture_hash: Some("skin-hash".to_owned()),
            texture_size: Some(8),
            texture_uploader: Some(7),
            texture_public: Some(true),
            texture_upload_at: Some("2026-10-01 10:00:00".to_owned()),
            texture_likes: Some(1),
            texture_uploader_uid: Some(7),
            texture_uploader_email: Some("alex@example.test".to_owned()),
            texture_uploader_nickname: Some("Alex User".to_owned()),
            texture_uploader_locale: Some("zh_CN".to_owned()),
            texture_uploader_score: Some(42),
            texture_uploader_avatar: Some(11),
            texture_uploader_permission: Some(0),
            texture_uploader_ip: Some("192.0.2.1".to_owned()),
            texture_uploader_last_sign_at: Some("2026-10-01 10:00:00".to_owned()),
            texture_uploader_register_at: Some("2025-01-02 03:04:05".to_owned()),
            texture_uploader_verified: Some(true),
            texture_uploader_is_dark_mode: Some(false),
            informer_uid: Some(8),
            informer_email: Some("admin@example.test".to_owned()),
            informer_nickname: Some("Admin".to_owned()),
            informer_locale: Some("en".to_owned()),
            informer_score: Some(50),
            informer_avatar: Some(0),
            informer_permission: Some(1),
            informer_ip: Some("192.0.2.2".to_owned()),
            informer_last_sign_at: Some(String::new()),
            informer_register_at: Some(String::new()),
            informer_verified: Some(true),
            informer_is_dark_mode: Some(false),
        });
        assert_eq!(report["id"], 5);
        assert_eq!(report["tid"], 41);
        assert_eq!(report["texture"]["type"], "alex");
        assert_eq!(report["texture_uploader"]["nickname"], "Alex User");
        assert_eq!(report["texture_uploader"]["ip"], "192.0.2.1");
        assert_eq!(report["informer"]["uid"], 8);
        assert_eq!(report["informer"]["email"], "admin@example.test");
        assert_eq!(report["reason"], "stolen skin");
    }

    #[tokio::test]
    async fn formats_report_review_validation_errors_by_action() {
        use axum::body::to_bytes;

        let response = super::report_review_validation_error("en");
        assert_eq!(
            response.status(),
            axum::http::StatusCode::UNPROCESSABLE_ENTITY
        );
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(value["errors"]["action"][0].as_str().is_some());
    }

    #[tokio::test]
    async fn formats_report_validation_errors_by_field() {
        use axum::body::to_bytes;

        let response = super::report_validation_error("reason", "en");
        assert_eq!(
            response.status(),
            axum::http::StatusCode::UNPROCESSABLE_ENTITY
        );
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(value["errors"]["reason"][0].as_str().is_some());
        assert!(value["errors"]["field"].is_null());
    }
    #[test]
    fn sanitizes_png_uploads_and_checks_skin_dimensions() {
        use image::ImageFormat;
        use std::io::Cursor;

        let mut encoded = Vec::new();
        image::DynamicImage::new_rgba8(64, 32)
            .write_to(&mut Cursor::new(&mut encoded), ImageFormat::Png)
            .unwrap();
        assert_eq!(super::png_dimensions(&encoded), Some((64, 32)));
        assert!(super::valid_texture_dimensions("steve", 64, 32));
        assert!(!super::valid_texture_dimensions("alex", 64, 32));
        assert!(super::valid_texture_dimensions("alex", 64, 64));
        assert!(super::valid_texture_dimensions("cape", 64, 32));
        assert!(!super::valid_texture_dimensions("steve", 63, 32));
        let sanitized = super::sanitize_png(&encoded).unwrap();
        assert_eq!(super::png_dimensions(&sanitized), Some((64, 32)));
        assert!(super::png_dimensions(b"not an image").is_none());
    }

    #[test]
    fn parses_legacy_multipart_boolean_values() {
        assert_eq!(super::parse_legacy_form_bool("1"), Some(true));
        assert_eq!(super::parse_legacy_form_bool("true"), Some(true));
        assert_eq!(super::parse_legacy_form_bool("0"), Some(false));
        assert_eq!(super::parse_legacy_form_bool("false"), Some(false));
        assert_eq!(super::parse_legacy_form_bool("maybe"), None);
    }

    #[test]
    fn calculates_legacy_texture_deletion_score_refunds() {
        let texture = crate::database::TextureInfoRecord {
            tid: 1,
            name: "Public".to_owned(),
            texture_type: "alex".to_owned(),
            hash: "hash".to_owned(),
            size: 4,
            uploader: 7,
            is_public: true,
            upload_at: String::new(),
            likes: 0,
        };
        assert_eq!(
            super::texture_delete_score_refund(&texture, true, 0, 10, 3, true),
            -3
        );
        assert_eq!(
            super::texture_delete_score_refund(&texture, true, 0, 10, 3, false),
            0
        );
        assert_eq!(
            super::texture_delete_score_refund(&texture, false, 0, 10, 3, true),
            -3
        );
    }

    #[test]
    fn calculates_legacy_texture_privacy_score_changes() {
        let public_texture = crate::database::TextureInfoRecord {
            tid: 1,
            name: "Public".to_owned(),
            texture_type: "alex".to_owned(),
            hash: "hash".to_owned(),
            size: 4,
            uploader: 7,
            is_public: true,
            upload_at: String::new(),
            likes: 0,
        };
        assert_eq!(
            super::texture_privacy_score_diff(&public_texture, 0, 10, 3, true),
            -43
        );
        assert_eq!(
            super::texture_privacy_score_diff(&public_texture, 0, 10, 3, false),
            -40
        );
        let private_texture = crate::database::TextureInfoRecord {
            is_public: false,
            ..public_texture
        };
        assert_eq!(
            super::texture_privacy_score_diff(&private_texture, 0, 10, 3, true),
            40
        );
    }

    #[test]
    fn validates_legacy_texture_types() {
        assert!(super::valid_texture_type("steve"));
        assert!(super::valid_texture_type("alex"));
        assert!(super::valid_texture_type("cape"));
        assert!(!super::valid_texture_type("slim"));
        assert!(!super::valid_texture_type("Cape"));
    }

    #[test]
    fn serializes_legacy_texture_info_fields() {
        use serde_json::json;

        let texture = super::texture_info_json(crate::database::TextureInfoRecord {
            tid: 13,
            name: "Other skin".to_owned(),
            texture_type: "alex".to_owned(),
            hash: "texture-hash".to_owned(),
            size: 10,
            uploader: 8,
            is_public: true,
            upload_at: "2026-10-01 10:02:00".to_owned(),
            likes: 2,
        });
        assert_eq!(
            texture,
            json!({
                "tid": 13,
                "name": "Other skin",
                "type": "alex",
                "hash": "texture-hash",
                "size": 10,
                "uploader": 8,
                "public": true,
                "upload_at": "2026-10-01 10:02:00",
                "likes": 2
            })
        );
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
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/user")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let report_response = app
            .oneshot(
                Request::builder()
                    .uri("/api/admin/reports")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(report_response.status(), StatusCode::UNAUTHORIZED);
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
        sqlx::query("CREATE TABLE users (uid INTEGER PRIMARY KEY, email TEXT NOT NULL, nickname TEXT NOT NULL, locale TEXT, score INTEGER NOT NULL, avatar INTEGER NOT NULL, password TEXT NOT NULL, ip TEXT NOT NULL DEFAULT '', permission INTEGER NOT NULL, last_sign_at TEXT NOT NULL, register_at TEXT NOT NULL, verified BOOLEAN NOT NULL, is_dark_mode BOOLEAN NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE players (pid INTEGER PRIMARY KEY, uid INTEGER NOT NULL, name TEXT NOT NULL, tid_skin INTEGER NOT NULL, tid_cape INTEGER NOT NULL, last_modified TEXT NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE textures (tid INTEGER PRIMARY KEY, name TEXT NOT NULL, type TEXT NOT NULL, hash TEXT NOT NULL, size INTEGER NOT NULL, uploader INTEGER NOT NULL, public BOOLEAN NOT NULL, upload_at TEXT NOT NULL, likes INTEGER NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE reports (id INTEGER PRIMARY KEY AUTOINCREMENT, tid INTEGER NOT NULL, uploader INTEGER NOT NULL, reporter INTEGER NOT NULL, reason TEXT NOT NULL, status INTEGER NOT NULL, report_at TEXT NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE user_closet (user_uid INTEGER NOT NULL, texture_tid INTEGER NOT NULL, item_name TEXT NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE options (id INTEGER PRIMARY KEY AUTOINCREMENT, option_name TEXT NOT NULL, option_value TEXT NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE oauth_clients (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, name TEXT NOT NULL, secret TEXT NOT NULL, provider TEXT, redirect TEXT NOT NULL, personal_access_client BOOLEAN NOT NULL, password_client BOOLEAN NOT NULL, revoked BOOLEAN NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE oauth_access_tokens (id TEXT PRIMARY KEY, user_id INTEGER, client_id INTEGER NOT NULL, scopes TEXT NOT NULL, revoked BOOLEAN NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE oauth_refresh_tokens (id TEXT PRIMARY KEY, access_token_id TEXT NOT NULL, revoked BOOLEAN NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE oauth_auth_codes (id TEXT PRIMARY KEY, user_id INTEGER, client_id INTEGER NOT NULL, scopes TEXT NOT NULL, revoked BOOLEAN NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        let password_hash = bcrypt::hash("correct horse", 4).unwrap();
        sqlx::query("INSERT INTO users (uid,email,nickname,locale,score,avatar,password,permission,last_sign_at,register_at,verified,is_dark_mode) VALUES (7,'alex@example.test','Alex User','en',5,0,?,1,'','',1,0)")
            .bind(password_hash)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO users (uid,email,nickname,locale,score,avatar,password,permission,last_sign_at,register_at,verified,is_dark_mode) VALUES (8,'uploader@example.test','Uploader','en',20,0,'',0,'','',1,0)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO players (pid,uid,name,tid_skin,tid_cape,last_modified) VALUES (3,7,'Alex',0,0,'2026-10-02 12:00:00')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO textures (tid,name,type,hash,size,uploader,public,upload_at,likes) VALUES (2,'Reported skin','alex','reported-hash',8,7,1,'2026-10-01 10:00:00',1)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO reports (id,tid,uploader,reporter,reason,status,report_at) VALUES (1,2,7,7,'stolen skin',0,'2026-10-02 14:00:00'), (2,2,8,7,'second report',0,'2026-10-02 15:00:00'), (3,2,7,7,'third report',0,'2026-10-02 13:00:00'), (4,99,8,7,'texture already deleted',0,'2026-10-02 12:00:00')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO options (option_name,option_value) VALUES ('reporter_score_modification','2'), ('reporter_reward_score','3')")
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
            database: Some(crate::database::DatabasePool::Sqlite(pool.clone())),
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
                    .header("cookie", cookie.clone())
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

        let clients_before = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/oauth/clients")
                    .header("cookie", cookie.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(clients_before.status(), StatusCode::OK);
        let clients_before: serde_json::Value = serde_json::from_slice(
            &to_bytes(clients_before.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(clients_before, serde_json::json!([]));

        let created_client = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth/clients")
                    .header("cookie", cookie.clone())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"name":"Desktop app","redirect":"https://client.test/callback"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(created_client.status(), StatusCode::OK);
        let created_client: serde_json::Value = serde_json::from_slice(
            &to_bytes(created_client.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let client_id = created_client["id"].as_i64().unwrap();
        let client_secret = created_client["secret"].as_str().unwrap();
        assert_eq!(client_secret.len(), 40);
        assert!(client_secret.chars().all(|ch| ch.is_ascii_alphanumeric()));
        assert_eq!(created_client["name"], "Desktop app");
        assert_eq!(created_client["redirect"], "https://client.test/callback");

        let updated_client = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/oauth/clients/{client_id}"))
                    .header("cookie", cookie.clone())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"name":"Updated app","redirect":"https://client.test/return"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(updated_client.status(), StatusCode::OK);
        let updated_client: serde_json::Value = serde_json::from_slice(
            &to_bytes(updated_client.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(updated_client["name"], "Updated app");
        assert_eq!(updated_client["secret"], client_secret);
        assert_eq!(updated_client["redirect"], "https://client.test/return");

        sqlx::query("INSERT INTO oauth_access_tokens (id,user_id,client_id,scopes,revoked) VALUES ('issued-access',7,?,'User.Read',0)")
            .bind(client_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO oauth_refresh_tokens (id,access_token_id,revoked) VALUES ('issued-refresh','issued-access',0)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO oauth_auth_codes (id,user_id,client_id,scopes,revoked) VALUES ('issued-code',7,?,'User.Read',0)")
            .bind(client_id)
            .execute(&pool)
            .await
            .unwrap();
        let deleted_client = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/oauth/clients/{client_id}"))
                    .header("cookie", cookie.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(deleted_client.status(), StatusCode::NO_CONTENT);
        for query in [
            "SELECT revoked FROM oauth_clients WHERE id = ?",
            "SELECT revoked FROM oauth_access_tokens WHERE id = 'issued-access'",
            "SELECT revoked FROM oauth_refresh_tokens WHERE id = 'issued-refresh'",
            "SELECT revoked FROM oauth_auth_codes WHERE id = 'issued-code'",
        ] {
            let revoked: bool = if query.contains("id = ?") {
                sqlx::query_scalar(query)
                    .bind(client_id)
                    .fetch_one(&pool)
                    .await
                    .unwrap()
            } else {
                sqlx::query_scalar(query).fetch_one(&pool).await.unwrap()
            };
            assert!(revoked, "expected revocation for {query}");
        }
        let clients_after = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/oauth/clients")
                    .header("cookie", cookie.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(clients_after.status(), StatusCode::OK);
        let clients_after: serde_json::Value = serde_json::from_slice(
            &to_bytes(clients_after.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(clients_after, serde_json::json!([]));

        let reports = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/admin/reports/list?q=status%3A0%20sort%3A-report_at")
                    .header("cookie", cookie.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(reports.status(), StatusCode::OK);
        let report_page = to_bytes(reports.into_body(), usize::MAX).await.unwrap();
        let report_page: serde_json::Value = serde_json::from_slice(&report_page).unwrap();
        assert_eq!(report_page["current_page"], 1);
        assert_eq!(report_page["last_page"], 1);
        assert_eq!(report_page["total"], 4);
        assert_eq!(report_page["data"][0]["tid"], 2);
        assert_eq!(report_page["data"][0]["texture"]["hash"], "reported-hash");
        assert_eq!(report_page["data"][0]["informer"]["ip"], "");

        let rejected = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/admin/reports/1")
                    .header("cookie", cookie.clone())
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"action":"reject"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rejected.status(), StatusCode::OK);
        let rejected_body = to_bytes(rejected.into_body(), usize::MAX).await.unwrap();
        let rejected_body: serde_json::Value = serde_json::from_slice(&rejected_body).unwrap();
        assert_eq!(rejected_body["code"], 0);
        assert_eq!(rejected_body["data"]["status"], 2);
        let score: i64 = sqlx::query_scalar("SELECT score FROM users WHERE uid = 7")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(score, 3);
        let report_status: i64 = sqlx::query_scalar("SELECT status FROM reports WHERE id = 1")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(report_status, 2);

        let banned = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/admin/reports/2")
                    .header("cookie", cookie.clone())
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"action":"ban"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(banned.status(), StatusCode::OK);
        let banned_body = to_bytes(banned.into_body(), usize::MAX).await.unwrap();
        let banned_body: serde_json::Value = serde_json::from_slice(&banned_body).unwrap();
        assert_eq!(banned_body["code"], 0);
        assert_eq!(banned_body["data"]["status"], 1);
        let uploader_permission: i64 =
            sqlx::query_scalar("SELECT permission FROM users WHERE uid = 8")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(uploader_permission, -1);
        let rewarded_score: i64 = sqlx::query_scalar("SELECT score FROM users WHERE uid = 7")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(rewarded_score, 6);

        let deleted = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/admin/reports/3")
                    .header("cookie", cookie.clone())
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"action":"delete"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(deleted.status(), StatusCode::OK);
        let deleted_body = to_bytes(deleted.into_body(), usize::MAX).await.unwrap();
        let deleted_body: serde_json::Value = serde_json::from_slice(&deleted_body).unwrap();
        assert_eq!(deleted_body["code"], 0);
        assert_eq!(deleted_body["data"]["status"], 1);
        let texture_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM textures WHERE tid = 2")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(texture_count, 0);
        let deletion_report_status: i64 =
            sqlx::query_scalar("SELECT status FROM reports WHERE id = 3")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(deletion_report_status, 1);
        let final_reporter_score: i64 = sqlx::query_scalar("SELECT score FROM users WHERE uid = 7")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(final_reporter_score, 9);

        let missing_texture_report = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/admin/reports/4")
                    .header("cookie", cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"action":"delete"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing_texture_report.status(), StatusCode::OK);
        let missing_body = to_bytes(missing_texture_report.into_body(), usize::MAX)
            .await
            .unwrap();
        let missing_body: serde_json::Value = serde_json::from_slice(&missing_body).unwrap();
        assert_eq!(missing_body["code"], 0);
        assert_eq!(
            missing_body["message"],
            "The requested texture has been deleted."
        );
        assert_eq!(missing_body["data"]["status"], 1);
        let final_reporter_score: i64 = sqlx::query_scalar("SELECT score FROM users WHERE uid = 7")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(final_reporter_score, 9);

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
