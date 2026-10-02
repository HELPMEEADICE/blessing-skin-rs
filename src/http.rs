use std::{
    collections::BTreeMap,
    time::{Duration, Instant, SystemTime},
};

use askama::Template;
use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{Path as RoutePath, State},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{
            CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, ETAG, IF_MODIFIED_SINCE,
            IF_NONE_MATCH, LAST_MODIFIED, SET_COOKIE,
        },
    },
    response::{Html, IntoResponse, Redirect, Response},
    routing::{any, get, post},
};
use chrono::{FixedOffset, NaiveDateTime, TimeZone};
use jsonwebtoken::{Algorithm, Header, encode};
use md5::{Digest, Md5};
use pulldown_cmark::{Options, Parser, html as markdown_html};
use serde::{Deserialize, Serialize};

use crate::{
    AppState,
    auth::{audience_matches, bearer_token, decode_access_token, decode_web_session},
    database::{DatabasePool, NotificationRecord, PlayerProfile, PlayerRecord, UserProfile},
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
        .route("/api/user/notifications", get(api_user_notifications))
        .route("/api/user/notifications/{id}", post(api_read_notification))
        .route("/api/players", get(api_players))
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
}
