use std::{
    collections::{BTreeMap, HashMap},
    io::Cursor,
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use askama::Template;
use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{
        DefaultBodyLimit, FromRequestParts, Multipart, OriginalUri, Path as RoutePath, Query,
        RawQuery, State,
    },
    http::{
        HeaderMap, HeaderValue, Method, StatusCode,
        header::{
            CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, ETAG, IF_MODIFIED_SINCE,
            IF_NONE_MATCH, LAST_MODIFIED, LOCATION, SET_COOKIE,
        },
        request::Parts,
    },
    response::{Html, IntoResponse, Redirect, Response},
    routing::{any, delete, get, post, put},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{FixedOffset, NaiveDateTime, TimeZone};
use fancy_regex::{BytesMode, RegexBuilder as FancyRegexBuilder};
use hmac::{Hmac, Mac};
use image::{DynamicImage, ImageFormat, ImageReader, Rgb, RgbImage, Rgba, RgbaImage};
use jsonwebtoken::{Algorithm, Header, encode};
use md5::{Digest, Md5};
use pulldown_cmark::{Options, Parser, html as markdown_html};
use rand::{
    Rng,
    distributions::{Alphanumeric, DistString},
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::{
    AppState,
    auth::{
        WebSessionClaims, audience_matches, bearer_token, decode_access_token, decode_web_session,
        hash_legacy_password, verify_legacy_password,
    },
    database::{
        AdminDashboardStats, AdminUserRecord, ClosetTextureRecord, DatabasePool,
        LanguageLineRecord, NotificationRecord, PlayerProfile, PlayerRecord, PlayerRenameOutcome,
        PlayerTextureOutcome, ReportManagementRecord, ReportSearchFilters, TextureInfoRecord,
        UserProfile,
    },
    image_cache::{CachedImage, ImageCacheKey},
};

const LEGACY_API_RATE_LIMIT: u64 = 60;
const LEGACY_API_RATE_WINDOW: Duration = Duration::from_secs(60);
const LEGACY_REMEMBER_TTL_SECONDS: u64 = 576_000 * 60;

#[derive(Clone, Default)]
struct ApiRateLimiter {
    state: Arc<std::sync::Mutex<ApiRateLimiterState>>,
}

#[derive(Default)]
struct ApiRateLimiterState {
    windows: HashMap<String, ApiRateWindow>,
    requests_since_sweep: u64,
}

struct ApiRateWindow {
    reset_at: Instant,
    attempts: u64,
}

#[derive(Clone, Copy)]
struct ApiRateDecision {
    allowed: bool,
    remaining: u64,
    retry_after: Duration,
}

impl ApiRateLimiter {
    fn hit(&self, key: String, now: Instant) -> ApiRateDecision {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.requests_since_sweep = state.requests_since_sweep.saturating_add(1);
        if state.requests_since_sweep >= 64 {
            state.windows.retain(|_, window| window.reset_at > now);
            state.requests_since_sweep = 0;
        }
        let window = state.windows.entry(key).or_insert_with(|| ApiRateWindow {
            reset_at: now + LEGACY_API_RATE_WINDOW,
            attempts: 0,
        });
        if now >= window.reset_at {
            window.reset_at = now + LEGACY_API_RATE_WINDOW;
            window.attempts = 0;
        }
        if window.attempts >= LEGACY_API_RATE_LIMIT {
            return ApiRateDecision {
                allowed: false,
                remaining: 0,
                retry_after: window.reset_at.saturating_duration_since(now),
            };
        }
        window.attempts += 1;
        ApiRateDecision {
            allowed: true,
            remaining: LEGACY_API_RATE_LIMIT - window.attempts,
            retry_after: window.reset_at.saturating_duration_since(now),
        }
    }
}

// Keep malformed IDs from short-circuiting legacy authentication and authorization checks.
#[derive(Clone, Copy)]
struct LegacyRouteId(i64);

impl<S> FromRequestParts<S> for LegacyRouteId
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let id = match RoutePath::<i64>::from_request_parts(parts, state).await {
            Ok(RoutePath(id)) => id,
            Err(_) => i64::MIN,
        };
        Ok(Self(id))
    }
}

#[derive(Clone)]
struct ApiRateThrottleState {
    passport_key: Option<jsonwebtoken::DecodingKey>,
    limiter: ApiRateLimiter,
}

fn legacy_api_throttle_layer<S>(
    app: Router<S>,
    passport_key: Option<jsonwebtoken::DecodingKey>,
) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    app.layer(axum::middleware::from_fn_with_state(
        ApiRateThrottleState {
            passport_key,
            limiter: ApiRateLimiter::default(),
        },
        legacy_api_throttle,
    ))
}

async fn legacy_api_throttle(
    State(state): State<ApiRateThrottleState>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let path = request.uri().path();
    if path != "/api" && !path.starts_with("/api/") {
        return next.run(request).await;
    }
    let peer_ip = request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|axum::extract::ConnectInfo(address)| address.ip())
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    let user_id = if path == "/api" || path == "/api/" {
        None
    } else {
        state.passport_key.as_ref().and_then(|key| {
            bearer_token(request.headers())
                .and_then(|token| decode_access_token(token, key))
                .filter(|claims| claims.exp > jsonwebtoken::get_current_timestamp())
                .and_then(|claims| claims.sub.parse::<i64>().ok())
        })
    };
    let key = user_id
        .map(|user_id| format!("user:{user_id}"))
        .unwrap_or_else(|| format!("ip:{peer_ip}"));
    let decision = state.limiter.hit(key, Instant::now());
    let mut response = if decision.allowed {
        next.run(request).await
    } else {
        (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({ "message": "Too Many Attempts." })),
        )
            .into_response()
    };
    response
        .headers_mut()
        .insert("x-ratelimit-limit", HeaderValue::from_static("60"));
    response.headers_mut().insert(
        "x-ratelimit-remaining",
        HeaderValue::from_str(&decision.remaining.to_string()).unwrap(),
    );
    if !decision.allowed {
        let retry_after = decision.retry_after.as_secs().max(1);
        let reset_at = SystemTime::now() + Duration::from_secs(retry_after);
        let reset_epoch = reset_at
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        response.headers_mut().insert(
            "retry-after",
            HeaderValue::from_str(&retry_after.to_string()).unwrap(),
        );
        response.headers_mut().insert(
            "x-ratelimit-reset",
            HeaderValue::from_str(&reset_epoch.to_string()).unwrap(),
        );
    }
    response
}

tokio::task_local! {
    static REQUEST_LOCALE: String;
    static REQUEST_INPUT_LOCALE: Option<String>;
    static REQUEST_APP_URL: String;
}

fn explicit_request_locale() -> Option<String> {
    REQUEST_INPUT_LOCALE.try_with(Clone::clone).ok().flatten()
}

pub(crate) fn request_locale(state: &AppState) -> String {
    REQUEST_LOCALE
        .try_with(Clone::clone)
        .unwrap_or_else(|_| state.config.locale.clone())
}

fn normalize_locale(locale: &str) -> Option<&'static str> {
    match locale
        .trim()
        .replace('-', "_")
        .to_ascii_lowercase()
        .as_str()
    {
        "zh" | "zh_cn" | "zh_hans" | "zh_hans_cn" => Some("zh_CN"),
        "zh_tw" | "zh_hant" | "zh_hant_tw" => Some("zh_TW"),
        "en" | "en_us" | "en_gb" => Some("en"),
        "de" | "de_de" => Some("de_DE"),
        "el" | "el_gr" => Some("el_GR"),
        "es" | "es_es" => Some("es_ES"),
        "fr" | "fr_fr" => Some("fr_FR"),
        "it" | "it_it" => Some("it_IT"),
        "ja" | "ja_jp" => Some("ja_JP"),
        "ko" | "ko_kr" => Some("ko_KR"),
        "nl" | "nl_nl" => Some("nl_NL"),
        "pt" | "pt_pt" => Some("pt_PT"),
        "ru" | "ru_ru" => Some("ru_RU"),
        _ => None,
    }
}

fn browser_preferred_locale(headers: &HeaderMap) -> Option<&'static str> {
    let header = headers.get("accept-language")?.to_str().ok()?;
    let mut candidates = header
        .split(',')
        .enumerate()
        .filter_map(|(position, language)| {
            let mut pieces = language.split(';');
            let tag = pieces.next()?.trim();
            if tag.is_empty() {
                return None;
            }
            let quality = pieces
                .filter_map(|parameter| parameter.trim().strip_prefix("q="))
                .next()
                .and_then(|value| value.parse::<f32>().ok())
                .unwrap_or(1.0);
            (quality > 0.0).then(|| (quality, position, normalize_locale(tag)))
        })
        .filter_map(|(quality, position, locale)| locale.map(|locale| (quality, position, locale)))
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        right
            .0
            .partial_cmp(&left.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| left.1.cmp(&right.1))
    });
    candidates.first().map(|(_, _, locale)| *locale)
}

fn requested_query_locale(request: &axum::extract::Request) -> Option<String> {
    request.uri().query().and_then(|query| {
        form_urlencoded::parse(query.as_bytes())
            .find(|(key, _)| key == "lang")
            .map(|(_, value)| value.into_owned())
            .filter(|value| !value.trim().is_empty())
    })
}

const MAX_LOCALE_REQUEST_BODY_BYTES: usize = 2 * 1024 * 1024;

fn body_locale(body: &[u8], media_type: &str) -> Option<String> {
    let locale = if media_type == "application/json" || media_type.ends_with("+json") {
        let language = serde_json::from_slice::<serde_json::Value>(body)
            .ok()?
            .get("lang")?
            .clone();
        if language.is_null() {
            return None;
        }
        language
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| language.to_string())
    } else if media_type == "application/x-www-form-urlencoded" {
        form_urlencoded::parse(body)
            .filter_map(|(key, value)| (key == "lang").then(|| value.into_owned()))
            .last()?
    } else {
        return None;
    };

    (!locale.trim().is_empty()).then_some(locale)
}

async fn buffer_request_body_for_locale(
    request: axum::extract::Request,
) -> Result<(axum::extract::Request, Option<String>, Option<String>), Response> {
    if matches!(*request.method(), Method::GET | Method::HEAD) {
        return Ok((request, None, None));
    }
    let Some(content_type) = request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
    else {
        return Ok((request, None, None));
    };
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if media_type != "application/json"
        && !media_type.ends_with("+json")
        && media_type != "application/x-www-form-urlencoded"
    {
        return Ok((request, None, None));
    }

    let (parts, request_body) = request.into_parts();
    let request_body = axum::body::to_bytes(request_body, MAX_LOCALE_REQUEST_BODY_BYTES)
        .await
        .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE.into_response())?;
    let locale = body_locale(&request_body, &media_type);
    let form_csrf_token = (media_type == "application/x-www-form-urlencoded")
        .then(|| {
            form_urlencoded::parse(&request_body)
                .filter_map(|(key, value)| (key == "_token").then(|| value.into_owned()))
                .last()
        })
        .flatten();
    Ok((
        axum::extract::Request::from_parts(parts, Body::from(request_body)),
        locale,
        form_csrf_token,
    ))
}

fn is_user_facing_web_path(path: &str) -> bool {
    path == "/"
        || path == "/auth"
        || path.starts_with("/auth/")
        || path == "/user"
        || path.starts_with("/user/")
        || path == "/admin"
        || path.starts_with("/admin/")
        || path == "/skinlib"
        || path.starts_with("/skinlib/")
        || path.starts_with("/texture/")
}

const WEB_CSRF_COOKIE: &str = "blessing_skin_csrf";
const WEB_CSRF_COOKIE_TTL_SECONDS: u64 = 365 * 24 * 60 * 60;

fn requires_web_csrf(path: &str, method: &Method) -> bool {
    !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
        && path != "/oauth/token"
        && path != "/oauth/authorize"
        && path != "/setup"
        && !path.starts_with("/setup/")
        && !path.starts_with("/api/")
        && path != "/api"
        && (is_user_facing_web_path(path) || path == "/texture" || path.starts_with("/oauth/"))
}

fn verify_web_csrf_token(key: &str, token: &str) -> bool {
    let Some((nonce, supplied_signature)) = token.split_once('.') else {
        return false;
    };
    if nonce.len() != 48
        || !nonce.bytes().all(|byte| byte.is_ascii_alphanumeric())
        || supplied_signature.len() != 64
    {
        return false;
    }
    let Some(expected_signature) =
        signature_hex(key, &format!("blessing-skin-web-csrf-v1:{nonce}"))
    else {
        return false;
    };
    bool::from(
        expected_signature
            .as_bytes()
            .ct_eq(supplied_signature.as_bytes()),
    )
}

fn valid_web_csrf_request(state: &AppState, headers: &HeaderMap, submitted: Option<&str>) -> bool {
    let Some(key) = state.config.app_key.as_deref() else {
        return false;
    };
    let Some(cookie) = cookie_value(headers, WEB_CSRF_COOKIE) else {
        return false;
    };
    let Some(submitted) = submitted else {
        return false;
    };
    cookie.len() == submitted.len()
        && bool::from(cookie.as_bytes().ct_eq(submitted.as_bytes()))
        && verify_web_csrf_token(key, cookie)
}

fn request_wants_json(headers: &HeaderMap) -> bool {
    headers
        .get("accept")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media_type| {
            let media_type = media_type.trim();
            media_type.eq_ignore_ascii_case("application/json")
                || media_type.to_ascii_lowercase().ends_with("+json")
        })
}

fn web_csrf_mismatch_response(headers: &HeaderMap) -> Response {
    let status = StatusCode::from_u16(419).expect("HTTP 419 is a valid status");
    if request_wants_json(headers) {
        (
            status,
            Json(serde_json::json!({"message": "CSRF token mismatched."})),
        )
            .into_response()
    } else {
        (
            status,
            Html("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Page Expired</title></head><body><h1>Page Expired</h1><p>CSRF token mismatched.</p></body></html>"),
        )
            .into_response()
    }
}

fn web_csrf_token_for_page(state: &AppState, headers: &HeaderMap) -> Option<(String, bool)> {
    let key = state.config.app_key.as_deref()?;
    if let Some(token) = cookie_value(headers, WEB_CSRF_COOKIE)
        && verify_web_csrf_token(key, token)
    {
        return Some((token.to_owned(), false));
    }
    let nonce = Alphanumeric.sample_string(&mut rand::thread_rng(), 48);
    let signature = signature_hex(key, &format!("blessing-skin-web-csrf-v1:{nonce}"))?;
    Some((format!("{nonce}.{signature}"), true))
}

fn add_plugin_head_links_to_html(html: &str, links: &serde_json::Value) -> String {
    let Some(links) = links.as_array() else {
        return html.to_owned();
    };
    let mut tags = String::new();
    for link in links {
        let Some(link) = link.as_object() else {
            continue;
        };
        let (Some(rel), Some(href)) = (
            link.get("rel").and_then(serde_json::Value::as_str),
            link.get("href").and_then(serde_json::Value::as_str),
        ) else {
            continue;
        };
        tags.push_str("<link rel=\"");
        tags.push_str(&escape_html_attribute(rel));
        tags.push_str("\" href=\"");
        tags.push_str(&escape_html_attribute(href));
        tags.push('"');
        for name in [
            "as",
            "crossorigin",
            "integrity",
            "media",
            "referrerpolicy",
            "sizes",
            "type",
        ] {
            if let Some(value) = link.get(name).and_then(serde_json::Value::as_str) {
                tags.push(' ');
                tags.push_str(name);
                tags.push_str("=\"");
                tags.push_str(&escape_html_attribute(value));
                tags.push('"');
            }
        }
        tags.push_str(" />");
    }
    if tags.is_empty() {
        return html.to_owned();
    }
    let Some(head_end) = html.find("</head>") else {
        return html.to_owned();
    };
    let mut rendered = html.to_owned();
    rendered.insert_str(head_end, &tags);
    rendered
}

fn escape_html_attribute(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\'', "&#39;")
}

fn add_web_csrf_to_html(html: &str, token: &str) -> String {
    static META_PATTERN: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let pattern = META_PATTERN.get_or_init(|| {
        regex::Regex::new(r#"(?i)<meta\s+name=["']csrf-token["']\s+content=["'][^"']*["']\s*/?>"#)
            .expect("CSRF meta tag expression is valid")
    });
    let meta = format!(r#"<meta name="csrf-token" content="{token}">"#);
    let rendered = if pattern.is_match(html) {
        pattern.replace_all(html, meta.as_str()).into_owned()
    } else if let Some(head_end) = html.find("</head>") {
        let mut rendered = html.to_owned();
        rendered.insert_str(head_end, &meta);
        rendered
    } else {
        html.to_owned()
    };
    static FORM_PATTERN: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let form_pattern = FORM_PATTERN.get_or_init(|| {
        regex::Regex::new(r"(?is)<form\b[^>]*>").expect("form tag expression is valid")
    });
    static METHOD_PATTERN: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let method_pattern = METHOD_PATTERN.get_or_init(|| {
        regex::Regex::new(r#"(?i)\bmethod\s*=\s*["']?([a-z]+)"#)
            .expect("form method expression is valid")
    });
    let mut rendered = form_pattern
        .replace_all(&rendered, |captures: &regex::Captures<'_>| {
            let tag = captures.get(0).expect("form tag capture exists").as_str();
            let method = method_pattern
                .captures(tag)
                .and_then(|captures| captures.get(1))
                .map(|method| method.as_str().to_ascii_lowercase())
                .unwrap_or_else(|| "get".to_owned());
            if matches!(method.as_str(), "get" | "head" | "options") {
                tag.to_owned()
            } else {
                format!("{tag}<input type=\"hidden\" name=\"_token\" value=\"{token}\">")
            }
        })
        .into_owned();
    const FETCH_CSRF_BRIDGE: &str = r#"<script>(()=>{const originalFetch=window.fetch.bind(window);window.fetch=(input,init)=>{const options=init||{};const method=(options.method||(input instanceof Request?input.method:'GET')).toUpperCase();let url;try{url=new URL(input instanceof Request?input.url:String(input),window.location.href)}catch(_){return originalFetch(input,init)}if(url.origin===window.location.origin&&!['GET','HEAD','OPTIONS'].includes(method)){const headers=new Headers(input instanceof Request?input.headers:undefined);if(options.headers)new Headers(options.headers).forEach((value,key)=>headers.set(key,value));const token=document.querySelector('meta[name="csrf-token"]')?.content;if(token&&!headers.has('X-CSRF-TOKEN'))headers.set('X-CSRF-TOKEN',token);return originalFetch(input,{...options,headers})}return originalFetch(input,init)}})();</script>"#;
    if let Some(head_end) = rendered.find("</head>") {
        rendered.insert_str(head_end, FETCH_CSRF_BRIDGE);
    }
    rendered
}

async fn inject_web_csrf_page(
    state: &AppState,
    request_headers: &HeaderMap,
    request_secure: bool,
    request_path: &str,
    response: Response,
) -> Response {
    if !response.status().is_success()
        || !response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.to_ascii_lowercase().starts_with("text/html"))
    {
        return response;
    }
    let Some((token, should_set_cookie)) = web_csrf_token_for_page(state, request_headers) else {
        return response;
    };
    let (mut parts, body) = response.into_parts();
    let bytes = match axum::body::to_bytes(body, 32 * 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::warn!(%error, "could not buffer HTML response to add CSRF token");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let html = match String::from_utf8(bytes.to_vec()) {
        Ok(html) => html,
        Err(_) => return Response::from_parts(parts, Body::from(bytes)),
    };
    let html = add_web_csrf_to_html(&html, &token);
    let head_links = apply_plugin_filter_value(
        state,
        "head_links",
        &serde_json::json!([]),
        &serde_json::json!({"path": request_path}),
    )
    .await;
    let html = add_plugin_head_links_to_html(&html, &head_links);
    parts.headers.remove(CONTENT_LENGTH);
    parts.headers.remove(ETAG);
    parts.headers.remove(LAST_MODIFIED);
    parts
        .headers
        .insert(CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    if should_set_cookie {
        let secure = if request_secure { "; Secure" } else { "" };
        let cookie = format!(
            "{WEB_CSRF_COOKIE}={token}; Path=/; Max-Age={WEB_CSRF_COOKIE_TTL_SECONDS}; HttpOnly; SameSite=Lax{secure}"
        );
        match HeaderValue::from_str(&cookie) {
            Ok(value) => {
                parts.headers.append(SET_COOKIE, value);
            }
            Err(error) => tracing::warn!(%error, "could not create web CSRF cookie"),
        }
    }
    Response::from_parts(parts, Body::from(html))
}

fn select_request_locale(
    state: &AppState,
    request: &axum::extract::Request,
    input_locale: Option<&str>,
) -> String {
    let cookie_locale = request
        .headers()
        .get(COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|cookie| {
                let (key, value) = cookie.trim().split_once('=')?;
                (key == "locale").then(|| value.to_owned())
            })
        });
    let requested = input_locale
        .map(str::to_owned)
        .or(cookie_locale)
        .or_else(|| browser_preferred_locale(request.headers()).map(str::to_owned));
    requested
        .as_deref()
        .and_then(normalize_locale)
        .or_else(|| normalize_locale(&state.config.locale))
        .or_else(|| normalize_locale(&state.config.fallback_locale))
        .unwrap_or("en")
        .to_owned()
}

pub(crate) fn request_app_url(state: &AppState) -> String {
    REQUEST_APP_URL
        .try_with(Clone::clone)
        .unwrap_or_else(|_| state.config.app_url.clone())
}

fn request_is_secure(request: &axum::extract::Request) -> bool {
    request.uri().scheme_str() == Some("https")
        || request
            .headers()
            .get("x-forwarded-proto")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value == "https")
        || request
            .headers()
            .get("x-forwarded-ssl")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value == "on")
}

fn force_https_url(app_url: &str) -> String {
    if app_url.starts_with("https://") {
        app_url.to_owned()
    } else if let Some(rest) = app_url.strip_prefix("http://") {
        format!("https://{rest}")
    } else {
        app_url.to_owned()
    }
}

fn detected_request_root(request: &axum::extract::Request, request_secure: bool) -> Option<String> {
    let host = request
        .headers()
        .get("host")
        .and_then(|value| value.to_str().ok())
        .or_else(|| {
            request
                .uri()
                .authority()
                .map(|authority| authority.as_str())
        })?;
    let authority = host.parse::<axum::http::uri::Authority>().ok()?;
    let scheme = if request_secure { "https" } else { "http" };
    Some(format!("{scheme}://{authority}"))
}

fn is_valid_site_url(value: &str) -> bool {
    value.parse::<axum::http::Uri>().ok().is_some_and(|uri| {
        matches!(uri.scheme_str(), Some("http" | "https")) && uri.authority().is_some()
    })
}

async fn select_request_app_url(
    state: &AppState,
    detected_root: Option<String>,
    request_secure: bool,
) -> String {
    let mut app_url = detected_root.unwrap_or_else(|| state.config.app_url.clone());
    let force_ssl = if let Some(database) = &state.database {
        let auto_detect = database
            .option(&state.config.database.table_prefix, "auto_detect_asset_url")
            .await
            .ok()
            .flatten()
            .map(|value| legacy_option_bool(Some(&value)))
            .unwrap_or(true);
        if !auto_detect {
            if let Some(site_url) = database
                .option(&state.config.database.table_prefix, "site_url")
                .await
                .ok()
                .flatten()
                .filter(|value| is_valid_site_url(value))
            {
                app_url = site_url;
            }
        }
        database
            .option(&state.config.database.table_prefix, "force_ssl")
            .await
            .ok()
            .flatten()
            .is_some_and(|value| legacy_option_bool(Some(&value)))
    } else {
        false
    };
    if force_ssl || request_secure {
        force_https_url(&app_url)
    } else {
        app_url
    }
}

async fn detect_locale_preference(
    State(state): State<AppState>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let (request, body_locale, form_csrf_token) =
        match buffer_request_body_for_locale(request).await {
            Ok(request) => request,
            Err(response) => return response,
        };
    let path = request.uri().path();
    let method = request.method().clone();
    let request_headers = request.headers().clone();
    let is_api = path == "/api" || path.starts_with("/api/");
    if state.session_key.is_some()
        && requires_web_csrf(path, &method)
        && !valid_web_csrf_request(
            &state,
            &request_headers,
            request_headers
                .get("X-CSRF-TOKEN")
                .and_then(|value| value.to_str().ok())
                .or(form_csrf_token.as_deref()),
        )
    {
        return web_csrf_mismatch_response(&request_headers);
    }
    let inject_csrf = state.session_key.is_some()
        && method == Method::GET
        && (is_user_facing_web_path(path) || path.starts_with("/oauth/"));
    let should_refresh_web_session = is_user_facing_web_path(path) || path.starts_with("/oauth/");
    if should_refresh_web_session
        && let Err(error) = refresh_web_session_revocation(&state, request.headers()).await
    {
        tracing::error!(%error, path, "failed to verify web session revocation state");
        return unavailable();
    }
    let session_to_refresh =
        if should_refresh_web_session && session_user_id(&state, request.headers()).is_some() {
            web_session_claims(&state, request.headers()).map(|(_, claims)| claims)
        } else {
            None
        };
    let input_locale = body_locale.or_else(|| requested_query_locale(&request));
    let mut locale = select_request_locale(&state, &request, input_locale.as_deref());
    if !is_api && is_user_facing_web_path(path) {
        if let (Some(user_id), Some(database)) = (
            session_user_id(&state, request.headers()),
            state.database.as_ref(),
        ) {
            if let Some(requested) = input_locale.as_deref() {
                if let Some(requested) = normalize_locale(requested) {
                    if let Err(error) = database
                        .update_user_locale(&state.config.database.table_prefix, user_id, requested)
                        .await
                    {
                        tracing::warn!(%error, user_id, "failed to save authenticated user locale");
                    }
                    locale = requested.to_owned();
                }
            } else {
                match database
                    .user_locale(&state.config.database.table_prefix, user_id)
                    .await
                {
                    Ok(Some(user_locale)) => {
                        if let Some(user_locale) = normalize_locale(&user_locale) {
                            locale = user_locale.to_owned();
                        }
                    }
                    Ok(None) => {}
                    Err(error) => {
                        tracing::warn!(%error, user_id, "failed to load authenticated user locale");
                    }
                }
            }
        }
    }
    let should_set_cookie = !is_api;
    let request_path = path.trim_start_matches('/').to_owned();
    let request_secure = request_is_secure(&request);
    let detected_root = detected_request_root(&request, request_secure);
    let app_url = select_request_app_url(&state, detected_root, request_secure).await;
    let response = REQUEST_LOCALE.scope(
        locale.clone(),
        REQUEST_APP_URL.scope(app_url, next.run(request)),
    );
    let mut response = REQUEST_INPUT_LOCALE.scope(input_locale, response).await;
    if let Some(claims) = session_to_refresh.as_ref()
        && !response_manages_web_session_cookie(&response)
    {
        match renewed_web_session_cookie(&state, claims, request_secure) {
            Ok(Some(cookie)) => {
                response.headers_mut().append(SET_COOKIE, cookie);
            }
            Ok(None) => {}
            Err(error) => tracing::warn!(%error, "could not extend authenticated web session"),
        }
    }
    if should_set_cookie {
        if let Ok(cookie) = HeaderValue::from_str(&format!(
            "locale={locale}; Path=/; Max-Age=7200; SameSite=Lax"
        )) {
            response.headers_mut().append(SET_COOKIE, cookie);
        }
    }
    if inject_csrf {
        response = inject_web_csrf_page(
            &state,
            &request_headers,
            request_secure,
            &request_path,
            response,
        )
        .await;
    }
    response
}
async fn apply_plugin_filter_value(
    state: &AppState,
    filter_name: &str,
    value: &serde_json::Value,
    context: &serde_json::Value,
) -> serde_json::Value {
    state
        .wasm_runtime
        .lock()
        .await
        .apply_filter(filter_name, value, context)
        .await
}

async fn filter_user_avatar_url(state: &AppState, user: &UserProfile, png: bool) -> String {
    let default_url = format!(
        "/avatar/{}?size=36{}",
        user.avatar,
        if png { "&png" } else { "" }
    );
    let filtered = apply_plugin_filter_value(
        state,
        "user_avatar",
        &serde_json::json!(default_url),
        &serde_json::json!({
            "user": {
                "uid": user.uid,
                "nickname": user.nickname,
                "score": user.score,
                "avatar": user.avatar,
                "permission": user.permission,
                "verified": user.verified,
            }
        }),
    )
    .await;
    filtered.as_str().unwrap_or(&default_url).to_owned()
}

fn public_user_plugin_context(user: &UserProfile) -> serde_json::Value {
    serde_json::json!({
        "user": {
            "uid": user.uid,
            "nickname": user.nickname,
            "score": user.score,
            "avatar": user.avatar,
            "permission": user.permission,
            "verified": user.verified,
        }
    })
}

async fn filter_user_badges(state: &AppState, user: &UserProfile) -> serde_json::Value {
    let initial_badges = if user.permission >= 1 {
        serde_json::json!([{ "text": "STAFF", "color": "primary" }])
    } else {
        serde_json::json!([])
    };
    apply_plugin_filter_value(
        state,
        "user_badges",
        &initial_badges,
        &public_user_plugin_context(user),
    )
    .await
}

async fn filter_user_menu(
    state: &AppState,
    user: &UserProfile,
    locale: &str,
) -> Vec<DashboardMenuItem> {
    let chinese = locale.starts_with("zh");
    let mut items = vec![
        DashboardMenuItem {
            label: if chinese {
                "用户中心"
            } else {
                "User Center"
            }
            .to_owned(),
            link: "/user".to_owned(),
        },
        DashboardMenuItem {
            label: if chinese {
                "个人资料"
            } else {
                "User Profile"
            }
            .to_owned(),
            link: "/user/profile".to_owned(),
        },
    ];
    if user.permission >= 1 {
        items.extend([
            DashboardMenuItem {
                label: String::new(),
                link: "#divider".to_owned(),
            },
            DashboardMenuItem {
                label: if chinese {
                    "管理面板"
                } else {
                    "Admin Panel"
                }
                .to_owned(),
                link: "/admin".to_owned(),
            },
            DashboardMenuItem {
                label: if chinese { "用户管理" } else { "Users" }.to_owned(),
                link: "/admin/users".to_owned(),
            },
            DashboardMenuItem {
                label: if chinese { "举报管理" } else { "Reports" }.to_owned(),
                link: "/admin/reports".to_owned(),
            },
            DashboardMenuItem {
                label: "Web CLI".to_owned(),
                link: "#launch-cli".to_owned(),
            },
        ]);
    }
    let initial = serde_json::to_value(&items).unwrap_or_else(|_| serde_json::json!([]));
    let filtered = apply_plugin_filter_value(
        state,
        "user_menu",
        &initial,
        &public_user_plugin_context(user),
    )
    .await;
    serde_json::from_value(filtered).unwrap_or(items)
}

fn dashboard_menu_item(label: &str, link: &str) -> DashboardMenuItem {
    DashboardMenuItem {
        label: label.to_owned(),
        link: link.to_owned(),
    }
}

async fn filter_side_menu(
    state: &AppState,
    menu_type: &str,
    items: Vec<DashboardMenuItem>,
) -> Vec<DashboardMenuItem> {
    let initial = serde_json::to_value(&items).unwrap_or_else(|_| serde_json::json!([]));
    let filtered = apply_plugin_filter_value(
        state,
        "side_menu",
        &initial,
        &serde_json::json!({ "type": menu_type }),
    )
    .await;
    serde_json::from_value(filtered).unwrap_or(items)
}

async fn filter_player_page_widgets(state: &AppState) -> Vec<String> {
    filter_page_widgets(
        state,
        "grid:user.player",
        &["player_management", "previewer"],
    )
    .await
}

async fn filter_skinlib_upload_widgets(state: &AppState) -> Vec<String> {
    filter_page_widgets(state, "grid:skinlib.upload", &["upload_form", "previewer"]).await
}

async fn filter_user_profile_widgets(state: &AppState) -> Vec<String> {
    filter_page_widgets(
        state,
        "grid:user.profile",
        &["avatar", "password", "nickname", "email", "delete_account"],
    )
    .await
}

async fn filter_user_dashboard_widgets(state: &AppState) -> Vec<String> {
    filter_page_widgets(
        state,
        "grid:user.index",
        &["email_verification", "usage", "announcement"],
    )
    .await
}

async fn filter_admin_dashboard_widgets(state: &AppState) -> Vec<String> {
    filter_page_widgets(
        state,
        "grid:admin.index",
        &["usage", "notification", "chart"],
    )
    .await
}

async fn filter_admin_status_widgets(state: &AppState) -> Vec<String> {
    filter_page_widgets(state, "grid:admin.status", &["system_info", "plugins"]).await
}

async fn filter_skinlib_show_widgets(state: &AppState) -> Vec<String> {
    filter_page_widgets(
        state,
        "grid:skinlib.show",
        &["texture_preview", "texture_details"],
    )
    .await
}

async fn filter_closet_page_widgets(state: &AppState) -> Vec<String> {
    filter_page_widgets(
        state,
        "grid:user.closet",
        &["closet_management", "previewer"],
    )
    .await
}

async fn filter_page_widgets(state: &AppState, name: &str, defaults: &[&str]) -> Vec<String> {
    let initial = serde_json::json!(defaults);
    let filtered = apply_plugin_filter_value(state, name, &initial, &serde_json::json!({})).await;
    serde_json::from_value(filtered)
        .unwrap_or_else(|_| defaults.iter().map(|widget| (*widget).to_owned()).collect())
}

async fn filter_auth_page_rows(state: &AppState, page: &str, defaults: &[&str]) -> Vec<String> {
    let name = format!("auth_page_rows:{page}");
    let default_value = serde_json::json!(defaults);
    let filtered =
        apply_plugin_filter_value(state, &name, &default_value, &serde_json::json!({})).await;
    serde_json::from_value(filtered)
        .unwrap_or_else(|_| defaults.iter().map(|row| (*row).to_owned()).collect())
}

async fn filter_user_password_hash(state: &AppState, password_hash: &str) -> String {
    let filtered = apply_plugin_filter_value(
        state,
        "user_password",
        &serde_json::json!(password_hash),
        &serde_json::json!({}),
    )
    .await;
    filtered
        .as_str()
        .filter(|hash| !hash.is_empty() && hash.len() <= 255)
        .unwrap_or(password_hash)
        .to_owned()
}

fn texture_plugin_record(texture: &TextureInfoRecord) -> serde_json::Value {
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

fn closet_item_plugin_record(item: &ClosetTextureRecord) -> serde_json::Value {
    let mut record = texture_plugin_record(&TextureInfoRecord {
        tid: item.tid,
        name: item.name.clone(),
        texture_type: item.texture_type.clone(),
        hash: item.hash.clone(),
        size: item.size,
        uploader: item.uploader,
        is_public: item.is_public,
        upload_at: item.upload_at.clone(),
        likes: item.likes,
    });
    if let Some(record) = record.as_object_mut() {
        record.insert(
            "pivot".to_owned(),
            serde_json::json!({
                "user_uid": item.user_uid,
                "texture_tid": item.texture_tid,
                "item_name": item.item_name,
            }),
        );
    }
    record
}

async fn closet_name_filter(
    state: &AppState,
    filter_name: &str,
    texture_id: i64,
    name: &str,
) -> String {
    let result = apply_plugin_filter_value(
        state,
        filter_name,
        &serde_json::json!(name),
        &serde_json::json!({"texture_id": texture_id}),
    )
    .await;
    result.as_str().unwrap_or(name).to_owned()
}

async fn closet_permission_filter(
    state: &AppState,
    filter_name: &str,
    context: serde_json::Value,
) -> Option<String> {
    let result =
        apply_plugin_filter_value(state, filter_name, &serde_json::json!(true), &context).await;
    plugin_filter_rejection(&result).map(str::to_owned)
}

async fn texture_permission_filter(
    state: &AppState,
    filter_name: &str,
    texture: &TextureInfoRecord,
    additional_context: serde_json::Value,
) -> Option<String> {
    let mut context =
        serde_json::Map::from_iter([("texture".to_owned(), texture_plugin_record(texture))]);
    if let Some(fields) = additional_context.as_object() {
        context.extend(
            fields
                .iter()
                .map(|(key, value)| (key.clone(), value.clone())),
        );
    }
    let result = state
        .wasm_runtime
        .lock()
        .await
        .apply_filter(
            filter_name,
            &serde_json::json!(true),
            &serde_json::Value::Object(context),
        )
        .await;
    plugin_filter_rejection(&result).map(str::to_owned)
}

fn user_score_updated_event(user_id: i64, previous_score: i64, score: i64) -> serde_json::Value {
    serde_json::json!({
        "user_id": user_id,
        "previous_score": previous_score,
        "score": score,
    })
}

fn legacy_sign_is_eligible(last_sign_at: &str, eligible_before: &str) -> bool {
    last_sign_at <= eligible_before
}

fn plugin_filter_rejection(value: &serde_json::Value) -> Option<&str> {
    value.get("rejection").and_then(serde_json::Value::as_str)
}

async fn load_owned_player(
    database: &crate::database::DatabasePool,
    prefix: &str,
    user_id: i64,
    player_id: i64,
    locale: &str,
) -> Result<crate::database::PlayerRecord, Response> {
    let player = match database.player_by_id(prefix, player_id).await {
        Ok(Some(player)) => player,
        Ok(None) => return Err(StatusCode::NOT_FOUND.into_response()),
        Err(error) => {
            tracing::error!(%error, player_id, "failed to load player before plugin filters");
            return Err(unavailable());
        }
    };
    if player.uid != user_id {
        return Err(player_forbidden_response(locale));
    }
    Ok(player)
}

async fn filter_player_delete(
    state: &AppState,
    user_id: i64,
    player: &crate::database::PlayerRecord,
) -> Result<(), String> {
    let payload = serde_json::json!({
        "user_id": user_id,
        "player_id": player.pid,
        "name": player.name,
    });
    emit_plugin_event(state, "player.delete.attempt", payload.clone()).await;
    let can_delete = state
        .wasm_runtime
        .lock()
        .await
        .apply_filter(
            "can_delete_player",
            &serde_json::json!(true),
            &serde_json::json!({
                "user_id": user_id,
                "player": player,
            }),
        )
        .await;
    if let Some(reason) = plugin_filter_rejection(&can_delete) {
        return Err(reason.to_owned());
    }
    emit_plugin_event(state, "player.deleting", payload).await;
    Ok(())
}

async fn filter_player_rename_name(
    state: &AppState,
    user_id: i64,
    player: &crate::database::PlayerRecord,
    submitted_name: &str,
) -> Result<String, String> {
    let filtered_name = state
        .wasm_runtime
        .lock()
        .await
        .apply_filter(
            "new_player_name",
            &serde_json::json!(submitted_name),
            &serde_json::json!({
                "user_id": user_id,
                "action": "rename",
                "player": player,
            }),
        )
        .await;
    let name = filtered_name.as_str().unwrap_or(submitted_name).to_owned();
    emit_plugin_event(
        state,
        "player.renaming",
        serde_json::json!({
            "user_id": user_id,
            "player_id": player.pid,
            "previous_name": player.name,
            "name": name,
        }),
    )
    .await;
    let can_rename = state
        .wasm_runtime
        .lock()
        .await
        .apply_filter(
            "can_rename_player",
            &serde_json::json!(true),
            &serde_json::json!({
                "user_id": user_id,
                "player": player,
                "name": name,
            }),
        )
        .await;
    if let Some(reason) = plugin_filter_rejection(&can_rename) {
        return Err(reason.to_owned());
    }
    Ok(name)
}

fn user_sign_plugin_event(user_id: i64, score: i64) -> serde_json::Value {
    serde_json::json!({
        "user_id": user_id,
        "score": score,
    })
}

fn password_reset_plugin_event(user_id: i64) -> serde_json::Value {
    serde_json::json!({"user_id": user_id, "action": "password"})
}

async fn emit_plugin_event(state: &AppState, name: &str, payload: serde_json::Value) {
    let payload = match serde_json::to_vec(&payload) {
        Ok(payload) => payload,
        Err(error) => {
            tracing::warn!(%error, event = name, "could not serialize WASM plugin event payload");
            return;
        }
    };
    state
        .wasm_runtime
        .lock()
        .await
        .dispatch_event(name, &payload)
        .await;
}

async fn emit_player_textures_updated(state: &AppState, player: &PlayerRecord) {
    emit_plugin_event(
        state,
        "player.textures.updated",
        serde_json::json!({
            "user_id": player.uid,
            "player_id": player.pid,
            "skin_texture_id": player.tid_skin,
            "cape_texture_id": player.tid_cape,
        }),
    )
    .await;
}

async fn apply_player_permission_filter(
    state: &AppState,
    name: &str,
    context: serde_json::Value,
) -> Result<(), String> {
    let result = state
        .wasm_runtime
        .lock()
        .await
        .apply_filter(name, &serde_json::json!(true), &context)
        .await;
    plugin_filter_rejection(&result)
        .map(str::to_owned)
        .map_or(Ok(()), Err)
}

async fn set_player_textures_with_plugins(
    state: &AppState,
    user_id: i64,
    player_id: i64,
    skin: Option<i64>,
    cape: Option<i64>,
    locale: &str,
) -> Response {
    let Some(database) = &state.database else {
        return unavailable();
    };
    let prefix = &state.config.database.table_prefix;
    let mut player = match load_owned_player(database, prefix, user_id, player_id, locale).await {
        Ok(player) => player,
        Err(response) => return response,
    };
    for (texture_type, texture_id) in [("skin", skin), ("cape", cape)] {
        if let Err(reason) = apply_player_permission_filter(
            state,
            "can_set_texture",
            serde_json::json!({
                "user_id": user_id,
                "player": player,
                "type": texture_type,
                "texture_id": texture_id,
            }),
        )
        .await
        {
            return login_result(1, &reason, None);
        }
        let Some(texture_id) = texture_id.filter(|texture_id| *texture_id != 0) else {
            continue;
        };
        match database.texture_info(prefix, texture_id).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return player_texture_response(
                    Ok(crate::database::PlayerTextureOutcome::TextureNotFound),
                    locale,
                    false,
                );
            }
            Err(error) => {
                tracing::error!(%error, texture_id, "failed to load player texture before plugin event");
                return unavailable();
            }
        }
        match database.user_has_texture(prefix, user_id, texture_id).await {
            Ok(true) => {}
            Ok(false) => {
                return player_texture_response(
                    Ok(crate::database::PlayerTextureOutcome::TextureNotInCloset),
                    locale,
                    false,
                );
            }
            Err(error) => {
                tracing::error!(%error, user_id, texture_id, "failed to check player texture closet membership");
                return unavailable();
            }
        }
        let previous_texture_id = if texture_type == "skin" {
            player.tid_skin
        } else {
            player.tid_cape
        };
        emit_plugin_event(
            state,
            "player.texture.updating",
            serde_json::json!({
                "user_id": user_id,
                "player_id": player_id,
                "name": player.name,
                "type": texture_type,
                "texture_id": texture_id,
            }),
        )
        .await;
        match database
            .set_player_textures(
                prefix,
                user_id,
                player_id,
                (texture_type == "skin").then_some(texture_id),
                (texture_type == "cape").then_some(texture_id),
            )
            .await
        {
            Ok(crate::database::PlayerTextureOutcome::Updated(updated)) => {
                emit_plugin_event(
                    state,
                    "player.texture.updated",
                    serde_json::json!({
                        "user_id": user_id,
                        "player_id": player_id,
                        "name": updated.name,
                        "type": texture_type,
                        "previous_texture_id": previous_texture_id,
                        "texture_id": texture_id,
                    }),
                )
                .await;
                player = updated;
            }
            result => return player_texture_response(result, locale, false),
        }
    }
    emit_player_textures_updated(state, &player).await;
    player_texture_response(
        Ok(crate::database::PlayerTextureOutcome::Updated(player)),
        locale,
        false,
    )
}

async fn clear_player_textures_with_plugins(
    state: &AppState,
    user_id: i64,
    player_id: i64,
    clear_skin: bool,
    clear_cape: bool,
    locale: &str,
) -> Response {
    let Some(database) = &state.database else {
        return unavailable();
    };
    let prefix = &state.config.database.table_prefix;
    let mut player = match load_owned_player(database, prefix, user_id, player_id, locale).await {
        Ok(player) => player,
        Err(response) => return response,
    };
    for (texture_type, should_clear) in [("skin", clear_skin), ("cape", clear_cape)] {
        if let Err(reason) = apply_player_permission_filter(
            state,
            "can_clear_texture",
            serde_json::json!({
                "user_id": user_id,
                "player": player,
                "type": texture_type,
            }),
        )
        .await
        {
            return login_result(1, &reason, None);
        }
        if !should_clear {
            continue;
        }
        let previous_texture_id = if texture_type == "skin" {
            player.tid_skin
        } else {
            player.tid_cape
        };
        emit_plugin_event(
            state,
            "player.texture.resetting",
            serde_json::json!({
                "user_id": user_id,
                "player_id": player_id,
                "name": player.name,
                "type": texture_type,
                "texture_id": previous_texture_id,
            }),
        )
        .await;
        match database
            .clear_player_textures(
                prefix,
                user_id,
                player_id,
                texture_type == "skin",
                texture_type == "cape",
            )
            .await
        {
            Ok(crate::database::PlayerTextureOutcome::Updated(updated)) => {
                emit_plugin_event(
                    state,
                    "player.texture.reset",
                    serde_json::json!({
                        "user_id": user_id,
                        "player_id": player_id,
                        "name": updated.name,
                        "type": texture_type,
                        "previous_texture_id": previous_texture_id,
                        "texture_id": 0,
                    }),
                )
                .await;
                player = updated;
            }
            result => return player_texture_response(result, locale, true),
        }
    }
    emit_player_textures_updated(state, &player).await;
    player_texture_response(
        Ok(crate::database::PlayerTextureOutcome::Updated(player)),
        locale,
        true,
    )
}

pub fn router(state: AppState) -> Router {
    let app = Router::new()
        .fallback(web_not_found)
        .route("/health/live", any(live))
        .route("/health/ready", any(ready))
        .route("/app/{*path}", get(frontend_asset))
        .route(
            "/.well-known/change-password",
            get(change_password_discovery),
        )
        .route("/api", any(api_root))
        .route("/api/", any(api_root))
        .route("/", get(home))
        .route("/setup", get(setup_welcome))
        .route("/setup/database", any(setup_database_dispatch))
        .route("/setup/info", get(setup_info_page))
        .route("/setup/finish", post(setup_finish))
        .route("/auth/login", get(login_page).post(handle_login))
        .route("/auth/bind", get(bind_email_page).post(bind_email))
        .route("/auth/register", get(register_page).post(handle_register))
        .route("/auth/forgot", get(forgot_page).post(handle_forgot))
        .route(
            "/auth/reset/{uid}",
            get(reset_page).post(handle_password_reset),
        )
        .route(
            "/auth/verify/{uid}",
            get(verify_email_page).post(handle_email_verification),
        )
        .route("/auth/captcha", any(captcha_image))
        .route("/auth/logout", post(logout))
        .route(
            "/oauth/authorize",
            get(crate::oauth::authorize)
                .post(crate::oauth::authorization_decision)
                .delete(crate::oauth::authorization_decision),
        )
        .route("/oauth/token", post(crate::oauth::token))
        .route("/oauth/scopes", get(crate::oauth::list_scopes))
        .route("/oauth/tokens", get(crate::oauth::list_authorized_tokens))
        .route(
            "/oauth/tokens/{token_id}",
            delete(crate::oauth::revoke_access_token),
        )
        .route(
            "/oauth/personal-access-tokens",
            get(crate::oauth::list_personal_access_tokens)
                .post(crate::oauth::create_personal_access_token),
        )
        .route(
            "/oauth/personal-access-tokens/{token_id}",
            delete(crate::oauth::revoke_access_token),
        )
        .route(
            "/oauth/clients",
            get(oauth_clients_list).post(oauth_client_create),
        )
        .route(
            "/oauth/clients/{id}",
            put(oauth_client_update).delete(oauth_client_delete),
        )
        .route("/user", get(web_dashboard))
        .route("/user/reports", get(web_user_reports))
        .route("/user/reports/list", get(web_user_report_list))
        .route("/user/oauth/manage", get(oauth_manage_page))
        .route("/user/notifications/{id}", post(web_read_notification))
        .route("/user/email-verification", post(send_verification_email))
        .route("/user/player", get(web_player_page).post(web_add_player))
        .route("/user/player/list", get(web_player_list))
        .route("/user/player/{pid}/name", put(web_rename_player))
        .route(
            "/user/player/{pid}/textures",
            put(web_set_player_textures).delete(web_clear_player_textures),
        )
        .route("/user/player/{pid}", delete(web_delete_player))
        .route(
            "/user/closet",
            get(web_closet_page).post(web_add_closet_item),
        )
        .route("/user/closet/list", get(web_closet_list))
        .route("/user/closet/ids", get(web_closet_ids))
        .route(
            "/user/closet/{tid}",
            put(web_rename_closet_item).delete(web_remove_closet_item),
        )
        .route(
            "/user/profile",
            get(user_profile_page).post(user_profile_update),
        )
        .route("/user/profile/avatar", post(user_set_avatar))
        .route("/user/dark-mode", put(toggle_user_dark_mode))
        .route("/user/score-info", get(user_score_info))
        .route("/user/sign", post(user_sign))
        .route("/admin", get(web_admin_dashboard))
        .route("/admin/chart", get(web_admin_chart))
        .route("/admin/status", get(web_admin_status))
        .route("/admin/update", get(web_admin_update))
        .route("/admin/update/download", post(web_admin_update_download))
        .route("/admin/plugins/data", get(web_admin_plugins_data))
        .route("/admin/plugins/market", get(web_admin_plugins_market_page))
        .route(
            "/admin/plugins/market/list",
            get(web_admin_plugins_market_list),
        )
        .route(
            "/admin/plugins/market/download",
            post(web_admin_plugins_market_download).layer(DefaultBodyLimit::max(16 * 1024)),
        )
        .route(
            "/admin/plugins/manage",
            get(web_admin_plugins_page).post(web_admin_plugins_manage),
        )
        .route("/admin/plugins/config/{name}", any(web_admin_plugin_config))
        .route("/admin/plugins/readme/{name}", get(web_admin_plugin_readme))
        .route(
            "/admin/plugins/upload",
            post(web_admin_plugins_upload).layer(DefaultBodyLimit::max(34 * 1024 * 1024)),
        )
        .route(
            "/admin/plugins/wget",
            post(web_admin_plugins_wget).layer(DefaultBodyLimit::max(16 * 1024)),
        )
        .route("/admin/notifications/send", post(web_send_notification))
        .route("/admin/users", get(web_admin_users_page))
        .route("/admin/users/list", get(admin_user_list))
        .route("/admin/users/{uid}/email", put(web_admin_user_email))
        .route(
            "/admin/users/{uid}/verification",
            put(web_admin_user_verification),
        )
        .route("/admin/users/{uid}/nickname", put(web_admin_user_nickname))
        .route("/admin/users/{uid}/password", put(web_admin_user_password))
        .route("/admin/users/{uid}/score", put(web_admin_user_score))
        .route(
            "/admin/users/{uid}/permission",
            put(web_admin_user_permission),
        )
        .route("/admin/users/{uid}", delete(web_admin_user_delete))
        .route("/admin/players", get(web_admin_players_page))
        .route("/admin/players/list", get(admin_player_list))
        .route("/admin/players/{pid}/name", put(web_admin_player_name))
        .route("/admin/players/{pid}/owner", put(web_admin_player_owner))
        .route(
            "/admin/players/{pid}/textures",
            put(web_admin_player_texture),
        )
        .route("/admin/players/{pid}", delete(web_admin_player_delete))
        .route(
            "/admin/closet/{uid}",
            post(web_admin_closet_add).delete(web_admin_closet_remove),
        )
        .route("/admin/reports", get(web_admin_reports_page))
        .route("/admin/reports/list", get(admin_report_list))
        .route("/admin/reports/{id}", put(web_review_report))
        .route(
            "/admin/i18n",
            get(web_admin_translations).post(web_create_language_line),
        )
        .route("/admin/i18n/list", get(web_admin_language_lines))
        .route(
            "/admin/i18n/{id}",
            put(web_update_language_line).delete(web_delete_language_line),
        )
        .route(
            "/admin/options",
            any(crate::admin_settings::options_dispatch),
        )
        .route("/admin/score", any(crate::admin_settings::score_dispatch))
        .route(
            "/admin/customize",
            any(crate::admin_settings::customize_dispatch),
        )
        .route(
            "/admin/resource",
            any(crate::admin_settings::resource_dispatch),
        )
        .route("/skinlib", get(skinlib_page))
        .route("/skinlib/upload", get(texture_upload_page))
        .route("/skinlib/show/{tid}", get(skinlib_show_page))
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
        .route("/api/admin/users", get(api_admin_user_list))
        .route("/api/admin/users/{uid}/email", put(api_admin_user_email))
        .route(
            "/api/admin/users/{uid}/verification",
            put(api_admin_user_verification),
        )
        .route(
            "/api/admin/users/{uid}/nickname",
            put(api_admin_user_nickname),
        )
        .route(
            "/api/admin/users/{uid}/password",
            put(api_admin_user_password),
        )
        .route("/api/admin/users/{uid}/score", put(api_admin_user_score))
        .route(
            "/api/admin/users/{uid}/permission",
            put(api_admin_user_permission),
        )
        .route("/api/admin/users/{uid}", delete(api_admin_user_delete))
        .route("/api/admin/players", get(api_admin_player_list))
        .route("/api/admin/players/{pid}/name", put(api_admin_player_name))
        .route(
            "/api/admin/players/{pid}/owner",
            put(api_admin_player_owner),
        )
        .route(
            "/api/admin/players/{pid}/textures",
            put(api_admin_player_texture),
        )
        .route("/api/admin/players/{pid}", delete(api_admin_player_delete))
        .route(
            "/api/admin/closet/{uid}",
            get(api_admin_closet_list)
                .post(api_admin_closet_add)
                .delete(api_admin_closet_remove),
        )
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
        .route("/avatar/player/{name}", get(avatar_by_player))
        .route("/avatar/user/{uid}", get(avatar_by_user))
        .route("/avatar/hash/{hash}", get(avatar_by_hash))
        .route("/avatar/{tid}", get(avatar_by_texture))
        .route("/preview/{tid}", get(preview_by_texture))
        .route("/preview/hash/{hash}", get(preview_by_hash))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            redirect_uninstalled,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            render_html_error_page,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            serve_public_assets,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            detect_locale_preference,
        ))
        .layer(axum::middleware::from_fn(infer_peer_client_ip));
    let app = if !cfg!(test)
        && crate::config::legacy_env("APP_ENV").unwrap_or_else(|| "production".to_owned())
            != "testing"
    {
        legacy_api_throttle_layer(app, state.passport_key.clone())
    } else {
        app
    };
    app.with_state(state)
}

async fn web_not_found(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    if !should_render_html_error(uri.path(), &headers) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let locale = request_locale(&state);
    let page = NotFoundPage {
        locale: locale.clone(),
        title: http_error_title(StatusCode::NOT_FOUND).to_owned(),
        site_name: site_name(&state).await,
        message: http_error_message(&locale, StatusCode::NOT_FOUND).to_owned(),
        home_url: request_app_url(&state),
    };
    match page.render() {
        Ok(html) => (StatusCode::NOT_FOUND, Html(html)).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to render not found page");
            StatusCode::NOT_FOUND.into_response()
        }
    }
}

fn should_render_html_error(path: &str, headers: &HeaderMap) -> bool {
    if path == "/api"
        || path.starts_with("/api/")
        || path.starts_with("/csl/")
        || path.starts_with("/textures/")
        || path.starts_with("/raw/")
        || path.starts_with("/avatar/")
        || path.starts_with("/preview/")
        || path == "/oauth/token"
    {
        return false;
    }
    headers
        .get(axum::http::header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|accept| {
            accept.split(',').any(|media_range| {
                let mut parts = media_range.trim().split(';');
                let media_type = parts.next().unwrap_or_default().trim();
                let quality = parts
                    .filter_map(|parameter| parameter.trim().strip_prefix("q="))
                    .filter_map(|value| value.parse::<f32>().ok())
                    .next()
                    .unwrap_or(1.0);
                media_type.eq_ignore_ascii_case("text/html") && quality > 0.0
            })
        })
}

fn http_error_title(status: StatusCode) -> &'static str {
    match status {
        StatusCode::FORBIDDEN => "403 Forbidden",
        StatusCode::NOT_FOUND => "404 Not Found",
        StatusCode::INTERNAL_SERVER_ERROR => "500 Internal Server Error",
        StatusCode::SERVICE_UNAVAILABLE => "503 Service Unavailable",
        _ => "Error",
    }
}

fn http_error_message(locale: &str, status: StatusCode) -> &'static str {
    match locale {
        "de_DE" => match status {
            StatusCode::FORBIDDEN => "Sie haben keine Zugriffsberechtigung für diese Seite.",
            StatusCode::NOT_FOUND => "Hier ist nichts.",
            StatusCode::INTERNAL_SERVER_ERROR => "Bitte später nochmal versuchen.",
            StatusCode::SERVICE_UNAVAILABLE => {
                "Die Anwendung befindet sich jetzt im Wartungsmodus."
            }
            _ => "Fehler aufgetreten",
        },
        "es_ES" => match status {
            StatusCode::FORBIDDEN => "No tiene permiso para accesar esta página.",
            StatusCode::NOT_FOUND => "No hay nada.",
            StatusCode::INTERNAL_SERVER_ERROR => "Por favor intente más tarde.",
            StatusCode::SERVICE_UNAVAILABLE => "La aplicación está ahora en modo de mantenimiento.",
            _ => "Se produjo un error",
        },
        "fr_FR" => match status {
            StatusCode::FORBIDDEN => "Vous n'avez pas la permission d'accéder à cette page.",
            StatusCode::NOT_FOUND => "Il n'y a rien ici.",
            StatusCode::INTERNAL_SERVER_ERROR => "Veuillez réessayer plus tard.",
            StatusCode::SERVICE_UNAVAILABLE => "L'application est maintenant en mode maintenance.",
            _ => "Une erreur s'est produite",
        },
        "ko_KR" => match status {
            StatusCode::FORBIDDEN => "이 페이지의 액세스 권한이 없습니다.",
            StatusCode::NOT_FOUND => "여기에 아무것도 없어!",
            StatusCode::INTERNAL_SERVER_ERROR => "나중에 다시 시도해주십시오.",
            StatusCode::SERVICE_UNAVAILABLE => "The application is now in maintenance mode.",
            _ => "오류가 발생했습니다",
        },
        "ru_RU" => match status {
            StatusCode::FORBIDDEN => "У вас нет прав доступа для этой страницы.",
            StatusCode::NOT_FOUND => "Здесь пусто.",
            StatusCode::INTERNAL_SERVER_ERROR => "Пожалуйста, повторите попытку позже.",
            StatusCode::SERVICE_UNAVAILABLE => {
                "В настоящее время приложение находится в режиме обслуживания."
            }
            _ => "Произошла ошибка",
        },
        "zh_CN" => match status {
            StatusCode::FORBIDDEN => "您无权访问此页面。",
            StatusCode::NOT_FOUND => "这里什么都没有哦",
            StatusCode::INTERNAL_SERVER_ERROR => "服务器内部错误，请稍后再试。",
            StatusCode::SERVICE_UNAVAILABLE => "网站维护中",
            _ => "出现错误",
        },
        "zh_TW" => match status {
            StatusCode::FORBIDDEN => "您無權使用這個頁面。",
            StatusCode::NOT_FOUND => "這裡甚麼都沒有。",
            StatusCode::INTERNAL_SERVER_ERROR => "請稍後再試一次。",
            StatusCode::SERVICE_UNAVAILABLE => "網站現在正在維護中。",
            _ => "發生錯誤",
        },
        _ => match status {
            StatusCode::FORBIDDEN => "You have no permission to access this page.",
            StatusCode::NOT_FOUND => "Nothing here.",
            StatusCode::INTERNAL_SERVER_ERROR => "Please try again later.",
            StatusCode::SERVICE_UNAVAILABLE => "The application is now in maintenance mode.",
            _ => "Error occurred",
        },
    }
}

async fn render_html_error_page(
    State(state): State<AppState>,
    request: axum::http::Request<Body>,
    next: axum::middleware::Next,
) -> Response {
    let path = request.uri().path().to_owned();
    let request_headers = request.headers().clone();
    let response = next.run(request).await;
    let status = response.status();
    if !matches!(
        status,
        StatusCode::FORBIDDEN | StatusCode::INTERNAL_SERVER_ERROR | StatusCode::SERVICE_UNAVAILABLE
    ) || !should_render_html_error(&path, &request_headers)
    {
        return response;
    }
    if response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|content_type| {
            content_type.to_ascii_lowercase().contains("text/html")
                || content_type.to_ascii_lowercase().contains("json")
        })
    {
        return response;
    }

    let (mut parts, body) = response.into_parts();
    let locale = request_locale(&state);
    let detail = if status == StatusCode::FORBIDDEN {
        axum::body::to_bytes(body, 32 * 1024)
            .await
            .ok()
            .and_then(|bytes| String::from_utf8(bytes.to_vec()).ok())
            .map(|detail| detail.trim().to_owned())
            .filter(|detail| !detail.is_empty())
    } else {
        None
    };
    let page = NotFoundPage {
        locale: locale.clone(),
        title: http_error_title(status).to_owned(),
        site_name: site_name(&state).await,
        message: detail.unwrap_or_else(|| http_error_message(&locale, status).to_owned()),
        home_url: request_app_url(&state),
    };
    let html = match page.render() {
        Ok(html) => html,
        Err(error) => {
            tracing::error!(%error, status = status.as_u16(), "failed to render HTTP error page");
            return (status, "").into_response();
        }
    };
    parts.headers.remove(CONTENT_LENGTH);
    parts.headers.remove(CONTENT_TYPE);
    parts.headers.remove(ETAG);
    parts.headers.remove(LAST_MODIFIED);
    parts
        .headers
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    let mut response = Response::from_parts(parts, Body::from(html));
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response
}

#[derive(Template)]
#[template(path = "not_found.html")]
struct NotFoundPage {
    locale: String,
    title: String,
    site_name: String,
    message: String,
    home_url: String,
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginPage {
    site_name: String,
    locale: String,
    redirect_to: String,
    title: String,
    prompt: String,
    identification_label: String,
    password_label: String,
    remember_label: String,
    submit_label: String,
    registration_link: String,
    forgot_link: String,
    rows: Vec<String>,
    show_form: bool,
    frontend_style_available: bool,
    frontend_stylesheet: String,
    frontend_script_available: bool,
    frontend_script: String,
    frontend_globals_b64: String,
}

#[derive(Template)]
#[template(path = "admin_i18n.html")]
struct AdminTranslationsPage {
    site_name: String,
    locale: String,
    added: bool,
    frontend_style_available: bool,
    frontend_stylesheet: String,
    frontend_script_available: bool,
    frontend_script: String,
    frontend_globals_b64: String,
}

#[derive(Deserialize, Default)]
struct UserReportsQuery {
    page: Option<i64>,
}

#[derive(Deserialize, Default)]
struct AdminTranslationsQuery {
    page: Option<i64>,
    added: Option<i64>,
}

#[derive(Template)]
#[template(path = "user_reports.html")]
struct UserReportsPage {
    site_name: String,
    locale: String,
    reports: Vec<UserReportView>,
    current_page: i64,
    last_page: i64,
    frontend_style_available: bool,
    frontend_stylesheet: String,
    frontend_script_available: bool,
    frontend_script: String,
    frontend_globals_b64: String,
}

#[derive(Serialize)]
struct UserReportView {
    id: i64,
    tid: i64,
    texture_name: Option<String>,
    reason: String,
    status: i32,
    report_at: String,
}

#[derive(Template)]
#[template(path = "oauth_manage.html")]
struct OAuthManagePage {
    site_name: String,
    locale: String,
    frontend_style_available: bool,
    frontend_stylesheet: String,
    frontend_script_available: bool,
    frontend_script: String,
    frontend_globals_b64: String,
}

#[derive(Template)]
#[template(path = "user_profile.html")]
struct UserProfilePage {
    site_name: String,
    locale: String,
    user: UserProfile,
    allow_delete: bool,
    page_widgets: Vec<String>,
    frontend_style_available: bool,
    frontend_stylesheet: String,
    frontend_script_available: bool,
    frontend_script: String,
    frontend_globals_b64: String,
}

#[derive(Template)]
#[template(path = "forgot.html")]
struct ForgotPage {
    site_name: String,
    locale: String,
    title: String,
    prompt: String,
    email_label: String,
    captcha_label: String,
    submit_label: String,
    use_recaptcha: bool,
    recaptcha_sitekey: String,
    frontend_style_available: bool,
    frontend_stylesheet: String,
    frontend_script_available: bool,
    frontend_script: String,
    frontend_globals_b64: String,
}

#[derive(Template)]
#[template(path = "reset.html")]
struct PasswordResetPage {
    site_name: String,
    locale: String,
    title: String,
    prompt: String,
    action_url: String,
    password_label: String,
    submit_label: String,
    frontend_style_available: bool,
    frontend_stylesheet: String,
    frontend_script_available: bool,
    frontend_script: String,
    frontend_globals_b64: String,
}

#[derive(Template)]
#[template(path = "verify.html")]
struct EmailVerificationPage {
    site_name: String,
    locale: String,
    title: String,
    prompt: String,
    action_url: String,
    email_label: String,
    submit_label: String,
    frontend_style_available: bool,
    frontend_stylesheet: String,
    frontend_script_available: bool,
    frontend_script: String,
    frontend_globals_b64: String,
}

#[derive(Deserialize, Default)]
struct LoginPageQuery {
    redirect_to: Option<String>,
}

fn safe_local_redirect(target: Option<&str>) -> Option<String> {
    let target = target?;
    if target.len() > 4096
        || !target.starts_with('/')
        || target.starts_with("//")
        || target.contains('\\')
        || target.chars().any(char::is_control)
    {
        return None;
    }
    Some(target.to_owned())
}
#[derive(Template)]
#[template(path = "bind_email.html")]
struct BindEmailPage {
    site_name: String,
    locale: String,
    frontend_style_available: bool,
    frontend_stylesheet: String,
    frontend_script_available: bool,
    frontend_script: String,
    frontend_globals_b64: String,
}

async fn bind_email_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
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
        Ok(Some(user)) => user,
        Ok(None) => return Redirect::to("/auth/login").into_response(),
        Err(error) => {
            tracing::error!(%error, user_id, "failed to load account for email binding");
            return unavailable();
        }
    };
    if user.permission == -1 {
        let message = if request_locale(&state).starts_with("zh") {
            "你已被本站封禁，详情请联系站点管理员"
        } else {
            "You are banned on this site. Please contact the admin."
        };
        let mut response = login_result(-1, message, None);
        *response.status_mut() = StatusCode::FORBIDDEN;
        return response;
    }
    if !user.email.is_empty() {
        return Redirect::to("/user").into_response();
    }
    let site_name = site_name(&state).await;
    let app_dir = state.public_dir.join("app");
    let stylesheet = frontend_entrypoint(&app_dir, "style", "css", &request_app_url(&state)).await;
    let frontend_script =
        frontend_entrypoint(&app_dir, "app", "js", &request_app_url(&state)).await;
    let i18n = load_frontend_translations(&state, &app_dir, &request_locale(&state)).await;
    let frontend_globals_b64 =
        encode_frontend_globals(&state, &site_name, "auth/bind", serde_json::json!({}), i18n);
    let page = BindEmailPage {
        site_name,
        locale: request_locale(&state),
        frontend_style_available: stylesheet.is_some(),
        frontend_stylesheet: stylesheet.unwrap_or_default(),
        frontend_script_available: frontend_script.is_some(),
        frontend_script: frontend_script.unwrap_or_default(),
        frontend_globals_b64,
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, user_id, "failed to render account email binding page");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn bind_email(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
    body: Bytes,
) -> Response {
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
        Ok(Some(user)) => user,
        Ok(None) => return Redirect::to("/auth/login").into_response(),
        Err(error) => {
            tracing::error!(%error, user_id, "failed to load account for email binding");
            return unavailable();
        }
    };
    if user.permission == -1 {
        let message = if request_locale(&state).starts_with("zh") {
            "你已被本站封禁，详情请联系站点管理员"
        } else {
            "You are banned on this site. Please contact the admin."
        };
        let mut response = login_result(-1, message, None);
        *response.status_mut() = StatusCode::FORBIDDEN;
        return response;
    }
    if !user.email.is_empty() {
        return Redirect::to("/user").into_response();
    }
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    let is_json = content_type.is_some_and(|value| value.starts_with("application/json"));
    let input_content_type = if is_json {
        content_type
    } else {
        Some("application/x-www-form-urlencoded")
    };
    let fields = match parse_legacy_input_object(&query, &body, input_content_type) {
        Ok(fields) => fields,
        Err(()) => {
            return registration_validation_error("email", "required", &request_locale(&state));
        }
    };
    let Some(email_value) = fields.get("email").filter(|value| !value.is_null()) else {
        return registration_validation_error("email", "required", &request_locale(&state));
    };
    let Some(email) = email_value.as_str() else {
        return registration_validation_error("email", "email", &request_locale(&state));
    };
    let email = email.trim();
    if email.is_empty() {
        return registration_validation_error("email", "required", &request_locale(&state));
    }
    if !valid_email_address(email) || email.len() > 100 {
        return registration_validation_error("email", "email", &request_locale(&state));
    }
    let email = email.to_owned();
    let prefix = &state.config.database.table_prefix;
    match database.user_email_exists(prefix, &email, user_id).await {
        Ok(true) => {
            return registration_validation_error("email", "unique", &request_locale(&state));
        }
        Ok(false) => {}
        Err(error) => {
            tracing::error!(%error, user_id, "failed to check account email uniqueness");
            return unavailable();
        }
    }
    if let Err(error) = database
        .update_user_text(prefix, user_id, "email", &email)
        .await
    {
        tracing::error!(%error, user_id, "failed to bind account email");
        return unavailable();
    }
    if !is_json {
        Redirect::to("/user").into_response()
    } else {
        login_result(
            0,
            if request_locale(&state).starts_with("zh") {
                "邮箱已绑定。"
            } else {
                "Email address bound successfully."
            },
            Some(serde_json::json!({ "redirectTo": "/user" })),
        )
    }
}
pub(crate) async fn frontend_entrypoint(
    app_dir: &std::path::Path,
    bundle: &str,
    extension: &str,
    app_url: &str,
) -> Option<String> {
    let mut entries = tokio::fs::read_dir(app_dir).await.ok()?;
    let exact_name = format!("{bundle}.{extension}");
    let prefix = format!("{bundle}.");
    let suffix = format!(".{extension}");
    let mut candidates = Vec::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name != exact_name && !(name.starts_with(&prefix) && name.ends_with(&suffix)) {
            continue;
        }
        let Ok(file_type) = entry.file_type().await else {
            continue;
        };
        if !file_type.is_file() {
            continue;
        }
        let modified = entry
            .metadata()
            .await
            .ok()
            .and_then(|metadata| metadata.modified().ok())
            .unwrap_or(SystemTime::UNIX_EPOCH);
        candidates.push((modified, name));
    }
    candidates.sort_unstable();
    let (_, filename) = candidates.pop()?;
    Some(format!("{}/app/{filename}", app_url.trim_end_matches('/')))
}

pub(crate) async fn load_frontend_translations(
    state: &AppState,
    app_dir: &std::path::Path,
    locale: &str,
) -> serde_json::Value {
    let valid_locale = |candidate: &str| {
        !candidate.is_empty()
            && candidate
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    };
    let mut translations = None;
    for candidate in [locale, "en"] {
        if !valid_locale(candidate) {
            continue;
        }
        let path = app_dir.join("i18n").join(format!("{candidate}.json"));
        let Ok(contents) = tokio::fs::read(path).await else {
            continue;
        };
        match serde_json::from_slice::<serde_json::Value>(&contents) {
            Ok(value) if value.is_object() => {
                translations = Some(value);
                break;
            }
            Ok(_) => tracing::warn!(locale = candidate, "frontend translations are not a map"),
            Err(error) => {
                tracing::warn!(locale = candidate, %error, "failed to read frontend translations")
            }
        }
    }
    let mut translations = translations.unwrap_or_else(|| serde_json::json!({}));
    if let Some(database) = state.database.as_ref() {
        match database
            .frontend_language_lines(&state.config.database.table_prefix)
            .await
        {
            Ok(lines) => merge_frontend_language_lines(&mut translations, locale, lines),
            Err(error) => {
                tracing::warn!(%error, "failed to load database frontend translations")
            }
        }
    }
    translations
}

fn merge_frontend_language_lines(
    translations: &mut serde_json::Value,
    locale: &str,
    lines: Vec<(String, String)>,
) {
    for (key, stored) in lines {
        let Ok(available) = serde_json::from_str::<serde_json::Value>(&stored) else {
            tracing::warn!("skipping malformed database frontend translation");
            continue;
        };
        let Some(available) = available.as_object() else {
            tracing::warn!("skipping non-map database frontend translation");
            continue;
        };
        let text = available
            .get(locale)
            .and_then(serde_json::Value::as_str)
            .or_else(|| available.get("en").and_then(serde_json::Value::as_str));
        if let Some(text) = text {
            set_frontend_translation(
                translations,
                &key,
                serde_json::Value::String(text.to_owned()),
            );
        }
    }
}

fn set_frontend_translation(
    translations: &mut serde_json::Value,
    key: &str,
    value: serde_json::Value,
) {
    let segments = key.split('.').collect::<Vec<_>>();
    if segments.is_empty() || segments.iter().any(|segment| segment.is_empty()) {
        return;
    }
    let mut current = translations;
    for segment in &segments[..segments.len() - 1] {
        if !current.is_object() {
            *current = serde_json::json!({});
        }
        current = current
            .as_object_mut()
            .expect("translation parent was made an object")
            .entry((*segment).to_owned())
            .or_insert_with(|| serde_json::json!({}));
    }
    if !current.is_object() {
        *current = serde_json::json!({});
    }
    current
        .as_object_mut()
        .expect("translation parent was made an object")
        .insert(segments[segments.len() - 1].to_owned(), value);
}
pub(crate) fn encode_frontend_globals(
    state: &AppState,
    site_name: &str,
    route: &str,
    extra: serde_json::Value,
    i18n: serde_json::Value,
) -> String {
    let globals = serde_json::json!({
        "version": state.config.legacy_app_version,
        "locale": request_locale(&state),
        "base_url": request_app_url(&state).trim_end_matches('/'),
        "site_name": site_name,
        "route": route,
        "debug": cfg!(debug_assertions),
        "env": if cfg!(debug_assertions) { "development" } else { "production" },
        "extra": extra,
        "i18n": i18n,
    });
    base64::engine::general_purpose::STANDARD
        .encode(serde_json::to_vec(&globals).expect("frontend config is serializable"))
}

fn login_failure_count(state: &AppState, identification: &str) -> u32 {
    state
        .login_failures
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(identification)
        .filter(|(_, updated)| updated.elapsed() < Duration::from_secs(3600))
        .map(|(count, _)| *count)
        .unwrap_or_default()
}

async fn login_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<LoginPageQuery>,
) -> Response {
    if let Some(response) = authenticated_guest_redirect(&state, &headers).await {
        return response;
    }
    let site_name = match &state.database {
        Some(database) => {
            let prefix = &state.config.database.table_prefix;
            let localized = format!("site_name_{}", request_locale(&state));
            database
                .option(prefix, &localized)
                .await
                .ok()
                .flatten()
                .or(database.option(prefix, "site_name").await.ok().flatten())
                .unwrap_or_else(|| "Blessing Skin".to_owned())
        }
        None => "Blessing Skin".to_owned(),
    };
    let chinese = request_locale(&state).starts_with("zh");
    let redirect_to = safe_local_redirect(query.redirect_to.as_deref()).unwrap_or_default();
    let app_dir = state.public_dir.join("app");
    let stylesheet = frontend_entrypoint(&app_dir, "style", "css", &request_app_url(&state)).await;
    let frontend_script =
        frontend_entrypoint(&app_dir, "app", "js", &request_app_url(&state)).await;
    let frontend_script_available = frontend_script.is_some();
    let stylesheet = stylesheet.unwrap_or_default();
    let frontend_script = frontend_script.unwrap_or_default();
    let i18n = load_frontend_translations(&state, &app_dir, &request_locale(&state)).await;
    let client_ip = filtered_client_ip(&state, &headers).await;
    let failures = login_failure_count(&state, &client_ip) > 3;
    let rows = filter_auth_page_rows(
        &state,
        "login",
        &[
            "auth.rows.login.notice",
            "auth.rows.login.message",
            "auth.rows.login.form",
            "auth.rows.login.registration-link",
        ],
    )
    .await;
    let show_form = rows.iter().any(|row| row == "auth.rows.login.form");
    let (recaptcha_sitekey, recaptcha_invisible) = match &state.database {
        Some(database) => {
            let prefix = &state.config.database.table_prefix;
            let sitekey = match database.option(prefix, "recaptcha_sitekey").await {
                Ok(sitekey) => sitekey.unwrap_or_default(),
                Err(error) => {
                    tracing::warn!(%error, "failed to read reCAPTCHA site key for login page");
                    String::new()
                }
            };
            let invisible = match database.option(prefix, "recaptcha_invisible").await {
                Ok(value) => legacy_option_bool(value.as_deref()),
                Err(error) => {
                    tracing::warn!(%error, "failed to read reCAPTCHA mode for login page");
                    false
                }
            };
            (sitekey, invisible)
        }
        None => (String::new(), false),
    };
    let frontend_globals_b64 = encode_frontend_globals(
        &state,
        &site_name,
        "auth/login",
        serde_json::json!({
            "tooManyFails": failures,
            "recaptcha": recaptcha_sitekey,
            "invisible": recaptcha_invisible,
            "redirectTo": redirect_to,
        }),
        i18n,
    );
    let page = LoginPage {
        site_name,
        locale: request_locale(&state),
        redirect_to,
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
        registration_link: if chinese {
            "注册新账号"
        } else {
            "Register a new account"
        }
        .to_owned(),
        forgot_link: if chinese {
            "忘记密码？"
        } else {
            "Forgot password?"
        }
        .to_owned(),
        frontend_style_available: !stylesheet.is_empty(),
        frontend_stylesheet: stylesheet,
        frontend_script_available,
        frontend_script,
        frontend_globals_b64,
        rows,
        show_form,
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to render login page");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Template)]
#[template(path = "register.html")]
struct RegisterPage {
    site_name: String,
    locale: String,
    title: String,
    prompt: String,
    email_label: String,
    account_label: String,
    password_label: String,
    captcha_label: String,
    submit_label: String,
    player_name_registration: bool,
    use_recaptcha: bool,
    recaptcha_sitekey: String,
    rows: Vec<String>,
    show_form: bool,
    frontend_style_available: bool,
    frontend_stylesheet: String,
    frontend_script_available: bool,
    frontend_script: String,
    frontend_globals_b64: String,
}

async fn register_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(response) = authenticated_guest_redirect(&state, &headers).await {
        return response;
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    let prefix = &state.config.database.table_prefix;
    let site_name = match database.option(prefix, "site_name").await {
        Ok(value) => value.unwrap_or_else(|| "Blessing Skin".to_owned()),
        Err(error) => {
            tracing::error!(%error, "failed to read site name for registration");
            return unavailable();
        }
    };
    let player_name_registration = match database.option(prefix, "register_with_player_name").await
    {
        Ok(value) => value
            .as_deref()
            .map(|value| legacy_option_bool(Some(value)))
            .unwrap_or(true),
        Err(error) => {
            tracing::error!(%error, "failed to read registration mode");
            return unavailable();
        }
    };
    let recaptcha_secret = match database.option(prefix, "recaptcha_secretkey").await {
        Ok(value) => value.unwrap_or_default(),
        Err(error) => {
            tracing::error!(%error, "failed to read registration CAPTCHA configuration");
            return unavailable();
        }
    };
    let recaptcha_invisible = match database.option(prefix, "recaptcha_invisible").await {
        Ok(value) => legacy_option_bool(value.as_deref()),
        Err(error) => {
            tracing::error!(%error, "failed to read registration CAPTCHA mode");
            return unavailable();
        }
    };
    let recaptcha_sitekey = if recaptcha_secret.is_empty() {
        String::new()
    } else {
        match database.option(prefix, "recaptcha_sitekey").await {
            Ok(value) => value.unwrap_or_default(),
            Err(error) => {
                tracing::error!(%error, "failed to read reCAPTCHA site key");
                return unavailable();
            }
        }
    };
    let chinese = request_locale(&state).starts_with("zh");
    let use_recaptcha = !recaptcha_secret.is_empty();
    let rows = filter_auth_page_rows(
        &state,
        "register",
        &["auth.rows.register.notice", "auth.rows.register.form"],
    )
    .await;
    let show_form = rows.iter().any(|row| row == "auth.rows.register.form");

    let app_dir = state.public_dir.join("app");
    let stylesheet = frontend_entrypoint(&app_dir, "style", "css", &request_app_url(&state)).await;
    let frontend_script =
        frontend_entrypoint(&app_dir, "app", "js", &request_app_url(&state)).await;
    let i18n = load_frontend_translations(&state, &app_dir, &request_locale(&state)).await;
    let frontend_globals_b64 = encode_frontend_globals(
        &state,
        &site_name,
        "auth/register",
        serde_json::json!({
            "player": player_name_registration,
            "recaptcha": if use_recaptcha { recaptcha_sitekey.as_str() } else { "" },
            "invisible": recaptcha_invisible,
        }),
        i18n,
    );
    let page = RegisterPage {
        site_name,
        locale: request_locale(&state),
        title: if chinese { "注册" } else { "Register" }.to_owned(),
        prompt: if chinese {
            "创建一个账号来管理你的皮肤与角色。"
        } else {
            "Create an account to manage your skins and players."
        }
        .to_owned(),
        email_label: if chinese { "邮箱" } else { "Email" }.to_owned(),
        account_label: (if chinese {
            if player_name_registration {
                "角色名"
            } else {
                "昵称"
            }
        } else if player_name_registration {
            "Player name"
        } else {
            "Nickname"
        })
        .to_owned(),
        password_label: if chinese { "密码" } else { "Password" }.to_owned(),
        captcha_label: if chinese { "验证码" } else { "CAPTCHA" }.to_owned(),
        submit_label: if chinese { "注册" } else { "Register" }.to_owned(),
        player_name_registration,
        use_recaptcha,
        recaptcha_sitekey,
        rows,
        show_form,
        frontend_style_available: stylesheet.is_some(),

        frontend_stylesheet: stylesheet.unwrap_or_default(),
        frontend_script_available: frontend_script.is_some(),
        frontend_script: frontend_script.unwrap_or_default(),
        frontend_globals_b64,
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to render registration page");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn forgot_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(response) = authenticated_guest_redirect(&state, &headers).await {
        return response;
    }
    let site_name = site_name(&state).await;
    let Some(database) = &state.database else {
        return unavailable();
    };
    let prefix = &state.config.database.table_prefix;
    let recaptcha_invisible = match database.option(prefix, "recaptcha_invisible").await {
        Ok(value) => legacy_option_bool(value.as_deref()),
        Err(error) => {
            tracing::error!(%error, "failed to load forgot-password CAPTCHA mode");
            return unavailable();
        }
    };
    let (recaptcha_sitekey, recaptcha_secret) = match (
        database.option(prefix, "recaptcha_sitekey").await,
        database.option(prefix, "recaptcha_secretkey").await,
    ) {
        (Ok(sitekey), Ok(secret)) => (sitekey.unwrap_or_default(), secret.unwrap_or_default()),
        (Err(error), _) | (_, Err(error)) => {
            tracing::error!(%error, "failed to load forgot-password CAPTCHA settings");
            return unavailable();
        }
    };
    let chinese = request_locale(&state).starts_with("zh");
    let use_recaptcha = !recaptcha_secret.is_empty();

    let app_dir = state.public_dir.join("app");
    let stylesheet = frontend_entrypoint(&app_dir, "style", "css", &request_app_url(&state)).await;
    let frontend_script =
        frontend_entrypoint(&app_dir, "app", "js", &request_app_url(&state)).await;
    let i18n = load_frontend_translations(&state, &app_dir, &request_locale(&state)).await;
    let frontend_globals_b64 = encode_frontend_globals(
        &state,
        &site_name,
        "auth/forgot",
        serde_json::json!({
            "recaptcha": if use_recaptcha { recaptcha_sitekey.as_str() } else { "" },
            "invisible": recaptcha_invisible,
        }),
        i18n,
    );
    let page = ForgotPage {
        site_name,
        locale: request_locale(&state),
        title: if chinese { "找回密码" } else { "Forgot Password" }.to_owned(),
        prompt: if chinese {
            "输入账户邮箱，我们会发送一条一小时内有效的重置链接。"
        } else {
            "Enter your account email and we will send a password reset link that expires in one hour."
        }
        .to_owned(),
        email_label: if chinese { "邮箱" } else { "Email" }.to_owned(),
        captcha_label: if chinese { "验证码" } else { "CAPTCHA" }.to_owned(),
        submit_label: if chinese { "发送重置邮件" } else { "Send reset email" }.to_owned(),
        use_recaptcha,
        recaptcha_sitekey,
        frontend_style_available: stylesheet.is_some(),
        frontend_stylesheet: stylesheet.unwrap_or_default(),
        frontend_script_available: frontend_script.is_some(),
        frontend_script: frontend_script.unwrap_or_default(),
        frontend_globals_b64,
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to render forgot-password page");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn handle_forgot(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
    body: Bytes,
) -> Response {
    if let Some(response) = authenticated_guest_redirect(&state, &headers).await {
        return response;
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    if state.config.mail.mailer.trim().is_empty() {
        return login_result(
            1,
            &auth_message(
                &state,
                "邮件发送未配置。",
                "Email delivery is not configured.",
            ),
            None,
        );
    }
    let request = match parse_legacy_input_object(
        &query,
        &body,
        headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
    ) {
        Ok(fields) => serde_json::Value::Object(fields),
        Err(()) => {
            return login_result(
                1,
                &auth_message(&state, "邮箱格式无效。", "Invalid email address."),
                None,
            );
        }
    };
    let email = request
        .get("email")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if !valid_email_address(email) || email.len() > 100 {
        return login_result(
            1,
            &auth_message(&state, "邮箱格式无效。", "Invalid email address."),
            None,
        );
    }
    let captcha = request
        .get("captcha")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    match verify_registration_captcha(&state, &headers, captcha).await {
        Ok(true) => {}
        Ok(false) => {
            return login_result(
                1,
                &auth_message(&state, "验证码无效。", "Invalid CAPTCHA."),
                None,
            );
        }
        Err(response) => return response,
    }
    emit_plugin_event(&state, "auth.forgot.attempt", serde_json::json!({})).await;
    let ip = filtered_client_ip(&state, &headers).await;
    let key = format!("forgot:{ip}");
    if reserve_mail_limit(&state, &key, Duration::from_secs(180)).is_err() {
        return login_result(
            2,
            &auth_message(
                &state,
                "邮件发送过于频繁，请稍后再试。",
                "You click the send button too fast. Wait for some minutes.",
            ),
            None,
        );
    }
    let uid = match database
        .user_id_by_email(&state.config.database.table_prefix, email)
        .await
    {
        Ok(Some(uid)) => uid,
        Ok(None) => {
            release_mail_limit(&state, &key);
            return login_result(
                1,
                &auth_message(
                    &state,
                    "该邮箱未注册。",
                    "The email address is not registered.",
                ),
                None,
            );
        }
        Err(error) => {
            release_mail_limit(&state, &key);
            tracing::error!(%error, "failed to find password reset recipient");
            return unavailable();
        }
    };
    emit_plugin_event(
        &state,
        "auth.forgot.ready",
        serde_json::json!({"user_id": uid}),
    )
    .await;
    let Some(path) = signed_relative_url(
        &state,
        &format!("/auth/reset/{uid}"),
        Some(unix_timestamp() + 3600),
    ) else {
        release_mail_limit(&state, &key);
        return unavailable();
    };
    let url = format!("{}{}", request_app_url(&state).trim_end_matches('/'), path);
    let site_name = site_name(&state).await;
    let body = if request_locale(&state).starts_with("zh") {
        format!(
            "你收到了这封邮件，因为有人请求重置 {site_name} 账户密码。\n\n请在一小时内访问以下链接重设密码：\n{url}\n\n如果你没有请求重置密码，请忽略此邮件。"
        )
    } else {
        format!(
            "You received this email because a password reset was requested for your {site_name} account.\n\nReset your password within one hour by visiting:\n{url}\n\nIf you did not request a password reset, you can ignore this email."
        )
    };
    let subject = if request_locale(&state).starts_with("zh") {
        format!("{site_name} 密码重置")
    } else {
        format!("Reset your {site_name} password")
    };
    match crate::mailer::send_email(&state.config.mail, email, &subject, &body).await {
        Ok(()) => {
            emit_plugin_event(
                &state,
                "auth.forgot.sent",
                serde_json::json!({"user_id": uid}),
            )
            .await;
            login_result(
                0,
                &auth_message(
                    &state,
                    "重置邮件已发送，请检查收件箱。",
                    "Mail sent, please check your inbox. The link will be expired in 1 hour.",
                ),
                None,
            )
        }
        Err(error) => {
            emit_plugin_event(
                &state,
                "auth.forgot.failed",
                serde_json::json!({"user_id": uid}),
            )
            .await;
            release_mail_limit(&state, &key);
            tracing::warn!(%error, recipient = %email, "failed to send password reset email");
            let message = forgot_password_failure_message(&request_locale(&state), &error);
            login_result(2, &message, None)
        }
    }
}

async fn reset_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(uid): RoutePath<String>,
    OriginalUri(uri): OriginalUri,
    RawQuery(query): RawQuery,
) -> Response {
    if let Some(response) = authenticated_guest_redirect(&state, &headers).await {
        return response;
    }
    let Some(uid) = uid.parse::<i64>().ok() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !valid_relative_signature(
        &state,
        uri.path(),
        query.as_deref().unwrap_or_default(),
        true,
    ) {
        return (StatusCode::FORBIDDEN, "Invalid or expired link.").into_response();
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    let user = match database
        .user_profile(&state.config.database.table_prefix, uid)
        .await
    {
        Ok(Some(user)) => user,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, uid, "failed to load password reset user");
            return unavailable();
        }
    };
    let chinese = request_locale(&state).starts_with("zh");
    let site_name = site_name(&state).await;
    let app_dir = state.public_dir.join("app");
    let stylesheet = frontend_entrypoint(&app_dir, "style", "css", &request_app_url(&state)).await;
    let frontend_script =
        frontend_entrypoint(&app_dir, "app", "js", &request_app_url(&state)).await;
    let i18n = load_frontend_translations(&state, &app_dir, &request_locale(&state)).await;
    let frontend_globals_b64 = encode_frontend_globals(
        &state,
        &site_name,
        &format!("auth/reset/{uid}"),
        serde_json::json!({}),
        i18n,
    );
    let page = PasswordResetPage {
        site_name,
        locale: request_locale(&state),
        title: if chinese {
            "重设密码"
        } else {
            "Reset Password"
        }
        .to_owned(),
        prompt: if chinese {
            format!("{}，请设置新密码。", user.nickname)
        } else {
            format!("{}, reset your password here.", user.nickname)
        },
        action_url: signed_action_url(&state, &uri),
        password_label: if chinese { "新密码" } else { "New password" }.to_owned(),
        submit_label: if chinese {
            "重设密码"
        } else {
            "Reset password"
        }
        .to_owned(),
        frontend_style_available: stylesheet.is_some(),
        frontend_stylesheet: stylesheet.unwrap_or_default(),
        frontend_script_available: frontend_script.is_some(),
        frontend_script: frontend_script.unwrap_or_default(),
        frontend_globals_b64,
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to render password reset page");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn handle_password_reset(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(input_query): Query<BTreeMap<String, String>>,
    RoutePath(uid): RoutePath<String>,
    OriginalUri(uri): OriginalUri,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> Response {
    if let Some(response) = authenticated_guest_redirect(&state, &headers).await {
        return response;
    }
    let Some(uid) = uid.parse::<i64>().ok() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !valid_relative_signature(
        &state,
        uri.path(),
        query.as_deref().unwrap_or_default(),
        true,
    ) {
        return (StatusCode::FORBIDDEN, "Invalid or expired link.").into_response();
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    let request = match parse_legacy_input_object(
        &input_query,
        &body,
        headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
    ) {
        Ok(fields) => serde_json::Value::Object(fields),
        Err(()) => {
            return login_result(
                1,
                &auth_message(&state, "密码无效。", "Invalid password."),
                None,
            );
        }
    };
    let password = request
        .get("password")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let length = password.chars().count();
    if !(8..=32).contains(&length) {
        return login_result(
            1,
            &auth_message(
                &state,
                "密码长度必须为 8 到 32 个字符。",
                "Password must be between 8 and 32 characters.",
            ),
            None,
        );
    }
    match database
        .user_profile(&state.config.database.table_prefix, uid)
        .await
    {
        Ok(Some(_)) => {}
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, uid, "failed to find password reset user");
            return unavailable();
        }
    }
    emit_plugin_event(
        &state,
        "auth.reset.before",
        serde_json::json!({"user_id": uid}),
    )
    .await;
    let Some(password_hash) = hash_legacy_password(
        password,
        &state.config.password_method,
        &state.config.password_salt,
        state.config.bcrypt_rounds,
    ) else {
        tracing::error!(method = %state.config.password_method, "configured legacy password method cannot hash passwords");
        return unavailable();
    };
    let password_hash = filter_user_password_hash(&state, &password_hash).await;
    if let Err(error) = database
        .update_user_text(
            &state.config.database.table_prefix,
            uid,
            "password",
            &password_hash,
        )
        .await
    {
        tracing::error!(%error, uid, "failed to update password through reset link");
        return unavailable();
    }
    emit_plugin_event(
        &state,
        "auth.reset.after",
        serde_json::json!({"user_id": uid}),
    )
    .await;
    emit_plugin_event(
        &state,
        "user.profile.updated",
        password_reset_plugin_event(uid),
    )
    .await;
    login_result(
        0,
        &auth_message(&state, "密码已重设。", "Password resetted successfully."),
        Some(serde_json::json!({"redirectTo":"/auth/login"})),
    )
}

async fn verify_email_page(
    State(state): State<AppState>,
    RoutePath(uid): RoutePath<String>,
    OriginalUri(uri): OriginalUri,
    RawQuery(query): RawQuery,
) -> Response {
    let Some(uid) = uid.parse::<i64>().ok() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    match verification_is_required(database, &state.config.database.table_prefix).await {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::FORBIDDEN,
                "Email verification is not available.",
            )
                .into_response();
        }
        Err(error) => {
            tracing::error!(%error, "failed to load email verification option");
            return unavailable();
        }
    }
    if !valid_relative_signature(
        &state,
        uri.path(),
        query.as_deref().unwrap_or_default(),
        false,
    ) {
        return (StatusCode::FORBIDDEN, "Invalid link.").into_response();
    }
    match database
        .user_profile(&state.config.database.table_prefix, uid)
        .await
    {
        Ok(Some(_)) => {}
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, uid, "failed to find email verification user");
            return unavailable();
        }
    }
    let chinese = request_locale(&state).starts_with("zh");
    let site_name = site_name(&state).await;
    let app_dir = state.public_dir.join("app");
    let stylesheet = frontend_entrypoint(&app_dir, "style", "css", &request_app_url(&state)).await;
    let frontend_script =
        frontend_entrypoint(&app_dir, "app", "js", &request_app_url(&state)).await;
    let i18n = load_frontend_translations(&state, &app_dir, &request_locale(&state)).await;
    let frontend_globals_b64 = encode_frontend_globals(
        &state,
        &site_name,
        &format!("auth/verify/{uid}"),
        serde_json::json!({}),
        i18n,
    );
    let page = EmailVerificationPage {
        site_name,
        locale: request_locale(&state),
        title: if chinese {
            "邮箱验证"
        } else {
            "Email Verification"
        }
        .to_owned(),
        prompt: if chinese {
            "请输入账户邮箱以完成验证。"
        } else {
            "Enter your account email address to complete verification."
        }
        .to_owned(),
        action_url: signed_action_url(&state, &uri),
        email_label: if chinese { "邮箱" } else { "Email" }.to_owned(),
        submit_label: if chinese {
            "验证邮箱"
        } else {
            "Verify email"
        }
        .to_owned(),
        frontend_style_available: stylesheet.is_some(),
        frontend_stylesheet: stylesheet.unwrap_or_default(),
        frontend_script_available: frontend_script.is_some(),
        frontend_script: frontend_script.unwrap_or_default(),
        frontend_globals_b64,
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to render email verification page");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn handle_email_verification(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(input_query): Query<BTreeMap<String, String>>,
    RoutePath(uid): RoutePath<String>,
    OriginalUri(uri): OriginalUri,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> Response {
    let Some(uid) = uid.parse::<i64>().ok() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    match verification_is_required(database, &state.config.database.table_prefix).await {
        Ok(true) => {}
        Ok(false) => {
            return login_result(
                1,
                &auth_message(
                    &state,
                    "邮箱验证未启用。",
                    "Email verification is not available.",
                ),
                None,
            );
        }
        Err(error) => {
            tracing::error!(%error, "failed to load email verification option");
            return unavailable();
        }
    }
    if !valid_relative_signature(
        &state,
        uri.path(),
        query.as_deref().unwrap_or_default(),
        false,
    ) {
        return (StatusCode::FORBIDDEN, "Invalid link.").into_response();
    }
    let request = match parse_legacy_input_object(
        &input_query,
        &body,
        headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
    ) {
        Ok(fields) => serde_json::Value::Object(fields),
        Err(()) => {
            return login_result(
                1,
                &auth_message(&state, "邮箱格式无效。", "Invalid email address."),
                None,
            );
        }
    };
    let email = request
        .get("email")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if !valid_email_address(email) {
        return login_result(
            1,
            &auth_message(&state, "邮箱格式无效。", "Invalid email address."),
            None,
        );
    }
    let user = match database
        .user_profile(&state.config.database.table_prefix, uid)
        .await
    {
        Ok(Some(user)) => user,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, uid, "failed to load email verification user");
            return unavailable();
        }
    };
    if user.email != email {
        return login_result(
            1,
            &auth_message(&state, "邮箱不匹配。", "Email doesn't match."),
            None,
        );
    }
    if let Err(error) = database
        .set_user_verified(&state.config.database.table_prefix, uid, true)
        .await
    {
        tracing::error!(%error, uid, "failed to verify user email");
        return unavailable();
    }
    login_result(
        0,
        &auth_message(&state, "邮箱验证成功。", "Email verified successfully."),
        Some(serde_json::json!({"redirectTo":"/user"})),
    )
}

async fn send_verification_email(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(uid) = session_user_id(&state, &headers) else {
        return unauthenticated();
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    match verification_is_required(database, &state.config.database.table_prefix).await {
        Ok(true) => {}
        Ok(false) => {
            return login_result(
                1,
                &auth_message(
                    &state,
                    "邮箱验证未启用。",
                    "Email verification is not available.",
                ),
                None,
            );
        }
        Err(error) => {
            tracing::error!(%error, "failed to load email verification option");
            return unavailable();
        }
    }
    if state.config.mail.mailer.trim().is_empty() {
        return login_result(
            1,
            &auth_message(
                &state,
                "邮件发送未配置。",
                "Email delivery is not configured.",
            ),
            None,
        );
    }
    let user = match database
        .user_profile(&state.config.database.table_prefix, uid)
        .await
    {
        Ok(Some(user)) => user,
        Ok(None) => return unauthenticated(),
        Err(error) => {
            tracing::error!(%error, uid, "failed to load email-verification recipient");
            return unavailable();
        }
    };
    if user.permission == -1 {
        let message = if request_locale(&state).starts_with("zh") {
            "你已被本站封禁，详情请联系站点管理员"
        } else {
            "You are banned on this site. Please contact the admin."
        };
        let mut response = login_result(-1, message, None);
        *response.status_mut() = StatusCode::FORBIDDEN;
        return response;
    }
    if user.verified {
        return login_result(
            1,
            &auth_message(
                &state,
                "账户已经验证。",
                "Your account is already verified.",
            ),
            None,
        );
    }
    let session_fingerprint = web_session_claims(&state, &headers)
        .map(|(token, claims)| {
            claims
                .jti
                .as_deref()
                .filter(|jti| !jti.is_empty())
                .map(web_session_identity_fingerprint)
                .unwrap_or_else(|| web_session_fingerprint(&token))
        })
        .unwrap_or_else(|| format!("user:{uid}"));
    let key = format!("verify:{uid}:{session_fingerprint}");
    if reserve_mail_limit(&state, &key, Duration::from_secs(60)).is_err() {
        return login_result(
            1,
            &auth_message(
                &state,
                "请等待一分钟后再发送验证邮件。",
                "You click the send button too fast. Wait for 60 secs.",
            ),
            None,
        );
    }
    let locale = request_locale(&state);
    let Some((subject, body)) = verification_mail_content(&state, uid, &locale).await else {
        release_mail_limit(&state, &key);
        return unavailable();
    };
    match crate::mailer::send_email(&state.config.mail, &user.email, &subject, &body).await {
        Ok(()) => login_result(
            0,
            &auth_message(
                &state,
                "验证邮件已发送，请检查收件箱。",
                "Verification link was sent, please check your inbox.",
            ),
            None,
        ),
        Err(error) => {
            release_mail_limit(&state, &key);
            tracing::warn!(%error, uid, "failed to send email verification mail");
            let message = verification_email_failure_message(&request_locale(&state), &error);
            login_result(2, &message, None)
        }
    }
}

fn forgot_password_failure_message(locale: &str, error: &impl std::fmt::Display) -> String {
    if locale.starts_with("zh") {
        format!("邮件发送失败，详细信息：{error}")
    } else {
        format!("Failed to send verification mail. {error}")
    }
}

fn verification_email_failure_message(locale: &str, error: &impl std::fmt::Display) -> String {
    if locale.starts_with("zh") {
        format!("邮件发送失败，详细信息：{error}")
    } else {
        format!("We failed to send you the verification link. Detailed message {error}")
    }
}

fn auth_message<'a>(state: &AppState, chinese: &'a str, english: &'a str) -> &'a str {
    if request_locale(&state).starts_with("zh") {
        chinese
    } else {
        english
    }
}

fn reserve_mail_limit(state: &AppState, key: &str, window: Duration) -> Result<(), Duration> {
    let now = Instant::now();
    let mut limits = state
        .mail_limits
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    limits.retain(|_, sent| sent.elapsed() < Duration::from_secs(3600));
    if let Some(sent) = limits.get(key) {
        let elapsed = sent.elapsed();
        if elapsed < window {
            return Err(window - elapsed);
        }
    }
    limits.insert(key.to_owned(), now);
    Ok(())
}

fn release_mail_limit(state: &AppState, key: &str) {
    state
        .mail_limits
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(key);
}

async fn verification_is_required(
    database: &DatabasePool,
    prefix: &str,
) -> Result<bool, sqlx::Error> {
    Ok(database
        .option(prefix, "require_verification")
        .await?
        .as_deref()
        .is_some_and(|value| legacy_option_bool(Some(value))))
}

fn signed_relative_url(state: &AppState, path: &str, expires: Option<u64>) -> Option<String> {
    let key = state.config.app_key.as_deref()?;
    let mut params = BTreeMap::new();
    if let Some(expires) = expires {
        params.insert("expires", expires.to_string());
    }
    let query = form_urlencoded::Serializer::new(String::new())
        .extend_pairs(params.iter())
        .finish();
    let unsigned = if query.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{query}")
    };
    let signature = signature_hex(key, &unsigned)?;
    let signed = if query.is_empty() {
        format!("{path}?signature={signature}")
    } else {
        format!("{path}?{query}&signature={signature}")
    };
    Some(signed)
}

async fn verification_mail_content(
    state: &AppState,
    uid: i64,
    locale: &str,
) -> Option<(String, String)> {
    let path = signed_relative_url(state, &format!("/auth/verify/{uid}"), None)?;
    let url = format!("{}{}", request_app_url(state).trim_end_matches('/'), path);
    let site_name = site_name(state).await;
    let (subject, body) = if locale.starts_with("zh") {
        (
            format!("验证你的 {site_name} 账户"),
            format!(
                "有人注册了 {site_name} 账户。如果这是你的账户，请访问以下链接验证邮箱：\n{url}\n\n如果你没有注册，请忽略此邮件。"
            ),
        )
    } else {
        (
            format!("Verify your account on {site_name}"),
            format!(
                "Someone registered an account with this email address on {site_name}. Verify your email by visiting:\n{url}\n\nIf you did not register, you can ignore this email."
            ),
        )
    };
    Some((subject, body))
}

async fn send_registration_verification_email(
    state: &AppState,
    uid: i64,
    email: &str,
    locale: &str,
) {
    let Some(database) = &state.database else {
        return;
    };
    match verification_is_required(database, &state.config.database.table_prefix).await {
        Ok(false) => return,
        Ok(true) => {}
        Err(error) => {
            tracing::warn!(%error, user_id = uid, "could not read email-verification setting after registration");
            return;
        }
    }
    let Some((subject, body)) = verification_mail_content(state, uid, locale).await else {
        tracing::warn!(
            user_id = uid,
            "could not create signed email-verification link after registration"
        );
        return;
    };
    if let Err(error) = crate::mailer::send_email(&state.config.mail, email, &subject, &body).await
    {
        tracing::warn!(%error, user_id = uid, "failed to send registration email-verification message");
    }
}

fn valid_relative_signature(
    state: &AppState,
    path: &str,
    raw_query: &str,
    require_expires: bool,
) -> bool {
    let Some(key) = state.config.app_key.as_deref() else {
        return false;
    };
    let mut params = BTreeMap::new();
    for (name, value) in form_urlencoded::parse(raw_query.as_bytes()) {
        params.insert(name.into_owned(), value.into_owned());
    }
    let Some(signature) = params.remove("signature") else {
        return false;
    };
    let expires = match params.get("expires") {
        Some(value) => match value.parse::<u64>() {
            Ok(expires) => Some(expires),
            Err(_) => return false,
        },
        None => None,
    };
    if require_expires && expires.is_none() {
        return false;
    }
    if expires.is_some_and(|expires| unix_timestamp() > expires) {
        return false;
    }
    let query = form_urlencoded::Serializer::new(String::new())
        .extend_pairs(params.iter())
        .finish();
    let unsigned = if query.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{query}")
    };
    let Some(expected) = signature_hex(key, &unsigned) else {
        return false;
    };
    bool::from(expected.as_bytes().ct_eq(signature.as_bytes()))
}

fn signature_hex(key: &str, value: &str) -> Option<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).ok()?;
    mac.update(value.as_bytes());
    let digest = mac.finalize().into_bytes();
    let digits = b"0123456789abcdef";
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push(digits[(byte >> 4) as usize] as char);
        hex.push(digits[(byte & 0x0f) as usize] as char);
    }
    Some(hex)
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn signed_action_url(state: &AppState, uri: &axum::http::Uri) -> String {
    format!(
        "{}{}",
        request_app_url(&state).trim_end_matches('/'),
        uri.path_and_query()
            .map(|value| value.as_str())
            .unwrap_or(uri.path())
    )
}

async fn captcha_image(State(state): State<AppState>) -> Response {
    let session_id = Alphanumeric.sample_string(&mut rand::thread_rng(), 32);
    let choices = b"23456789";
    let phrase = (0..6)
        .map(|_| choices[rand::thread_rng().gen_range(0..choices.len())] as char)
        .collect::<String>();
    {
        let mut challenges = state
            .captcha_challenges
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        challenges.retain(|_, (_, created)| created.elapsed() < Duration::from_secs(300));
        challenges.insert(session_id.clone(), (phrase.clone(), Instant::now()));
    }
    let bytes = match captcha_jpeg(&phrase) {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::error!(%error, "failed to render CAPTCHA image");
            return unavailable();
        }
    };
    let secure = if request_app_url(&state).starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    let cookie = format!(
        "blessing_skin_captcha={session_id}; Path=/auth; HttpOnly; SameSite=Lax; Max-Age=300{secure}"
    );
    let mut response = Response::new(Body::from(bytes));
    *response.status_mut() = StatusCode::OK;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("image/jpeg"));
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store, private"));
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().insert(SET_COOKIE, value);
    }
    response
}

fn captcha_jpeg(phrase: &str) -> Result<Vec<u8>, image::ImageError> {
    let mut rng = rand::thread_rng();
    let mut image = RgbImage::from_pixel(180, 60, Rgb([248, 250, 252]));
    for _ in 0..180 {
        let x = rng.gen_range(0..180);
        let y = rng.gen_range(0..60);
        let shade = rng.gen_range(170..225);
        image.put_pixel(x, y, Rgb([shade, shade, shade]));
    }
    for _ in 0..4 {
        let color = Rgb([
            rng.gen_range(140..190),
            rng.gen_range(140..190),
            rng.gen_range(140..190),
        ]);
        draw_captcha_line(
            &mut image,
            rng.gen_range(0..180),
            rng.gen_range(0..60),
            rng.gen_range(0..180),
            rng.gen_range(0..60),
            color,
        );
    }
    for (index, digit) in phrase.chars().enumerate() {
        let rows = captcha_digit_rows(digit);
        let origin_x = 10 + index as u32 * 27;
        let origin_y = 12;
        for (row, bits) in rows.iter().enumerate() {
            for column in 0..3 {
                if bits & (1 << (2 - column)) == 0 {
                    continue;
                }
                for dy in 0..7 {
                    for dx in 0..7 {
                        image.put_pixel(
                            origin_x + column * 7 + dx,
                            origin_y + row as u32 * 7 + dy,
                            Rgb([35, 45, 60]),
                        );
                    }
                }
            }
        }
    }
    let mut output = Cursor::new(Vec::new());
    image::DynamicImage::ImageRgb8(image).write_to(&mut output, ImageFormat::Jpeg)?;
    Ok(output.into_inner())
}

fn captcha_digit_rows(digit: char) -> [u8; 5] {
    match digit {
        '2' => [0b111, 0b001, 0b111, 0b100, 0b111],
        '3' => [0b111, 0b001, 0b111, 0b001, 0b111],
        '4' => [0b101, 0b101, 0b111, 0b001, 0b001],
        '5' => [0b111, 0b100, 0b111, 0b001, 0b111],
        '6' => [0b111, 0b100, 0b111, 0b101, 0b111],
        '7' => [0b111, 0b001, 0b010, 0b010, 0b010],
        '8' => [0b111, 0b101, 0b111, 0b101, 0b111],
        '9' => [0b111, 0b101, 0b111, 0b001, 0b111],
        _ => [0b111, 0b101, 0b101, 0b101, 0b111],
    }
}

fn draw_captcha_line(
    image: &mut RgbImage,
    mut x0: u32,
    mut y0: u32,
    x1: u32,
    y1: u32,
    color: Rgb<u8>,
) {
    let dx = x0.abs_diff(x1) as i32;
    let sx = if x0 < x1 { 1 } else { -1 };
    let dy = -(y0.abs_diff(y1) as i32);
    let sy = if y0 < y1 { 1 } else { -1 };
    let mut error = dx + dy;
    loop {
        image.put_pixel(x0, y0, color);
        if x0 == x1 && y0 == y1 {
            break;
        }
        let twice = 2 * error;
        if twice >= dy {
            error += dy;
            x0 = (i64::from(x0) + i64::from(sx)).clamp(0, i64::from(image.width() - 1)) as u32;
        }
        if twice <= dx {
            error += dx;
            y0 = (i64::from(y0) + i64::from(sy)).clamp(0, i64::from(image.height() - 1)) as u32;
        }
    }
}

#[derive(Deserialize)]
struct RecaptchaVerification {
    success: bool,
}

async fn verify_registration_captcha(
    state: &AppState,
    headers: &HeaderMap,
    value: &str,
) -> Result<bool, Response> {
    let Some(database) = &state.database else {
        return Err(unavailable());
    };
    let secret = match database
        .option(&state.config.database.table_prefix, "recaptcha_secretkey")
        .await
    {
        Ok(secret) => secret.unwrap_or_default(),
        Err(error) => {
            tracing::error!(%error, "failed to read reCAPTCHA secret");
            return Err(unavailable());
        }
    };
    if !secret.is_empty() {
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
        {
            Ok(client) => client,
            Err(error) => {
                tracing::error!(%error, "failed to construct reCAPTCHA client");
                return Err(unavailable());
            }
        };
        let verification = match client
            .post("https://www.recaptcha.net/recaptcha/api/siteverify")
            .form(&[("secret", secret.as_str()), ("response", value)])
            .send()
            .await
        {
            Ok(response) => match response.error_for_status() {
                Ok(response) => match response.json::<RecaptchaVerification>().await {
                    Ok(verification) => verification,
                    Err(error) => {
                        tracing::warn!(%error, "reCAPTCHA returned invalid JSON");
                        return Ok(false);
                    }
                },
                Err(error) => {
                    tracing::warn!(%error, "reCAPTCHA returned an HTTP error");
                    return Ok(false);
                }
            },
            Err(error) => {
                tracing::warn!(%error, "reCAPTCHA verification request failed");
                return Err(unavailable());
            }
        };
        return Ok(verification.success);
    }

    let Some(session_id) = cookie_value(headers, "blessing_skin_captcha") else {
        return Ok(false);
    };
    let challenge = state
        .captcha_challenges
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(session_id);
    Ok(challenge.is_some_and(|(answer, created)| {
        created.elapsed() <= Duration::from_secs(300) && answer.eq_ignore_ascii_case(value.trim())
    }))
}

fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|cookie| {
            let (cookie_name, value) = cookie.trim().split_once('=')?;
            (cookie_name == name && !value.is_empty()).then_some(value)
        })
}

async fn filtered_client_ip(state: &AppState, headers: &HeaderMap) -> String {
    let ip = registration_client_ip(headers);
    let filtered = apply_plugin_filter_value(
        state,
        "client_ip",
        &serde_json::json!(ip),
        &serde_json::json!({"ip": ip}),
    )
    .await;
    filtered.as_str().unwrap_or(&ip).to_owned()
}

fn registration_client_ip(headers: &HeaderMap) -> String {
    for name in ["x-real-ip", "x-forwarded-for"] {
        let Some(value) = headers.get(name).and_then(|value| value.to_str().ok()) else {
            continue;
        };
        let candidate = value.split(',').next().unwrap_or_default().trim();
        if candidate.parse::<std::net::IpAddr>().is_ok() {
            return candidate.to_owned();
        }
    }
    "unknown".to_owned()
}

async fn infer_peer_client_ip(
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if registration_client_ip(request.headers()) == "unknown"
        && let Some(axum::extract::ConnectInfo(address)) =
            request
                .extensions()
                .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
    {
        let peer_ip = address.ip().to_string();
        if let Ok(value) = HeaderValue::from_str(&peer_ip) {
            request.headers_mut().insert("x-real-ip", value);
        }
    }
    next.run(request).await
}

fn registration_plugin_events(
    uid: i64,
    initial_player: Option<&crate::database::PlayerRecord>,
) -> Vec<(&'static str, serde_json::Value)> {
    let user_event = serde_json::json!({"user_id": uid});
    let mut events = vec![
        ("auth.registration.completed", user_event.clone()),
        ("user.registered", user_event.clone()),
    ];
    if let Some(player) = initial_player {
        events.push((
            "player.added",
            serde_json::json!({"user_id": uid, "player_id": player.pid, "name": player.name}),
        ));
    }
    events.push(("auth.login.ready", user_event.clone()));
    events.push(("auth.login.succeeded", user_event.clone()));
    events.push(("user.logged-in", user_event));
    events
}

async fn handle_register(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
    body: Bytes,
) -> Response {
    if let Some(response) = authenticated_guest_redirect(&state, &headers).await {
        return response;
    }
    let can_register = apply_plugin_filter_value(
        &state,
        "can_register",
        &serde_json::Value::Null,
        &serde_json::json!({}),
    )
    .await;
    if let Some(reason) = plugin_filter_rejection(&can_register) {
        return login_result(1, reason, None);
    }
    if state.session_key.is_none() {
        tracing::error!("APP_KEY is required to create a web login session");
        return unavailable();
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    let request = match parse_legacy_input_object(
        &query,
        &body,
        headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
    ) {
        Ok(fields) => serde_json::Value::Object(fields),
        Err(()) => {
            return registration_validation_error("email", "required", &request_locale(&state));
        }
    };
    let body_locale = request
        .get("lang")
        .and_then(serde_json::Value::as_str)
        .and_then(normalize_locale);
    let locale = body_locale
        .map(str::to_owned)
        .unwrap_or_else(|| request_locale(&state));
    let Some(email) = request
        .get("email")
        .and_then(serde_json::Value::as_str)
        .filter(|email| valid_email_address(email) && email.len() <= 100)
    else {
        return registration_validation_error("email", "email", &locale);
    };
    let Some(password) = request
        .get("password")
        .and_then(serde_json::Value::as_str)
        .filter(|password| (8..=32).contains(&password.chars().count()))
    else {
        return registration_validation_error("password", "length", &locale);
    };
    let Some(captcha) = request
        .get("captcha")
        .or_else(|| request.get("g-recaptcha-response"))
        .and_then(serde_json::Value::as_str)
        .filter(|captcha| !captcha.trim().is_empty())
    else {
        return registration_validation_error("captcha", "required", &locale);
    };
    match verify_registration_captcha(&state, &headers, captcha).await {
        Ok(true) => {}
        Ok(false) => {
            return registration_validation_error("captcha", "invalid", &locale);
        }
        Err(response) => return response,
    }

    let prefix = &state.config.database.table_prefix;
    let player_name_registration = match database.option(prefix, "register_with_player_name").await
    {
        Ok(value) => value
            .as_deref()
            .map(|value| legacy_option_bool(Some(value)))
            .unwrap_or(true),
        Err(error) => {
            tracing::error!(%error, "failed to read registration mode");
            return unavailable();
        }
    };
    let mut player_name = None;
    let nickname = if player_name_registration {
        let Some(name) = request
            .get("player_name")
            .and_then(serde_json::Value::as_str)
            .filter(|name| !name.is_empty())
        else {
            return registration_validation_error("player_name", "required", &locale);
        };
        let rule = match database.option(prefix, "player_name_rule").await {
            Ok(value) => value.unwrap_or_else(|| "official".to_owned()),
            Err(error) => {
                tracing::error!(%error, "failed to read player-name rule");
                return unavailable();
            }
        };
        let custom_rule = match database.option(prefix, "custom_player_name_regexp").await {
            Ok(value) => value.unwrap_or_default(),
            Err(error) => {
                tracing::error!(%error, "failed to read custom player-name rule");
                return unavailable();
            }
        };
        let min_length = match database.option(prefix, "player_name_length_min").await {
            Ok(value) => value
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(3),
            Err(error) => {
                tracing::error!(%error, "failed to read minimum player-name length");
                return unavailable();
            }
        };
        let max_length = match database.option(prefix, "player_name_length_max").await {
            Ok(value) => value
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(16),
            Err(error) => {
                tracing::error!(%error, "failed to read maximum player-name length");
                return unavailable();
            }
        };
        if !valid_player_name(name, &rule, &custom_rule, min_length, max_length) {
            return registration_validation_error("player_name", "format", &locale);
        }
        player_name = Some(name);
        name
    } else {
        let Some(nickname) = request
            .get("nickname")
            .and_then(serde_json::Value::as_str)
            .filter(|nickname| !nickname.is_empty() && nickname.chars().count() <= 255)
        else {
            return registration_validation_error("nickname", "required", &locale);
        };
        nickname
    };

    match database.user_email_exists(prefix, email, 0).await {
        Ok(true) => return registration_validation_error("email", "unique", &locale),
        Ok(false) => {}
        Err(error) => {
            tracing::error!(%error, "failed to check registration email uniqueness");
            return unavailable();
        }
    }
    emit_plugin_event(
        &state,
        "auth.registration.attempt",
        serde_json::json!({"with_player_name": player_name.is_some()}),
    )
    .await;
    if let Some(name) = player_name {
        match database.admin_player_name_exists(prefix, name).await {
            Ok(true) => {
                return login_result(
                    1,
                    if locale.starts_with("zh") {
                        "该角色名已被占用"
                    } else {
                        "The player name is already registered."
                    },
                    None,
                );
            }
            Ok(false) => {}
            Err(error) => {
                tracing::error!(%error, "failed to check registration player name");
                return unavailable();
            }
        }
    }
    let client_ip = filtered_client_ip(&state, &headers).await;
    let max_registrations_per_ip = match database.option(prefix, "regs_per_ip").await {
        Ok(value) => legacy_option_integer(value.as_deref(), 3),
        Err(error) => {
            tracing::error!(%error, "failed to read registration IP limit");
            return unavailable();
        }
    };
    let registered_from_ip = match database
        .registered_user_count_by_ip(prefix, &client_ip)
        .await
    {
        Ok(count) => count,
        Err(error) => {
            tracing::error!(%error, "failed to count registrations from client IP");
            return unavailable();
        }
    };
    if registered_from_ip >= max_registrations_per_ip {
        return login_result(
            1,
            &if locale.starts_with("zh") {
                format!("你在本站注册的账号已达到上限 {max_registrations_per_ip} 个，无法继续注册")
            } else {
                format!("You can't register more than {max_registrations_per_ip} accounts.")
            },
            None,
        );
    }
    emit_plugin_event(
        &state,
        "auth.registration.ready",
        serde_json::json!({"with_player_name": player_name.is_some()}),
    )
    .await;
    let initial_score = match database.option(prefix, "user_initial_score").await {
        Ok(value) => legacy_option_integer(value.as_deref(), 1000),
        Err(error) => {
            tracing::error!(%error, "failed to read initial user score");
            return unavailable();
        }
    };
    let Some(password_hash) = hash_legacy_password(
        password,
        &state.config.password_method,
        &state.config.password_salt,
        state.config.bcrypt_rounds,
    ) else {
        tracing::error!(method = %state.config.password_method, "unsupported configured legacy password method");
        return unavailable();
    };
    let password_hash = filter_user_password_hash(&state, &password_hash).await;
    let now = shanghai_now();
    let last_sign_at = now - chrono::Duration::days(1);
    let now = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let last_sign_at = last_sign_at.format("%Y-%m-%d %H:%M:%S").to_string();
    match database
        .register_user(
            prefix,
            email,
            nickname,
            initial_score,
            &password_hash,
            &client_ip,
            &now,
            &last_sign_at,
            max_registrations_per_ip,
            player_name,
        )
        .await
    {
        Ok(crate::database::UserRegistrationOutcome::EmailExists) => {
            registration_validation_error("email", "unique", &locale)
        }
        Ok(crate::database::UserRegistrationOutcome::PlayerNameExists) => login_result(
            1,
            if locale.starts_with("zh") {
                "该角色名已被占用"
            } else {
                "The player name is already registered."
            },
            None,
        ),
        Ok(crate::database::UserRegistrationOutcome::IpLimit) => login_result(
            1,
            &if locale.starts_with("zh") {
                format!("你在本站注册的账号已达到上限 {max_registrations_per_ip} 个，无法继续注册")
            } else {
                format!("You can't register more than {max_registrations_per_ip} accounts.")
            },
            None,
        ),
        Ok(crate::database::UserRegistrationOutcome::Registered { uid, player }) => {
            let requested_locale = body_locale
                .or_else(|| explicit_request_locale().and_then(|locale| normalize_locale(&locale)));
            if let Some(locale) = requested_locale {
                if let Err(error) = database.update_user_locale(prefix, uid, locale).await {
                    tracing::warn!(%error, user_id = uid, "failed to save registration locale");
                }
            }
            send_registration_verification_email(&state, uid, email, &locale).await;
            let now_epoch = jsonwebtoken::get_current_timestamp();
            let claims = crate::auth::WebSessionClaims {
                jti: Some(Alphanumeric.sample_string(&mut rand::thread_rng(), 32)),
                sub: uid.to_string(),
                iat: now_epoch,
                exp: now_epoch.saturating_add(state.config.session_lifetime_seconds),
                remember: false,
            };
            let Some(key) = &state.session_key else {
                return unavailable();
            };
            let session = match encode(&Header::new(Algorithm::HS256), &claims, key) {
                Ok(session) => session,
                Err(error) => {
                    tracing::error!(%error, user_id = uid, "failed to issue post-registration session");
                    return unavailable();
                }
            };
            let message = if locale.starts_with("zh") {
                "注册成功，正在跳转..."
            } else {
                "Your account was registered. Redirecting..."
            };
            let mut response = login_result(0, message, None);
            let secure = if request_app_url(&state).starts_with("https://") {
                "; Secure"
            } else {
                ""
            };
            let cookie = format!(
                "blessing_skin_session={session}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}{secure}",
                state.config.session_lifetime_seconds
            );
            match HeaderValue::from_str(&cookie) {
                Ok(value) => {
                    response.headers_mut().insert(SET_COOKIE, value);
                }
                Err(error) => {
                    tracing::error!(%error, user_id = uid, "failed to create post-registration session cookie");
                    return unavailable();
                }
            }
            for (event, payload) in registration_plugin_events(uid, player.as_ref()) {
                emit_plugin_event(&state, event, payload).await;
            }
            response
        }
        Err(error) => {
            tracing::error!(%error, "failed to create new user registration");
            unavailable()
        }
    }
}

fn registration_validation_error(field: &str, rule: &str, locale: &str) -> Response {
    let chinese = locale.starts_with("zh");
    let message = if chinese {
        "给定数据无效。"
    } else {
        "The given data was invalid."
    };
    let error = match (field, rule, chinese) {
        ("email", "unique", true) => "该邮箱已被使用。",
        ("email", "unique", false) => "The email has already been taken.",
        ("email", "email", true) => "邮箱格式无效。",
        ("email", "email", false) => "The email must be a valid email address.",
        ("email", _, true) => "邮箱为必填项。",
        ("email", _, false) => "The email field is required.",
        ("password", _, true) => "密码为必填项且长度必须为 8 至 32 个字符。",
        ("password", _, false) => {
            "The password field is required and must be between 8 and 32 characters."
        }
        ("captcha", "invalid", true) => "验证码无效。",
        ("captcha", "invalid", false) => "The CAPTCHA is invalid.",
        ("captcha", _, true) => "验证码为必填项。",
        ("captcha", _, false) => "The CAPTCHA field is required.",
        ("player_name", "format", true) => "角色名格式或长度无效。",
        ("player_name", "format", false) => "The player name format or length is invalid.",
        ("player_name", _, true) => "角色名为必填项。",
        ("player_name", _, false) => "The player_name field is required.",
        ("nickname", _, true) => "昵称为必填项且不能超过 255 个字符。",
        ("nickname", _, false) => {
            "The nickname field is required and may not exceed 255 characters."
        }
        _ => "The given field is invalid.",
    };
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(serde_json::json!({ "message": message, "errors": { field: [error] } })),
    )
        .into_response()
}

#[derive(Deserialize)]
struct LoginRequest {
    identification: Option<String>,
    password: Option<String>,
    keep: Option<bool>,
    captcha: Option<String>,
    redirect_to: Option<String>,
    lang: Option<String>,
}

async fn handle_login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
    body: Bytes,
) -> Response {
    if let Some(response) = authenticated_guest_redirect(&state, &headers).await {
        return response;
    }
    let mut fields = match parse_legacy_input_object(
        &query,
        &body,
        headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
    ) {
        Ok(fields) => fields,
        Err(()) => return validation_error("identification", &request_locale(&state)),
    };
    if let Some(serde_json::Value::String(keep)) = fields.get("keep") {
        let keep = !keep.is_empty() && keep != "0";
        fields.insert("keep".to_owned(), serde_json::Value::Bool(keep));
    }
    let request: LoginRequest = match serde_json::from_value(serde_json::Value::Object(fields)) {
        Ok(request) => request,
        Err(_) => return validation_error("identification", &request_locale(&state)),
    };
    let body_locale = request.lang.as_deref().and_then(normalize_locale);
    let locale = body_locale
        .map(str::to_owned)
        .unwrap_or_else(|| request_locale(&state));
    let Some(identification) = request
        .identification
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.trim().to_owned())
    else {
        return validation_error("identification", &locale);
    };
    let Some(password) = request.password.filter(|value| !value.is_empty()) else {
        return validation_error("password", &locale);
    };
    if !(6..=32).contains(&password.chars().count()) {
        return validation_error("password", &locale);
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    let auth_type = if looks_like_email(&identification) {
        "email"
    } else {
        "username"
    };
    emit_plugin_event(
        &state,
        "auth.login.attempt",
        serde_json::json!({"auth_type": auth_type}),
    )
    .await;
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
        Ok(credential) => credential,
        Err(error) => {
            tracing::error!(%error, "failed to look up login account");
            return unavailable();
        }
    };
    let failure_key = filtered_client_ip(&state, &headers).await;
    let failures = login_failure_count(&state, &failure_key);
    if failures > 3 {
        let captcha_valid = if let Some(captcha) = request.captcha.as_deref() {
            match verify_registration_captcha(&state, &headers, captcha).await {
                Ok(valid) => valid,
                Err(response) => return response,
            }
        } else {
            false
        };
        if !captcha_valid {
            return login_result(
                1,
                if locale.starts_with("zh") {
                    "验证码无效。"
                } else {
                    "The CAPTCHA is invalid."
                },
                Some(serde_json::json!({ "login_fails": failures })),
            );
        }
    }
    let Some(credential) = credential else {
        let message = if locale.starts_with("zh") {
            "用户不存在"
        } else {
            "No such user."
        };
        return login_result(2, message, None);
    };
    emit_plugin_event(
        &state,
        "auth.login.ready",
        serde_json::json!({"user_id": credential.uid}),
    )
    .await;
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
            let entry = attempts.entry(failure_key.clone()).or_insert((0, now));
            if now.duration_since(entry.1) >= Duration::from_secs(3600) {
                entry.0 = 0;
            }
            entry.0 = entry.0.saturating_add(1);
            entry.1 = now;
            entry.0
        };
        emit_plugin_event(
            &state,
            "auth.login.failed",
            serde_json::json!({"user_id": credential.uid, "login_fails": failures}),
        )
        .await;
        let message = if locale.starts_with("zh") {
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
    let remember = request.keep.unwrap_or(false);
    let max_age = if remember {
        LEGACY_REMEMBER_TTL_SECONDS
    } else {
        state.config.session_lifetime_seconds
    };
    let claims = crate::auth::WebSessionClaims {
        jti: Some(Alphanumeric.sample_string(&mut rand::thread_rng(), 32)),
        sub: credential.uid.to_string(),
        iat: now,
        exp: now.saturating_add(max_age),
        remember,
    };
    let session = match encode(&Header::new(Algorithm::HS256), &claims, key) {
        Ok(session) => session,
        Err(error) => {
            tracing::error!(%error, "failed to issue web login session");
            return unavailable();
        }
    };
    let requested_locale = body_locale
        .or_else(|| explicit_request_locale().and_then(|locale| normalize_locale(&locale)));
    if let Some(locale) = requested_locale {
        if let Err(error) = database
            .update_user_locale(&state.config.database.table_prefix, credential.uid, locale)
            .await
        {
            tracing::warn!(%error, user_id = credential.uid, "failed to save login locale");
        }
    }

    state
        .login_failures
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(&failure_key);

    let message = if locale.starts_with("zh") {
        "登录成功，欢迎回来"
    } else {
        "Logged in successfully."
    };
    let mut response = login_result(
        0,
        message,
        Some(
            serde_json::json!({ "redirectTo": safe_local_redirect(request.redirect_to.as_deref()).unwrap_or_else(|| "/user".to_owned()) }),
        ),
    );
    let secure = if request_app_url(&state).starts_with("https://") {
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
            emit_plugin_event(
                &state,
                "auth.login.succeeded",
                serde_json::json!({"user_id": credential.uid}),
            )
            .await;
            emit_plugin_event(
                &state,
                "user.logged-in",
                serde_json::json!({"user_id": credential.uid}),
            )
            .await;
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
    browse_skinlib: String,
    favicon: String,
    theme_color: &'static str,
    meta_keywords: String,
    meta_description: String,
    meta_extras: String,
    cdn_address: String,
    home_css_available: bool,
    home_stylesheet: String,
    frontend_style_available: bool,
    frontend_stylesheet: String,
    frontend_script_available: bool,
    frontend_script: String,
    home_script_available: bool,
    home_script: String,
    custom_css: String,
    custom_js: String,
    frontend_globals_b64: String,
}

fn legacy_site_description(value: Option<String>) -> String {
    value.unwrap_or_else(|| crate::admin_settings::LEGACY_DEFAULT_SITE_DESCRIPTION.to_owned())
}

fn legacy_copyright_text(value: Option<String>, site_name: &str, site_url: &str) -> String {
    value
        .unwrap_or_else(|| crate::admin_settings::LEGACY_DEFAULT_COPYRIGHT_TEXT.to_owned())
        .replace("{site_name}", site_name)
        .replace("{site_url}", site_url)
}
async fn home(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let site_name = site_name(&state).await;
    let locale = &request_locale(&state);
    let chinese = locale.starts_with("zh");
    let title = if chinese { "皮肤站" } else { "Skin Server" }.to_owned();
    let login = if chinese { "登录" } else { "Log in" }.to_owned();
    let register = if chinese {
        "现在注册"
    } else {
        "Register Now"
    }
    .to_owned();
    let browse_skinlib = if chinese { "皮肤库" } else { "Skin Library" }.to_owned();
    let user_center = if chinese {
        "用户中心"
    } else {
        "User Center"
    }
    .to_owned();
    let admin_panel = if chinese {
        "管理面板"
    } else {
        "Admin Panel"
    }
    .to_owned();
    let logout = if chinese { "登出" } else { "Log Out" }.to_owned();
    let site_description =
        legacy_site_description(localized_site_option(&state, "site_description").await);
    let home_pic_url = resolve_legacy_home_background(
        site_option(&state, "home_pic_url")
            .await
            .filter(|value| legacy_option_bool(Some(value))),
        state.public_dir.join("app/bg.jpg").is_file(),
        state.public_dir.join("app/bg.webp").is_file(),
    );
    let fixed_bg = option_is_enabled(&state, "fixed_bg").await;
    let hide_intro = option_is_enabled(&state, "hide_intro").await;
    let transparent_navbar = option_is_enabled(&state, "transparent_navbar").await;
    let navbar_color = site_option(&state, "navbar_color")
        .await
        .filter(|color| {
            matches!(
                color.as_str(),
                "primary"
                    | "secondary"
                    | "success"
                    | "danger"
                    | "indigo"
                    | "purple"
                    | "pink"
                    | "teal"
                    | "cyan"
                    | "dark"
                    | "gray"
                    | "fuchsia"
                    | "maroon"
                    | "olive"
                    | "navy"
                    | "lime"
                    | "light"
                    | "warning"
                    | "white"
                    | "orange"
            )
        })
        .unwrap_or_else(|| "cyan".to_owned());
    let theme_color = match navbar_color.as_str() {
        "primary" => "#007bff",
        "secondary" | "gray" => "#6c757d",
        "success" => "#28a745",
        "warning" => "#ffc107",
        "danger" => "#dc3545",
        "navy" => "#001f3f",
        "olive" => "#3d9970",
        "lime" => "#01ff70",
        "fuchsia" => "#f012be",
        "maroon" => "#d81b60",
        "indigo" => "#6610f2",
        "purple" => "#6f42c1",
        "pink" => "#e83e8c",
        "orange" => "#fd7e14",
        "teal" => "#20c997",
        "cyan" => "#17a2b8",
        _ => "#ffffff",
    };
    let meta_keywords = site_option(&state, "meta_keywords")
        .await
        .unwrap_or_default();
    let meta_description = site_option(&state, "meta_description")
        .await
        .unwrap_or_else(|| site_description.clone());
    let meta_extras_raw = site_option(&state, "meta_extras").await.unwrap_or_default();
    let mut meta_sanitizer = ammonia::Builder::default();
    meta_sanitizer.tags(["meta"].into_iter().collect());
    meta_sanitizer.generic_attributes(std::collections::HashSet::new());
    meta_sanitizer.tag_attributes(
        [(
            "meta",
            ["name", "content", "property", "charset", "http-equiv"]
                .into_iter()
                .collect(),
        )]
        .into_iter()
        .collect(),
    );
    let meta_extras = meta_sanitizer.clean(&meta_extras_raw).to_string();
    let app_url = request_app_url(&state);
    let base_url = app_url.trim_end_matches('/');
    let favicon_option = site_option(&state, "favicon_url")
        .await
        .unwrap_or_else(|| "app/favicon.ico".to_owned());
    let favicon = if favicon_option.starts_with("http://") || favicon_option.starts_with("https://")
    {
        favicon_option
    } else {
        format!("{base_url}/{}", favicon_option.trim_start_matches('/'))
    };
    let cdn_address = site_option(&state, "cdn_address").await.unwrap_or_default();
    let custom_css =
        strip_configured_html_tags(&site_option(&state, "custom_css").await.unwrap_or_default());
    let custom_js =
        strip_configured_html_tags(&site_option(&state, "custom_js").await.unwrap_or_default());
    let site_url = site_option(&state, "site_url")
        .await
        .unwrap_or_else(|| base_url.to_owned());
    let copyright_prefer_key = format!("copyright_prefer_{locale}");
    let copyright_prefer = site_option(&state, &copyright_prefer_key)
        .await
        .or(site_option(&state, "copyright_prefer").await)
        .and_then(|value| {
            legacy_boolean_option_index(&value).or_else(|| value.parse::<usize>().ok())
        })
        .filter(|value| *value <= 6)
        .unwrap_or_default();
    let copyright_text = legacy_copyright_text(
        localized_site_option(&state, "copyright_text").await,
        &site_name,
        &site_url,
    );

    let mut authenticated_user = None;
    if let (Some(database), Some(uid)) =
        (state.database.as_ref(), session_user_id(&state, &headers))
    {
        match database
            .user_profile(&state.config.database.table_prefix, uid)
            .await
        {
            Ok(user) => authenticated_user = user,
            Err(error) => tracing::warn!(%error, uid, "could not load homepage session user"),
        }
    }
    let authenticated = authenticated_user.is_some();
    let home_extra = serde_json::json!({
        "title": &title,
        "login": &login,
        "register": &register,
        "browse_skinlib": &browse_skinlib,
        "user_center": &user_center,
        "admin_panel": &admin_panel,
        "logout": &logout,
        "description": &site_description,
        "background": &home_pic_url,
        "fixed_bg": fixed_bg,
        "hide_intro": hide_intro,
        "navbar_color": &navbar_color,
        "authenticated": authenticated,
        "user_id": authenticated_user.as_ref().map(|user| user.uid),
        "user_label": authenticated_user.as_ref().map(|user| {
            if user.nickname.is_empty() { &user.email } else { &user.nickname }
        }),
        "permission": authenticated_user.as_ref().map(|user| user.permission),
        "copyright_prefer": copyright_prefer,
        "copyright_text": &copyright_text,
    });
    let app_dir = state.public_dir.join("app");
    let stylesheet = frontend_entrypoint(&app_dir, "style", "css", &request_app_url(&state)).await;
    let home_stylesheet =
        frontend_entrypoint(&app_dir, "home-css", "css", &request_app_url(&state)).await;
    let frontend_script =
        frontend_entrypoint(&app_dir, "app", "js", &request_app_url(&state)).await;
    let home_script = frontend_entrypoint(&app_dir, "home", "js", &request_app_url(&state)).await;
    let i18n = load_frontend_translations(&state, &app_dir, locale).await;
    let frontend_globals_b64 = encode_frontend_globals(
        &state,
        &site_name,
        "home",
        serde_json::json!({
            "home": home_extra,
            "transparent_navbar": transparent_navbar,
        }),
        i18n,
    );
    let page = HomePage {
        site_name,
        locale: locale.clone(),
        title,
        login,
        browse_skinlib,
        favicon,
        theme_color,
        meta_keywords,
        meta_description,
        meta_extras,
        cdn_address,
        home_css_available: home_stylesheet.is_some(),
        home_stylesheet: home_stylesheet.unwrap_or_default(),
        frontend_style_available: stylesheet.is_some(),
        frontend_stylesheet: stylesheet.unwrap_or_default(),
        frontend_script_available: frontend_script.is_some(),
        frontend_script: frontend_script.unwrap_or_default(),
        home_script_available: home_script.is_some(),
        home_script: home_script.unwrap_or_default(),
        custom_css,
        custom_js,
        frontend_globals_b64,
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to render home page");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn site_option(state: &AppState, key: &str) -> Option<String> {
    state
        .database
        .as_ref()?
        .option(&state.config.database.table_prefix, key)
        .await
        .ok()
        .flatten()
}

async fn localized_site_option(state: &AppState, key: &str) -> Option<String> {
    let localized_key = format!("{key}_{}", request_locale(&state));
    site_option(state, &localized_key)
        .await
        .or(site_option(state, key).await)
}

async fn option_is_enabled(state: &AppState, key: &str) -> bool {
    site_option(state, key)
        .await
        .is_some_and(|value| legacy_option_bool(Some(&value)))
}

fn strip_configured_html_tags(value: &str) -> String {
    let Ok(tag) = regex::Regex::new(r"(?is)</?[a-z!][^>]*>") else {
        return value.to_owned();
    };
    tag.replace_all(value, "").into_owned()
}
#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardPage {
    site_name: String,
    avatar_url: String,
    avatar_png_url: String,
    badges: Vec<DashboardBadge>,
    menu: Vec<DashboardMenuItem>,
    user: UserProfile,
    players: Vec<PlayerRecord>,
    notifications: Vec<DashboardNotification>,
    announcement_html: String,
    page_widgets: Vec<String>,
    side_menu_user: Vec<DashboardMenuItem>,
    side_menu_explore: Vec<DashboardMenuItem>,
    show_email_verification: bool,
    locale: String,
    frontend_style_available: bool,
    frontend_stylesheet: String,
    frontend_script_available: bool,
    frontend_script: String,
    frontend_globals_b64: String,
}

#[derive(Deserialize)]
struct DashboardBadge {
    text: String,
    color: String,
}

#[derive(Deserialize, Serialize)]
struct DashboardMenuItem {
    label: String,
    link: String,
}

struct DashboardNotification {
    id: String,
    title: String,
}

#[derive(Template)]
#[template(path = "admin_dashboard.html")]
struct AdminDashboardPage {
    site_name: String,
    locale: String,
    stats: AdminDashboardStats,
    page_widgets: Vec<String>,
    side_menu: Vec<DashboardMenuItem>,
    frontend_style_available: bool,
    frontend_stylesheet: String,
    frontend_script_available: bool,
    frontend_script: String,
    frontend_globals_b64: String,
}

#[derive(Template)]
#[template(path = "admin_status.html")]
struct AdminStatusPage {
    site_name: String,
    locale: String,
    groups: Vec<AdminStatusGroup>,
    wasm_plugins: Vec<String>,
    page_widgets: Vec<String>,
    frontend_style_available: bool,
    frontend_stylesheet: String,
    frontend_script_available: bool,
    frontend_script: String,
    frontend_globals_b64: String,
}

#[derive(Template)]
#[template(path = "admin_update.html")]
struct AdminUpdatePage {
    site_name: String,
    locale: String,
    version: String,
    latest_version: String,
    has_release_info: bool,
    update_available: bool,
    update_check_failed: bool,
    update_check_disabled: bool,
    update_check_no_release: bool,
    releases_url: String,
}

#[derive(Template)]
#[template(path = "admin_plugins.html")]
struct AdminPluginsPage {
    site_name: String,
    locale: String,
    base_url: String,
    can_upload: bool,
    frontend_style_available: bool,
    frontend_stylesheet: String,
    frontend_script_available: bool,
    frontend_script: String,
    frontend_globals_b64: String,
}

#[derive(Template)]
#[template(path = "admin_plugins_market.html")]
struct AdminPluginMarketPage {
    site_name: String,
    locale: String,
    base_url: String,
    frontend_style_available: bool,
    frontend_stylesheet: String,
    frontend_script_available: bool,
    frontend_script: String,
    frontend_globals_b64: String,
}

#[derive(Template)]
#[template(
    source = r#"<!doctype html><html lang="{{ locale }}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{{ plugin_name }} - {{ heading }}</title><style>body{font-family:system-ui,sans-serif;max-width:920px;margin:2rem auto;padding:0 1rem;color:#222}.message:empty{display:none}textarea{box-sizing:border-box;width:100%;min-height:26rem;font:13px ui-monospace,monospace;padding:.75rem}button{padding:.55rem 1rem} .message{padding:.75rem;background:#f3f4f6;margin:1rem 0;white-space:pre-wrap}</style></head><body><main><h1>{{ heading }}: {{ plugin_name }}</h1><p class="message">{{ message }}</p><form method="post" action="{{ base_url }}/admin/plugins/config/{{ plugin_name }}"><label for="configuration">{{ configuration_label }}</label><p>{{ description }}</p><textarea id="configuration" name="configuration" spellcheck="false">{{ configuration }}</textarea><p><button type="submit">{{ save_label }}</button> <a href="{{ base_url }}/admin/plugins/manage">{{ back_label }}</a></p></form></main></body></html>"#,
    ext = "html"
)]
struct PluginConfigurationPage {
    locale: String,
    base_url: String,
    plugin_name: String,
    heading: String,
    configuration_label: String,
    description: String,
    configuration: String,
    message: String,
    save_label: String,
    back_label: String,
}

#[derive(Template)]
#[template(path = "setup_welcome.html")]
struct SetupWelcomePage {
    locale: String,
    version: String,
    frontend_script_available: bool,
    frontend_script: String,
    frontend_globals_b64: String,
}

#[derive(Template)]
#[template(path = "setup_database.html")]
struct SetupDatabasePage {
    locale: String,
    csrf: String,
    driver: String,
    host: String,
    port: String,
    username: String,
    database: String,
    prefix: String,
    error: String,
    saved: bool,
    frontend_script_available: bool,
    frontend_script: String,
    frontend_globals_b64: String,
}

#[derive(Template)]
#[template(path = "setup_info.html")]
struct SetupInfoPage {
    locale: String,
    csrf: String,
    site_name: String,
    error: String,
    frontend_script_available: bool,
    frontend_script: String,
    frontend_globals_b64: String,
}

#[derive(Template)]
#[template(path = "setup_finish.html")]
struct SetupFinishPage {
    locale: String,
    frontend_script_available: bool,
    frontend_script: String,
    frontend_globals_b64: String,
}

#[derive(Template)]
#[template(path = "setup_locked.html")]
struct SetupLockedPage {
    locale: String,
}

struct SetupPageAssets {
    frontend_script_available: bool,
    frontend_script: String,
    frontend_globals_b64: String,
}

#[derive(Deserialize)]
struct SetupDatabaseRequest {
    csrf: String,
    #[serde(rename = "type")]
    driver: String,
    host: String,
    port: String,
    username: String,
    password: String,
    #[serde(rename = "db")]
    database: String,
    prefix: String,
}

#[derive(Deserialize)]
struct SetupFinishRequest {
    csrf: String,
    email: String,
    nickname: String,
    password: String,
    password_confirmation: String,
    site_name: String,
}

#[derive(Deserialize)]
struct AdminPluginManageRequest {
    action: String,
    name: String,
}

#[derive(Deserialize)]
struct AdminPluginWgetRequest {
    url: String,
}

#[derive(Deserialize)]
struct AdminPluginMarketDownloadRequest {
    name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WasmPluginRegistryManifest {
    schema_version: u32,
    plugins: Vec<WasmPluginRegistryEntry>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WasmPluginRegistryEntry {
    name: String,
    version: String,
    title: String,
    description: String,
    author: String,
    download_url: String,
    sha256: String,
}
#[derive(Deserialize, Serialize)]
struct WasmPluginMarketMetadata {
    version: String,
    sha256: String,
}
#[derive(Template)]
#[template(path = "admin_users.html")]
struct AdminUsersPage {
    site_name: String,
    locale: String,
    current_uid: i64,
    current_permission: i32,
    frontend_style_available: bool,
    frontend_stylesheet: String,
    frontend_script_available: bool,
    frontend_script: String,
    frontend_globals_b64: String,
}

#[derive(Template)]
#[template(path = "admin_players.html")]
struct AdminPlayersPage {
    site_name: String,
    locale: String,
    current_uid: i64,
    current_permission: i32,
    frontend_style_available: bool,
    frontend_stylesheet: String,
    frontend_script_available: bool,
    frontend_script: String,
    frontend_globals_b64: String,
}

#[derive(Template)]
#[template(path = "admin_reports.html")]
struct AdminReportsPage {
    site_name: String,
    locale: String,
    frontend_style_available: bool,
    frontend_stylesheet: String,
    frontend_script_available: bool,
    frontend_script: String,
    frontend_globals_b64: String,
}

#[derive(serde::Serialize)]
struct AdminStatusGroup {
    title: String,
    fields: Vec<AdminStatusField>,
}

#[derive(serde::Serialize)]
struct AdminStatusField {
    label: String,
    value: String,
}

#[derive(Template)]
#[template(path = "players.html")]
struct PlayerManagementPage {
    site_name: String,
    locale: String,
    user: UserProfile,
    page_widgets: Vec<String>,
    has_player_management: bool,
    score_per_player: i64,
    rule_label: String,
    min_length: usize,
    max_length: usize,
    frontend_style_available: bool,
    frontend_stylesheet: String,
    frontend_script_available: bool,
    frontend_script: String,
    frontend_globals_b64: String,
}

#[derive(Template)]
#[template(path = "closet.html")]
struct ClosetManagementPage {
    site_name: String,
    locale: String,
    user: UserProfile,
    page_widgets: Vec<String>,
    has_closet_management: bool,
    frontend_style_available: bool,
    frontend_stylesheet: String,
    frontend_script_available: bool,
    frontend_script: String,
    frontend_globals_b64: String,
}

#[derive(Template)]
#[template(path = "skinlib.html")]
struct SkinLibraryPage {
    site_name: String,
    locale: String,
    logged_in: bool,
    current_uid: i64,
    frontend_style_available: bool,
    frontend_stylesheet: String,
    frontend_script_available: bool,
    frontend_script: String,
    frontend_globals_b64: String,
}

#[derive(Template)]
#[template(path = "skinlib_show.html")]
struct SkinLibraryShowPage {
    site_name: String,
    locale: String,
    tid: i64,
    name: String,
    texture_type: String,
    hash: String,
    size: i64,
    uploader: i64,
    is_public: bool,
    upload_at: String,
    likes: i64,
    logged_in: bool,
    can_manage: bool,
    page_widgets: Vec<String>,
    has_texture_details: bool,
    frontend_style_available: bool,
    frontend_stylesheet: String,
    frontend_script_available: bool,
    frontend_script: String,
    frontend_globals_b64: String,
}

#[derive(Template)]
#[template(path = "texture_upload.html")]
struct TextureUploadPage {
    site_name: String,
    locale: String,
    user: UserProfile,
    public_rate: i64,
    private_rate: i64,
    closet_cost: i64,
    upload_award: i64,
    max_upload_kb: i64,
    content_policy: String,
    page_widgets: Vec<String>,
    has_upload_form: bool,
    frontend_style_available: bool,
    frontend_stylesheet: String,
    frontend_script_available: bool,
    frontend_script: String,
    frontend_globals_b64: String,
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
        Err(_) => return oauth_client_validation_error("name", &request_locale(&state)),
    };
    let Some(name) = request
        .name
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty() && name.chars().count() <= 255)
    else {
        return oauth_client_validation_error("name", &request_locale(&state));
    };
    let Some(redirect) = request
        .redirect
        .map(|redirect| redirect.trim().to_owned())
        .filter(|redirect| valid_oauth_redirect(redirect))
    else {
        return oauth_client_validation_error("redirect", &request_locale(&state));
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
    LegacyRouteId(id): LegacyRouteId,
    body: Bytes,
) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let request = match serde_json::from_slice::<OAuthClientRequest>(&body) {
        Ok(request) => request,
        Err(_) => return oauth_client_validation_error("name", &request_locale(&state)),
    };
    let Some(name) = request
        .name
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty() && name.chars().count() <= 255)
    else {
        return oauth_client_validation_error("name", &request_locale(&state));
    };
    let Some(redirect) = request
        .redirect
        .map(|redirect| redirect.trim().to_owned())
        .filter(|redirect| valid_oauth_redirect(redirect))
    else {
        return oauth_client_validation_error("redirect", &request_locale(&state));
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
    LegacyRouteId(id): LegacyRouteId,
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
    let notifications = match database
        .unread_notifications(&state.config.database.table_prefix, user_id)
        .await
    {
        Ok(notifications) => notifications
            .into_iter()
            .map(|notification| {
                let data = serde_json::from_str::<serde_json::Value>(&notification.data)
                    .unwrap_or(serde_json::Value::Null);
                DashboardNotification {
                    id: notification.id,
                    title: data
                        .get("title")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                }
            })
            .collect(),
        Err(error) => {
            tracing::error!(%error, user_id, "failed to load dashboard notifications");
            return unavailable();
        }
    };
    let show_email_verification = match database
        .option(&state.config.database.table_prefix, "require_verification")
        .await
    {
        Ok(value) => {
            !user.verified
                && value
                    .as_deref()
                    .is_some_and(|value| legacy_option_bool(Some(value)))
        }
        Err(error) => {
            tracing::error!(%error, "failed to load dashboard verification option");
            return unavailable();
        }
    };
    let locale = request_locale(&state);
    let prefix = &state.config.database.table_prefix;
    let localized_announcement_key = format!("announcement_{locale}");
    let announcement = match database.option(prefix, &localized_announcement_key).await {
        Ok(Some(announcement)) => announcement,
        Ok(None) => match database.option(prefix, "announcement").await {
            Ok(announcement) => announcement.unwrap_or_default(),
            Err(error) => {
                tracing::error!(%error, "failed to load dashboard announcement fallback");
                return unavailable();
            }
        },
        Err(error) => {
            tracing::error!(%error, "failed to load localized dashboard announcement");
            return unavailable();
        }
    };
    let announcement_html = render_notification_markdown(&announcement);
    let page_widgets = filter_user_dashboard_widgets(&state).await;
    let avatar_url = filter_user_avatar_url(&state, &user, false).await;
    let avatar_png_url = filter_user_avatar_url(&state, &user, true).await;
    let badges =
        serde_json::from_value::<Vec<DashboardBadge>>(filter_user_badges(&state, &user).await)
            .unwrap_or_default();
    let menu = filter_user_menu(&state, &user, &locale).await;
    let chinese = locale.starts_with("zh");
    let side_menu_user = filter_side_menu(
        &state,
        "user",
        vec![
            dashboard_menu_item(
                if chinese {
                    "管理角色"
                } else {
                    "Manage players"
                },
                "/user/player",
            ),
            dashboard_menu_item(
                if chinese {
                    "管理衣柜"
                } else {
                    "Manage closet"
                },
                "/user/closet",
            ),
            dashboard_menu_item(
                if chinese {
                    "我的举报"
                } else {
                    "My reports"
                },
                "/user/reports",
            ),
            dashboard_menu_item(
                if chinese {
                    "账户设置"
                } else {
                    "Account settings"
                },
                "/user/profile",
            ),
            dashboard_menu_item(
                if chinese {
                    "OAuth 应用"
                } else {
                    "OAuth apps"
                },
                "/user/oauth/manage",
            ),
        ],
    )
    .await;
    let side_menu_explore = filter_side_menu(
        &state,
        "explore",
        vec![dashboard_menu_item(
            if chinese { "皮肤库" } else { "Skin library" },
            "/skinlib",
        )],
    )
    .await;
    let site_name = site_name(&state).await;
    let app_dir = state.public_dir.join("app");
    let stylesheet = frontend_entrypoint(&app_dir, "style", "css", &request_app_url(&state)).await;
    let frontend_script =
        frontend_entrypoint(&app_dir, "app", "js", &request_app_url(&state)).await;
    let i18n = load_frontend_translations(&state, &app_dir, &request_locale(&state)).await;
    let frontend_globals_b64 = encode_frontend_globals(
        &state,
        &site_name,
        "user",
        serde_json::json!({
            "unverified": show_email_verification,
            "page_widgets": &page_widgets,
            "side_menu": {
                "user": &side_menu_user,
                "explore": &side_menu_explore,
            },
        }),
        i18n,
    );
    let page = DashboardPage {
        site_name,
        avatar_url,
        avatar_png_url,
        badges,
        menu,
        user,
        players,
        notifications,
        announcement_html,
        page_widgets,
        side_menu_user,
        side_menu_explore,
        show_email_verification,
        locale,
        frontend_style_available: stylesheet.is_some(),
        frontend_stylesheet: stylesheet.unwrap_or_default(),
        frontend_script_available: frontend_script.is_some(),
        frontend_script: frontend_script.unwrap_or_default(),
        frontend_globals_b64,
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to render user dashboard");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn web_admin_translations(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AdminTranslationsQuery>,
) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if user.permission < 1 {
        return StatusCode::FORBIDDEN.into_response();
    }
    let site_name = site_name(&state).await;
    let app_dir = state.public_dir.join("app");
    let stylesheet = frontend_entrypoint(&app_dir, "style", "css", &request_app_url(&state)).await;
    let frontend_script =
        frontend_entrypoint(&app_dir, "app", "js", &request_app_url(&state)).await;
    let i18n = load_frontend_translations(&state, &app_dir, &request_locale(&state)).await;
    let frontend_globals_b64 = encode_frontend_globals(
        &state,
        &site_name,
        "admin/i18n",
        serde_json::json!({}),
        i18n,
    );
    let page = AdminTranslationsPage {
        site_name,
        locale: request_locale(&state),
        added: query.added.unwrap_or_default() == 1,
        frontend_style_available: stylesheet.is_some(),
        frontend_stylesheet: stylesheet.unwrap_or_default(),
        frontend_script_available: frontend_script.is_some(),
        frontend_script: frontend_script.unwrap_or_default(),
        frontend_globals_b64,
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to render translation management page");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn web_admin_language_lines(
    State(state): State<AppState>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    Query(query): Query<AdminTranslationsQuery>,
) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if user.permission < 1 {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    const PER_PAGE: i64 = 10;
    let page = query.page.unwrap_or(1).max(1);
    let path = format!(
        "{}{}",
        request_app_url(&state).trim_end_matches('/'),
        uri.path()
    );
    let (lines, total) = match database
        .language_lines_page(&state.config.database.table_prefix, page, PER_PAGE)
        .await
    {
        Ok(result) => result,
        Err(error) => {
            tracing::error!(%error, "failed to load language lines");
            return unavailable();
        }
    };
    let data = lines
        .into_iter()
        .map(|line: LanguageLineRecord| {
            let text = serde_json::from_str::<serde_json::Value>(&line.text)
                .ok()
                .filter(serde_json::Value::is_object)
                .unwrap_or_else(|| serde_json::json!({}));
            serde_json::json!({
                "id": line.id,
                "group": line.group_name,
                "key": line.key,
                "text": text,
                "created_at": line.created_at,
                "updated_at": line.updated_at,
            })
        })
        .collect::<Vec<_>>();
    Json(legacy_paginator_json(
        data,
        total,
        page,
        PER_PAGE,
        &path,
        uri.query(),
    ))
    .into_response()
}
async fn web_create_language_line(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
    body: Bytes,
) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if user.permission < 1 {
        return StatusCode::FORBIDDEN.into_response();
    }
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    let fields = match parse_legacy_input_object(&query, &body, content_type) {
        Ok(fields) => fields,
        Err(()) => return translation_validation_error("group", &request_locale(&state)),
    };
    let Some(group) = fields.get("group").and_then(serde_json::Value::as_str) else {
        return translation_validation_error("group", &request_locale(&state));
    };
    let Some(key) = fields.get("key").and_then(serde_json::Value::as_str) else {
        return translation_validation_error("key", &request_locale(&state));
    };
    let Some(text) = fields.get("text").and_then(serde_json::Value::as_str) else {
        return translation_validation_error("text", &request_locale(&state));
    };
    let group = group.trim();
    let key = key.trim();
    if group.is_empty() || group.chars().count() > 255 {
        return translation_validation_error("group", &request_locale(&state));
    }
    if key.is_empty() || key.chars().count() > 255 {
        return translation_validation_error("key", &request_locale(&state));
    }
    let text = text.trim();
    if text.is_empty() {
        return translation_validation_error("text", &request_locale(&state));
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    let prefix = &state.config.database.table_prefix;
    match database.language_line_exists(prefix, group, key).await {
        Ok(true) => return translation_validation_error("key", &request_locale(&state)),
        Err(error) => {
            tracing::error!(%error, "failed to check language line key");
            return unavailable();
        }
        Ok(false) => {}
    }
    if let Err(error) = database
        .create_language_line(prefix, group, key, &request_locale(&state), text)
        .await
    {
        tracing::error!(%error, "failed to create language line");
        return unavailable();
    }
    Redirect::to("/admin/i18n?added=1").into_response()
}

async fn web_update_language_line(
    State(state): State<AppState>,
    headers: HeaderMap,
    LegacyRouteId(id): LegacyRouteId,
    Query(query): Query<BTreeMap<String, String>>,
    body: Bytes,
) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if user.permission < 1 {
        return StatusCode::FORBIDDEN.into_response();
    }
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    let fields = match parse_legacy_input_object(&query, &body, content_type) {
        Ok(fields) => fields,
        Err(()) => return translation_validation_error("text", &request_locale(&state)),
    };
    let Some(text) = fields
        .get("text")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
    else {
        return translation_validation_error("text", &request_locale(&state));
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    match database
        .update_language_line(
            &state.config.database.table_prefix,
            id,
            &request_locale(&state),
            text,
        )
        .await
    {
        Ok(true) => Json(serde_json::json!({
            "code": 0,
            "message": translation_admin_message("updated", &request_locale(&state))
        }))
        .into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "code": 1,
                "message": translation_admin_message("missing", &request_locale(&state))
            })),
        )
            .into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to update language line");
            unavailable()
        }
    }
}

async fn web_delete_language_line(
    State(state): State<AppState>,
    headers: HeaderMap,
    LegacyRouteId(id): LegacyRouteId,
) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if user.permission < 1 {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    match database
        .delete_language_line(&state.config.database.table_prefix, id)
        .await
    {
        Ok(true) => Json(serde_json::json!({
            "code": 0,
            "message": translation_admin_message("deleted", &request_locale(&state))
        }))
        .into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "code": 1,
                "message": translation_admin_message("missing", &request_locale(&state))
            })),
        )
            .into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to delete language line");
            unavailable()
        }
    }
}

fn translation_validation_error(field: &str, locale: &str) -> Response {
    let chinese = locale.starts_with("zh");
    let field_error = match (field, chinese) {
        ("group", true) => "分组为必填项，且不能超过 255 个字符。",
        ("key", true) => "键为必填项，且不能超过 255 个字符。",
        ("text", true) => "文本为必填项。",
        ("group", false) => "The group field is required and may not exceed 255 characters.",
        ("key", false) => "The key field is required and may not exceed 255 characters.",
        _ => "The text field is required.",
    };
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(serde_json::json!({
            "message": if chinese { "给定数据无效。" } else { "The given data was invalid." },
            "errors": { (field): [field_error] }
        })),
    )
        .into_response()
}

fn translation_admin_message(kind: &str, locale: &str) -> &'static str {
    match (kind, locale.starts_with("zh")) {
        ("updated", true) => "条目更新成功",
        ("deleted", true) => "条目已删除",
        ("missing", true) => "翻译条目不存在。",
        ("updated", false) => "Language line updated.",
        ("deleted", false) => "Language line deleted.",
        _ => "Language line not found.",
    }
}
async fn web_admin_dashboard(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if user.permission < 1 {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    let stats = match database
        .admin_dashboard_stats(&state.config.database.table_prefix)
        .await
    {
        Ok(stats) => stats,
        Err(error) => {
            tracing::error!(%error, "failed to load admin dashboard statistics");
            return unavailable();
        }
    };
    let page_widgets = filter_admin_dashboard_widgets(&state).await;
    let locale = request_locale(&state);
    let chinese = locale.starts_with("zh");
    let side_menu = filter_side_menu(
        &state,
        "admin",
        vec![
            dashboard_menu_item(if chinese { "用户" } else { "Users" }, "/admin/users"),
            dashboard_menu_item(if chinese { "角色" } else { "Players" }, "/admin/players"),
            dashboard_menu_item(if chinese { "举报" } else { "Reports" }, "/admin/reports"),
            dashboard_menu_item(
                if chinese {
                    "多语言"
                } else {
                    "Internationalization"
                },
                "/admin/i18n",
            ),
            dashboard_menu_item(
                if chinese {
                    "站点设置"
                } else {
                    "Site settings"
                },
                "/admin/options",
            ),
            dashboard_menu_item(
                if chinese {
                    "系统状态"
                } else {
                    "System status"
                },
                "/admin/status",
            ),
            dashboard_menu_item(
                if chinese { "插件" } else { "Plugins" },
                "/admin/plugins/manage",
            ),
            dashboard_menu_item(
                if chinese { "版本更新" } else { "Updates" },
                "/admin/update",
            ),
        ],
    )
    .await;
    let site_name = site_name(&state).await;
    let app_dir = state.public_dir.join("app");
    let stylesheet = frontend_entrypoint(&app_dir, "style", "css", &request_app_url(&state)).await;
    let frontend_script =
        frontend_entrypoint(&app_dir, "app", "js", &request_app_url(&state)).await;
    let i18n = load_frontend_translations(&state, &app_dir, &request_locale(&state)).await;
    let frontend_globals_b64 = encode_frontend_globals(
        &state,
        &site_name,
        "admin",
        serde_json::json!({
            "dashboard_stats": &stats,
            "page_widgets": &page_widgets,
            "side_menu": &side_menu,
        }),
        i18n,
    );
    let page = AdminDashboardPage {
        site_name,
        locale,
        stats,
        page_widgets,
        side_menu,
        frontend_style_available: stylesheet.is_some(),
        frontend_stylesheet: stylesheet.unwrap_or_default(),
        frontend_script_available: frontend_script.is_some(),
        frontend_script: frontend_script.unwrap_or_default(),
        frontend_globals_b64,
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to render admin dashboard");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn web_admin_status(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if user.permission < 1 {
        return StatusCode::FORBIDDEN.into_response();
    }

    let chinese = request_locale(&state).starts_with("zh");
    let debug = crate::config::legacy_env("APP_DEBUG").is_some_and(|value| {
        matches!(
            value.to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    });
    let commit = crate::config::legacy_env("GIT_COMMIT")
        .or_else(|| crate::config::legacy_env("SOURCE_VERSION"))
        .unwrap_or_default();
    let commit = if commit.is_empty() {
        if chinese {
            "未知".to_owned()
        } else {
            "Unknown".to_owned()
        }
    } else {
        commit.chars().take(16).collect()
    };
    let database = &state.config.database;
    let groups = vec![
        AdminStatusGroup {
            title: "Blessing Skin".to_owned(),
            fields: vec![
                AdminStatusField {
                    label: if chinese { "版本" } else { "Version" }.to_owned(),
                    value: state.config.legacy_app_version.clone(),
                },
                AdminStatusField {
                    label: if chinese {
                        "运行环境"
                    } else {
                        "Environment"
                    }
                    .to_owned(),
                    value: crate::config::legacy_env("APP_ENV")
                        .unwrap_or_else(|| "production".to_owned()),
                },
                AdminStatusField {
                    label: if chinese {
                        "调试模式"
                    } else {
                        "Debug mode"
                    }
                    .to_owned(),
                    value: if chinese {
                        if debug { "是" } else { "否" }
                    } else if debug {
                        "Yes"
                    } else {
                        "No"
                    }
                    .to_owned(),
                },
                AdminStatusField {
                    label: if chinese { "提交" } else { "Commit" }.to_owned(),
                    value: commit,
                },
            ],
        },
        AdminStatusGroup {
            title: if chinese { "服务" } else { "Server" }.to_owned(),
            fields: vec![
                AdminStatusField {
                    label: if chinese { "运行时" } else { "Runtime" }.to_owned(),
                    value: "Rust / Axum / Tokio".to_owned(),
                },
                AdminStatusField {
                    label: if chinese {
                        "操作系统"
                    } else {
                        "Operating system"
                    }
                    .to_owned(),
                    value: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
                },
            ],
        },
        AdminStatusGroup {
            title: if chinese { "数据库" } else { "Database" }.to_owned(),
            fields: vec![
                AdminStatusField {
                    label: if chinese { "类型" } else { "Type" }.to_owned(),
                    value: database.driver.clone(),
                },
                AdminStatusField {
                    label: if chinese { "主机" } else { "Host" }.to_owned(),
                    value: database.host.clone().unwrap_or_else(|| "—".to_owned()),
                },
                AdminStatusField {
                    label: if chinese { "端口" } else { "Port" }.to_owned(),
                    value: database
                        .port
                        .map_or_else(|| "—".to_owned(), |port| port.to_string()),
                },
                AdminStatusField {
                    label: if chinese { "用户名" } else { "Username" }.to_owned(),
                    value: database.username.clone().unwrap_or_else(|| "—".to_owned()),
                },
                AdminStatusField {
                    label: if chinese { "数据库" } else { "Database" }.to_owned(),
                    value: database.database.clone(),
                },
                AdminStatusField {
                    label: if chinese { "表前缀" } else { "Table prefix" }.to_owned(),
                    value: if database.table_prefix.is_empty() {
                        if chinese { "（空）" } else { "(none)" }.to_owned()
                    } else {
                        database.table_prefix.clone()
                    },
                },
            ],
        },
    ];
    let page_widgets = filter_admin_status_widgets(&state).await;
    let site_name = site_name(&state).await;
    let wasm_plugins = state.wasm_plugins.clone();
    let app_dir = state.public_dir.join("app");
    let stylesheet = frontend_entrypoint(&app_dir, "style", "css", &request_app_url(&state)).await;
    let frontend_script =
        frontend_entrypoint(&app_dir, "app", "js", &request_app_url(&state)).await;
    let i18n = load_frontend_translations(&state, &app_dir, &request_locale(&state)).await;
    let frontend_globals_b64 = encode_frontend_globals(
        &state,
        &site_name,
        "admin/status",
        serde_json::json!({
            "admin_status": {
                "groups": &groups,
                "wasm_plugins": &wasm_plugins,
                "page_widgets": &page_widgets,
            }
        }),
        i18n,
    );
    let page = AdminStatusPage {
        site_name,
        locale: request_locale(&state),
        groups,
        wasm_plugins,
        page_widgets,
        frontend_style_available: stylesheet.is_some(),
        frontend_stylesheet: stylesheet.unwrap_or_default(),
        frontend_script_available: frontend_script.is_some(),
        frontend_script: frontend_script.unwrap_or_default(),
        frontend_globals_b64,
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to render admin status page");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn web_admin_update(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if user.permission < 2 {
        return StatusCode::FORBIDDEN.into_response();
    }

    let (
        latest_version,
        has_release_info,
        update_available,
        update_check_failed,
        update_check_no_release,
    ) = if let Some(api_url) = &state.config.rust_releases_api_url {
        match crate::update::check_latest_release(api_url, state.config.rust_version).await {
            Ok(Some(release)) => (
                release.version,
                true,
                release.update_available,
                false,
                false,
            ),
            Ok(None) => (String::new(), false, false, false, true),
            Err(error) => {
                tracing::warn!(%error, "failed to check for a newer Rust release");
                (String::new(), false, false, true, false)
            }
        }
    } else {
        (String::new(), false, false, false, false)
    };
    let page = AdminUpdatePage {
        site_name: site_name(&state).await,
        locale: request_locale(&state),
        version: state.config.rust_version.to_owned(),
        latest_version,
        has_release_info,
        update_available,
        update_check_failed,
        update_check_disabled: state.config.rust_releases_api_url.is_none(),
        update_check_no_release,
        releases_url: "https://github.com/HELPMEEADICE/blessing-skin-rs/releases".to_owned(),
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to render administrator release page");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn web_admin_update_download(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if user.permission < 2 {
        return StatusCode::FORBIDDEN.into_response();
    }

    let message = if request_locale(&state).starts_with("zh") {
        "Rust 服务以独立程序发行。请下载对应平台的软件包，停止服务并替换程序和前端资源，然后运行 blessing-skin-rs update 并重新启动。"
    } else {
        "The Rust service is distributed as a standalone program. Download the package for your platform, stop the service, replace the program and frontend assets, run blessing-skin-rs update, then restart it."
    };
    Json(serde_json::json!({ "code": 1, "message": message })).into_response()
}

async fn web_admin_plugins_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if user.permission < 1 {
        return StatusCode::FORBIDDEN.into_response();
    }
    let site_name = site_name(&state).await;
    let app_dir = state.public_dir.join("app");
    let stylesheet = frontend_entrypoint(&app_dir, "style", "css", &request_app_url(&state)).await;
    let frontend_script =
        frontend_entrypoint(&app_dir, "app", "js", &request_app_url(&state)).await;
    let i18n = load_frontend_translations(&state, &app_dir, &request_locale(&state)).await;
    let can_upload = user.permission >= 2;
    let frontend_globals_b64 = encode_frontend_globals(
        &state,
        &site_name,
        "admin/plugins/manage",
        serde_json::json!({
            "wasm_plugins": true,
            "can_upload": can_upload,
        }),
        i18n,
    );
    let page = AdminPluginsPage {
        site_name,
        locale: request_locale(&state),
        base_url: request_app_url(&state).trim_end_matches('/').to_owned(),
        can_upload,
        frontend_style_available: stylesheet.is_some(),
        frontend_stylesheet: stylesheet.unwrap_or_default(),
        frontend_script_available: frontend_script.is_some(),
        frontend_script: frontend_script.unwrap_or_default(),
        frontend_globals_b64,
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to render administrator plugins page");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn web_admin_plugins_market_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if user.permission < 2 {
        return StatusCode::FORBIDDEN.into_response();
    }
    let site_name = site_name(&state).await;
    let app_dir = state.public_dir.join("app");
    let stylesheet = frontend_entrypoint(&app_dir, "style", "css", &request_app_url(&state)).await;
    let frontend_script =
        frontend_entrypoint(&app_dir, "app", "js", &request_app_url(&state)).await;
    let locale = request_locale(&state);
    let i18n = load_frontend_translations(&state, &app_dir, &locale).await;
    let frontend_globals_b64 = encode_frontend_globals(
        &state,
        &site_name,
        "admin/plugins/market",
        serde_json::json!({ "wasm_plugins": true }),
        i18n,
    );
    let page = AdminPluginMarketPage {
        site_name,
        locale,
        base_url: request_app_url(&state).trim_end_matches('/').to_owned(),
        frontend_style_available: stylesheet.is_some(),
        frontend_stylesheet: stylesheet.unwrap_or_default(),
        frontend_script_available: frontend_script.is_some(),
        frontend_script: frontend_script.unwrap_or_default(),
        frontend_globals_b64,
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to render administrator WASM plugin market page");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn web_admin_plugins_data(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if user.permission < 1 {
        return StatusCode::FORBIDDEN.into_response();
    }
    match admin_plugin_inventory(&state) {
        Ok(plugins) => Json(plugins).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to list WASM plugins");
            unavailable()
        }
    }
}

async fn web_admin_plugin_readme(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(name): RoutePath<String>,
) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if user.permission < 1 {
        return StatusCode::FORBIDDEN.into_response();
    }
    if !crate::plugin_runtime::valid_plugin_name(&name) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let readme = state
        .wasm_runtime
        .lock()
        .await
        .read_plugin_readme(&name)
        .await;
    let markdown = match readme {
        Ok(Some(markdown)) => markdown,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, plugin = %name, "failed to read WASM plugin documentation");
            return unavailable();
        }
    };
    let content = render_notification_markdown(&markdown);
    let language = if request_locale(&state).starts_with("zh") {
        "zh-CN"
    } else {
        "en"
    };
    let html = format!(
        "<!doctype html><html lang=\"{language}\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>{name}</title><style>body{{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;line-height:1.55}}img{{max-width:100%}}pre{{overflow:auto;padding:1rem;background:#f3f4f6}}</style></head><body><main><h1>{name}</h1>{content}</main></body></html>",
    );
    let mut response = Html(html).into_response();
    response.headers_mut().insert(
        axum::http::header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'self'"),
    );
    response
}

async fn web_admin_plugin_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(name): RoutePath<String>,
    method: Method,
    body: Bytes,
) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if user.permission < 1 {
        return StatusCode::FORBIDDEN.into_response();
    }
    if !crate::plugin_runtime::valid_plugin_name(&name) {
        return StatusCode::NOT_FOUND.into_response();
    }

    let mut message = String::new();
    if method == Method::POST {
        let configuration = if headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("application/json"))
        {
            let value: serde_json::Value = match serde_json::from_slice(&body) {
                Ok(value) => value,
                Err(_) => return StatusCode::BAD_REQUEST.into_response(),
            };
            match serde_json::to_string(&value) {
                Ok(value) => value,
                Err(_) => return StatusCode::BAD_REQUEST.into_response(),
            }
        } else {
            match form_urlencoded::parse(&body)
                .find(|(key, _)| key == "configuration")
                .map(|(_, value)| value.into_owned())
                .filter(|value| !value.trim().is_empty())
            {
                Some(value) => value,
                None => return StatusCode::BAD_REQUEST.into_response(),
            }
        };
        match state
            .wasm_runtime
            .lock()
            .await
            .save_plugin_configuration(&name, &configuration)
            .await
        {
            Ok(true) => {
                message = if request_locale(&state).starts_with("zh") {
                    "配置已保存。".to_owned()
                } else {
                    "Configuration saved.".to_owned()
                };
            }
            Ok(false) => return StatusCode::NOT_FOUND.into_response(),
            Err(error) => {
                tracing::warn!(%error, plugin = %name, "WASM plugin rejected configuration");
                message = if request_locale(&state).starts_with("zh") {
                    format!("配置未保存：{error}")
                } else {
                    format!("Configuration was not saved: {error}")
                };
            }
        }
    }

    let configuration = match state
        .wasm_runtime
        .lock()
        .await
        .read_plugin_configuration(&name)
        .await
    {
        Ok(Some(configuration)) => configuration,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, plugin = %name, "failed to read WASM plugin configuration");
            return unavailable();
        }
    };
    let chinese = request_locale(&state).starts_with("zh");
    let page = PluginConfigurationPage {
        locale: request_locale(&state),
        base_url: request_app_url(&state).trim_end_matches('/').to_owned(),
        plugin_name: name,
        heading: if chinese {
            "插件设置"
        } else {
            "Plugin configuration"
        }
        .to_owned(),
        configuration_label: if chinese {
            "JSON 配置"
        } else {
            "JSON configuration"
        }
        .to_owned(),
        description: if chinese {
            "配置以 JSON 对象形式保存在组件的隔离状态中，保存时会校验格式。"
        } else {
            "Settings are stored by this component and validated when saved."
        }
        .to_owned(),
        configuration: match serde_json::from_str::<serde_json::Value>(&configuration)
            .and_then(|value| serde_json::to_string_pretty(&value))
        {
            Ok(configuration) => configuration,
            Err(_) => configuration,
        },
        message,
        save_label: if chinese { "保存" } else { "Save" }.to_owned(),
        back_label: if chinese {
            "返回插件管理"
        } else {
            "Back to plugins"
        }
        .to_owned(),
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to render WASM plugin configuration page");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn web_admin_plugins_manage(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
    body: Bytes,
) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if user.permission < 1 {
        return StatusCode::FORBIDDEN.into_response();
    }
    let fields = match parse_legacy_input_object(
        &query,
        &body,
        headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
    ) {
        Ok(fields) => fields,
        Err(()) => return admin_plugin_result(1, "Invalid plugin request."),
    };
    let request =
        match serde_json::from_value::<AdminPluginManageRequest>(serde_json::Value::Object(fields))
        {
            Ok(request) => request,
            Err(_) => return admin_plugin_result(1, "Invalid plugin request."),
        };
    if !crate::plugin_runtime::valid_plugin_name(&request.name) {
        return admin_plugin_result(1, "Invalid plugin name.");
    }
    let enabled = state
        .config
        .plugins_dir
        .join(format!("{}.wasm", request.name));
    let disabled = state
        .config
        .plugins_dir
        .join(format!("{}.wasm.disabled", request.name));
    let operation = match request.action.as_str() {
        "enable" => {
            if enabled.exists() {
                return admin_plugin_result(1, "The plugin is already enabled.");
            }
            std::fs::rename(&disabled, &enabled)
        }
        "disable" => {
            if disabled.exists() {
                return admin_plugin_result(1, "The plugin is already disabled.");
            }
            std::fs::rename(&enabled, &disabled)
        }
        "delete" => {
            let mut deleted = false;
            let metadata =
                wasm_plugin_market_metadata_path(&state.config.plugins_dir, &request.name);
            for path in [&enabled, &disabled, &metadata] {
                match std::fs::remove_file(path) {
                    Ok(()) => deleted = true,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => {
                        tracing::error!(%error, plugin = %request.name, "failed to remove WASM plugin");
                        return admin_plugin_result(1, "Could not remove the plugin file.");
                    }
                }
            }
            if !deleted {
                return admin_plugin_result(1, "Plugin not found.");
            }
            return admin_plugin_result(
                0,
                "Plugin file removed. Restart the service for the change to take effect.",
            );
        }
        _ => return admin_plugin_result(1, "Invalid plugin action."),
    };
    match operation {
        Ok(()) => admin_plugin_result(
            0,
            "Plugin file updated. Restart the service for the change to take effect.",
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            admin_plugin_result(1, "Plugin not found.")
        }
        Err(error) => {
            tracing::error!(%error, plugin = %request.name, action = %request.action, "failed to update WASM plugin state");
            admin_plugin_result(1, "Could not update the plugin file.")
        }
    }
}

async fn web_admin_plugins_market_list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if user.permission < 2 {
        return StatusCode::FORBIDDEN.into_response();
    }

    let entries = match fetch_wasm_plugin_registry(&state).await {
        Ok(Some(entries)) => entries,
        Ok(None) => {
            return Json(serde_json::json!({ "configured": false, "plugins": [] })).into_response();
        }
        Err(error) => {
            tracing::warn!(error = ?error, "could not load configured WASM plugin registry");
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "message": "The configured WASM plugin registry is unavailable or invalid."
                })),
            )
                .into_response();
        }
    };
    let plugins = entries
        .into_iter()
        .map(|entry| {
            let enabled = state
                .config
                .plugins_dir
                .join(format!("{}.wasm", entry.name))
                .is_file();
            let disabled = state
                .config
                .plugins_dir
                .join(format!("{}.wasm.disabled", entry.name))
                .is_file();
            let loaded = state
                .wasm_plugins
                .iter()
                .any(|plugin| plugin == &format!("{}.wasm", entry.name));
            let installed = enabled || disabled || loaded;
            let installed_version = read_wasm_plugin_market_metadata(&state, &entry.name)
                .map(|metadata| metadata.version);
            let can_update = installed
                && installed_version
                    .as_ref()
                    .is_none_or(|version| version != &entry.version);
            serde_json::json!({
                "name": entry.name,
                "version": entry.version,
                "title": entry.title,
                "description": entry.description,
                "author": entry.author,
                "installed": installed,
                "installed_version": installed_version,
                "can_update": can_update,
            })
        })
        .collect::<Vec<_>>();
    Json(serde_json::json!({ "configured": true, "plugins": plugins })).into_response()
}

async fn web_admin_plugins_market_download(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
    body: Bytes,
) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if user.permission < 2 {
        return StatusCode::FORBIDDEN.into_response();
    }
    if body.len() > 8 * 1024 {
        return admin_plugin_result(1, "Invalid plugin request.");
    }
    let fields = match parse_legacy_input_object(
        &query,
        &body,
        headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
    ) {
        Ok(fields) => fields,
        Err(()) => return admin_plugin_result(1, "Invalid plugin request."),
    };
    let request = match serde_json::from_value::<AdminPluginMarketDownloadRequest>(
        serde_json::Value::Object(fields),
    ) {
        Ok(request) => request,
        Err(_) => return admin_plugin_result(1, "Invalid plugin request."),
    };
    if !crate::plugin_runtime::valid_plugin_name(&request.name) {
        return admin_plugin_result(1, "Invalid plugin name.");
    }
    let entries = match fetch_wasm_plugin_registry(&state).await {
        Ok(Some(entries)) => entries,
        Ok(None) => return admin_plugin_result(1, "The WASM plugin registry is not configured."),
        Err(error) => {
            tracing::warn!(error = ?error, "could not load configured WASM plugin registry");
            return admin_plugin_result(
                1,
                "The configured WASM plugin registry is unavailable or invalid.",
            );
        }
    };
    let Some(entry) = entries.into_iter().find(|entry| entry.name == request.name) else {
        return admin_plugin_result(1, "Plugin not found in the configured WASM registry.");
    };
    let (filename, bytes) = match fetch_remote_wasm_component(&entry.download_url).await {
        Ok(component) => component,
        Err(error) => {
            tracing::warn!(error = ?error, plugin = %entry.name, "WASM market component download failed");
            return admin_plugin_result(1, "Could not download the WASM component.");
        }
    };
    if filename != format!("{}.wasm", entry.name) {
        return admin_plugin_result(
            1,
            "The registry component filename does not match its plugin name.",
        );
    }
    let expected_sha256 = entry.sha256.to_ascii_lowercase();
    if hex::encode(Sha256::digest(&bytes)) != expected_sha256 {
        return admin_plugin_result(
            1,
            "The downloaded component does not match its SHA-256 checksum.",
        );
    }
    install_wasm_market_component(&state, filename, bytes, &entry.version, &expected_sha256).await
}
async fn install_wasm_market_component(
    state: &AppState,
    filename: String,
    bytes: Vec<u8>,
    version: &str,
    sha256: &str,
) -> Response {
    let Some(name) = filename.strip_suffix(".wasm") else {
        return admin_plugin_result(1, "Only .wasm components are supported.");
    };
    if !crate::plugin_runtime::valid_plugin_name(name) {
        return admin_plugin_result(1, "Invalid plugin name.");
    }
    if let Err(error) = crate::plugin_runtime::PluginRuntime::validate_component_bytes(&bytes) {
        tracing::warn!(%error, plugin = %filename, "rejected invalid WASM plugin market component");
        return admin_plugin_result(1, "The file is not a valid Blessing Skin WASM component.");
    }

    let enabled = state.config.plugins_dir.join(&filename);
    let disabled = state
        .config
        .plugins_dir
        .join(format!("{name}.wasm.disabled"));
    if enabled.exists() && disabled.exists() {
        return admin_plugin_result(1, "Conflicting enabled and disabled plugin files exist.");
    }
    let existing_path = if enabled.exists() {
        Some(enabled.clone())
    } else if disabled.exists() {
        Some(disabled.clone())
    } else {
        None
    };
    if let Some(path) = existing_path {
        if let Some(metadata) = read_wasm_plugin_market_metadata(state, name)
            && metadata.version == version
            && metadata.sha256.eq_ignore_ascii_case(sha256)
        {
            return admin_plugin_result(0, "This plugin version is already installed.");
        }
        let plugin_dir = state.config.plugins_dir.clone();
        let name = name.to_owned();
        let write_result = tokio::task::spawn_blocking(move || {
            replace_component_file(&plugin_dir, &name, &path, &bytes)
        })
        .await;
        match write_result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::error!(%error, plugin = %filename, "failed to replace WASM market component");
                return unavailable();
            }
            Err(error) => {
                tracing::error!(%error, plugin = %filename, "WASM market update task failed");
                return unavailable();
            }
        }
    } else {
        let response = store_wasm_component(state, filename.clone(), bytes).await;
        if !response.status().is_success() {
            return response;
        }
    }

    let plugin_dir = state.config.plugins_dir.clone();
    let name = name.to_owned();
    let version = version.to_owned();
    let sha256 = sha256.to_ascii_lowercase();
    match tokio::task::spawn_blocking(move || {
        write_wasm_plugin_market_metadata(&plugin_dir, &name, &version, &sha256)
    })
    .await
    {
        Ok(Ok(())) => admin_plugin_result(
            0,
            "WASM component installed or updated. Restart the service to load it.",
        ),
        Ok(Err(error)) => {
            tracing::error!(%error, "could not save WASM plugin market version metadata");
            admin_plugin_result(
                0,
                "Component installed or updated, but version metadata could not be saved. Restart the service.",
            )
        }
        Err(error) => {
            tracing::error!(%error, "WASM plugin market metadata task failed");
            admin_plugin_result(
                0,
                "Component installed or updated, but version metadata could not be saved. Restart the service.",
            )
        }
    }
}

fn wasm_plugin_market_metadata_path(
    plugins_dir: &std::path::Path,
    name: &str,
) -> std::path::PathBuf {
    plugins_dir.join(format!("{name}.wasm.market.json"))
}

fn read_wasm_plugin_market_metadata(
    state: &AppState,
    name: &str,
) -> Option<WasmPluginMarketMetadata> {
    let path = wasm_plugin_market_metadata_path(&state.config.plugins_dir, name);
    let metadata = std::fs::read(path).ok()?;
    let metadata = serde_json::from_slice::<WasmPluginMarketMetadata>(&metadata).ok()?;
    (!metadata.version.trim().is_empty()
        && metadata.sha256.len() == 64
        && metadata.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()))
    .then_some(metadata)
}

fn write_wasm_plugin_market_metadata(
    plugins_dir: &std::path::Path,
    name: &str,
    version: &str,
    sha256: &str,
) -> std::io::Result<()> {
    use std::io::Write;

    std::fs::create_dir_all(plugins_dir)?;
    let sequence = WASM_PLUGIN_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = plugins_dir.join(format!(
        ".{name}.market-{}-{sequence}.tmp",
        std::process::id()
    ));
    let destination = wasm_plugin_market_metadata_path(plugins_dir, name);
    match std::fs::remove_file(&destination) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let metadata = serde_json::to_vec(&WasmPluginMarketMetadata {
        version: version.to_owned(),
        sha256: sha256.to_ascii_lowercase(),
    })
    .map_err(std::io::Error::other)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    if let Err(error) = file.write_all(&metadata).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    drop(file);
    if let Err(error) = std::fs::rename(&temporary, &destination) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    Ok(())
}

fn replace_component_file(
    plugins_dir: &std::path::Path,
    name: &str,
    destination: &std::path::Path,
    bytes: &[u8],
) -> std::io::Result<()> {
    use std::io::Write;

    let sequence = WASM_PLUGIN_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = plugins_dir.join(format!(
        ".{name}.component-{}-{sequence}.tmp",
        std::process::id()
    ));
    let backup = plugins_dir.join(format!(
        ".{name}.component-{}-{sequence}.bak",
        std::process::id()
    ));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    drop(file);
    if let Err(error) = std::fs::rename(destination, &backup) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    if let Err(error) = std::fs::rename(&temporary, destination) {
        let restore = std::fs::rename(&backup, destination);
        let _ = std::fs::remove_file(&temporary);
        return restore.and(Err(error));
    }
    if let Err(error) = std::fs::remove_file(backup) {
        tracing::warn!(%error, plugin = name, "could not remove previous WASM component backup");
    }
    Ok(())
}

static WASM_PLUGIN_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);
async fn web_admin_plugins_upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if user.permission < 2 {
        return StatusCode::FORBIDDEN.into_response();
    }
    let mut upload = None;
    loop {
        let field = match multipart.next_field().await {
            Ok(Some(field)) => field,
            Ok(None) => break,
            Err(error) => {
                tracing::warn!(%error, "invalid WASM plugin upload request");
                return admin_plugin_result(1, "Invalid upload request.");
            }
        };
        if field.name() != Some("file") {
            continue;
        }
        if upload.is_some() {
            return admin_plugin_result(1, "Upload exactly one WASM component.");
        }
        let Some(filename) = field.file_name().map(str::to_owned) else {
            return admin_plugin_result(1, "Choose a .wasm component file.");
        };
        let bytes = match field.bytes().await {
            Ok(bytes) => bytes,
            Err(error) => {
                tracing::warn!(%error, "could not read WASM plugin upload");
                return admin_plugin_result(1, "Could not read the uploaded file.");
            }
        };
        if bytes.len() as u64 > crate::plugin_runtime::COMPONENT_FILE_LIMIT {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(serde_json::json!({
                    "code": 1,
                    "message": "WASM components must be 32 MiB or smaller."
                })),
            )
                .into_response();
        }
        upload = Some((filename, bytes.to_vec()));
    }
    let Some((filename, bytes)) = upload else {
        return admin_plugin_result(1, "Choose a .wasm component file.");
    };
    store_wasm_component(&state, filename, bytes).await
}

async fn web_admin_plugins_wget(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if user.permission < 2 {
        return StatusCode::FORBIDDEN.into_response();
    }
    if body.len() > 8 * 1024 {
        return admin_plugin_result(1, "The component URL is too long.");
    }
    let request = match serde_json::from_slice::<AdminPluginWgetRequest>(&body) {
        Ok(request) => request,
        Err(_) => return admin_plugin_result(1, "Invalid component download request."),
    };
    if request.url.len() > 8 * 1024 {
        return admin_plugin_result(1, "The component URL is too long.");
    }
    let (filename, bytes) = match fetch_remote_wasm_component(&request.url).await {
        Ok(component) => component,
        Err(error) => {
            tracing::warn!(error = ?error, "remote WASM component download failed");
            return match error {
                RemoteComponentError::InvalidUrl => admin_plugin_result(
                    1,
                    "Only public HTTPS URLs to .wasm component files are supported.",
                ),
                RemoteComponentError::UnsafeAddress => admin_plugin_result(
                    1,
                    "The component URL must resolve only to public IP addresses.",
                ),
                RemoteComponentError::InvalidFilename => admin_plugin_result(
                    1,
                    "The remote URL must end in a valid .wasm component filename.",
                ),
                RemoteComponentError::TooLarge => (
                    StatusCode::PAYLOAD_TOO_LARGE,
                    Json(serde_json::json!({
                        "code": 1,
                        "message": "WASM components must be 32 MiB or smaller."
                    })),
                )
                    .into_response(),
                RemoteComponentError::HttpStatus(status) => {
                    admin_plugin_result(1, &format!("The component server returned HTTP {status}."))
                }
                _ => admin_plugin_result(1, "Could not download the WASM component."),
            };
        }
    };
    store_wasm_component(&state, filename, bytes).await
}

async fn store_wasm_component(state: &AppState, filename: String, bytes: Vec<u8>) -> Response {
    let Some(name) = filename.strip_suffix(".wasm") else {
        return admin_plugin_result(1, "Only .wasm component files are supported.");
    };
    if !crate::plugin_runtime::valid_plugin_name(name) {
        return admin_plugin_result(1, "The uploaded filename is not valid.");
    }
    if bytes.len() as u64 > crate::plugin_runtime::COMPONENT_FILE_LIMIT {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({
                "code": 1,
                "message": "WASM components must be 32 MiB or smaller."
            })),
        )
            .into_response();
    }
    if let Err(error) = crate::plugin_runtime::PluginRuntime::validate_component_bytes(&bytes) {
        tracing::warn!(%error, plugin = %filename, "rejected invalid WASM plugin component");
        return admin_plugin_result(1, "The file is not a valid Blessing Skin WASM component.");
    }
    if let Err(error) = std::fs::create_dir_all(&state.config.plugins_dir) {
        tracing::error!(%error, "could not create WASM plugin directory");
        return unavailable();
    }
    let path = state.config.plugins_dir.join(&filename);
    let disabled = state
        .config
        .plugins_dir
        .join(format!("{name}.wasm.disabled"));
    if state.wasm_plugins.iter().any(|plugin| plugin == &filename) {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "code": 1,
                "message": "This plugin is still loaded. Restart the service before replacing it."
            })),
        )
            .into_response();
    }
    if path.exists() || disabled.exists() {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "code": 1,
                "message": "A plugin with that name already exists."
            })),
        )
            .into_response();
    }
    let write_path = path.clone();
    let write_result = tokio::task::spawn_blocking(move || {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&write_path)?;
        if let Err(error) = file.write_all(&bytes) {
            drop(file);
            let _ = std::fs::remove_file(&write_path);
            return Err(error);
        }
        Ok::<(), std::io::Error>(())
    })
    .await;
    match write_result {
        Ok(Ok(())) => admin_plugin_result(
            0,
            "WASM component installed. Restart the service to load it.",
        ),
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "code": 1,
                "message": "A plugin with that name already exists."
            })),
        )
            .into_response(),
        Ok(Err(error)) => {
            tracing::error!(%error, plugin = %filename, "failed to save WASM plugin");
            unavailable()
        }
        Err(error) => {
            tracing::error!(%error, plugin = %filename, "WASM plugin file operation failed");
            unavailable()
        }
    }
}

#[derive(Debug)]
enum RemoteComponentError {
    InvalidUrl,
    UnsafeAddress,
    Dns,
    Request,
    TooManyRedirects,
    InvalidRedirect,
    HttpStatus(u16),
    TooLarge,
    InvalidFilename,
}

fn safe_remote_component_url(url: &reqwest::Url) -> bool {
    if url.scheme() != "https"
        || url.username() != ""
        || url.password().is_some()
        || url.fragment().is_some()
        || url.port_or_known_default() != Some(443)
    {
        return false;
    }
    let Some(host) = url.host_str() else {
        return false;
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.parse::<IpAddr>().is_ok() {
        return false;
    }
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host.contains('.')
        && !host.ends_with(".localhost")
        && host != "localhost"
        && !host.ends_with(".local")
        && !host.ends_with(".internal")
        && !host.ends_with(".test")
        && !host.ends_with(".invalid")
        && !host.ends_with(".example")
}

fn public_download_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(address) => {
            let octets = address.octets();
            !(address.is_unspecified()
                || address.is_loopback()
                || address.is_private()
                || address.is_link_local()
                || address.is_broadcast()
                || address.is_documentation()
                || address.is_multicast()
                || octets[0] == 0
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
                || (octets[0] == 198 && (18..=19).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 88 && octets[2] == 99)
                || octets[0] >= 240)
        }
        IpAddr::V6(address) => {
            if let Some(mapped) = address.to_ipv4_mapped() {
                return public_download_ip(IpAddr::V4(mapped));
            }
            let segments = address.segments();
            (segments[0] & 0xe000) == 0x2000
                && !address.is_loopback()
                && !address.is_unspecified()
                && !address.is_unique_local()
                && !address.is_unicast_link_local()
                && !address.is_multicast()
                && !(segments[0] == 0x2001 && segments[1] <= 0x01ff)
                && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
                && segments[0] != 0x2002
        }
    }
}

async fn fetch_remote_wasm_component(
    raw_url: &str,
) -> Result<(String, Vec<u8>), RemoteComponentError> {
    let (url, bytes) =
        fetch_remote_public_resource(raw_url, crate::plugin_runtime::COMPONENT_FILE_LIMIT).await?;
    let filename = url
        .path_segments()
        .and_then(|mut segments| segments.next_back())
        .filter(|filename| !filename.is_empty())
        .ok_or(RemoteComponentError::InvalidFilename)?;
    let Some(name) = filename.strip_suffix(".wasm") else {
        return Err(RemoteComponentError::InvalidFilename);
    };
    if !crate::plugin_runtime::valid_plugin_name(name) {
        return Err(RemoteComponentError::InvalidFilename);
    }
    Ok((filename.to_owned(), bytes))
}

async fn fetch_remote_public_resource(
    raw_url: &str,
    max_bytes: u64,
) -> Result<(reqwest::Url, Vec<u8>), RemoteComponentError> {
    let mut url = reqwest::Url::parse(raw_url).map_err(|_| RemoteComponentError::InvalidUrl)?;
    for redirect_count in 0..=5 {
        if !safe_remote_component_url(&url) {
            return Err(RemoteComponentError::InvalidUrl);
        }
        let host = url.host_str().ok_or(RemoteComponentError::InvalidUrl)?;
        let addresses = tokio::time::timeout(
            Duration::from_secs(10),
            tokio::net::lookup_host((host, 443)),
        )
        .await
        .map_err(|_| RemoteComponentError::Dns)?
        .map_err(|_| RemoteComponentError::Dns)?
        .collect::<Vec<_>>();
        if addresses.is_empty() {
            return Err(RemoteComponentError::Dns);
        }
        if addresses
            .iter()
            .any(|address| !public_download_ip(address.ip()))
        {
            return Err(RemoteComponentError::UnsafeAddress);
        }
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .no_proxy()
            .resolve_to_addrs(host, &addresses)
            .build()
            .map_err(|_| RemoteComponentError::Request)?;
        let mut response = client
            .get(url.clone())
            .send()
            .await
            .map_err(|_| RemoteComponentError::Request)?;
        if response.status().is_redirection() {
            if redirect_count == 5 {
                return Err(RemoteComponentError::TooManyRedirects);
            }
            let location = response
                .headers()
                .get(axum::http::header::LOCATION)
                .and_then(|location| location.to_str().ok())
                .ok_or(RemoteComponentError::InvalidRedirect)?;
            url = url
                .join(location)
                .map_err(|_| RemoteComponentError::InvalidRedirect)?;
            continue;
        }
        if !response.status().is_success() {
            return Err(RemoteComponentError::HttpStatus(response.status().as_u16()));
        }
        if response
            .content_length()
            .is_some_and(|length| length > max_bytes)
        {
            return Err(RemoteComponentError::TooLarge);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| RemoteComponentError::Request)?
        {
            if bytes.len().saturating_add(chunk.len()) > max_bytes as usize {
                return Err(RemoteComponentError::TooLarge);
            }
            bytes.extend_from_slice(&chunk);
        }
        return Ok((url, bytes));
    }
    Err(RemoteComponentError::TooManyRedirects)
}

async fn fetch_wasm_plugin_registry(
    state: &AppState,
) -> Result<Option<Vec<WasmPluginRegistryEntry>>, RemoteComponentError> {
    let Some(url) = state.config.wasm_plugin_registry_url.as_deref() else {
        return Ok(None);
    };
    let (_, bytes) = fetch_remote_public_resource(url, 1024 * 1024).await?;
    parse_wasm_plugin_registry(&bytes)
        .map(Some)
        .map_err(|_| RemoteComponentError::InvalidFilename)
}

fn parse_wasm_plugin_registry(
    bytes: &[u8],
) -> Result<Vec<WasmPluginRegistryEntry>, serde_json::Error> {
    let manifest: WasmPluginRegistryManifest = serde_json::from_slice(bytes)?;
    if manifest.schema_version != 1 || manifest.plugins.len() > 500 {
        return Err(serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unsupported WASM plugin registry manifest",
        )));
    }
    let mut names = std::collections::HashSet::new();
    for entry in &manifest.plugins {
        let component_url = reqwest::Url::parse(&entry.download_url);
        let filename_matches = component_url.as_ref().is_ok_and(|url| {
            url.path_segments()
                .and_then(|mut segments| segments.next_back())
                .is_some_and(|filename| filename == format!("{}.wasm", entry.name))
                && safe_remote_component_url(url)
        });
        if !crate::plugin_runtime::valid_plugin_name(&entry.name)
            || entry.name.len() > 128
            || !names.insert(entry.name.as_str())
            || entry.version.trim().is_empty()
            || entry.version.len() > 128
            || entry.title.trim().is_empty()
            || entry.title.len() > 200
            || entry.description.len() > 4096
            || entry.author.trim().is_empty()
            || entry.author.len() > 200
            || entry.sha256.len() != 64
            || !entry.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
            || !filename_matches
        {
            return Err(serde_json::Error::io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid WASM plugin registry entry",
            )));
        }
    }
    Ok(manifest.plugins)
}
fn admin_plugin_inventory(state: &AppState) -> Result<Vec<serde_json::Value>, std::io::Error> {
    let mut plugins = std::collections::BTreeMap::<String, (bool, bool)>::new();
    for filename in &state.wasm_plugins {
        if let Some(name) = filename.strip_suffix(".wasm")
            && crate::plugin_runtime::valid_plugin_name(name)
        {
            plugins.insert(name.to_owned(), (true, false));
        }
    }
    let entries = match std::fs::read_dir(&state.config.plugins_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(plugins
                .into_iter()
                .map(|(name, (enabled, _))| {
                    let has_readme = state
                        .wasm_plugin_readmes
                        .iter()
                        .any(|plugin| plugin == &name);
                    let has_config = state
                        .wasm_plugin_configurations
                        .iter()
                        .any(|plugin| plugin == &name);
                    admin_plugin_record(state, name, enabled, false, has_readme, has_config)
                })
                .collect());
        }
        Err(error) => return Err(error),
    };
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let filename = entry.file_name();
        let Some(filename) = filename.to_str() else {
            continue;
        };
        let (name, enabled) = if let Some(name) = filename.strip_suffix(".wasm") {
            (name, true)
        } else if let Some(name) = filename.strip_suffix(".wasm.disabled") {
            (name, false)
        } else {
            continue;
        };
        if !crate::plugin_runtime::valid_plugin_name(name) {
            continue;
        }
        plugins
            .entry(name.to_owned())
            .and_modify(|state| {
                if !state.1 {
                    state.0 = enabled;
                } else {
                    state.0 |= enabled;
                }
                state.1 = true;
            })
            .or_insert((enabled, true));
    }
    Ok(plugins
        .into_iter()
        .map(|(name, (enabled, on_disk))| {
            let has_readme = state
                .wasm_plugin_readmes
                .iter()
                .any(|plugin| plugin == &name);
            let has_config = state
                .wasm_plugin_configurations
                .iter()
                .any(|plugin| plugin == &name);
            admin_plugin_record(state, name, enabled, on_disk, has_readme, has_config)
        })
        .collect())
}

fn admin_plugin_description(
    loaded: bool,
    load_failed: bool,
    enabled: bool,
    on_disk: bool,
    chinese: bool,
) -> &'static str {
    if load_failed {
        if chinese {
            "加载失败；请查看服务日志"
        } else {
            "Failed to load; check service logs"
        }
    } else if loaded && !on_disk {
        if chinese {
            "文件已移除；当前进程重启前仍会运行"
        } else {
            "File removed; still running until restart"
        }
    } else if loaded {
        if chinese {
            "已加载；文件状态变更需重启服务"
        } else {
            "Loaded; file changes require restart"
        }
    } else if enabled {
        if chinese {
            "已启用；将在下次启动时加载"
        } else {
            "Enabled; will load on next startup"
        }
    } else if chinese {
        "已停用"
    } else {
        "Disabled"
    }
}

fn admin_plugin_record(
    state: &AppState,
    name: String,
    enabled: bool,
    on_disk: bool,
    has_readme: bool,
    has_config: bool,
) -> serde_json::Value {
    let filename = format!("{name}.wasm");
    let loaded = state.wasm_plugins.iter().any(|plugin| plugin == &filename);
    let load_failed = !loaded
        && state
            .wasm_plugin_load_failures
            .iter()
            .any(|plugin| plugin == &filename);
    let chinese = request_locale(&state).starts_with("zh");
    let description = admin_plugin_description(loaded, load_failed, enabled, on_disk, chinese);
    serde_json::json!({
        "name": name,
        "title": name,
        "description": description,
        "version": "WASM host API 1.7.0",
        "enabled": enabled,
        "loaded": loaded,
        "load_failed": load_failed,
        "on_disk": on_disk,
        "readme": has_readme,
        "config": has_config,
        "icon": {"fa": "puzzle-piece", "faType": "fas", "bg": "teal"}
    })
}

fn admin_plugin_result(code: i32, message: &str) -> Response {
    Json(serde_json::json!({"code": code, "message": message})).into_response()
}

async fn web_admin_chart(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if user.permission < 1 {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(database) = &state.database else {
        return unavailable();
    };

    let today = shanghai_now().date();
    let month_ago = today
        .checked_sub_months(chrono::Months::new(1))
        .unwrap_or_else(|| today - chrono::Duration::days(30));
    let since = month_ago
        .and_hms_opt(0, 0, 0)
        .unwrap()
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    let (user_registrations, texture_uploads) = match database
        .admin_activity_counts(&state.config.database.table_prefix, &since)
        .await
    {
        Ok(counts) => counts,
        Err(error) => {
            tracing::error!(%error, "failed to load admin chart activity");
            return unavailable();
        }
    };

    let user_counts = user_registrations
        .into_iter()
        .collect::<std::collections::HashMap<_, _>>();
    let texture_counts = texture_uploads
        .into_iter()
        .collect::<std::collections::HashMap<_, _>>();
    let axis_dates: Vec<_> = (0..=30)
        .map(|days_ago| today - chrono::Duration::days(30 - days_ago))
        .collect();
    let x_axis = axis_dates
        .iter()
        .map(|date| admin_chart_date_label(*date, &request_locale(&state)))
        .collect::<Vec<_>>();
    let user_data = axis_dates
        .iter()
        .map(|date| {
            *user_counts
                .get(&date.format("%Y-%m-%d").to_string())
                .unwrap_or(&0)
        })
        .collect::<Vec<_>>();
    let texture_data = axis_dates
        .iter()
        .map(|date| {
            *texture_counts
                .get(&date.format("%Y-%m-%d").to_string())
                .unwrap_or(&0)
        })
        .collect::<Vec<_>>();
    let (user_label, texture_label) = admin_chart_series_labels(&request_locale(&state));

    Json(serde_json::json!({
        "labels": [user_label, texture_label],
        "xAxis": x_axis,
        "data": [user_data, texture_data],
    }))
    .into_response()
}

fn admin_chart_series_labels(locale: &str) -> (&'static str, &'static str) {
    if locale.starts_with("zh_TW") {
        ("使用者註冊", "材質上載")
    } else if locale.starts_with("zh") {
        ("用户注册", "材质上传")
    } else if locale.starts_with("de") {
        ("Benutzerregistrierungen", "Hochgeladene Texturen")
    } else if locale.starts_with("fr") {
        ("Enregister un utilisateur", "Chargements de textures")
    } else if locale.starts_with("es") {
        ("Registro de Usuario", "Subidas de Texturas")
    } else if locale.starts_with("ru") {
        ("Регистрация пользователя", "Загрузки текстур")
    } else if locale.starts_with("ja") {
        ("ユーザー登録", "スキンのアップロード")
    } else if locale.starts_with("ko") {
        ("사용자 등록", "택스쳐 업로드")
    } else if locale.starts_with("nl") {
        ("Gebruikers Registratie", "Texture Uploads")
    } else {
        ("User Registration", "Texture Uploads")
    }
}

fn admin_chart_date_label(date: chrono::NaiveDate, locale: &str) -> String {
    use chrono::Datelike;

    let year = date.year();
    let month = date.month();
    let day = date.day();
    if locale.starts_with("zh") {
        format!("{year}/{month}/{day}")
    } else if locale.starts_with("ja") || locale.starts_with("ko") {
        format!("{year}/{month:02}/{day:02}")
    } else if locale.starts_with("en") {
        format!("{month}/{day}/{year}")
    } else if locale.starts_with("de") || locale.starts_with("ru") {
        format!("{day:02}.{month:02}.{year}")
    } else {
        format!("{day:02}/{month:02}/{year}")
    }
}

pub(crate) async fn site_name(state: &AppState) -> String {
    localized_site_option(state, "site_name")
        .await
        .unwrap_or_else(|| "Blessing Skin".to_owned())
}

async fn oauth_manage_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) = authenticated_web_user(&state, &headers).await {
        return response;
    }
    let site_name = site_name(&state).await;
    let app_dir = state.public_dir.join("app");
    let stylesheet = frontend_entrypoint(&app_dir, "style", "css", &request_app_url(&state)).await;
    let frontend_script =
        frontend_entrypoint(&app_dir, "app", "js", &request_app_url(&state)).await;
    let i18n = load_frontend_translations(&state, &app_dir, &request_locale(&state)).await;
    let frontend_globals_b64 = encode_frontend_globals(
        &state,
        &site_name,
        "user/oauth/manage",
        serde_json::json!({}),
        i18n,
    );
    let page = OAuthManagePage {
        site_name,
        locale: request_locale(&state),
        frontend_style_available: stylesheet.is_some(),
        frontend_stylesheet: stylesheet.unwrap_or_default(),
        frontend_script_available: frontend_script.is_some(),
        frontend_script: frontend_script.unwrap_or_default(),
        frontend_globals_b64,
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to render OAuth client management page");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn user_profile_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let page_widgets = filter_user_profile_widgets(&state).await;
    let site_name = site_name(&state).await;
    let app_dir = state.public_dir.join("app");
    let stylesheet = frontend_entrypoint(&app_dir, "style", "css", &request_app_url(&state)).await;
    let frontend_script =
        frontend_entrypoint(&app_dir, "app", "js", &request_app_url(&state)).await;
    let i18n = load_frontend_translations(&state, &app_dir, &request_locale(&state)).await;
    let allow_delete = user.permission < 1;
    let extra = serde_json::json!({
        "profile": {
            "nickname": &user.nickname,
            "email": &user.email,
            "avatar": user.avatar,
            "allow_delete": allow_delete,
        },
        "page_widgets": &page_widgets,
    });
    let frontend_globals_b64 =
        encode_frontend_globals(&state, &site_name, "user/profile", extra, i18n);
    let page = UserProfilePage {
        site_name,
        locale: request_locale(&state),
        user,
        allow_delete,
        page_widgets,
        frontend_style_available: stylesheet.is_some(),
        frontend_stylesheet: stylesheet.unwrap_or_default(),
        frontend_script_available: frontend_script.is_some(),
        frontend_script: frontend_script.unwrap_or_default(),
        frontend_globals_b64,
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to render user profile page");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn web_user_reports(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<UserReportsQuery>,
) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    const PER_PAGE: i64 = 10;
    let current_page = query.page.unwrap_or(1).max(1);
    let (reports, total) = match user_report_page_data(
        database,
        &state.config.database.table_prefix,
        user.uid,
        current_page,
        PER_PAGE,
    )
    .await
    {
        Ok(result) => result,
        Err(error) => {
            tracing::error!(%error, user_id = user.uid, "failed to load user report history");
            return unavailable();
        }
    };
    let site_name = site_name(&state).await;
    let app_dir = state.public_dir.join("app");
    let stylesheet = frontend_entrypoint(&app_dir, "style", "css", &request_app_url(&state)).await;
    let frontend_script =
        frontend_entrypoint(&app_dir, "app", "js", &request_app_url(&state)).await;
    let i18n = load_frontend_translations(&state, &app_dir, &request_locale(&state)).await;
    let frontend_globals_b64 = encode_frontend_globals(
        &state,
        &site_name,
        "user/reports",
        serde_json::json!({}),
        i18n,
    );
    let page = UserReportsPage {
        site_name,
        locale: request_locale(&state),
        reports,
        current_page,
        last_page: total
            .saturating_add(PER_PAGE - 1)
            .div_euclid(PER_PAGE)
            .max(1),
        frontend_style_available: stylesheet.is_some(),
        frontend_stylesheet: stylesheet.unwrap_or_default(),
        frontend_script_available: frontend_script.is_some(),
        frontend_script: frontend_script.unwrap_or_default(),
        frontend_globals_b64,
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to render user report history");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn web_user_report_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    Query(query): Query<UserReportsQuery>,
) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    const PER_PAGE: i64 = 10;
    let page = query.page.unwrap_or(1).max(1);
    let path = format!(
        "{}{}",
        request_app_url(&state).trim_end_matches('/'),
        uri.path()
    );
    let (reports, total) = match user_report_page_data(
        database,
        &state.config.database.table_prefix,
        user.uid,
        page,
        PER_PAGE,
    )
    .await
    {
        Ok(result) => result,
        Err(error) => {
            tracing::error!(%error, user_id = user.uid, "failed to load user report list");
            return unavailable();
        }
    };
    Json(legacy_paginator_json(
        reports,
        total,
        page,
        PER_PAGE,
        &path,
        uri.query(),
    ))
    .into_response()
}

async fn user_report_page_data(
    database: &DatabasePool,
    prefix: &str,
    user_id: i64,
    page: i64,
    per_page: i64,
) -> Result<(Vec<UserReportView>, i64), sqlx::Error> {
    let filters = ReportSearchFilters {
        reporter: Some(user_id),
        ..Default::default()
    };
    let (items, total) = database
        .report_management_items(prefix, &filters, "report_at", true, page, per_page)
        .await?;
    let reports = items
        .into_iter()
        .map(|report| UserReportView {
            id: report.id,
            tid: report.tid,
            texture_name: report.texture_name,
            reason: report.reason,
            status: report.status,
            report_at: report.report_at,
        })
        .collect();
    Ok((reports, total))
}

async fn web_read_notification(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(id): RoutePath<String>,
) -> Response {
    let Some(user_id) = session_user_id(&state, &headers) else {
        return unauthenticated();
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    match database
        .read_notification(&state.config.database.table_prefix, user_id, &id)
        .await
    {
        Ok(Some(notification)) => {
            emit_plugin_event(
                &state,
                "notification.read",
                serde_json::json!({"user_id": user_id, "notification_id": notification.id}),
            )
            .await;
            notification_detail(notification)
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "message": "Notification not found." })),
        )
            .into_response(),
        Err(error) => {
            tracing::error!(%error, user_id, notification_id = %id, "failed to mark web notification as read");
            unavailable()
        }
    }
}

async fn user_score_info(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let prefix = &state.config.database.table_prefix;
    let (players, storage) = match database.user_usage(prefix, user.uid).await {
        Ok(usage) => usage,
        Err(error) => {
            tracing::error!(%error, user_id = user.uid, "failed to read user score usage");
            return unavailable();
        }
    };
    let option_number =
        |value: Option<String>, default: i64| legacy_option_integer(value.as_deref(), default);
    let storage_rate = match database.option(prefix, "score_per_storage").await {
        Ok(value) => option_number(value, 1),
        Err(error) => {
            tracing::error!(%error, "failed to read storage score rate");
            return unavailable();
        }
    };
    let player_rate = match database.option(prefix, "score_per_player").await {
        Ok(value) => option_number(value, 100),
        Err(error) => {
            tracing::error!(%error, "failed to read player score rate");
            return unavailable();
        }
    };
    let sign_after_zero = match database.option(prefix, "sign_after_zero").await {
        Ok(value) => legacy_option_bool(value.as_deref()),
        Err(error) => {
            tracing::error!(%error, "failed to read sign reset option");
            return unavailable();
        }
    };
    let sign_gap_time = match database.option(prefix, "sign_gap_time").await {
        Ok(value) => option_number(value, 24),
        Err(error) => {
            tracing::error!(%error, "failed to read sign gap option");
            return unavailable();
        }
    };
    Json(serde_json::json!({
        "user": { "score": user.score, "lastSignAt": user.last_sign_at },
        "rate": { "storage": storage_rate, "players": player_rate },
        "usage": { "players": players, "storage": storage },
        "signAfterZero": sign_after_zero,
        "signGapTime": sign_gap_time
    }))
    .into_response()
}

async fn user_sign(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let can_sign = state
        .wasm_runtime
        .lock()
        .await
        .apply_filter(
            "can_sign",
            &serde_json::json!(true),
            &serde_json::json!({ "user_id": user.uid }),
        )
        .await;
    if let Some(reason) = plugin_filter_rejection(&can_sign) {
        return login_result(2, reason, None);
    }
    let prefix = &state.config.database.table_prefix;
    let sign_after_zero = match database.option(prefix, "sign_after_zero").await {
        Ok(value) => legacy_option_bool(value.as_deref()),
        Err(error) => {
            tracing::error!(%error, "failed to read sign reset option");
            return unavailable();
        }
    };
    let sign_gap_time = match database.option(prefix, "sign_gap_time").await {
        Ok(value) => legacy_option_integer(value.as_deref(), 24).max(0),
        Err(error) => {
            tracing::error!(%error, "failed to read sign gap option");
            return unavailable();
        }
    };
    let (minimum, maximum) = match database.option(prefix, "sign_score").await {
        Ok(value) => value
            .as_deref()
            .and_then(|value| value.split_once(','))
            .and_then(|(minimum, maximum)| {
                Some((
                    minimum.trim().parse::<i64>().ok()?,
                    maximum.trim().parse::<i64>().ok()?,
                ))
            })
            .unwrap_or((10, 100)),
        Err(error) => {
            tracing::error!(%error, "failed to read sign score range");
            return unavailable();
        }
    };
    let (minimum, maximum) = (minimum.min(maximum), minimum.max(maximum));
    let now = shanghai_now();
    let eligible_before = if sign_after_zero {
        now.date().and_hms_opt(0, 0, 0).unwrap_or(now)
    } else {
        now - chrono::Duration::hours(sign_gap_time)
    };
    let now = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let eligible_before = eligible_before.format("%Y-%m-%d %H:%M:%S").to_string();
    if !legacy_sign_is_eligible(&user.last_sign_at, &eligible_before) {
        return login_result(1, "", None);
    }
    let base_reward = rand::thread_rng().gen_range(minimum..=maximum);
    let filtered_reward = state
        .wasm_runtime
        .lock()
        .await
        .apply_filter(
            "sign_score",
            &serde_json::json!(base_reward),
            &serde_json::json!({ "user_id": user.uid }),
        )
        .await;
    let reward = filtered_reward.as_i64().unwrap_or(base_reward);
    emit_plugin_event(
        &state,
        "user.sign.before",
        user_sign_plugin_event(user.uid, reward),
    )
    .await;
    match database
        .sign_user(prefix, user.uid, reward, &now, &eligible_before)
        .await
    {
        Ok(crate::database::UserSignOutcome::Signed(score)) => {
            emit_plugin_event(
                &state,
                "user.sign.after",
                user_sign_plugin_event(user.uid, reward),
            )
            .await;
            emit_plugin_event(
                &state,
                "user.score.updated",
                user_score_updated_event(user.uid, user.score, score),
            )
            .await;
            let message = if request_locale(&state).starts_with("zh") {
                format!("签到成功，获得了 {reward} 积分")
            } else {
                format!("Signed successfully. You got {reward} scores.")
            };
            login_result(0, &message, Some(serde_json::json!({ "score": score })))
        }
        Ok(crate::database::UserSignOutcome::NotEligible) => login_result(1, "", None),
        Err(error) => {
            tracing::error!(%error, user_id = user.uid, "failed to apply sign reward");
            unavailable()
        }
    }
}

async fn web_player_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if session_user_id(&state, &headers).is_none() {
        return Redirect::to("/auth/login").into_response();
    }
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let prefix = &state.config.database.table_prefix;
    let (min_length, max_length, rule, _) = match player_name_settings(database, prefix).await {
        Ok(settings) => settings,
        Err(error) => {
            tracing::error!(%error, "failed to load player-name settings");
            return unavailable();
        }
    };
    let score_per_player = match database.option(prefix, "score_per_player").await {
        Ok(value) => legacy_option_integer(value.as_deref(), 100),
        Err(error) => {
            tracing::error!(%error, "failed to load player score cost");
            return unavailable();
        }
    };
    let player_count = match database.players_for_user(prefix, user.uid).await {
        Ok(players) => players.len(),
        Err(error) => {
            tracing::error!(%error, user_id = user.uid, "failed to load player count for management page");
            return unavailable();
        }
    };
    let chinese = request_locale(&state).starts_with("zh");
    let rule_label = match (chinese, rule.as_str()) {
        (true, "official") => "仅允许官方角色名字符".to_owned(),
        (true, "cjk") => "允许中文角色名".to_owned(),
        (true, "utf8") => "允许非空白 UTF-8 字符".to_owned(),
        (true, "custom") => "使用站点自定义正则规则".to_owned(),
        (false, "official") => "Official player-name characters only".to_owned(),
        (false, "cjk") => "CJK player names are allowed".to_owned(),
        (false, "utf8") => "Any non-whitespace UTF-8 characters".to_owned(),
        (false, "custom") => "Site-defined regular expression".to_owned(),
        (true, _) => "站点自定义角色名规则".to_owned(),
        (false, _) => "Site-defined player-name rule".to_owned(),
    };
    let length_label = if chinese {
        format!("角色名长度至少为 {min_length} 个字符，最多不超过 {max_length} 个字符。")
    } else {
        format!(
            "The player name should be at least {min_length} characters and not greater than {max_length} characters."
        )
    };
    let page_widgets = filter_player_page_widgets(&state).await;
    let site_name = site_name(&state).await;
    let app_dir = state.public_dir.join("app");
    let stylesheet = frontend_entrypoint(&app_dir, "style", "css", &request_app_url(&state)).await;
    let frontend_script =
        frontend_entrypoint(&app_dir, "app", "js", &request_app_url(&state)).await;
    let i18n = load_frontend_translations(&state, &app_dir, &request_locale(&state)).await;
    let frontend_globals_b64 = encode_frontend_globals(
        &state,
        &site_name,
        "user/player",
        serde_json::json!({
            "count": player_count,
            "rule": rule_label,
            "length": length_label,
            "score": user.score,
            "cost": score_per_player,
        }),
        i18n,
    );
    let has_player_management = page_widgets
        .iter()
        .any(|widget| widget == "player_management");
    let page = PlayerManagementPage {
        site_name,
        locale: request_locale(&state),
        user,
        page_widgets,
        has_player_management,
        score_per_player,
        rule_label,
        min_length,
        max_length,
        frontend_style_available: stylesheet.is_some(),
        frontend_stylesheet: stylesheet.unwrap_or_default(),
        frontend_script_available: frontend_script.is_some(),
        frontend_script: frontend_script.unwrap_or_default(),
        frontend_globals_b64,
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to render player-management page");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn web_player_list(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    match database
        .players_for_user(&state.config.database.table_prefix, user.uid)
        .await
    {
        Ok(players) => Json(players).into_response(),
        Err(error) => {
            tracing::error!(%error, user_id = user.uid, "failed to load web player's list");
            unavailable()
        }
    }
}

async fn player_name_settings(
    database: &DatabasePool,
    prefix: &str,
) -> Result<(usize, usize, String, String), sqlx::Error> {
    let min_length = database
        .option(prefix, "player_name_length_min")
        .await?
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(3);
    let max_length = database
        .option(prefix, "player_name_length_max")
        .await?
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(16);
    let rule = database
        .option(prefix, "player_name_rule")
        .await?
        .unwrap_or_else(|| "official".to_owned());
    let custom_rule = database
        .option(prefix, "custom_player_name_regexp")
        .await?
        .unwrap_or_default();
    Ok((min_length, max_length, rule, custom_rule))
}

async fn web_add_player(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
    body: Bytes,
) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let request = match parse_player_name_request(
        &query,
        &body,
        headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
    ) {
        Ok(request) => request,
        Err(()) => return validation_error("name", &request_locale(&state)),
    };
    let Some(name) = request.name.filter(|name| !name.is_empty()) else {
        return validation_error("name", &request_locale(&state));
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let prefix = &state.config.database.table_prefix;
    let (min_length, max_length, rule, custom_rule) =
        match player_name_settings(database, prefix).await {
            Ok(settings) => settings,
            Err(error) => {
                tracing::error!(%error, "failed to load player-name settings");
                return unavailable();
            }
        };
    if !valid_player_name(&name, &rule, &custom_rule, min_length, max_length) {
        return validation_error("name", &request_locale(&state));
    }
    let filtered_name = state
        .wasm_runtime
        .lock()
        .await
        .apply_filter(
            "new_player_name",
            &serde_json::json!(name),
            &serde_json::json!({ "user_id": user.uid, "action": "add" }),
        )
        .await;
    let name = filtered_name.as_str().unwrap_or(&name).to_owned();
    emit_plugin_event(
        &state,
        "player.add.attempt",
        serde_json::json!({ "user_id": user.uid, "name": name.as_str() }),
    )
    .await;
    let can_add = state
        .wasm_runtime
        .lock()
        .await
        .apply_filter(
            "can_add_player",
            &serde_json::json!(true),
            &serde_json::json!({ "user_id": user.uid, "name": name.as_str() }),
        )
        .await;
    if let Some(reason) = plugin_filter_rejection(&can_add) {
        return login_result(1, reason, None);
    }
    let score_cost = match database.option(prefix, "score_per_player").await {
        Ok(value) => legacy_option_integer(value.as_deref(), 100),
        Err(error) => {
            tracing::error!(%error, "failed to load player score cost");
            return unavailable();
        }
    };
    if user.score < score_cost {
        return login_result(
            7,
            if request_locale(&state).starts_with("zh") {
                "添加角色失败，积分不足"
            } else {
                "You don't have enough score to add a player."
            },
            None,
        );
    }
    emit_plugin_event(
        &state,
        "player.adding",
        serde_json::json!({ "user_id": user.uid, "name": name.as_str() }),
    )
    .await;
    match database
        .add_player(prefix, user.uid, &name, score_cost)
        .await
    {
        Ok(crate::database::PlayerAddOutcome::Added(player)) => {
            emit_plugin_event(
                &state,
                "player.added",
                serde_json::json!({"user_id": user.uid, "player_id": player.pid, "name": player.name}),
            )
            .await;
            let message = if request_locale(&state).starts_with("zh") {
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
            duplicate_player_name_error(&request_locale(&state))
        }
        Ok(crate::database::PlayerAddOutcome::InsufficientScore) => login_result(
            7,
            if request_locale(&state).starts_with("zh") {
                "添加角色失败，积分不足"
            } else {
                "You don't have enough score to add a player."
            },
            None,
        ),
        Err(error) => {
            tracing::error!(%error, user_id = user.uid, "failed to add web player");
            unavailable()
        }
    }
}

async fn web_rename_player(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(raw_id): RoutePath<String>,
    Query(query): Query<BTreeMap<String, String>>,
    body: Bytes,
) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Ok(player_id) = raw_id.parse::<i64>() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let request = match parse_player_name_request(
        &query,
        &body,
        headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
    ) {
        Ok(request) => request,
        Err(()) => return validation_error("name", &request_locale(&state)),
    };
    let Some(name) = request.name.filter(|name| !name.is_empty()) else {
        return validation_error("name", &request_locale(&state));
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let prefix = &state.config.database.table_prefix;
    let (min_length, max_length, rule, custom_rule) =
        match player_name_settings(database, prefix).await {
            Ok(settings) => settings,
            Err(error) => {
                tracing::error!(%error, "failed to load player-name settings");
                return unavailable();
            }
        };
    if !valid_player_name(&name, &rule, &custom_rule, min_length, max_length) {
        return validation_error("name", &request_locale(&state));
    }
    let player = match load_owned_player(
        database,
        prefix,
        user.uid,
        player_id,
        &request_locale(&state),
    )
    .await
    {
        Ok(player) => player,
        Err(response) => return response,
    };
    let name = match filter_player_rename_name(&state, user.uid, &player, &name).await {
        Ok(name) => name,
        Err(reason) => return login_result(1, &reason, None),
    };
    match database
        .rename_player(prefix, user.uid, player_id, &name)
        .await
    {
        Ok(PlayerRenameOutcome::Renamed {
            previous_name,
            player,
        }) => {
            emit_plugin_event(
                &state,
                "player.renamed",
                serde_json::json!({"user_id": user.uid, "player_id": player_id, "previous_name": previous_name, "name": name}),
            )
            .await;
            let message = if request_locale(&state).starts_with("zh") {
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
        Ok(PlayerRenameOutcome::NameExists) => duplicate_player_name_error(&request_locale(&state)),
        Ok(PlayerRenameOutcome::Forbidden) => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "code": 1,
                "message": if request_locale(&state).starts_with("zh") {
                    "无权操作此角色"
                } else {
                    "You are not allowed to modify this player."
                }
            })),
        )
            .into_response(),
        Ok(PlayerRenameOutcome::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, user_id = user.uid, player_id, "failed to rename web player");
            unavailable()
        }
    }
}

async fn web_set_player_textures(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(raw_id): RoutePath<String>,
    Query(query): Query<BTreeMap<String, String>>,
    body: Bytes,
) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Ok(player_id) = raw_id.parse::<i64>() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let (skin, cape) = player_texture_input_ids(
        &query,
        &body,
        headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
    );
    return set_player_textures_with_plugins(
        &state,
        user.uid,
        player_id,
        skin,
        cape,
        &request_locale(&state),
    )
    .await;
}

async fn web_clear_player_textures(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(raw_id): RoutePath<String>,
    Query(query): Query<BTreeMap<String, String>>,
    body: Bytes,
) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Ok(player_id) = raw_id.parse::<i64>() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let (clear_skin, clear_cape) = player_texture_clear_flags(
        &query,
        &body,
        headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
    );
    return clear_player_textures_with_plugins(
        &state,
        user.uid,
        player_id,
        clear_skin,
        clear_cape,
        &request_locale(&state),
    )
    .await;
}

fn player_texture_clear_flags(
    query: &BTreeMap<String, String>,
    body: &[u8],
    content_type: Option<&str>,
) -> (bool, bool) {
    let mut skin = query.contains_key("skin");
    let mut cape = query.contains_key("cape");
    let mut types = Vec::new();
    if let Some(value) = query.get("type") {
        types.extend(value.split(',').map(str::to_owned));
    }
    if let Some(value) = query.get("type[]") {
        types.push(value.clone());
    }

    let media_type = content_type
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .trim();
    if media_type.eq_ignore_ascii_case("application/json")
        || media_type.to_ascii_lowercase().ends_with("+json")
    {
        if let Ok(serde_json::Value::Object(fields)) =
            serde_json::from_slice::<serde_json::Value>(body)
        {
            skin |= fields.contains_key("skin");
            cape |= fields.contains_key("cape");
            match fields.get("type") {
                Some(serde_json::Value::Array(values)) => {
                    types.extend(
                        values
                            .iter()
                            .filter_map(serde_json::Value::as_str)
                            .map(str::to_owned),
                    );
                }
                Some(serde_json::Value::String(value)) => {
                    types.extend(value.split(',').map(str::to_owned));
                }
                _ => {}
            }
        }
    } else if media_type.eq_ignore_ascii_case("application/x-www-form-urlencoded") {
        for (key, value) in form_urlencoded::parse(body) {
            match key.as_ref() {
                "skin" => skin = true,
                "cape" => cape = true,
                "type" | "type[]" => {
                    types.extend(value.split(',').map(str::to_owned));
                }
                key if key.starts_with("type[") => types.push(value.into_owned()),
                _ => {}
            }
        }
    }

    skin |= types.iter().any(|value| value == "skin");
    cape |= types.iter().any(|value| value == "cape");
    (skin, cape)
}

async fn web_delete_player(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(raw_id): RoutePath<String>,
) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Ok(player_id) = raw_id.parse::<i64>() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let prefix = &state.config.database.table_prefix;
    let player = match load_owned_player(
        database,
        prefix,
        user.uid,
        player_id,
        &request_locale(&state),
    )
    .await
    {
        Ok(player) => player,
        Err(response) => return response,
    };
    if let Err(reason) = filter_player_delete(&state, user.uid, &player).await {
        return login_result(1, &reason, None);
    }
    let return_score = match database.option(prefix, "return_score").await {
        Ok(value) => legacy_option_bool(value.as_deref()),
        Err(error) => {
            tracing::error!(%error, "failed to load player score refund option");
            return unavailable();
        }
    };
    let score_reward = if return_score {
        match database.option(prefix, "score_per_player").await {
            Ok(value) => legacy_option_integer(value.as_deref(), 100),
            Err(error) => {
                tracing::error!(%error, "failed to load player score reward");
                return unavailable();
            }
        }
    } else {
        0
    };
    match database
        .delete_player(prefix, user.uid, player_id, return_score, score_reward)
        .await
    {
        Ok(crate::database::PlayerDeleteOutcome::Deleted(name)) => {
            emit_plugin_event(
                &state,
                "player.deleted",
                serde_json::json!({"user_id": user.uid, "player_id": player_id, "name": name}),
            )
            .await;
            login_result(
                0,
                &if request_locale(&state).starts_with("zh") {
                    format!("角色 {name} 已被删除")
                } else {
                    format!("Player {name} was deleted successfully.")
                },
                None,
            )
        }
        Ok(crate::database::PlayerDeleteOutcome::Forbidden) => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "code": 1,
                "message": if request_locale(&state).starts_with("zh") {
                    "无权操作此角色"
                } else {
                    "You are not allowed to modify this player."
                }
            })),
        )
            .into_response(),
        Ok(crate::database::PlayerDeleteOutcome::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, user_id = user.uid, player_id, "failed to delete web player");
            unavailable()
        }
    }
}

async fn web_closet_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if session_user_id(&state, &headers).is_none() {
        return Redirect::to("/auth/login").into_response();
    }
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let page_widgets = filter_closet_page_widgets(&state).await;
    let has_closet_management = page_widgets
        .iter()
        .any(|widget| widget == "closet_management");
    let site_name = site_name(&state).await;
    let app_dir = state.public_dir.join("app");
    let stylesheet = frontend_entrypoint(&app_dir, "style", "css", &request_app_url(&state)).await;
    let frontend_script =
        frontend_entrypoint(&app_dir, "app", "js", &request_app_url(&state)).await;
    let i18n = load_frontend_translations(&state, &app_dir, &request_locale(&state)).await;
    let frontend_globals_b64 = encode_frontend_globals(
        &state,
        &site_name,
        "user/closet",
        serde_json::json!({ "unverified": false }),
        i18n,
    );
    let page = ClosetManagementPage {
        site_name,
        locale: request_locale(&state),
        user,
        page_widgets,
        has_closet_management,
        frontend_style_available: stylesheet.is_some(),
        frontend_stylesheet: stylesheet.unwrap_or_default(),
        frontend_script_available: frontend_script.is_some(),
        frontend_script: frontend_script.unwrap_or_default(),
        frontend_globals_b64,
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to render closet page");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn web_closet_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    Query(query): Query<ClosetListQuery>,
) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(6).clamp(1, 100);
    let category = query.category.as_deref().unwrap_or("skin");
    let search = query
        .q
        .as_deref()
        .filter(|value| !value.is_empty() && *value != "0");
    let path = format!(
        "{}{}",
        request_app_url(&state).trim_end_matches('/'),
        uri.path()
    );
    match database
        .closet_items(
            &state.config.database.table_prefix,
            user.uid,
            category,
            search,
            page,
            per_page,
        )
        .await
    {
        Ok((items, total)) => {
            let data = items.into_iter().map(closet_item_json).collect::<Vec<_>>();
            Json(legacy_paginator_json(
                data,
                total,
                page,
                per_page,
                &path,
                uri.query(),
            ))
            .into_response()
        }
        Err(error) => {
            tracing::error!(%error, user_id=user.uid, "failed to load web closet items");
            unavailable()
        }
    }
}
async fn web_closet_ids(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    match database
        .closet_item_ids(&state.config.database.table_prefix, user.uid)
        .await
    {
        Ok(ids) => Json(ids).into_response(),
        Err(error) => {
            tracing::error!(%error, user_id=user.uid, "failed to load web closet texture IDs");
            unavailable()
        }
    }
}

async fn web_add_closet_item(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
    body: Bytes,
) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let request = match parse_legacy_input_object(
        &query,
        &body,
        headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
    ) {
        Ok(fields) => serde_json::Value::Object(fields),
        Err(()) => return closet_validation_error("tid", &request_locale(&state)),
    };
    let Some(tid) = texture_id_from_request(request.get("tid")) else {
        return closet_validation_error("tid", &request_locale(&state));
    };
    let Some(name) = request
        .get("name")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
    else {
        return closet_validation_error("name", &request_locale(&state));
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let prefix = &state.config.database.table_prefix;
    let filtered_name = closet_name_filter(&state, "add_closet_item_name", tid, name).await;
    emit_plugin_event(
        &state,
        "closet.adding",
        serde_json::json!({"user_id": user.uid, "texture_id": tid, "item_name": filtered_name}),
    )
    .await;
    if let Some(reason) = closet_permission_filter(
        &state,
        "can_add_closet_item",
        serde_json::json!({"texture_id": tid, "name": filtered_name}),
    )
    .await
    {
        return login_result(1, &reason, None);
    }
    let score_cost = match database.option(prefix, "score_per_closet_item").await {
        Ok(value) => legacy_option_integer(value.as_deref(), 0),
        Err(error) => {
            tracing::error!(%error, "failed to load closet score cost");
            return unavailable();
        }
    };
    let like_award = match database.option(prefix, "score_award_per_like").await {
        Ok(value) => legacy_option_integer(value.as_deref(), 0),
        Err(error) => {
            tracing::error!(%error, "failed to load texture like award");
            return unavailable();
        }
    };
    match database
        .add_closet_item(
            prefix,
            user.uid,
            tid,
            name,
            score_cost,
            user.permission >= 1,
            like_award,
        )
        .await
    {
        Ok(crate::database::ClosetAddOutcome::Added) => {
            emit_plugin_event(
                &state,
                "closet.added",
                serde_json::json!({
                    "user_id": user.uid,
                    "texture_id": tid,
                    "item_name": filtered_name,
                }),
            )
            .await;
            login_result(
                0,
                &if request_locale(&state).starts_with("zh") {
                    format!("材质 {name} 收藏成功")
                } else {
                    format!("Added {name} to closet successfully.")
                },
                None,
            )
        }
        Ok(crate::database::ClosetAddOutcome::NameExists) => login_result(
            1,
            if request_locale(&state).starts_with("zh") {
                "你已经收藏过这个材质啦"
            } else {
                "You have already added this texture."
            },
            None,
        ),
        Ok(crate::database::ClosetAddOutcome::InsufficientScore) => login_result(
            1,
            if request_locale(&state).starts_with("zh") {
                "收藏失败，积分不足"
            } else {
                "You don't have enough score to add it to closet."
            },
            None,
        ),
        Ok(crate::database::ClosetAddOutcome::TextureNotFound) => login_result(
            1,
            if request_locale(&state).starts_with("zh") {
                "该材质不存在"
            } else {
                "We cannot find this texture."
            },
            None,
        ),
        Ok(crate::database::ClosetAddOutcome::PrivateTexture) => login_result(
            1,
            if request_locale(&state).starts_with("zh") {
                "请求的材质已经设为私密，仅上传者和管理员可查看"
            } else {
                "The requested texture is private and only visible to the uploader and admins."
            },
            None,
        ),
        Err(error) => {
            tracing::error!(%error, user_id=user.uid, tid, "failed to add web closet item");
            unavailable()
        }
    }
}

async fn web_rename_closet_item(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(raw_tid): RoutePath<String>,
    Query(query): Query<BTreeMap<String, String>>,
    body: Bytes,
) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Ok(tid) = raw_tid.parse::<i64>() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let request = match parse_legacy_input_object(
        &query,
        &body,
        headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
    ) {
        Ok(fields) => serde_json::Value::Object(fields),
        Err(()) => return closet_validation_error("name", &request_locale(&state)),
    };
    let Some(name) = request
        .get("name")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
    else {
        return closet_validation_error("name", &request_locale(&state));
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let filtered_name = closet_name_filter(&state, "rename_closet_item_name", tid, name).await;
    emit_plugin_event(
        &state,
        "closet.renaming",
        serde_json::json!({"user_id": user.uid, "texture_id": tid, "item_name": filtered_name}),
    )
    .await;
    let closet_item = match database
        .closet_item(&state.config.database.table_prefix, user.uid, tid)
        .await
    {
        Ok(Some(item)) => item,
        Ok(None) => return closet_item_missing(&state),
        Err(error) => {
            tracing::error!(%error, user_id=user.uid, tid, "failed to load closet item for rename filter");
            return unavailable();
        }
    };
    if let Some(reason) = closet_permission_filter(
        &state,
        "can_rename_closet_item",
        serde_json::json!({"item": closet_item_plugin_record(&closet_item), "name": filtered_name}),
    )
    .await
    {
        return login_result(1, &reason, None);
    }
    match database
        .rename_closet_item(
            &state.config.database.table_prefix,
            user.uid,
            tid,
            &filtered_name,
        )
        .await
    {
        Ok(crate::database::ClosetRenameOutcome::Renamed) => {
            emit_plugin_event(
                &state,
                "closet.renamed",
                serde_json::json!({
                    "user_id": user.uid,
                    "texture_id": tid,
                    "item_name": filtered_name,
                }),
            )
            .await;
            login_result(
                0,
                &if request_locale(&state).starts_with("zh") {
                    format!("衣柜物品成功重命名至 {filtered_name}")
                } else {
                    format!("The item is successfully renamed to {filtered_name}")
                },
                None,
            )
        }
        Ok(crate::database::ClosetRenameOutcome::NotInCloset) => closet_item_missing(&state),
        Err(error) => {
            tracing::error!(%error, user_id=user.uid, tid, "failed to rename web closet item");
            unavailable()
        }
    }
}

async fn web_remove_closet_item(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(raw_tid): RoutePath<String>,
) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Ok(tid) = raw_tid.parse::<i64>() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let prefix = &state.config.database.table_prefix;
    emit_plugin_event(
        &state,
        "closet.removing",
        serde_json::json!({"user_id": user.uid, "texture_id": tid}),
    )
    .await;
    let closet_item = match database.closet_item(prefix, user.uid, tid).await {
        Ok(Some(item)) => item,
        Ok(None) => return closet_item_missing(&state),
        Err(error) => {
            tracing::error!(%error, user_id=user.uid, tid, "failed to load closet item for remove filter");
            return unavailable();
        }
    };
    if let Some(reason) = closet_permission_filter(
        &state,
        "can_remove_closet_item",
        serde_json::json!({"item": closet_item_plugin_record(&closet_item)}),
    )
    .await
    {
        return login_result(1, &reason, None);
    }
    let refund = match database.option(prefix, "return_score").await {
        Ok(value) => legacy_option_bool(value.as_deref()),
        Err(error) => {
            tracing::error!(%error, "failed to load closet refund option");
            return unavailable();
        }
    };
    let score_refund = if refund {
        match database.option(prefix, "score_per_closet_item").await {
            Ok(value) => legacy_option_integer(value.as_deref(), 0),
            Err(error) => {
                tracing::error!(%error, "failed to load closet refund score");
                return unavailable();
            }
        }
    } else {
        0
    };
    let like_award = match database.option(prefix, "score_award_per_like").await {
        Ok(value) => legacy_option_integer(value.as_deref(), 0),
        Err(error) => {
            tracing::error!(%error, "failed to load like award");
            return unavailable();
        }
    };
    match database
        .remove_closet_item(prefix, user.uid, tid, refund, score_refund, like_award)
        .await
    {
        Ok(crate::database::ClosetRemoveOutcome::Removed) => {
            emit_plugin_event(
                &state,
                "closet.removed",
                serde_json::json!({"user_id": user.uid, "texture_id": tid}),
            )
            .await;
            login_result(
                0,
                if request_locale(&state).starts_with("zh") {
                    "材质已从衣柜中移除"
                } else {
                    "The texture was removed from closet successfully."
                },
                None,
            )
        }
        Ok(crate::database::ClosetRemoveOutcome::NotInCloset) => closet_item_missing(&state),
        Err(error) => {
            tracing::error!(%error, user_id=user.uid, tid, "failed to remove web closet item");
            unavailable()
        }
    }
}

fn shanghai_now() -> NaiveDateTime {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let timestamp = i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX);
    let utc = chrono::DateTime::<chrono::Utc>::from_timestamp(timestamp, elapsed.subsec_nanos())
        .unwrap_or_else(|| chrono::DateTime::<chrono::Utc>::from_timestamp(0, 0).unwrap());
    utc.with_timezone(&FixedOffset::east_opt(8 * 60 * 60).unwrap())
        .naive_local()
}

async fn user_profile_update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
    body: Bytes,
) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Some((session_token, session_claims)) = web_session_claims(&state, &headers) else {
        return unauthenticated();
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let request = match parse_legacy_input_object(
        &query,
        &body,
        headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
    ) {
        Ok(fields) => serde_json::Value::Object(fields),
        Err(()) => {
            return login_result(1, illegal_parameters_message(&request_locale(&state)), None);
        }
    };
    let action = request
        .get("action")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let prefix = &state.config.database.table_prefix;
    let chinese = request_locale(&state).starts_with("zh");
    let can_edit = state
        .wasm_runtime
        .lock()
        .await
        .apply_filter(
            "user_can_edit_profile",
            &serde_json::json!(true),
            &serde_json::json!({
                "user_id": user.uid,
                "action": action,
            }),
        )
        .await;
    if let Some(reason) = plugin_filter_rejection(&can_edit) {
        return login_result(1, reason, None);
    }
    emit_plugin_event(
        &state,
        "user.profile.updating",
        serde_json::json!({"user_id": user.uid, "action": action}),
    )
    .await;
    match action {
        "nickname" => {
            let Some(nickname) = request
                .get("new_nickname")
                .and_then(serde_json::Value::as_str)
                .filter(|nickname| !nickname.is_empty())
            else {
                return profile_validation_error(
                    "new_nickname",
                    "required",
                    &request_locale(&state),
                );
            };
            if let Err(error) = database
                .update_user_text(prefix, user.uid, "nickname", nickname)
                .await
            {
                tracing::error!(%error, user_id = user.uid, "failed to update user nickname");
                return unavailable();
            }
            emit_plugin_event(
                &state,
                "user.profile.updated",
                serde_json::json!({"user_id": user.uid, "action": "nickname"}),
            )
            .await;
            let message = if chinese {
                format!("昵称已成功设置为 {nickname}")
            } else {
                format!("Nickname is successfully updated to {nickname}")
            };
            login_result(0, &message, None)
        }
        "password" => {
            let Some(current_password) = request
                .get("current_password")
                .and_then(serde_json::Value::as_str)
                .filter(|password| (6..=32).contains(&password.chars().count()))
            else {
                return profile_validation_error(
                    "current_password",
                    "password",
                    &request_locale(&state),
                );
            };
            let Some(new_password) = request
                .get("new_password")
                .and_then(serde_json::Value::as_str)
                .filter(|password| (8..=32).contains(&password.chars().count()))
            else {
                return profile_validation_error(
                    "new_password",
                    "new_password",
                    &request_locale(&state),
                );
            };
            let credential = match database.credentials_by_user_id(prefix, user.uid).await {
                Ok(Some(credential)) => credential,
                Ok(None) => return unauthenticated(),
                Err(error) => {
                    tracing::error!(%error, user_id = user.uid, "failed to load user password for profile update");
                    return unavailable();
                }
            };
            if !verify_legacy_password(
                current_password,
                &credential.password,
                &state.config.password_method,
                &state.config.password_salt,
            ) {
                return login_result(
                    1,
                    if chinese {
                        "原密码错误"
                    } else {
                        "Wrong original password."
                    },
                    None,
                );
            }
            let Some(hash) = hash_legacy_password(
                new_password,
                &state.config.password_method,
                &state.config.password_salt,
                state.config.bcrypt_rounds,
            ) else {
                tracing::error!(method = %state.config.password_method, "unsupported configured legacy password method");
                return unavailable();
            };
            let hash = filter_user_password_hash(&state, &hash).await;
            if let Err(error) = database
                .update_user_text(prefix, user.uid, "password", &hash)
                .await
            {
                tracing::error!(%error, user_id = user.uid, "failed to update user password");
                return unavailable();
            }
            emit_plugin_event(
                &state,
                "user.profile.updated",
                serde_json::json!({"user_id": user.uid, "action": "password"}),
            )
            .await;
            if let Err(error) =
                persist_web_session_revocation(&state, database, &session_token, &session_claims)
                    .await
            {
                tracing::error!(%error, user_id = user.uid, "failed to revoke session after password change");
                return unavailable();
            }
            let response = login_result(
                0,
                if chinese {
                    "密码修改成功，请重新登录"
                } else {
                    "Password updated successfully, please log in again."
                },
                None,
            );
            expire_web_session(&state, response)
        }
        "email" => {
            let Some(email) = request
                .get("email")
                .and_then(serde_json::Value::as_str)
                .filter(|email| valid_email_address(email) && email.len() <= 100)
            else {
                return profile_validation_error("email", "email", &request_locale(&state));
            };
            let Some(password) = request
                .get("password")
                .and_then(serde_json::Value::as_str)
                .filter(|password| (6..=32).contains(&password.chars().count()))
            else {
                return profile_validation_error("password", "password", &request_locale(&state));
            };
            let credential = match database.credentials_by_user_id(prefix, user.uid).await {
                Ok(Some(credential)) => credential,
                Ok(None) => return unauthenticated(),
                Err(error) => {
                    tracing::error!(%error, user_id = user.uid, "failed to load user password for email update");
                    return unavailable();
                }
            };
            if !verify_legacy_password(
                password,
                &credential.password,
                &state.config.password_method,
                &state.config.password_salt,
            ) {
                return login_result(
                    1,
                    if chinese {
                        "密码错误"
                    } else {
                        "Wrong password."
                    },
                    None,
                );
            }
            match database.user_email_exists(prefix, email, user.uid).await {
                Ok(true) => {
                    return login_result(
                        1,
                        if chinese {
                            "此邮箱已被占用"
                        } else {
                            "This email address is occupied."
                        },
                        None,
                    );
                }
                Ok(false) => {}
                Err(error) => {
                    tracing::error!(%error, user_id = user.uid, "failed to check email uniqueness");
                    return unavailable();
                }
            }
            if let Err(error) = database
                .update_user_email_and_reset_verification(prefix, user.uid, email)
                .await
            {
                tracing::error!(%error, user_id = user.uid, "failed to update user email");
                return unavailable();
            }
            emit_plugin_event(
                &state,
                "user.profile.updated",
                serde_json::json!({"user_id": user.uid, "action": "email"}),
            )
            .await;
            if let Err(error) =
                persist_web_session_revocation(&state, database, &session_token, &session_claims)
                    .await
            {
                tracing::error!(%error, user_id = user.uid, "failed to revoke session after email change");
                return unavailable();
            }
            let response = login_result(
                0,
                if chinese {
                    "邮箱修改成功，请重新登录"
                } else {
                    "Email address updated successfully, please log in again."
                },
                None,
            );
            expire_web_session(&state, response)
        }
        "delete" => {
            let Some(password) = request
                .get("password")
                .and_then(serde_json::Value::as_str)
                .filter(|password| (6..=32).contains(&password.chars().count()))
            else {
                return profile_validation_error("password", "password", &request_locale(&state));
            };
            if user.permission >= 1 {
                return login_result(
                    1,
                    if chinese {
                        "拥有管理员权限的账号不能被删除"
                    } else {
                        "Admin account can not be deleted."
                    },
                    None,
                );
            }
            let credential = match database.credentials_by_user_id(prefix, user.uid).await {
                Ok(Some(credential)) => credential,
                Ok(None) => return unauthenticated(),
                Err(error) => {
                    tracing::error!(%error, user_id = user.uid, "failed to load user password for account deletion");
                    return unavailable();
                }
            };
            if !verify_legacy_password(
                password,
                &credential.password,
                &state.config.password_method,
                &state.config.password_salt,
            ) {
                return login_result(
                    1,
                    if chinese {
                        "密码错误"
                    } else {
                        "Wrong password."
                    },
                    None,
                );
            }
            if let Err(error) =
                persist_web_session_revocation(&state, database, &session_token, &session_claims)
                    .await
            {
                tracing::error!(%error, user_id = user.uid, "failed to revoke session before account deletion");
                return unavailable();
            }
            emit_plugin_event(
                &state,
                "user.deleting",
                serde_json::json!({"user_id": user.uid}),
            )
            .await;
            match database.delete_user(prefix, user.uid).await {
                Ok(true) => {
                    emit_plugin_event(
                        &state,
                        "user.deleted",
                        serde_json::json!({"user_id": user.uid}),
                    )
                    .await;
                    let response = login_result(
                        0,
                        if chinese {
                            "账号已被成功删除"
                        } else {
                            "Your account is deleted successfully."
                        },
                        None,
                    );
                    expire_web_session(&state, response)
                }
                Ok(false) => unauthenticated(),
                Err(error) => {
                    tracing::error!(%error, user_id = user.uid, "failed to delete user account");
                    unavailable()
                }
            }
        }
        _ => login_result(1, illegal_parameters_message(&request_locale(&state)), None),
    }
}

async fn user_set_avatar(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
    body: Bytes,
) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let request = parse_legacy_input_object(
        &query,
        &body,
        headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
    )
    .ok()
    .map(serde_json::Value::Object);
    let Some(tid) = request
        .as_ref()
        .and_then(|value| value.get("tid"))
        .and_then(|value| request_i64(Some(value)))
    else {
        return profile_validation_error("tid", "integer", &request_locale(&state));
    };
    let can_update = state
        .wasm_runtime
        .lock()
        .await
        .apply_filter(
            "user_can_update_avatar",
            &serde_json::json!(true),
            &serde_json::json!({
                "user_id": user.uid,
                "texture_id": tid,
            }),
        )
        .await;
    if let Some(reason) = plugin_filter_rejection(&can_update) {
        return login_result(1, reason, None);
    }
    emit_plugin_event(
        &state,
        "user.avatar.updating",
        serde_json::json!({"user_id": user.uid, "texture_id": tid}),
    )
    .await;
    if tid != 0 {
        let texture = match database
            .texture_info(&state.config.database.table_prefix, tid)
            .await
        {
            Ok(Some(texture)) => texture,
            Ok(None) => {
                return login_result(
                    1,
                    if request_locale(&state).starts_with("zh") {
                        "材质不存在"
                    } else {
                        "No such texture."
                    },
                    None,
                );
            }
            Err(error) => {
                tracing::error!(%error, tid, "failed to load requested user avatar texture");
                return unavailable();
            }
        };
        if texture.texture_type == "cape" {
            return login_result(
                1,
                if request_locale(&state).starts_with("zh") {
                    "披风不能被设置为头像"
                } else {
                    "You can't set a cape as avatar."
                },
                None,
            );
        }
        if !texture.is_public && texture.uploader != user.uid && user.permission < 1 {
            return login_result(
                1,
                if request_locale(&state).starts_with("zh") {
                    "请求的材质已经设为私密，仅上传者和管理员可查看"
                } else {
                    "The requested texture is private and only visible to the uploader and admins."
                },
                None,
            );
        }
    }
    if let Err(error) = database
        .update_user_integer(&state.config.database.table_prefix, user.uid, "avatar", tid)
        .await
    {
        tracing::error!(%error, user_id = user.uid, tid, "failed to update user avatar");
        return unavailable();
    }
    emit_plugin_event(
        &state,
        "user.avatar.updated",
        serde_json::json!({"user_id": user.uid, "texture_id": tid}),
    )
    .await;
    login_result(
        0,
        if request_locale(&state).starts_with("zh") {
            "设置成功"
        } else {
            "New avatar was set successfully."
        },
        None,
    )
}

async fn toggle_user_dark_mode(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    if let Err(error) = database
        .toggle_user_dark_mode(&state.config.database.table_prefix, user.uid)
        .await
    {
        tracing::error!(%error, user_id = user.uid, "failed to toggle user dark mode");
        return unavailable();
    }
    StatusCode::NO_CONTENT.into_response()
}

fn profile_validation_error(field: &str, rule: &str, locale: &str) -> Response {
    let chinese = locale.starts_with("zh");
    let message = if chinese {
        "给定数据无效。"
    } else {
        "The given data was invalid."
    };
    let error = match (field, rule, chinese) {
        ("new_nickname", _, true) => "昵称为必填项。",
        ("new_nickname", _, false) => "The new_nickname field is required.",
        ("email", _, true) => "邮箱必须是有效的电子邮件地址。",
        ("email", _, false) => "The email must be a valid email address.",
        ("current_password", _, true) => "当前密码为必填项且长度必须为 6 至 32 个字符。",
        ("current_password", _, false) => {
            "The current_password field is required and must be between 6 and 32 characters."
        }
        ("new_password", _, true) => "新密码长度必须为 8 至 32 个字符。",
        ("new_password", _, false) => "The new_password must be between 8 and 32 characters.",
        ("tid", _, true) => "tid 必须是整数。",
        ("tid", _, false) => "The tid must be an integer.",
        (_, _, true) => "密码为必填项且长度必须为 6 至 32 个字符。",
        (_, _, false) => "The password field is required and must be between 6 and 32 characters.",
    };
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(serde_json::json!({ "message": message, "errors": { field: [error] } })),
    )
        .into_response()
}

fn illegal_parameters_message(locale: &str) -> &'static str {
    if locale.starts_with("zh") {
        "非法参数"
    } else {
        "Illegal parameters."
    }
}

async fn persist_web_session_revocation(
    state: &AppState,
    database: &DatabasePool,
    token: &str,
    claims: &WebSessionClaims,
) -> Result<(), sqlx::Error> {
    let now = jsonwebtoken::get_current_timestamp();
    let ttl = if claims.remember {
        LEGACY_REMEMBER_TTL_SECONDS
    } else {
        state.config.session_lifetime_seconds
    };
    // Revoke through the furthest possible sliding expiry and JWT's leeway.
    let revoke_until = claims.exp.max(now.saturating_add(ttl)).saturating_add(61);
    let revoke_until_i64 = i64::try_from(revoke_until).unwrap_or(i64::MAX);
    let keys = web_session_revocation_keys(token, claims);
    for key in &keys {
        database
            .revoke_web_session(&state.config.database.table_prefix, key, revoke_until_i64)
            .await?;
    }
    state
        .revoked_web_sessions
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .extend(keys.into_iter().map(|key| (key, revoke_until)));
    Ok(())
}

fn response_manages_web_session_cookie(response: &Response) -> bool {
    response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| value.trim_start().starts_with("blessing_skin_session="))
}

fn renewed_web_session_cookie(
    state: &AppState,
    claims: &WebSessionClaims,
    request_secure: bool,
) -> Result<Option<HeaderValue>, String> {
    if claims.remember {
        return Ok(None);
    }
    let Some(jti) = claims.jti.as_deref().filter(|jti| !jti.is_empty()) else {
        return Ok(None);
    };
    let Some(key) = &state.session_key else {
        return Err("APP_KEY is required to renew a web session".to_owned());
    };
    let now = jsonwebtoken::get_current_timestamp();
    let lifetime = state.config.session_lifetime_seconds;
    let renewed = WebSessionClaims {
        jti: Some(jti.to_owned()),
        sub: claims.sub.clone(),
        iat: now,
        exp: now.saturating_add(lifetime),
        remember: false,
    };
    let session =
        encode(&Header::new(Algorithm::HS256), &renewed, key).map_err(|error| error.to_string())?;
    let secure = if request_secure { "; Secure" } else { "" };
    let cookie = format!(
        "blessing_skin_session={session}; Path=/; HttpOnly; SameSite=Lax; Max-Age={lifetime}{secure}"
    );
    HeaderValue::from_str(&cookie)
        .map(Some)
        .map_err(|error| error.to_string())
}

fn expire_web_session(state: &AppState, mut response: Response) -> Response {
    let secure = if request_app_url(&state).starts_with("https://") {
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

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some((token, claims)) = web_session_claims(&state, &headers) else {
        return (StatusCode::FOUND, [(LOCATION, "/auth/login")]).into_response();
    };
    let Some(user_id) = session_user_id(&state, &headers) else {
        return (StatusCode::FOUND, [(LOCATION, "/auth/login")]).into_response();
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    match database
        .user_profile(&state.config.database.table_prefix, user_id)
        .await
    {
        Ok(Some(_)) => {}
        Ok(None) => return (StatusCode::FOUND, [(LOCATION, "/auth/login")]).into_response(),
        Err(error) => {
            tracing::error!(%error, user_id, "failed to load account for logout");
            return unavailable();
        }
    }
    emit_plugin_event(
        &state,
        "auth.logout.before",
        serde_json::json!({"user_id": user_id}),
    )
    .await;
    if let Err(error) = persist_web_session_revocation(&state, database, &token, &claims).await {
        tracing::error!(%error, user_id, "failed to revoke web session during logout");
        return unavailable();
    }
    let response = login_result(
        0,
        if request_locale(&state).starts_with("zh") {
            "已退出登录"
        } else {
            "Logged out successfully."
        },
        None,
    );
    let response = expire_web_session(&state, response);
    emit_plugin_event(
        &state,
        "auth.logout.after",
        serde_json::json!({"user_id": user_id}),
    )
    .await;
    emit_plugin_event(
        &state,
        "user.logged-out",
        serde_json::json!({"user_id": user_id}),
    )
    .await;
    response
}

async fn authenticated_guest_redirect(state: &AppState, headers: &HeaderMap) -> Option<Response> {
    let user_id = session_user_id(state, headers)?;
    let database = state.database.as_ref()?;
    match database
        .user_profile(&state.config.database.table_prefix, user_id)
        .await
    {
        Ok(Some(_)) => {
            let mut response = StatusCode::FOUND.into_response();
            response
                .headers_mut()
                .insert(LOCATION, HeaderValue::from_static("/user"));
            Some(response)
        }
        Ok(None) => None,
        Err(error) => {
            tracing::warn!(%error, user_id, "could not verify authenticated guest redirect");
            None
        }
    }
}

fn web_session_token(headers: &HeaderMap) -> Option<&str> {
    let cookie_header = headers.get(COOKIE)?.to_str().ok()?;
    cookie_header.split(';').find_map(|cookie| {
        let (name, value) = cookie.trim().split_once('=')?;
        (name == "blessing_skin_session" && !value.is_empty()).then_some(value)
    })
}

fn web_session_fingerprint(token: &str) -> String {
    format!("{:x}", Sha256::digest(token.as_bytes()))
}

fn web_session_identity_fingerprint(jti: &str) -> String {
    format!(
        "{:x}",
        Sha256::digest(format!("blessing-skin-session:{jti}").as_bytes())
    )
}

fn web_session_revocation_keys(token: &str, claims: &WebSessionClaims) -> Vec<String> {
    let mut keys = Vec::with_capacity(2);
    if let Some(jti) = claims.jti.as_deref().filter(|jti| !jti.is_empty()) {
        keys.push(web_session_identity_fingerprint(jti));
    }
    keys.push(web_session_fingerprint(token));
    keys
}

fn web_session_claims(state: &AppState, headers: &HeaderMap) -> Option<(String, WebSessionClaims)> {
    let token = web_session_token(headers)?;
    let claims = decode_web_session(token, state.config.app_key.as_deref()?)?;
    Some((token.to_owned(), claims))
}

async fn refresh_web_session_revocation(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(), sqlx::Error> {
    let Some((token, claims)) = web_session_claims(state, headers) else {
        return Ok(());
    };
    let keys = web_session_revocation_keys(&token, &claims);
    let now = jsonwebtoken::get_current_timestamp();
    let already_revoked = {
        let local_revocations = state
            .revoked_web_sessions
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        keys.iter().any(|key| {
            local_revocations
                .get(key)
                .is_some_and(|expires_at| *expires_at > now)
        })
    };
    if already_revoked {
        return Ok(());
    }
    let Some(database) = &state.database else {
        return Ok(());
    };
    let now_i64 = i64::try_from(now).unwrap_or(i64::MAX);
    for key in &keys {
        if database
            .web_session_is_revoked(&state.config.database.table_prefix, key, now_i64)
            .await?
        {
            let ttl = if claims.remember {
                LEGACY_REMEMBER_TTL_SECONDS
            } else {
                state.config.session_lifetime_seconds
            };
            let revoke_until = claims.exp.max(now.saturating_add(ttl)).saturating_add(61);
            state
                .revoked_web_sessions
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend(keys.into_iter().map(|key| (key, revoke_until)));
            break;
        }
    }
    Ok(())
}

pub(crate) fn session_user_id(state: &AppState, headers: &HeaderMap) -> Option<i64> {
    let (token, claims) = web_session_claims(state, headers)?;
    let keys = web_session_revocation_keys(&token, &claims);
    let now = jsonwebtoken::get_current_timestamp();
    let already_revoked = {
        let local_revocations = state
            .revoked_web_sessions
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        keys.iter().any(|key| {
            local_revocations
                .get(key)
                .is_some_and(|expires_at| *expires_at > now)
        })
    };
    if already_revoked {
        return None;
    }
    claims.sub.parse().ok()
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
fn player_forbidden_response(locale: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "code": 1,
            "message": if locale.starts_with("zh") {
                "无权操作此角色"
            } else {
                "You are not allowed to modify this player."
            }
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

async fn frontend_asset(
    State(state): State<AppState>,
    RoutePath(asset_path): RoutePath<String>,
    headers: HeaderMap,
) -> Response {
    let relative = std::path::PathBuf::from(&asset_path);
    if relative
        .components()
        .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return StatusCode::NOT_FOUND.into_response();
    }

    let app_root = state.public_dir.join("app");
    let canonical_root = match tokio::fs::canonicalize(&app_root).await {
        Ok(path) => path,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    let canonical_asset = match tokio::fs::canonicalize(app_root.join(relative)).await {
        Ok(path) if path.starts_with(&canonical_root) => path,
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    let contents = match tokio::fs::read(canonical_asset).await {
        Ok(contents) => contents,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    frontend_asset_response(&asset_path, contents, &headers)
}

fn frontend_asset_response(asset_path: &str, contents: Vec<u8>, headers: &HeaderMap) -> Response {
    let digest = hex::encode(Md5::digest(&contents));
    let etag = format!("\"{digest}\"");
    let cache_control = if frontend_asset_is_fingerprinted(asset_path) {
        "public, max-age=31536000, immutable"
    } else {
        "public, max-age=300"
    };
    let not_modified = headers
        .get(IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .map(str::trim)
                .any(|candidate| candidate == "*" || candidate == etag)
        });

    let mut response = if not_modified {
        (StatusCode::NOT_MODIFIED, Body::empty()).into_response()
    } else {
        let length = contents.len().to_string();
        let mut response = Response::new(Body::from(contents));
        response.headers_mut().insert(
            CONTENT_LENGTH,
            HeaderValue::from_str(&length).expect("content length is numeric"),
        );
        response
    };
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static(frontend_asset_content_type(asset_path)),
    );
    response.headers_mut().insert(
        ETAG,
        HeaderValue::from_str(&etag).expect("MD5 ETag is ASCII"),
    );
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static(cache_control));
    response.headers_mut().insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

fn frontend_asset_is_fingerprinted(asset_path: &str) -> bool {
    let Some(filename) = std::path::Path::new(asset_path)
        .file_name()
        .and_then(|filename| filename.to_str())
    else {
        return false;
    };
    let segments = filename.split('.').collect::<Vec<_>>();
    segments.len() >= 3
        && segments[segments.len() - 2].len() == 7
        && segments[segments.len() - 2]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
}

fn frontend_asset_content_type(asset_path: &str) -> &'static str {
    match std::path::Path::new(asset_path)
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "json" | "map" => "application/json; charset=utf-8",
        "html" | "htm" => "text/html; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "webp" => "image/webp",
        "gif" => "image/gif",
        "ico" => "image/x-icon",
        "wasm" => "application/wasm",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "eot" => "application/vnd.ms-fontobject",
        _ => "application/octet-stream",
    }
}

async fn serve_public_assets(
    State(state): State<AppState>,
    request: axum::http::Request<Body>,
    next: axum::middleware::Next,
) -> Response {
    let path = request.uri().path();
    let is_head = request.method() == Method::HEAD;
    if (request.method() == Method::GET || is_head) && !path.starts_with("/app/") {
        let headers = request.headers().clone();
        if let Some(response) = serve_public_asset(&state, path, &headers, is_head).await {
            return response;
        }
    }
    next.run(request).await
}

async fn serve_public_asset(
    state: &AppState,
    uri_path: &str,
    request_headers: &HeaderMap,
    head_only: bool,
) -> Option<Response> {
    let decoded_path = decode_uri_path(uri_path)?;
    let relative_path = decoded_path.strip_prefix('/')?;
    if relative_path.is_empty() || relative_path.contains(['\\', ':']) {
        return None;
    }
    let relative = std::path::PathBuf::from(relative_path);
    if relative.components().next().is_some_and(|component| {
        component
            .as_os_str()
            .to_string_lossy()
            .eq_ignore_ascii_case("storage")
    }) {
        return None;
    }
    if relative.components().any(|component| {
        let std::path::Component::Normal(name) = component else {
            return true;
        };
        name.to_string_lossy().starts_with('.')
    }) {
        return None;
    }
    let extension = relative
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if matches!(
        extension.as_str(),
        "php" | "php3" | "php4" | "php5" | "php7" | "php8" | "phtml" | "phar" | "inc"
    ) {
        return None;
    }

    let public_root = tokio::fs::canonicalize(&state.public_dir).await.ok()?;
    let asset_path = tokio::fs::canonicalize(state.public_dir.join(&relative))
        .await
        .ok()?;
    if !asset_path.starts_with(&public_root) {
        return None;
    }
    let file = tokio::fs::File::open(&asset_path).await.ok()?;
    let metadata = file.metadata().await.ok()?;
    if !metadata.is_file() {
        return None;
    }
    let etag = public_file_etag(&metadata);
    let modified = metadata.modified().ok();
    let not_modified = if request_headers.contains_key(IF_NONE_MATCH) {
        header_has_etag(request_headers, &etag)
    } else {
        modified.is_some_and(|time| not_modified_since(request_headers, time))
    };
    let mut response = if not_modified {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        let body = if head_only {
            Body::empty()
        } else {
            Body::from_stream(tokio_util::io::ReaderStream::new(file))
        };
        Response::new(body)
    };
    response.headers_mut().insert(
        ETAG,
        HeaderValue::from_str(&etag).expect("public file ETag is ASCII"),
    );
    if let Some(modified) = modified {
        response.headers_mut().insert(
            LAST_MODIFIED,
            HeaderValue::from_str(&httpdate::fmt_http_date(modified)).unwrap(),
        );
    }
    if not_modified {
        response.headers_mut().remove(CONTENT_TYPE);
        response.headers_mut().remove(CONTENT_LENGTH);
    } else {
        response.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static(frontend_asset_content_type(relative_path)),
        );
        response.headers_mut().insert(
            CONTENT_LENGTH,
            HeaderValue::from_str(&metadata.len().to_string()).unwrap(),
        );
    }
    Some(response)
}

fn public_file_etag(metadata: &std::fs::Metadata) -> String {
    let modified = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("\"{:x}-{:x}\"", metadata.len(), modified)
}
fn decode_uri_path(uri_path: &str) -> Option<String> {
    let path = uri_path.as_bytes();
    let mut decoded = Vec::with_capacity(path.len());
    let mut index = 0;
    while index < path.len() {
        if path[index] == b'%' {
            let hex = std::str::from_utf8(path.get(index + 1..index + 3)?).ok()?;
            decoded.push(u8::from_str_radix(hex, 16).ok()?);
            index += 3;
        } else {
            decoded.push(path[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).ok()
}
async fn redirect_uninstalled(
    State(state): State<AppState>,
    request: axum::http::Request<Body>,
    next: axum::middleware::Next,
) -> Response {
    let path = request.uri().path();
    if state.storage_dir.join("install.lock").exists()
        || path == "/setup"
        || path.starts_with("/setup/")
        || path == "/api"
        || path.starts_with("/api/")
        || path == "/health/live"
        || path == "/health/ready"
        || path == "/app"
        || path.starts_with("/app/")
        || path.ends_with(".json")
        || ["/csl/", "/textures/", "/raw/", "/avatar/", "/preview/"]
            .iter()
            .any(|prefix| path.starts_with(prefix))
    {
        next.run(request).await
    } else {
        (StatusCode::FOUND, [(LOCATION, "/setup")]).into_response()
    }
}

async fn change_password_discovery() -> Response {
    (StatusCode::FOUND, [(LOCATION, "/user/profile")]).into_response()
}

async fn setup_welcome(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if setup_is_locked(&state) {
        return render_setup_page(
            &SetupLockedPage {
                locale: request_locale(&state),
            },
            &headers,
            None,
        );
    }
    let version = state.config.legacy_app_version.clone();
    let assets = setup_page_assets(
        &state,
        "setup",
        serde_json::json!({ "setup_welcome": { "version": &version } }),
    )
    .await;
    render_setup_page(
        &SetupWelcomePage {
            locale: request_locale(&state),
            version,
            frontend_script_available: assets.frontend_script_available,
            frontend_script: assets.frontend_script,
            frontend_globals_b64: assets.frontend_globals_b64,
        },
        &headers,
        None,
    )
}

async fn setup_database_dispatch(
    State(state): State<AppState>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
    body: Bytes,
) -> Response {
    if method == Method::GET {
        return setup_database_page(State(state), headers).await;
    }

    let mut fields = uri
        .query()
        .map(|query| {
            form_urlencoded::parse(query.as_bytes())
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect::<HashMap<_, _>>()
        })
        .unwrap_or_default();
    let is_json = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"))
        });
    if is_json {
        if let Ok(serde_json::Value::Object(values)) =
            serde_json::from_slice::<serde_json::Value>(&body)
        {
            for (key, value) in values {
                fields.insert(
                    key,
                    value
                        .as_str()
                        .map(str::to_owned)
                        .unwrap_or_else(|| value.to_string()),
                );
            }
        }
    } else {
        for (key, value) in form_urlencoded::parse(&body) {
            fields.insert(key.into_owned(), value.into_owned());
        }
    }
    let mut take = |key: &str| fields.remove(key).unwrap_or_default();
    let form = SetupDatabaseRequest {
        csrf: take("csrf"),
        driver: take("type"),
        host: take("host"),
        port: take("port"),
        username: take("username"),
        password: take("password"),
        database: take("db"),
        prefix: take("prefix"),
    };
    setup_database_save(state, headers, form).await
}

async fn setup_database_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if setup_is_locked(&state) {
        return render_setup_page(
            &SetupLockedPage {
                locale: request_locale(&state),
            },
            &headers,
            None,
        );
    }
    if let Some(database) = &state.database
        && database.ping().await.is_ok()
    {
        return Redirect::to("/setup/info").into_response();
    }
    let config = &state.config.database;
    let (driver, host, port, username) = match &config.connection {
        crate::config::DatabaseConnection::Sqlite(_) => {
            ("sqlite", String::new(), String::new(), String::new())
        }
        crate::config::DatabaseConnection::MySql(_) => (
            "mysql",
            config.host.clone().unwrap_or_default(),
            config.port.map(|port| port.to_string()).unwrap_or_default(),
            config.username.clone().unwrap_or_default(),
        ),
        crate::config::DatabaseConnection::Postgres(_) => (
            "pgsql",
            config.host.clone().unwrap_or_default(),
            config.port.map(|port| port.to_string()).unwrap_or_default(),
            config.username.clone().unwrap_or_default(),
        ),
    };
    let csrf = setup_csrf_for_page(&headers);
    let extra = setup_database_extra(
        &csrf,
        driver,
        &host,
        &port,
        &username,
        &config.database,
        &config.table_prefix,
        "",
        false,
    );
    let assets = setup_page_assets(&state, "setup/database", extra).await;
    render_setup_page(
        &SetupDatabasePage {
            locale: request_locale(&state),
            csrf: csrf.clone(),
            driver: driver.to_owned(),
            host,
            port,
            username,
            database: config.database.clone(),
            prefix: config.table_prefix.clone(),
            error: String::new(),
            saved: false,
            frontend_script_available: assets.frontend_script_available,
            frontend_script: assets.frontend_script,
            frontend_globals_b64: assets.frontend_globals_b64,
        },
        &headers,
        Some(&csrf),
    )
}

async fn setup_database_save(
    state: AppState,
    headers: HeaderMap,
    form: SetupDatabaseRequest,
) -> Response {
    if setup_is_locked(&state) {
        return render_setup_page(
            &SetupLockedPage {
                locale: request_locale(&state),
            },
            &headers,
            None,
        );
    }
    if !valid_setup_csrf(&headers, &form.csrf) {
        return setup_database_error(
            &state,
            &headers,
            &form,
            setup_message(
                &state,
                "The setup form expired. Reload this page and try again.",
                "安装表单已过期，请刷新页面后重试。",
            ),
            StatusCode::FORBIDDEN,
        )
        .await;
    }
    let database = match crate::config::DatabaseConfig::from_setup(
        &form.driver,
        &form.host,
        &form.port,
        &form.username,
        &form.password,
        &form.database,
        &form.prefix,
    ) {
        Ok(database) => database,
        Err(error) => {
            let message = setup_message(
                &state,
                "Check the database type, required fields, port, and table prefix.",
                "请检查数据库类型、必填字段、端口和表前缀。 ",
            );
            tracing::warn!(%error, "invalid database setup form");
            return setup_database_error(&state, &headers, &form, message, StatusCode::BAD_REQUEST)
                .await;
        }
    };
    if matches!(
        &database.connection,
        crate::config::DatabaseConnection::Sqlite(_)
    ) && let Some(parent) = std::path::Path::new(&database.database)
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        && let Err(error) = std::fs::create_dir_all(parent)
    {
        tracing::error!(%error, "could not create SQLite database directory during setup");
        return setup_database_error(
            &state,
            &headers,
            &form,
            setup_message(
                &state,
                "The SQLite database path could not be prepared.",
                "无法准备 SQLite 数据库路径。",
            ),
            StatusCode::BAD_REQUEST,
        )
        .await;
    }
    let pool = match DatabasePool::connect_for_install(&database).await {
        Ok(pool) => pool,
        Err(error) => {
            tracing::warn!(%error, driver = %form.driver, "database connection failed during setup");
            let message = setup_message(
                &state,
                &format!("Could not connect to the database: {error}"),
                &format!("无法连接数据库：{error}"),
            );
            return setup_database_error(&state, &headers, &form, message, StatusCode::BAD_GATEWAY)
                .await;
        }
    };
    let ping_result = pool.ping().await;
    match &pool {
        DatabasePool::Sqlite(pool) => pool.close().await,
        DatabasePool::MySql(pool) => pool.close().await,
        DatabasePool::Postgres(pool) => pool.close().await,
    }
    if let Err(error) = ping_result {
        tracing::warn!(%error, driver = %form.driver, "database ping failed during setup");
        let message = setup_message(
            &state,
            &format!("Could not use the database: {error}"),
            &format!("无法使用该数据库：{error}"),
        );
        return setup_database_error(&state, &headers, &form, message, StatusCode::BAD_GATEWAY)
            .await;
    }
    let env_file = state.env_file.clone();
    let entries = vec![
        ("DB_CONNECTION", form.driver.clone()),
        ("DB_HOST", form.host.clone()),
        ("DB_PORT", form.port.clone()),
        ("DB_DATABASE", form.database.clone()),
        ("DB_USERNAME", form.username.clone()),
        ("DB_PASSWORD", form.password.clone()),
        ("DB_PREFIX", form.prefix.clone()),
    ];
    let write_path = env_file.clone();
    let saved = tokio::task::spawn_blocking(move || write_env_file(&write_path, &entries)).await;
    match saved {
        Ok(Ok(())) => {
            let csrf = setup_csrf_for_page(&headers);
            let extra = setup_database_extra(
                &csrf,
                &form.driver,
                &form.host,
                &form.port,
                &form.username,
                &form.database,
                &form.prefix,
                "",
                true,
            );
            let assets = setup_page_assets(&state, "setup/database", extra).await;
            render_setup_page(
                &SetupDatabasePage {
                    locale: request_locale(&state),
                    csrf: csrf.clone(),
                    driver: form.driver,
                    host: form.host,
                    port: form.port,
                    username: form.username,
                    database: form.database,
                    prefix: form.prefix,
                    error: String::new(),
                    saved: true,
                    frontend_script_available: assets.frontend_script_available,
                    frontend_script: assets.frontend_script,
                    frontend_globals_b64: assets.frontend_globals_b64,
                },
                &headers,
                Some(&csrf),
            )
        }
        Ok(Err(error)) => {
            tracing::error!(%error, path = %env_file.display(), "could not save database setup");
            setup_database_error(
                &state,
                &headers,
                &form,
                setup_message(
                    &state,
                    "The database connected, but the environment file could not be saved.",
                    "数据库连接成功，但无法保存环境配置文件。",
                ),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
            .await
        }
        Err(error) => {
            tracing::error!(%error, "database setup file operation failed");
            setup_database_error(
                &state,
                &headers,
                &form,
                setup_message(
                    &state,
                    "The database connected, but saving its configuration failed.",
                    "数据库连接成功，但保存配置失败。",
                ),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
            .await
        }
    }
}

async fn setup_info_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if setup_is_locked(&state) {
        return render_setup_page(
            &SetupLockedPage {
                locale: request_locale(&state),
            },
            &headers,
            None,
        );
    }
    let Some(database) = &state.database else {
        return Redirect::to("/setup/database").into_response();
    };
    if database.ping().await.is_err() {
        return Redirect::to("/setup/database").into_response();
    }
    let site_name = database
        .option(&state.config.database.table_prefix, "site_name")
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| "Blessing Skin".to_owned());
    let csrf = setup_csrf_for_page(&headers);
    let extra = serde_json::json!({
        "setup_info": {
            "csrf": &csrf,
            "site_name": &site_name,
            "error": "",
        }
    });
    let assets = setup_page_assets(&state, "setup/info", extra).await;
    render_setup_page(
        &SetupInfoPage {
            locale: request_locale(&state),
            csrf: csrf.clone(),
            site_name,
            error: String::new(),
            frontend_script_available: assets.frontend_script_available,
            frontend_script: assets.frontend_script,
            frontend_globals_b64: assets.frontend_globals_b64,
        },
        &headers,
        Some(&csrf),
    )
}

async fn setup_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
    body: Bytes,
) -> Response {
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    let fields = parse_legacy_input_object(&query, &body, content_type).unwrap_or_default();
    let site_name = fields
        .get("site_name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let form = match serde_json::from_value::<SetupFinishRequest>(serde_json::Value::Object(fields))
    {
        Ok(form) => form,
        Err(_) => {
            return setup_info_error(
                &state,
                &headers,
                &site_name,
                setup_message(
                    &state,
                    "Complete all required setup fields.",
                    "请填写所有必需的安装信息。",
                ),
                StatusCode::BAD_REQUEST,
            )
            .await;
        }
    };
    if setup_is_locked(&state) {
        return render_setup_page(
            &SetupLockedPage {
                locale: request_locale(&state),
            },
            &headers,
            None,
        );
    }
    if !valid_setup_csrf(&headers, &form.csrf) {
        return setup_info_error(
            &state,
            &headers,
            &form.site_name,
            setup_message(
                &state,
                "The setup form expired. Reload this page and try again.",
                "安装表单已过期，请刷新页面后重试。",
            ),
            StatusCode::FORBIDDEN,
        )
        .await;
    }
    let validation_error = if !form.email.contains('@')
        || form.email.len() > 100
        || form.email.chars().any(char::is_control)
    {
        Some(setup_message(
            &state,
            "Enter a valid administrator email address.",
            "请输入有效的管理员邮箱。",
        ))
    } else if form.nickname.trim().is_empty()
        || form.nickname.len() > 50
        || form.nickname.chars().any(char::is_control)
    {
        Some(setup_message(
            &state,
            "Enter a nickname of 1 to 50 characters.",
            "昵称长度需为 1 至 50 个字符。",
        ))
    } else if !(8..=32).contains(&form.password.chars().count()) {
        Some(setup_message(
            &state,
            "The password must contain 8 to 32 characters.",
            "密码长度需为 8 至 32 个字符。",
        ))
    } else if form.password != form.password_confirmation {
        Some(setup_message(
            &state,
            "The passwords do not match.",
            "两次输入的密码不一致。",
        ))
    } else if form.site_name.trim().is_empty()
        || form.site_name.len() > 100
        || form.site_name.chars().any(char::is_control)
    {
        Some(setup_message(
            &state,
            "Enter a valid site name.",
            "请输入有效的站点名称。",
        ))
    } else {
        None
    };
    if let Some(error) = validation_error {
        return setup_info_error(
            &state,
            &headers,
            &form.site_name,
            error,
            StatusCode::BAD_REQUEST,
        )
        .await;
    }
    match crate::installer::install_with_details(
        &state.config,
        &state.storage_dir,
        &form.email,
        &form.nickname,
        &form.password,
        &form.site_name,
    )
    .await
    {
        Ok(()) => {
            let assets = setup_page_assets(&state, "setup/finish", serde_json::json!({})).await;
            render_setup_page(
                &SetupFinishPage {
                    locale: request_locale(&state),
                    frontend_script_available: assets.frontend_script_available,
                    frontend_script: assets.frontend_script,
                    frontend_globals_b64: assets.frontend_globals_b64,
                },
                &headers,
                None,
            )
        }
        Err(crate::installer::InstallError::AlreadyInstalled) => render_setup_page(
            &SetupLockedPage {
                locale: request_locale(&state),
            },
            &headers,
            None,
        ),
        Err(error) => {
            tracing::error!(%error, "web setup installation failed");
            let message = match error {
                crate::installer::InstallError::DatabaseNotEmpty => setup_message(
                    &state,
                    "The database already contains Blessing Skin data, so installation was stopped.",
                    "数据库中已有 Blessing Skin 数据，已停止安装。",
                ),
                crate::installer::InstallError::UnsupportedPasswordMethod => setup_message(
                    &state,
                    "The configured password method cannot create a compatible password hash.",
                    "当前密码算法无法生成兼容的密码哈希。",
                ),
                _ => setup_message(
                    &state,
                    "Installation failed. Check the server log and database configuration, then try again.",
                    "安装失败。请检查服务日志和数据库配置后重试。",
                ),
            };
            setup_info_error(
                &state,
                &headers,
                &form.site_name,
                message,
                StatusCode::BAD_REQUEST,
            )
            .await
        }
    }
}

async fn setup_database_error(
    state: &AppState,
    headers: &HeaderMap,
    form: &SetupDatabaseRequest,
    error: String,
    status: StatusCode,
) -> Response {
    let csrf = setup_csrf_for_page(&headers);
    let extra = setup_database_extra(
        &csrf,
        &form.driver,
        &form.host,
        &form.port,
        &form.username,
        &form.database,
        &form.prefix,
        &error,
        false,
    );
    let assets = setup_page_assets(state, "setup/database", extra).await;
    let mut response = render_setup_page(
        &SetupDatabasePage {
            locale: request_locale(&state),
            csrf: csrf.clone(),
            driver: form.driver.clone(),
            host: form.host.clone(),
            port: form.port.clone(),
            username: form.username.clone(),
            database: form.database.clone(),
            prefix: form.prefix.clone(),
            error,
            saved: false,
            frontend_script_available: assets.frontend_script_available,
            frontend_script: assets.frontend_script,
            frontend_globals_b64: assets.frontend_globals_b64,
        },
        headers,
        Some(&csrf),
    );
    *response.status_mut() = status;
    response
}

async fn setup_info_error(
    state: &AppState,
    headers: &HeaderMap,
    site_name: &str,
    error: String,
    status: StatusCode,
) -> Response {
    let csrf = setup_csrf_for_page(&headers);
    let extra = serde_json::json!({
        "setup_info": {
            "csrf": &csrf,
            "site_name": site_name,
            "error": &error,
        }
    });
    let assets = setup_page_assets(state, "setup/info", extra).await;
    let mut response = render_setup_page(
        &SetupInfoPage {
            locale: request_locale(&state),
            csrf: csrf.clone(),
            site_name: site_name.to_owned(),
            error,
            frontend_script_available: assets.frontend_script_available,
            frontend_script: assets.frontend_script,
            frontend_globals_b64: assets.frontend_globals_b64,
        },
        headers,
        Some(&csrf),
    );
    *response.status_mut() = status;
    response
}

fn setup_is_locked(state: &AppState) -> bool {
    state.storage_dir.join("install.lock").exists()
}

fn setup_message(state: &AppState, english: &str, chinese: &str) -> String {
    if request_locale(&state).starts_with("zh") {
        chinese.to_owned()
    } else {
        english.to_owned()
    }
}

async fn setup_page_assets(
    state: &AppState,
    route: &str,
    extra: serde_json::Value,
) -> SetupPageAssets {
    let app_dir = state.public_dir.join("app");
    let frontend_script =
        frontend_entrypoint(&app_dir, "app", "js", &request_app_url(&state)).await;
    let i18n = load_frontend_translations(&state, &app_dir, &request_locale(&state)).await;
    let frontend_globals_b64 = encode_frontend_globals(state, "Blessing Skin", route, extra, i18n);
    SetupPageAssets {
        frontend_script_available: frontend_script.is_some(),
        frontend_script: frontend_script.unwrap_or_default(),
        frontend_globals_b64,
    }
}

fn setup_database_extra(
    csrf: &str,
    driver: &str,
    host: &str,
    port: &str,
    username: &str,
    database: &str,
    prefix: &str,
    error: &str,
    saved: bool,
) -> serde_json::Value {
    serde_json::json!({
        "setup_database": {
            "csrf": csrf,
            "driver": driver,
            "host": host,
            "port": port,
            "username": username,
            "database": database,
            "prefix": prefix,
            "error": error,
            "saved": saved,
        }
    })
}

fn setup_csrf_token() -> String {
    Alphanumeric.sample_string(&mut rand::thread_rng(), 48)
}

fn setup_csrf_cookie(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value.split(';').find_map(|part| {
                let (name, value) = part.trim().split_once('=')?;
                name.eq_ignore_ascii_case("blessing_skin_setup_csrf")
                    .then_some(value)
            })
        })
}

fn setup_csrf_for_page(headers: &HeaderMap) -> String {
    setup_csrf_cookie(headers)
        .filter(|token| token.len() == 48 && token.bytes().all(|byte| byte.is_ascii_alphanumeric()))
        .map(str::to_owned)
        .unwrap_or_else(setup_csrf_token)
}

fn valid_setup_csrf(headers: &HeaderMap, submitted: &str) -> bool {
    let Some(cookie) = setup_csrf_cookie(headers) else {
        return false;
    };
    cookie.len() == submitted.len()
        && cookie.as_bytes().ct_eq(submitted.as_bytes()).unwrap_u8() == 1
}

fn render_setup_page(
    template: &impl Template,
    headers: &HeaderMap,
    csrf: Option<&str>,
) -> Response {
    let html = match template.render() {
        Ok(html) => html,
        Err(error) => {
            tracing::error!(%error, "failed to render setup page");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let mut response = Html(html).into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Some(csrf) = csrf {
        let secure = headers
            .get("x-forwarded-proto")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(',')
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .eq_ignore_ascii_case("https")
            });
        let secure = if secure { "; Secure" } else { "" };
        if let Ok(cookie) = HeaderValue::from_str(&format!(
            "blessing_skin_setup_csrf={csrf}; Path=/setup; Max-Age=3600; HttpOnly; SameSite=Strict{secure}"
        )) {
            response.headers_mut().append(SET_COOKIE, cookie);
        }
    }
    response
}

pub(crate) fn write_env_file(
    path: &std::path::Path,
    entries: &[(&str, String)],
) -> Result<(), std::io::Error> {
    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error),
    };
    let updates = entries.iter().cloned().collect::<BTreeMap<_, _>>();
    let mut written = std::collections::HashSet::new();
    let mut lines = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim_start();
        let assignment = trimmed.strip_prefix("export ").unwrap_or(trimmed);
        if let Some((key, _)) = assignment.split_once('=')
            && let Some(value) = updates.get(key.trim())
        {
            lines.push(format!("{}={}", key.trim(), quote_env_value(value)));
            written.insert(key.trim().to_owned());
        } else {
            lines.push(line.to_owned());
        }
    }
    for (key, value) in updates {
        if !written.contains(key) {
            lines.push(format!("{key}={}", quote_env_value(&value)));
        }
    }
    let mut output = lines.join("\n");
    output.push('\n');
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    use std::io::Write;
    options.open(path)?.write_all(output.as_bytes())
}

fn quote_env_value(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
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
    blessing_skin: String,
    spec: u8,
    copyright: Option<&'static str>,
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

async fn web_send_notification(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
    body: Bytes,
) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if user.permission < 1 {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "message": "This action is unauthorized." })),
        )
            .into_response();
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    let is_json = content_type.is_some_and(|value| value.starts_with("application/json"));
    let input_content_type = if is_json {
        content_type
    } else {
        Some("application/x-www-form-urlencoded")
    };
    let request = match parse_legacy_input_object(&query, &body, input_content_type) {
        Ok(fields) => serde_json::Value::Object(fields),
        Err(()) => return notification_validation_error("receiver", &request_locale(&state)),
    };
    let Some(receiver) = request.get("receiver").and_then(serde_json::Value::as_str) else {
        return notification_validation_error("receiver", &request_locale(&state));
    };
    let receiver = receiver.trim();
    let audience = match receiver {
        "all" => crate::database::NotificationAudience::All,
        "normal" => crate::database::NotificationAudience::Normal,
        "uid" => {
            let Some(uid) = request_i64(request.get("uid")) else {
                return notification_validation_error("uid", &request_locale(&state));
            };
            crate::database::NotificationAudience::User(uid)
        }
        "email" => {
            let Some(email) = request.get("email").and_then(serde_json::Value::as_str) else {
                return notification_validation_error("email", &request_locale(&state));
            };
            let email = email.trim();
            if !valid_email_address(email) {
                return notification_validation_error("email", &request_locale(&state));
            }
            crate::database::NotificationAudience::Email(email.to_owned())
        }
        _ => return notification_validation_error("receiver", &request_locale(&state)),
    };
    let Some(title) = request.get("title").and_then(serde_json::Value::as_str) else {
        return notification_validation_error("title", &request_locale(&state));
    };
    let title = title.trim();
    if title.is_empty() || title.chars().count() > 20 {
        return notification_validation_error("title", &request_locale(&state));
    }
    let content = match request.get("content") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(content)) => Some(content.trim()),
        _ => return notification_validation_error("content", &request_locale(&state)),
    };
    let prefix = &state.config.database.table_prefix;
    let recipients = match database.notification_recipients(prefix, &audience).await {
        Ok(Some(recipients)) => recipients,
        Ok(None) => {
            let field = match audience {
                crate::database::NotificationAudience::User(_) => "uid",
                crate::database::NotificationAudience::Email(_) => "email",
                _ => "receiver",
            };
            return notification_validation_error(field, &request_locale(&state));
        }
        Err(error) => {
            tracing::error!(%error, sender_uid = user.uid, "failed to select notification recipients");
            return unavailable();
        }
    };
    let data = serde_json::json!({ "title": title, "content": content }).to_string();
    for recipient in recipients {
        let notification_id = new_notification_id();
        if let Err(error) = database
            .create_site_notification(prefix, &notification_id, recipient, &data)
            .await
        {
            tracing::error!(%error, recipient, sender_uid = user.uid, "failed to store admin notification");
            return unavailable();
        }
        emit_plugin_event(
            &state,
            "notification.sent",
            serde_json::json!({"sender_id": user.uid, "recipient_id": recipient, "notification_id": notification_id}),
        )
        .await;
    }
    if !is_json {
        Redirect::to("/admin").into_response()
    } else {
        login_result(
            0,
            if request_locale(&state).starts_with("zh") {
                "站内通知已发送。"
            } else {
                "The site notification was sent."
            },
            None,
        )
    }
}
async fn api_send_notification(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
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

    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    let request = match parse_legacy_input_object(&query, &body, content_type) {
        Ok(fields) => serde_json::Value::Object(fields),
        Err(()) => return notification_validation_error("receiver", &request_locale(&state)),
    };
    let Some(receiver) = request.get("receiver").and_then(serde_json::Value::as_str) else {
        return notification_validation_error("receiver", &request_locale(&state));
    };
    let receiver = receiver.trim();
    let audience = match receiver {
        "all" => crate::database::NotificationAudience::All,
        "normal" => crate::database::NotificationAudience::Normal,
        "uid" => {
            let Some(uid) = request_i64(request.get("uid")) else {
                return notification_validation_error("uid", &request_locale(&state));
            };
            crate::database::NotificationAudience::User(uid)
        }
        "email" => {
            let Some(email) = request.get("email").and_then(serde_json::Value::as_str) else {
                return notification_validation_error("email", &request_locale(&state));
            };
            let email = email.trim();
            if !valid_email_address(email) {
                return notification_validation_error("email", &request_locale(&state));
            }
            crate::database::NotificationAudience::Email(email.to_owned())
        }
        _ => return notification_validation_error("receiver", &request_locale(&state)),
    };
    let Some(title) = request.get("title").and_then(serde_json::Value::as_str) else {
        return notification_validation_error("title", &request_locale(&state));
    };
    let title = title.trim();
    if title.is_empty() || title.chars().count() > 20 {
        return notification_validation_error("title", &request_locale(&state));
    }
    let content = match request.get("content") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(content)) => Some(content.trim()),
        _ => return notification_validation_error("content", &request_locale(&state)),
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
                &request_locale(&state),
            );
        }
        Err(error) => {
            tracing::error!(%error, "failed to select notification recipients");
            return unavailable();
        }
    };
    let data = serde_json::json!({ "title": title, "content": content }).to_string();
    for recipient in recipients {
        let notification_id = new_notification_id();
        if let Err(error) = database
            .create_site_notification(prefix, &notification_id, recipient, &data)
            .await
        {
            tracing::error!(%error, recipient, "failed to store notification");
            return unavailable();
        }
        emit_plugin_event(
            &state,
            "notification.sent",
            serde_json::json!({"sender_id": identity.user_id, "recipient_id": recipient, "notification_id": notification_id}),
        )
        .await;
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
        Ok(Some(notification)) => {
            emit_plugin_event(
                &state,
                "notification.read",
                serde_json::json!({"user_id": identity.user_id, "notification_id": notification.id}),
            )
            .await;
            notification_detail(notification)
        }
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

fn parse_legacy_input_object(
    query: &BTreeMap<String, String>,
    body: &[u8],
    content_type: Option<&str>,
) -> Result<serde_json::Map<String, serde_json::Value>, ()> {
    let mut fields = query
        .iter()
        .map(|(key, value)| (key.clone(), serde_json::Value::String(value.clone())))
        .collect::<serde_json::Map<_, _>>();
    if let Ok(serde_json::Value::Object(body_fields)) =
        serde_json::from_slice::<serde_json::Value>(body)
    {
        fields.extend(body_fields);
    } else if content_type
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .eq_ignore_ascii_case("application/x-www-form-urlencoded")
    {
        for (key, value) in form_urlencoded::parse(body) {
            fields.insert(
                key.into_owned(),
                serde_json::Value::String(value.into_owned()),
            );
        }
    } else if !body.is_empty() {
        return Err(());
    }
    Ok(fields)
}

fn legacy_input_body(
    query: &BTreeMap<String, String>,
    body: &[u8],
    content_type: Option<&str>,
) -> Bytes {
    parse_legacy_input_object(query, body, content_type)
        .map(serde_json::Value::Object)
        .ok()
        .and_then(|value| serde_json::to_vec(&value).ok())
        .map(Bytes::from)
        .unwrap_or_default()
}

fn parse_player_name_request(
    query: &BTreeMap<String, String>,
    body: &[u8],
    content_type: Option<&str>,
) -> Result<RenamePlayerRequest, ()> {
    let fields = parse_legacy_input_object(query, body, content_type)?;
    serde_json::from_value(serde_json::Value::Object(fields)).map_err(|_| ())
}
async fn api_rename_player(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(raw_id): RoutePath<String>,
    Query(query): Query<BTreeMap<String, String>>,
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
    let request = match parse_player_name_request(
        &query,
        &body,
        headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
    ) {
        Ok(request) => request,
        Err(()) => return validation_error("name", &request_locale(&state)),
    };
    let Some(name) = request.name.filter(|name| !name.is_empty()) else {
        return validation_error("name", &request_locale(&state));
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
        return validation_error("name", &request_locale(&state));
    }
    let player = match load_owned_player(
        database,
        options,
        identity.user_id,
        player_id,
        &request_locale(&state),
    )
    .await
    {
        Ok(player) => player,
        Err(response) => return response,
    };
    let name = match filter_player_rename_name(&state, identity.user_id, &player, &name).await {
        Ok(name) => name,
        Err(reason) => return login_result(1, &reason, None),
    };

    match database
        .rename_player(options, identity.user_id, player_id, &name)
        .await
    {
        Ok(PlayerRenameOutcome::Renamed {
            previous_name,
            player,
        }) => {
            emit_plugin_event(
                &state,
                "player.renamed",
                serde_json::json!({"user_id": identity.user_id, "player_id": player_id, "previous_name": previous_name, "name": name}),
            )
            .await;
            let message = if request_locale(&state).starts_with("zh") {
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
            if request_locale(&state).starts_with("zh") {
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
                "message": if request_locale(&state).starts_with("zh") {
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
    Query(query): Query<BTreeMap<String, String>>,
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
    let (skin, cape) = player_texture_input_ids(
        &query,
        &body,
        headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
    );
    return set_player_textures_with_plugins(
        &state,
        identity.user_id,
        player_id,
        skin,
        cape,
        &request_locale(&state),
    )
    .await;
}

async fn api_clear_player_textures(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(raw_id): RoutePath<String>,
    Query(query): Query<BTreeMap<String, String>>,
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
    let (clear_skin, clear_cape) = player_texture_clear_flags(
        &query,
        &body,
        headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
    );
    return clear_player_textures_with_plugins(
        &state,
        identity.user_id,
        player_id,
        clear_skin,
        clear_cape,
        &request_locale(&state),
    )
    .await;
}

fn player_texture_input_ids(
    query: &BTreeMap<String, String>,
    body: &[u8],
    content_type: Option<&str>,
) -> (Option<i64>, Option<i64>) {
    let mut skin = query
        .get("skin")
        .map(|value| serde_json::Value::String(value.clone()));
    let mut cape = query
        .get("cape")
        .map(|value| serde_json::Value::String(value.clone()));
    let media_type = content_type
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .trim();
    if let Ok(serde_json::Value::Object(fields)) = serde_json::from_slice::<serde_json::Value>(body)
    {
        if let Some(value) = fields.get("skin") {
            skin = Some(value.clone());
        }
        if let Some(value) = fields.get("cape") {
            cape = Some(value.clone());
        }
    } else if media_type.eq_ignore_ascii_case("application/x-www-form-urlencoded") {
        for (key, value) in form_urlencoded::parse(body) {
            let value = serde_json::Value::String(value.into_owned());
            match key.as_ref() {
                "skin" => skin = Some(value),
                "cape" => cape = Some(value),
                _ => {}
            }
        }
    }
    (
        texture_request_id(skin.as_ref()),
        texture_request_id(cape.as_ref()),
    )
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
        "utf8" => !name
            .chars()
            .any(|ch| matches!(ch, ' ' | '\t' | '\n' | '\u{000b}' | '\u{000c}' | '\r')),
        "custom" => custom_player_name_matches(name, custom_rule),
        _ => true,
    }
}

fn custom_player_name_matches(name: &str, pattern: &str) -> bool {
    if !legacy_option_bool(Some(pattern)) {
        return true;
    }
    let Some((pattern, flags)) = split_php_delimited_regex(pattern) else {
        return false;
    };
    if pattern.len() > 512
        || flags.chars().any(|flag| {
            !matches!(
                flag,
                'i' | 'm' | 's' | 'x' | 'A' | 'D' | 'S' | 'U' | 'X' | 'u'
            )
        })
    {
        return false;
    }

    let pattern = if flags.contains('m') {
        pattern.to_owned()
    } else {
        dollar_end_only_pattern(pattern, !flags.contains('D'))
    };
    let pattern = if flags.contains('U') {
        format!("(?U){pattern}")
    } else {
        pattern
    };
    let mut builder = FancyRegexBuilder::new(&pattern);
    builder
        .case_insensitive(flags.contains('i'))
        .multi_line(flags.contains('m'))
        .dot_matches_new_line(flags.contains('s'))
        .ignore_whitespace(flags.contains('x'))
        .unicode_mode(flags.contains('u'))
        .bytes_mode(if flags.contains('u') {
            BytesMode::Unicode
        } else {
            BytesMode::Ascii
        })
        .backtrack_limit(100_000);
    builder.build().is_ok_and(|regex| {
        let match_start = if flags.contains('u') {
            regex.find(name).ok().flatten().map(|found| found.start())
        } else {
            regex
                .find(name.as_bytes())
                .ok()
                .flatten()
                .map(|found| found.start())
        };
        match_start.is_some_and(|start| !flags.contains('A') || start == 0)
    })
}

fn split_php_delimited_regex(pattern: &str) -> Option<(&str, &str)> {
    let opening = pattern.chars().next()?;
    if opening.is_ascii_alphanumeric() || opening.is_ascii_whitespace() || opening == '\\' {
        return None;
    }
    let closing = match opening {
        '(' => ')',
        '[' => ']',
        '{' => '}',
        '<' => '>',
        delimiter => delimiter,
    };
    let pattern_start = opening.len_utf8();
    let mut nesting = 1usize;
    let mut escaped = false;
    for (relative_offset, character) in pattern[pattern_start..].char_indices() {
        let offset = pattern_start + relative_offset;
        if escaped {
            escaped = false;
            continue;
        }
        if character == '\\' {
            escaped = true;
            continue;
        }
        if opening != closing && character == opening {
            nesting += 1;
            continue;
        }
        if character == closing {
            nesting -= 1;
            if nesting == 0 {
                let flags_start = offset + closing.len_utf8();
                return Some((&pattern[pattern_start..offset], &pattern[flags_start..]));
            }
        }
    }
    None
}

fn dollar_end_only_pattern(pattern: &str, allow_final_newline: bool) -> String {
    let mut output = String::with_capacity(pattern.len());
    let mut escaped = false;
    let mut in_character_class = false;
    for character in pattern.chars() {
        if escaped {
            output.push(character);
            escaped = false;
            continue;
        }
        if character == '\\' {
            output.push(character);
            escaped = true;
            continue;
        }
        if character == '[' {
            in_character_class = true;
        } else if character == ']' {
            in_character_class = false;
        }
        if character == '$' && !in_character_class {
            output.push_str(if allow_final_newline {
                r"(?:\n)?\z"
            } else {
                r"\z"
            });
        } else {
            output.push(character);
        }
    }
    output
}

async fn api_add_player(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
    body: Bytes,
) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_scope("Player.ReadWrite") {
        return missing_scope();
    }
    let request = match parse_player_name_request(
        &query,
        &body,
        headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
    ) {
        Ok(request) => request,
        Err(()) => return validation_error("name", &request_locale(&state)),
    };
    let Some(name) = request.name.filter(|name| !name.is_empty()) else {
        return validation_error("name", &request_locale(&state));
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
        return validation_error("name", &request_locale(&state));
    }
    let score_cost = match database.option(prefix, "score_per_player").await {
        Ok(value) => legacy_option_integer(value.as_deref(), 100),
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
            emit_plugin_event(
                &state,
                "player.added",
                serde_json::json!({"user_id": identity.user_id, "player_id": player.pid, "name": player.name}),
            )
            .await;
            let message = if request_locale(&state).starts_with("zh") {
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
            duplicate_player_name_error(&request_locale(&state))
        }
        Ok(crate::database::PlayerAddOutcome::InsufficientScore) => login_result(
            7,
            if request_locale(&state).starts_with("zh") {
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
    let player = match load_owned_player(
        database,
        prefix,
        identity.user_id,
        player_id,
        &request_locale(&state),
    )
    .await
    {
        Ok(player) => player,
        Err(response) => return response,
    };
    if let Err(reason) = filter_player_delete(&state, identity.user_id, &player).await {
        return login_result(1, &reason, None);
    }
    let return_score = match database.option(prefix, "return_score").await {
        Ok(value) => legacy_option_bool(value.as_deref()),
        Err(error) => {
            tracing::error!(%error, "failed to load player score refund option");
            return unavailable();
        }
    };
    let score_reward = if return_score {
        match database.option(prefix, "score_per_player").await {
            Ok(value) => legacy_option_integer(value.as_deref(), 100),
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
        Ok(crate::database::PlayerDeleteOutcome::Deleted(name)) => {
            emit_plugin_event(
                &state,
                "player.deleted",
                serde_json::json!({"user_id": identity.user_id, "player_id": player_id, "name": name}),
            )
            .await;
            login_result(
                0,
                &if request_locale(&state).starts_with("zh") {
                format!("角色 {name} 已被删除")
            } else {
                format!("Player {name} was deleted successfully.")
            },
            None,
            )
        }
        Ok(crate::database::PlayerDeleteOutcome::Forbidden) => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "code": 1,
                "message": if request_locale(&state).starts_with("zh") { "无权操作此角色" } else { "You are not allowed to modify this player." }
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

fn legacy_image_dimension(value: Option<&str>, default: u32) -> u32 {
    u32::try_from(legacy_option_integer(value, i64::from(default)))
        .ok()
        .filter(|dimension| (1..=1024).contains(dimension))
        .unwrap_or(default)
}
fn legacy_option_integer(value: Option<&str>, default: i64) -> i64 {
    let Some(value) = value else {
        return default;
    };
    match value.to_ascii_lowercase().as_str() {
        "true" | "(true)" => return 1,
        "false" | "(false)" | "null" | "(null)" => return 0,
        _ => {}
    }

    let value = value.trim_start();
    let bytes = value.as_bytes();
    let mut end = usize::from(
        bytes
            .first()
            .is_some_and(|byte| matches!(byte, b'+' | b'-')),
    );
    let negative = bytes.first() == Some(&b'-');
    let integer_start = end;
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    let integer_digits = end - integer_start;
    let mut has_fraction = false;
    let mut fraction_digits = 0;
    if bytes.get(end) == Some(&b'.') {
        has_fraction = true;
        end += 1;
        let fraction_start = end;
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
        fraction_digits = end - fraction_start;
    }
    if integer_digits + fraction_digits == 0 {
        return 0;
    }

    let mut has_exponent = false;
    if matches!(bytes.get(end), Some(b'e' | b'E')) {
        let exponent_start = end;
        end += 1;
        if bytes
            .get(end)
            .is_some_and(|byte| matches!(byte, b'+' | b'-'))
        {
            end += 1;
        }
        let exponent_digits_start = end;
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
        if end == exponent_digits_start {
            end = exponent_start;
        } else {
            has_exponent = true;
        }
    }

    if has_fraction || has_exponent {
        return value[..end]
            .parse::<f64>()
            .ok()
            .filter(|number| number.is_finite())
            .map(|number| number.trunc() as i64)
            .unwrap_or(0);
    }
    value[..end]
        .parse::<i64>()
        .unwrap_or(if negative { i64::MIN } else { i64::MAX })
}

fn legacy_texture_width_limit(value: Option<&str>) -> (f64, String) {
    let Some(value) = value else {
        return (8192.0, "8192".to_owned());
    };
    match value.to_ascii_lowercase().as_str() {
        "true" | "(true)" => (f64::INFINITY, "1".to_owned()),
        "false" | "(false)" | "null" | "(null)" => (0.0, String::new()),
        _ => match value.trim().parse::<f64>() {
            Ok(limit) if limit.is_finite() => (limit, value.to_owned()),
            _ => (8192.0, "8192".to_owned()),
        },
    }
}

fn private_texture_status_code(value: Option<&str>) -> StatusCode {
    if legacy_option_integer(value, 403) == 404 {
        StatusCode::NOT_FOUND
    } else {
        StatusCode::FORBIDDEN
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
    Query(query): Query<BTreeMap<String, String>>,
    body: Bytes,
) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_scope("Closet.ReadWrite") {
        return missing_scope();
    }
    let request = match parse_legacy_input_object(
        &query,
        &body,
        headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
    ) {
        Ok(fields) => serde_json::Value::Object(fields),
        Err(()) => return closet_validation_error("tid", &request_locale(&state)),
    };
    let Some(tid) = texture_id_from_request(request.get("tid")) else {
        return closet_validation_error("tid", &request_locale(&state));
    };
    let Some(name) = request.get("name").and_then(serde_json::Value::as_str) else {
        return closet_validation_error("name", &request_locale(&state));
    };
    let name = name.trim();
    if name.is_empty() {
        return closet_validation_error("name", &request_locale(&state));
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
    let filtered_name = closet_name_filter(&state, "add_closet_item_name", tid, name).await;
    emit_plugin_event(
        &state,
        "closet.adding",
        serde_json::json!({"user_id": identity.user_id, "texture_id": tid, "item_name": filtered_name}),
    )
    .await;
    if let Some(reason) = closet_permission_filter(
        &state,
        "can_add_closet_item",
        serde_json::json!({"texture_id": tid, "name": filtered_name}),
    )
    .await
    {
        return login_result(1, &reason, None);
    }
    let score_cost = match database.option(prefix, "score_per_closet_item").await {
        Ok(value) => legacy_option_integer(value.as_deref(), 0),
        Err(error) => {
            tracing::error!(%error, "failed to load closet score cost");
            return unavailable();
        }
    };
    let like_award = match database.option(prefix, "score_award_per_like").await {
        Ok(value) => legacy_option_integer(value.as_deref(), 0),
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
        Ok(crate::database::ClosetAddOutcome::Added) => {
            emit_plugin_event(
                &state,
                "closet.added",
                serde_json::json!({
                    "user_id": identity.user_id,
                    "texture_id": tid,
                    "item_name": filtered_name,
                }),
            )
            .await;
            login_result(
                0,
                &if request_locale(&state).starts_with("zh") {
                    format!("材质 {name} 收藏成功")
                } else {
                    format!("Added {name} to closet successfully.")
                },
                None,
            )
        }
        Ok(crate::database::ClosetAddOutcome::NameExists) => login_result(
            1,
            if request_locale(&state).starts_with("zh") {
                "你已经收藏过这个材质啦"
            } else {
                "You have already added this texture."
            },
            None,
        ),
        Ok(crate::database::ClosetAddOutcome::InsufficientScore) => login_result(
            1,
            if request_locale(&state).starts_with("zh") {
                "收藏失败，积分不足"
            } else {
                "You don't have enough score to add it to closet."
            },
            None,
        ),
        Ok(crate::database::ClosetAddOutcome::TextureNotFound) => login_result(
            1,
            if request_locale(&state).starts_with("zh") {
                "该材质不存在"
            } else {
                "We cannot find this texture."
            },
            None,
        ),
        Ok(crate::database::ClosetAddOutcome::PrivateTexture) => login_result(
            1,
            if request_locale(&state).starts_with("zh") {
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
    Query(query): Query<BTreeMap<String, String>>,
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
    let request = match parse_legacy_input_object(
        &query,
        &body,
        headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
    ) {
        Ok(fields) => serde_json::Value::Object(fields),
        Err(()) => return closet_validation_error("name", &request_locale(&state)),
    };
    let Some(name) = request.get("name").and_then(serde_json::Value::as_str) else {
        return closet_validation_error("name", &request_locale(&state));
    };
    let name = name.trim();
    if name.is_empty() {
        return closet_validation_error("name", &request_locale(&state));
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    let filtered_name = closet_name_filter(&state, "rename_closet_item_name", tid, name).await;
    emit_plugin_event(
        &state,
        "closet.renaming",
        serde_json::json!({"user_id": identity.user_id, "texture_id": tid, "item_name": filtered_name}),
    )
    .await;
    let closet_item = match database
        .closet_item(&state.config.database.table_prefix, identity.user_id, tid)
        .await
    {
        Ok(Some(item)) => item,
        Ok(None) => return closet_item_missing(&state),
        Err(error) => {
            tracing::error!(%error, user_id=identity.user_id, tid, "failed to load closet item for rename filter");
            return unavailable();
        }
    };
    if let Some(reason) = closet_permission_filter(
        &state,
        "can_rename_closet_item",
        serde_json::json!({"item": closet_item_plugin_record(&closet_item), "name": filtered_name}),
    )
    .await
    {
        return login_result(1, &reason, None);
    }
    match database
        .rename_closet_item(
            &state.config.database.table_prefix,
            identity.user_id,
            tid,
            &filtered_name,
        )
        .await
    {
        Ok(crate::database::ClosetRenameOutcome::Renamed) => {
            emit_plugin_event(
                &state,
                "closet.renamed",
                serde_json::json!({
                    "user_id": identity.user_id,
                    "texture_id": tid,
                    "item_name": filtered_name,
                }),
            )
            .await;
            login_result(
                0,
                &if request_locale(&state).starts_with("zh") {
                    format!("衣柜物品成功重命名至 {filtered_name}")
                } else {
                    format!("The item is successfully renamed to {filtered_name}")
                },
                None,
            )
        }
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
    emit_plugin_event(
        &state,
        "closet.removing",
        serde_json::json!({"user_id": identity.user_id, "texture_id": tid}),
    )
    .await;
    let closet_item = match database.closet_item(prefix, identity.user_id, tid).await {
        Ok(Some(item)) => item,
        Ok(None) => return closet_item_missing(&state),
        Err(error) => {
            tracing::error!(%error, user_id=identity.user_id, tid, "failed to load closet item for remove filter");
            return unavailable();
        }
    };
    if let Some(reason) = closet_permission_filter(
        &state,
        "can_remove_closet_item",
        serde_json::json!({"item": closet_item_plugin_record(&closet_item)}),
    )
    .await
    {
        return login_result(1, &reason, None);
    }
    let return_score = match database.option(prefix, "return_score").await {
        Ok(value) => legacy_option_bool(value.as_deref()),
        Err(error) => {
            tracing::error!(%error, "failed to load closet score refund option");
            return unavailable();
        }
    };
    let score_refund = if return_score {
        match database.option(prefix, "score_per_closet_item").await {
            Ok(value) => legacy_option_integer(value.as_deref(), 0),
            Err(error) => {
                tracing::error!(%error, "failed to load closet score refund");
                return unavailable();
            }
        }
    } else {
        0
    };
    let like_award = match database.option(prefix, "score_award_per_like").await {
        Ok(value) => legacy_option_integer(value.as_deref(), 0),
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
        Ok(crate::database::ClosetRemoveOutcome::Removed) => {
            emit_plugin_event(
                &state,
                "closet.removed",
                serde_json::json!({"user_id": identity.user_id, "texture_id": tid}),
            )
            .await;
            login_result(
                0,
                if request_locale(&state).starts_with("zh") {
                    "材质已从衣柜中移除"
                } else {
                    "The texture was removed from closet successfully."
                },
                None,
            )
        }
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
        if request_locale(&state).starts_with("zh") {
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

async fn skinlib_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let current_uid = session_user_id(&state, &headers).unwrap_or_default();
    let logged_in = current_uid > 0;
    let site_name = site_name(&state).await;
    let app_dir = state.public_dir.join("app");
    let stylesheet = frontend_entrypoint(&app_dir, "style", "css", &request_app_url(&state)).await;
    let frontend_script =
        frontend_entrypoint(&app_dir, "app", "js", &request_app_url(&state)).await;
    let i18n = load_frontend_translations(&state, &app_dir, &request_locale(&state)).await;
    let frontend_globals_b64 = encode_frontend_globals(
        &state,
        &site_name,
        "skinlib",
        serde_json::json!({ "currentUid": logged_in.then_some(current_uid) }),
        i18n,
    );
    let page = SkinLibraryPage {
        site_name,
        locale: request_locale(&state),
        logged_in,
        current_uid,
        frontend_style_available: stylesheet.is_some(),
        frontend_stylesheet: stylesheet.unwrap_or_default(),
        frontend_script_available: frontend_script.is_some(),
        frontend_script: frontend_script.unwrap_or_default(),
        frontend_globals_b64,
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to render skin library page");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn skinlib_show_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(raw_tid): RoutePath<String>,
) -> Response {
    let Ok(tid) = raw_tid.parse::<i64>() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let texture = match database
        .texture_info(&state.config.database.table_prefix, tid)
        .await
    {
        Ok(Some(texture)) => texture,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, tid, "failed to load texture for skin library page");
            return unavailable();
        }
    };
    let current_uid = session_user_id(&state, &headers);
    let (viewer_uid, is_admin) = match current_uid {
        Some(uid) => match database
            .user_profile(&state.config.database.table_prefix, uid)
            .await
        {
            Ok(Some(user)) => (Some(uid), user.permission >= 1),
            Ok(None) => (None, false),
            Err(error) => {
                tracing::error!(%error, "failed to load texture page viewer");
                return unavailable();
            }
        },
        None => (None, false),
    };
    if !texture.is_public && viewer_uid != Some(texture.uploader) && !is_admin {
        let code = match database
            .option(
                &state.config.database.table_prefix,
                "status_code_for_private",
            )
            .await
        {
            Ok(value) => private_texture_status_code(value.as_deref()),
            Err(error) => {
                tracing::error!(%error, "failed to read private texture status option");
                return unavailable();
            }
        };
        return code.into_response();
    }
    if !valid_texture_hash(&texture.hash) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let uploader_profile = match database
        .user_profile(&state.config.database.table_prefix, texture.uploader)
        .await
    {
        Ok(user) => user,
        Err(error) => {
            tracing::error!(%error, tid, uploader = texture.uploader, "failed to load skin library uploader");
            return unavailable();
        }
    };
    let uploader_exists = uploader_profile.is_some();
    let nickname = uploader_profile
        .as_ref()
        .map(|user| user.nickname.clone())
        .unwrap_or_else(|| {
            if request_locale(&state).starts_with("zh") {
                "不存在的用户".to_owned()
            } else {
                "No such user.".to_owned()
            }
        });
    let badges = if let Some(uploader) = uploader_profile.as_ref() {
        filter_user_badges(&state, uploader).await
    } else {
        serde_json::json!([])
    };
    let in_closet = if let Some(viewer_uid) = viewer_uid {
        match database
            .closet_item_ids(&state.config.database.table_prefix, viewer_uid)
            .await
        {
            Ok(ids) => ids.contains(&texture.tid),
            Err(error) => {
                tracing::error!(%error, tid, viewer_uid, "failed to load skin library viewer closet");
                return unavailable();
            }
        }
    } else {
        false
    };
    let can_download = match database
        .option(
            &state.config.database.table_prefix,
            "allow_downloading_texture",
        )
        .await
    {
        Ok(value) => value
            .as_deref()
            .map(|value| legacy_option_bool(Some(value)))
            .unwrap_or(true),
        Err(error) => {
            tracing::error!(%error, tid, "failed to load texture download option");
            return unavailable();
        }
    };
    let report_score = match database
        .option(
            &state.config.database.table_prefix,
            "reporter_score_modification",
        )
        .await
    {
        Ok(value) => legacy_option_integer(value.as_deref(), 0),
        Err(error) => {
            tracing::error!(%error, tid, "failed to load texture report score option");
            return unavailable();
        }
    };
    let page_widgets = filter_skinlib_show_widgets(&state).await;
    let has_texture_details = page_widgets
        .iter()
        .any(|widget| widget == "texture_details");
    let site_name = site_name(&state).await;
    let app_dir = state.public_dir.join("app");
    let stylesheet = frontend_entrypoint(&app_dir, "style", "css", &request_app_url(&state)).await;
    let frontend_script =
        frontend_entrypoint(&app_dir, "app", "js", &request_app_url(&state)).await;
    let i18n = load_frontend_translations(&state, &app_dir, &request_locale(&state)).await;
    let frontend_globals_b64 = encode_frontend_globals(
        &state,
        &site_name,
        &format!("skinlib/show/{tid}"),
        serde_json::json!({
            "nickname": nickname,
            "uploaderExists": uploader_exists,
            "currentUid": viewer_uid.unwrap_or_default(),
            "admin": is_admin,
            "badges": badges,
            "download": can_download,
            "report": report_score,
            "inCloset": in_closet,
        }),
        i18n,
    );
    let page = SkinLibraryShowPage {
        site_name,
        locale: request_locale(&state),
        tid: texture.tid,
        name: texture.name,
        texture_type: texture.texture_type,
        hash: texture.hash,
        size: texture.size,
        uploader: texture.uploader,
        is_public: texture.is_public,
        upload_at: texture.upload_at,
        likes: texture.likes,
        logged_in: viewer_uid.is_some(),
        can_manage: viewer_uid == Some(texture.uploader) || is_admin,
        page_widgets,
        has_texture_details,
        frontend_style_available: stylesheet.is_some(),
        frontend_stylesheet: stylesheet.unwrap_or_default(),
        frontend_script_available: frontend_script.is_some(),
        frontend_script: frontend_script.unwrap_or_default(),
        frontend_globals_b64,
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, tid, "failed to render skin library detail page");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn texture_upload_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if session_user_id(&state, &headers).is_none() {
        return Redirect::to("/auth/login").into_response();
    }
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let prefix = &state.config.database.table_prefix;
    let read_number = async |name: &str, default: i64| match database.option(prefix, name).await {
        Ok(value) => Ok(legacy_option_integer(value.as_deref(), default)),
        Err(error) => Err(error),
    };
    let public_rate = match read_number("score_per_storage", 1).await {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(%error, "failed to read public upload cost");
            return unavailable();
        }
    };
    let private_rate = match read_number("private_score_per_storage", 10).await {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(%error, "failed to read private upload cost");
            return unavailable();
        }
    };
    let closet_cost = match read_number("score_per_closet_item", 0).await {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(%error, "failed to read closet upload cost");
            return unavailable();
        }
    };
    let upload_award = match read_number("score_award_per_texture", 0).await {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(%error, "failed to read upload award");
            return unavailable();
        }
    };
    let max_upload_kb = match read_number("max_upload_file_size", 1024).await {
        Ok(value) => value.max(0),
        Err(error) => {
            tracing::error!(%error, "failed to read maximum upload size");
            return unavailable();
        }
    };
    let localized_policy_key = format!("content_policy_{}", request_locale(&state));
    let content_policy = match database.option(prefix, &localized_policy_key).await {
        Ok(Some(value)) if !value.is_empty() => value,
        Ok(_) => match database.option(prefix, "content_policy").await {
            Ok(value) => value.unwrap_or_default(),
            Err(error) => {
                tracing::error!(%error, "failed to read texture content policy");
                return unavailable();
            }
        },
        Err(error) => {
            tracing::error!(%error, "failed to read localized texture content policy");
            return unavailable();
        }
    };
    let texture_name_regexp = match database.option(prefix, "texture_name_regexp").await {
        Ok(value) => value.filter(|value| legacy_option_bool(Some(value))),
        Err(error) => {
            tracing::error!(%error, "failed to read texture name rule");
            return unavailable();
        }
    };
    let chinese = request_locale(&state).starts_with("zh");
    let rule = match texture_name_regexp {
        Some(regexp) if chinese => format!("本站已应用特殊的名称规则：{regexp}"),
        Some(regexp) => format!("Custom name rules are applied as {regexp}"),
        None if chinese => "材质名称应该小于 32 个字节且不能包含奇怪的符号".to_owned(),
        None => "Less than 32 characters and must not contain any special one.".to_owned(),
    };
    let privacy_notice = if chinese {
        format!("私密材质将会消耗更多的积分：每 KB 存储空间 {private_rate} 积分")
    } else {
        format!(
            "It will spend you more scores for setting it as private. You will be charged {private_rate} scores for per KB storage."
        )
    };
    let rendered_content_policy = render_notification_markdown(&content_policy);
    let page_widgets = filter_skinlib_upload_widgets(&state).await;
    let has_upload_form = page_widgets.iter().any(|widget| widget == "upload_form");
    let site_name = site_name(&state).await;
    let app_dir = state.public_dir.join("app");
    let stylesheet = frontend_entrypoint(&app_dir, "style", "css", &request_app_url(&state)).await;
    let frontend_script =
        frontend_entrypoint(&app_dir, "app", "js", &request_app_url(&state)).await;
    let i18n = load_frontend_translations(&state, &app_dir, &request_locale(&state)).await;
    let frontend_globals_b64 = encode_frontend_globals(
        &state,
        &site_name,
        "skinlib/upload",
        serde_json::json!({
            "rule": rule,
            "privacyNotice": privacy_notice,
            "score": user.score,
            "scorePublic": public_rate,
            "scorePrivate": private_rate,
            "closetItemCost": closet_cost,
            "award": upload_award,
            "contentPolicy": rendered_content_policy,
        }),
        i18n,
    );
    let page = TextureUploadPage {
        site_name,
        locale: request_locale(&state),
        user,
        public_rate,
        private_rate,
        closet_cost,
        upload_award,
        max_upload_kb,
        content_policy,
        page_widgets,
        has_upload_form,
        frontend_style_available: stylesheet.is_some(),
        frontend_stylesheet: stylesheet.unwrap_or_default(),
        frontend_script_available: frontend_script.is_some(),
        frontend_script: frontend_script.unwrap_or_default(),
        frontend_globals_b64,
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to render texture upload page");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
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
        let status = match database
            .option(
                &state.config.database.table_prefix,
                "status_code_for_private",
            )
            .await
        {
            Ok(value) => private_texture_status_code(value.as_deref()),
            Err(error) => {
                tracing::error!(%error, "failed to read private texture status option");
                return unavailable();
            }
        };
        let message = if request_locale(&state).starts_with("zh") {
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

pub(crate) async fn authenticated_web_user(
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
        let message = if request_locale(&state).starts_with("zh") {
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
            let message = if request_locale(&state).starts_with("zh") {
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

fn normalize_skin_dimensions(skin: &RgbaImage, texture_type: &str) -> Option<RgbaImage> {
    if !valid_texture_dimensions(texture_type, skin.width(), skin.height()) {
        return None;
    }

    let hd_ratio = skin.width() / 64;
    let height = skin.height() / hd_ratio;
    Some(if hd_ratio == 1 {
        skin.clone()
    } else {
        image::imageops::resize(skin, 64, height, image::imageops::FilterType::Nearest)
    })
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
    let mut file_name = None;
    loop {
        let field = match multipart.next_field().await {
            Ok(Some(field)) => field,
            Ok(None) => break,
            Err(error) => {
                tracing::warn!(%error, "invalid texture upload multipart body");
                return upload_validation_error("file", &request_locale(&state));
            }
        };
        let Some(field_name) = field.name().map(str::to_owned) else {
            continue;
        };
        let upload_filename = field.file_name().map(str::to_owned);
        let bytes = match field.bytes().await {
            Ok(bytes) => bytes,
            Err(error) => {
                tracing::warn!(%error, field = field_name, "failed to read texture upload field");
                return upload_validation_error(&field_name, &request_locale(&state));
            }
        };
        if field_name == "file" {
            file_name = upload_filename;
            file_bytes = Some(bytes.to_vec());
            continue;
        }
        let Ok(value) = String::from_utf8(bytes.to_vec()) else {
            return upload_validation_error(&field_name, &request_locale(&state));
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
        return upload_validation_error("name", &request_locale(&state));
    };
    let Some(mut file_bytes) = file_bytes.filter(|bytes: &Vec<u8>| !bytes.is_empty()) else {
        return upload_validation_error("file", &request_locale(&state));
    };
    let Some(texture_type) = texture_type else {
        return upload_validation_error("type", &request_locale(&state));
    };
    if !valid_texture_type(&texture_type) {
        return upload_validation_error("type", &request_locale(&state));
    }
    let Some(is_public) = public.as_deref().and_then(parse_legacy_form_bool) else {
        return upload_validation_error("public", &request_locale(&state));
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
    if legacy_option_bool(Some(&name_rule)) {
        if !legacy_texture_name_rule_is_valid(&name_rule) {
            tracing::error!("invalid legacy texture name validation regex");
            return unavailable();
        }
        if !valid_texture_name(&name, &name_rule) {
            return upload_validation_error("name", &request_locale(&state));
        }
    }
    let max_upload_kb = match database
        .option(&state.config.database.table_prefix, "max_upload_file_size")
        .await
    {
        Ok(value) => legacy_option_integer(value.as_deref(), 1024).max(0),
        Err(error) => {
            tracing::error!(%error, "failed to read maximum texture upload size");
            return unavailable();
        }
    };
    if file_bytes.len() as u64 > max_upload_kb.saturating_mul(1024) as u64 {
        return upload_validation_error("file", &request_locale(&state));
    }
    if file_bytes.len() <= crate::plugin_runtime::PLUGIN_FILTER_FILE_BYTES_LIMIT {
        let encoded_file = STANDARD.encode(&file_bytes);
        let filtered_file = apply_plugin_filter_value(
            &state,
            "uploaded_texture_file",
            &serde_json::json!(encoded_file),
            &serde_json::json!({"file": {"name": file_name, "size": file_bytes.len(), "mime_type": "image/png"}}),
        )
        .await;
        let Some(encoded_file) = filtered_file.as_str() else {
            return upload_validation_error("file", &request_locale(&state));
        };
        let Ok(filtered_file) = STANDARD.decode(encoded_file) else {
            return upload_validation_error("file", &request_locale(&state));
        };
        file_bytes = filtered_file;
    }
    let file_context = serde_json::json!({
        "name": file_name,
        "size": file_bytes.len(),
        "mime_type": "image/png",
    });
    let filtered_name = apply_plugin_filter_value(
        &state,
        "uploaded_texture_name",
        &serde_json::json!(name),
        &serde_json::json!({"file": file_context.clone()}),
    )
    .await;
    let name = filtered_name.as_str().unwrap_or(&name).to_owned();
    let can_upload = apply_plugin_filter_value(
        &state,
        "can_upload_texture",
        &serde_json::json!(true),
        &serde_json::json!({"file": file_context, "name": name}),
    )
    .await;
    if let Some(reason) = plugin_filter_rejection(&can_upload) {
        return login_result(1, reason, None);
    }
    let Some((width, height)) = png_dimensions(&file_bytes) else {
        return upload_validation_error("file", &request_locale(&state));
    };
    let (max_width, max_width_label) = match database
        .option(&state.config.database.table_prefix, "max_texture_width")
        .await
    {
        Ok(value) => legacy_texture_width_limit(value.as_deref()),
        Err(error) => {
            tracing::error!(%error, "failed to read maximum texture width");
            return unavailable();
        }
    };
    if f64::from(width) > max_width {
        let message = if request_locale(&state).starts_with("zh") {
            format!("材质过宽（{width}px），本站允许的最大宽度为 {max_width_label}px")
        } else {
            format!(
                "The texture is too wide ({width}px). Maximum width allowed is {max_width_label}px"
            )
        };
        return login_result(1, &message, None);
    }
    if !valid_texture_dimensions(&texture_type, width, height) {
        return upload_size_error(&request_locale(&state), &texture_type, width, height);
    }
    let sanitized = match sanitize_png(&file_bytes) {
        Ok(sanitized) => sanitized,
        Err(error) => {
            tracing::warn!(%error, "failed to decode uploaded PNG texture");
            return upload_validation_error("file", &request_locale(&state));
        }
    };
    let computed_hash = Sha256::digest(&sanitized)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let filtered_hash = apply_plugin_filter_value(
        &state,
        "uploaded_texture_hash",
        &serde_json::json!(computed_hash),
        &serde_json::json!({"image": {"width": width, "height": height, "format": "png"}}),
    )
    .await;
    let Some(hash) = filtered_hash
        .as_str()
        .filter(|hash| valid_texture_hash(hash))
        .map(str::to_owned)
    else {
        tracing::warn!("WASM texture hash filter returned an unsafe hash");
        return unavailable();
    };
    match database
        .texture_upload_duplicate_id(&state.config.database.table_prefix, &hash, reporter.uid)
        .await
    {
        Ok(Some(tid)) => {
            return login_result(
                2,
                if request_locale(&state).starts_with("zh") {
                    "已经有人上传过这个材质了，直接添加到衣柜使用吧~"
                } else {
                    "The texture is already uploaded by someone else. You can add it to your closet directly."
                },
                Some(serde_json::json!({"tid": tid})),
            );
        }
        Ok(None) => {}
        Err(error) => {
            tracing::error!(%error, hash, "failed to check duplicate texture upload");
            return unavailable();
        }
    }
    let size_kb = ((sanitized.len() as i64).saturating_add(1023) / 1024).max(1);
    let public_cost_per_kb = match database
        .option(&state.config.database.table_prefix, "score_per_storage")
        .await
    {
        Ok(value) => legacy_option_integer(value.as_deref(), 1),
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
        Ok(value) => legacy_option_integer(value.as_deref(), 10),
        Err(error) => {
            tracing::error!(%error, "failed to read private texture storage score");
            return unavailable();
        }
    };
    let closet_cost = match database
        .option(&state.config.database.table_prefix, "score_per_closet_item")
        .await
    {
        Ok(value) => legacy_option_integer(value.as_deref(), 0),
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
        Ok(value) => legacy_option_integer(value.as_deref(), 0),
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
            if request_locale(&state).starts_with("zh") {
                "积分不足"
            } else {
                "You don't have enough score to upload this texture."
            },
            None,
        );
    }

    emit_plugin_event(
        &state,
        "texture.uploading",
        serde_json::json!({
            "user_id": reporter.uid,
            "hash": hash,
            "name": name,
            "type": texture_type,
            "public": is_public,
        }),
    )
    .await;
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
            emit_plugin_event(
                &state,
                "texture.uploaded",
                serde_json::json!({"user_id": reporter.uid, "texture_id": tid, "hash": hash, "name": name, "type": texture_type, "public": is_public}),
            )
            .await;
            let message = if request_locale(&state).starts_with("zh") {
                format!("材质 {name} 上传成功")
            } else {
                format!("Texture {name} was uploaded successfully.")
            };
            login_result(0, &message, Some(serde_json::json!({ "tid": tid })))
        }
        Ok(crate::database::TextureUploadOutcome::AlreadyUploaded(tid)) => login_result(
            2,
            if request_locale(&state).starts_with("zh") {
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
                if request_locale(&state).starts_with("zh") {
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
        let message = if request_locale(&state).starts_with("zh") {
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
    Query(query): Query<BTreeMap<String, String>>,
    body: Bytes,
) -> Response {
    let Some(database) = &state.database else {
        return unavailable();
    };
    let reporter = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let fields = match parse_legacy_input_object(
        &query,
        &body,
        headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
    ) {
        Ok(fields) => fields,
        Err(()) => return report_validation_error("tid", &request_locale(&state)),
    };
    let request = serde_json::Value::Object(fields);
    let Some(tid) = texture_id_from_request(request.get("tid")) else {
        return report_validation_error("tid", &request_locale(&state));
    };
    let Some(reason) = request.get("reason").and_then(serde_json::Value::as_str) else {
        return report_validation_error("reason", &request_locale(&state));
    };
    let reason = reason.trim();
    if reason.is_empty() {
        return report_validation_error("reason", &request_locale(&state));
    }
    let texture = match database
        .texture_info(&state.config.database.table_prefix, tid)
        .await
    {
        Ok(Some(texture)) => texture,
        Ok(None) => return report_validation_error("tid", &request_locale(&state)),
        Err(error) => {
            tracing::error!(%error, tid, "failed to load reported texture");
            return unavailable();
        }
    };
    let report_permission = apply_plugin_filter_value(
        &state,
        "user_can_report",
        &serde_json::json!(true),
        &serde_json::json!({
            "report": {"texture_id": tid, "reason": reason},
            "reporter": {
                "uid": reporter.uid,
                "nickname": reporter.nickname,
                "score": reporter.score,
                "permission": reporter.permission,
                "verified": reporter.verified,
            },
        }),
    )
    .await;
    if let Some(reason) = plugin_filter_rejection(&report_permission) {
        return login_result(1, reason, None);
    }
    emit_plugin_event(
        &state,
        "report.submitting",
        serde_json::json!({"reporter_id": reporter.uid, "texture_id": tid, "uploader_id": texture.uploader}),
    )
    .await;
    let score_modification = match database
        .option(
            &state.config.database.table_prefix,
            "reporter_score_modification",
        )
        .await
    {
        Ok(value) => legacy_option_integer(value.as_deref(), 0),
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
        Ok(crate::database::ReportSubmissionOutcome::Submitted) => {
            emit_plugin_event(
                &state,
                "report.submitted",
                serde_json::json!({"reporter_id": reporter.uid, "texture_id": tid, "uploader_id": texture.uploader}),
            )
            .await;
            login_result(
                0,
                if request_locale(&state).starts_with("zh") {
                    "举报已提交，请等待管理员处理"
                } else {
                    "Thanks for reporting! The administrators will review it as soon as possible."
                },
                None,
            )
        }
        Ok(crate::database::ReportSubmissionOutcome::AlreadyReported) => login_result(
            1,
            if request_locale(&state).starts_with("zh") {
                "您已经举报过该材质了，请耐心等待管理员处理。您可以在用户中心查看举报的处理进度。"
            } else {
                "You have already reported this texture. The administrators will review it as soon as possible. You can also track the status of your report at User Center."
            },
            None,
        ),
        Ok(crate::database::ReportSubmissionOutcome::InsufficientScore) => login_result(
            1,
            if request_locale(&state).starts_with("zh") {
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
    !legacy_option_bool(Some(rule)) || legacy_texture_name_rule_matches(name, rule)
}

fn legacy_texture_name_rule_is_valid(rule: &str) -> bool {
    !legacy_option_bool(Some(rule)) || legacy_texture_name_regex(rule).is_some()
}

fn legacy_texture_name_rule_matches(name: &str, rule: &str) -> bool {
    let Some((regex, unicode, anchored)) = legacy_texture_name_regex(rule) else {
        return false;
    };
    let match_start = if unicode {
        regex.find(name).ok().flatten().map(|found| found.start())
    } else {
        regex
            .find(name.as_bytes())
            .ok()
            .flatten()
            .map(|found| found.start())
    };
    match_start.is_some_and(|start| !anchored || start == 0)
}

fn legacy_texture_name_regex(rule: &str) -> Option<(fancy_regex::Regex, bool, bool)> {
    let (pattern, flags) = split_php_delimited_regex(rule).unwrap_or((rule, ""));
    if pattern.len() > 512
        || flags.chars().any(|flag| {
            !matches!(
                flag,
                'i' | 'm' | 's' | 'x' | 'A' | 'D' | 'S' | 'U' | 'X' | 'u'
            )
        })
    {
        return None;
    }

    let pattern = if flags.contains('m') {
        pattern.to_owned()
    } else {
        dollar_end_only_pattern(pattern, !flags.contains('D'))
    };
    let pattern = if flags.contains('U') {
        format!("(?U){pattern}")
    } else {
        pattern
    };
    let mut builder = FancyRegexBuilder::new(&pattern);
    builder
        .case_insensitive(flags.contains('i'))
        .multi_line(flags.contains('m'))
        .dot_matches_new_line(flags.contains('s'))
        .ignore_whitespace(flags.contains('x'))
        .unicode_mode(flags.contains('u'))
        .bytes_mode(if flags.contains('u') {
            BytesMode::Unicode
        } else {
            BytesMode::Ascii
        })
        .backtrack_limit(100_000);
    builder
        .build()
        .ok()
        .map(|regex| (regex, flags.contains('u'), flags.contains('A')))
}

fn valid_texture_type(texture_type: &str) -> bool {
    matches!(texture_type, "steve" | "alex" | "cape")
}

async fn rename_texture(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(tid_path): RoutePath<String>,
    Query(query): Query<BTreeMap<String, String>>,
    body: Bytes,
) -> Response {
    let (tid, texture) = match texture_mutation_context(&state, &headers, &tid_path).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let fields = match parse_legacy_input_object(
        &query,
        &body,
        headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
    ) {
        Ok(fields) => fields,
        Err(()) => return texture_name_validation_error(&request_locale(&state)),
    };
    let request = serde_json::Value::Object(fields);
    let Some(name) = request.get("name").and_then(serde_json::Value::as_str) else {
        return texture_name_validation_error(&request_locale(&state));
    };
    let name = name.trim();
    if name.is_empty() {
        return texture_name_validation_error(&request_locale(&state));
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
    if legacy_option_bool(Some(&name_rule)) {
        if !legacy_texture_name_rule_is_valid(&name_rule) {
            tracing::error!("invalid legacy texture name validation regex");
            return unavailable();
        }
        if !valid_texture_name(name, &name_rule) {
            return texture_name_validation_error(&request_locale(&state));
        }
    }
    if let Some(reason) = texture_permission_filter(
        &state,
        "can_update_texture_name",
        &texture,
        serde_json::json!({"name": name}),
    )
    .await
    {
        return login_result(1, &reason, None);
    }
    emit_plugin_event(
        &state,
        "texture.name.updating",
        serde_json::json!({"texture_id": tid, "previous_name": texture.name, "name": name}),
    )
    .await;
    if let Err(error) = database
        .rename_texture(&state.config.database.table_prefix, tid, name)
        .await
    {
        tracing::error!(%error, tid, "failed to rename texture");
        return unavailable();
    }
    emit_plugin_event(
        &state,
        "texture.renamed",
        serde_json::json!({"texture_id": tid, "previous_name": texture.name, "name": name}),
    )
    .await;
    emit_plugin_event(
        &state,
        "texture.name.updated",
        serde_json::json!({"texture_id": tid, "previous_name": texture.name, "name": name}),
    )
    .await;
    let message = if request_locale(&state).starts_with("zh") {
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
    if let Some(reason) = texture_permission_filter(
        &state,
        "can_delete_texture",
        &texture,
        serde_json::json!({}),
    )
    .await
    {
        return login_result(1, &reason, None);
    }
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
        Ok(value) => legacy_option_integer(value.as_deref(), 1),
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
        Ok(value) => legacy_option_integer(value.as_deref(), 10),
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
        Ok(value) => legacy_option_integer(value.as_deref(), 0),
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
            Ok(value) => legacy_option_integer(value.as_deref(), 0),
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
    emit_plugin_event(
        &state,
        "texture.deleting",
        serde_json::json!({
            "texture_id": tid,
            "uploader_id": texture.uploader,
            "hash": texture.hash,
            "name": texture.name,
        }),
    )
    .await;
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
    emit_plugin_event(
        &state,
        "texture.deleted",
        serde_json::json!({"texture_id": tid, "uploader_id": texture.uploader, "hash": texture.hash, "name": texture.name}),
    )
    .await;
    login_result(
        0,
        if request_locale(&state).starts_with("zh") {
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
    if let Some(reason) = texture_permission_filter(
        &state,
        "can_update_texture_privacy",
        &texture,
        serde_json::json!({}),
    )
    .await
    {
        return login_result(1, &reason, None);
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    let public_cost_per_kb = match database
        .option(&state.config.database.table_prefix, "score_per_storage")
        .await
    {
        Ok(value) => legacy_option_integer(value.as_deref(), 1),
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
        Ok(value) => legacy_option_integer(value.as_deref(), 10),
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
        Ok(value) => legacy_option_integer(value.as_deref(), 0),
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
    let return_closet_score = match read_bool_option(
        database,
        &state.config.database.table_prefix,
        "return_score",
        true,
    )
    .await
    {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(%error, "failed to read closet score return option");
            return unavailable();
        }
    };
    let closet_score_refund = if return_closet_score {
        match read_score_option(
            database,
            &state.config.database.table_prefix,
            "score_per_closet_item",
            0,
        )
        .await
        {
            Ok(value) => value,
            Err(error) => {
                tracing::error!(%error, "failed to read closet item score");
                return unavailable();
            }
        }
    } else {
        0
    };
    let score_diff = texture_privacy_score_diff(
        &texture,
        public_cost_per_kb,
        private_cost_per_kb,
        public_award,
        take_back_award,
    );
    match database
        .user_profile(&state.config.database.table_prefix, texture.uploader)
        .await
    {
        Ok(Some(uploader)) if uploader.score.saturating_add(score_diff) >= 0 => {}
        Ok(Some(_)) | Ok(None) => {
            return login_result(
                1,
                if request_locale(&state).starts_with("zh") {
                    "积分不足"
                } else {
                    "You don't have enough score to upload this texture."
                },
                None,
            );
        }
        Err(error) => {
            tracing::error!(%error, uploader_id = texture.uploader, "failed to check texture privacy balance");
            return unavailable();
        }
    };
    if !texture.is_public {
        match database
            .public_texture_duplicate_id(&state.config.database.table_prefix, &texture.hash, tid)
            .await
        {
            Ok(Some(duplicate_tid)) => {
                let message = if request_locale(&state).starts_with("zh") {
                    "已经有人上传过这个材质了，直接添加到衣柜使用吧~"
                } else {
                    "The texture is already uploaded by someone else. You can add it to your closet directly."
                };
                return login_result(2, message, Some(serde_json::json!({"tid": duplicate_tid})));
            }
            Ok(None) => {}
            Err(error) => {
                tracing::error!(%error, hash = texture.hash, "failed to check public texture duplicate");
                return unavailable();
            }
        }
    }
    emit_plugin_event(
        &state,
        "texture.privacy.updating",
        serde_json::json!({
            "texture_id": tid,
            "previous_public": texture.is_public,
            "public": !texture.is_public,
        }),
    )
    .await;
    match database
        .toggle_texture_privacy(
            &state.config.database.table_prefix,
            tid,
            texture.uploader,
            &texture.hash,
            texture.is_public,
            score_diff,
            &texture.texture_type,
            return_closet_score,
            closet_score_refund,
        )
        .await
    {
        Ok(crate::database::TexturePrivacyOutcome::Updated { is_public }) => {
            emit_plugin_event(
                &state,
                "texture.visibility.updated",
                serde_json::json!({"texture_id": tid, "public": is_public}),
            )
            .await;
            emit_plugin_event(
                &state,
                "texture.privacy.updated",
                serde_json::json!({"texture_id": tid, "public": is_public}),
            )
            .await;
            let privacy = if request_locale(&state).starts_with("zh") {
                if is_public { "公开" } else { "私密" }
            } else if is_public {
                "Public"
            } else {
                "Private"
            };
            let message = if request_locale(&state).starts_with("zh") {
                format!("材质已被设为 {privacy}")
            } else {
                format!("The texture was set to {privacy} successfully.")
            };
            login_result(0, &message, None)
        }
        Ok(crate::database::TexturePrivacyOutcome::DuplicatePublicTexture(duplicate_tid)) => {
            let message = if request_locale(&state).starts_with("zh") {
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
            if request_locale(&state).starts_with("zh") {
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
    Query(query): Query<BTreeMap<String, String>>,
    body: Bytes,
) -> Response {
    let (tid, texture) = match texture_mutation_context(&state, &headers, &tid_path).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let fields = match parse_legacy_input_object(
        &query,
        &body,
        headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
    ) {
        Ok(fields) => fields,
        Err(()) => return texture_type_validation_error(&request_locale(&state)),
    };
    let request = serde_json::Value::Object(fields);
    let Some(texture_type) = request.get("type").and_then(serde_json::Value::as_str) else {
        return texture_type_validation_error(&request_locale(&state));
    };
    if !valid_texture_type(texture_type) {
        return texture_type_validation_error(&request_locale(&state));
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    if let Some(reason) = texture_permission_filter(
        &state,
        "can_update_texture_type",
        &texture,
        serde_json::json!({"type": texture_type}),
    )
    .await
    {
        return login_result(1, &reason, None);
    }
    emit_plugin_event(
        &state,
        "texture.type.updating",
        serde_json::json!({"texture_id": tid, "previous_type": texture.texture_type, "type": texture_type}),
    )
    .await;
    if let Err(error) = database
        .set_texture_type(&state.config.database.table_prefix, tid, texture_type)
        .await
    {
        tracing::error!(%error, tid, "failed to update texture type");
        return unavailable();
    }
    emit_plugin_event(
        &state,
        "texture.type.updated",
        serde_json::json!({"texture_id": tid, "previous_type": texture.texture_type, "type": texture_type}),
    )
    .await;
    let message = if request_locale(&state).starts_with("zh") {
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
    OriginalUri(uri): OriginalUri,
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
    let uploader_filter = query
        .uploader
        .as_deref()
        .filter(|value| !value.is_empty() && *value != "0");
    let uploader = uploader_filter.and_then(|value| value.parse::<i64>().ok());
    let sort = query.sort.as_deref().unwrap_or("time");
    let page = query.page.unwrap_or(1).max(1);
    let per_page = 20_i64;
    let path = format!(
        "{}{}",
        request_app_url(&state).trim_end_matches('/'),
        uri.path()
    );
    if uploader_filter.is_some() && uploader.is_none() {
        return Json(legacy_paginator_json(
            Vec::<serde_json::Value>::new(),
            0,
            page,
            per_page,
            &path,
            uri.query(),
        ))
        .into_response();
    }
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
            Json(legacy_paginator_json(
                data,
                total,
                page,
                per_page,
                &path,
                uri.query(),
            ))
            .into_response()
        }
        Err(error) => {
            tracing::error!(%error, "failed to query the skin library");
            unavailable()
        }
    }
}

fn legacy_paginator_json<T: Serialize>(
    data: Vec<T>,
    total: i64,
    page: i64,
    per_page: i64,
    path: &str,
    raw_query: Option<&str>,
) -> serde_json::Value {
    let last_page = total.saturating_add(per_page - 1) / per_page;
    let last_page = last_page.max(1);
    let page_url = |number: i64| legacy_paginator_page_url(path, raw_query, number);
    let previous = (page > 1).then(|| page_url(page - 1));
    let next = (page < last_page).then(|| page_url(page + 1));
    let offset = page.saturating_sub(1).saturating_mul(per_page);
    let from = (!data.is_empty()).then_some(offset + 1);
    let to = (!data.is_empty()).then_some(offset + data.len() as i64);

    let page_numbers = if last_page <= 14 {
        (1..=last_page).map(Some).collect::<Vec<_>>()
    } else if page <= 7 {
        (1..=7).map(Some).chain([None, Some(last_page)]).collect()
    } else if page >= last_page.saturating_sub(6) {
        [Some(1), None]
            .into_iter()
            .chain((last_page - 7..=last_page).map(Some))
            .collect()
    } else {
        [Some(1), None]
            .into_iter()
            .chain((page.saturating_sub(3)..=page.saturating_add(3).min(last_page)).map(Some))
            .chain([None, Some(last_page)])
            .collect()
    };
    let mut links = vec![serde_json::json!({
        "url": previous,
        "label": "&laquo; Previous",
        "active": false
    })];
    for number in page_numbers {
        match number {
            Some(number) => links.push(serde_json::json!({
                "url": page_url(number),
                "label": number.to_string(),
                "active": number == page
            })),
            None => links.push(serde_json::json!({
                "url": null,
                "label": "...",
                "active": false
            })),
        }
    }
    links.push(serde_json::json!({
        "url": next,
        "label": "Next &raquo;",
        "active": false
    }));

    serde_json::json!({
        "current_page": page,
        "data": data,
        "first_page_url": page_url(1),
        "from": from,
        "last_page": last_page,
        "last_page_url": page_url(last_page),
        "links": links,
        "next_page_url": next,
        "path": path,
        "per_page": per_page,
        "prev_page_url": previous,
        "to": to,
        "total": total
    })
}

fn legacy_paginator_page_url(path: &str, raw_query: Option<&str>, page: i64) -> String {
    let mut query = form_urlencoded::Serializer::new(String::new());
    let mut has_page = false;
    if let Some(raw_query) = raw_query {
        for (name, value) in form_urlencoded::parse(raw_query.as_bytes()) {
            if name == "page" {
                if !has_page {
                    query.append_pair("page", &page.to_string());
                    has_page = true;
                }
            } else {
                query.append_pair(&name, &value);
            }
        }
    }
    if !has_page {
        query.append_pair("page", &page.to_string());
    }
    format!("{path}?{}", query.finish())
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

#[derive(Clone, Copy)]
enum AdminUserMutation {
    Email,
    Verification,
    Nickname,
    Password,
    Score,
    Permission,
    Delete,
}

macro_rules! define_admin_user_mutation_handlers {
    ($(($web:ident, $api:ident, $kind:ident)),+ $(,)?) => {
        $(
            async fn $web(
                State(state): State<AppState>,
                headers: HeaderMap,
                LegacyRouteId(uid): LegacyRouteId,
                Query(query): Query<BTreeMap<String, String>>,
                body: Bytes,
            ) -> Response {
                let body = legacy_input_body(
                    &query,
                    &body,
                    headers.get(CONTENT_TYPE).and_then(|value| value.to_str().ok()),
                );
                web_admin_user_mutation(state, headers, uid, body, AdminUserMutation::$kind).await
            }

            async fn $api(
                State(state): State<AppState>,
                headers: HeaderMap,
                LegacyRouteId(uid): LegacyRouteId,
                Query(query): Query<BTreeMap<String, String>>,
                body: Bytes,
            ) -> Response {
                let body = legacy_input_body(
                    &query,
                    &body,
                    headers.get(CONTENT_TYPE).and_then(|value| value.to_str().ok()),
                );
                api_admin_user_mutation(state, headers, uid, body, AdminUserMutation::$kind).await
            }
        )+
    };
}

define_admin_user_mutation_handlers!(
    (web_admin_user_email, api_admin_user_email, Email),
    (
        web_admin_user_verification,
        api_admin_user_verification,
        Verification
    ),
    (web_admin_user_nickname, api_admin_user_nickname, Nickname),
    (web_admin_user_password, api_admin_user_password, Password),
    (web_admin_user_score, api_admin_user_score, Score),
    (
        web_admin_user_permission,
        api_admin_user_permission,
        Permission
    ),
    (web_admin_user_delete, api_admin_user_delete, Delete),
);

async fn web_admin_user_mutation(
    state: AppState,
    headers: HeaderMap,
    target_uid: i64,
    body: Bytes,
    mutation: AdminUserMutation,
) -> Response {
    let Some(actor_uid) = session_user_id(&state, &headers) else {
        return Redirect::to("/auth/login").into_response();
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let actor = match database
        .user_profile(&state.config.database.table_prefix, actor_uid)
        .await
    {
        Ok(Some(user)) if user.permission >= 1 => user,
        Ok(Some(_)) => return forbidden_action(),
        Ok(None) => return Redirect::to("/auth/login").into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to load user administrator");
            return unavailable();
        }
    };
    apply_admin_user_mutation(
        &state,
        actor.uid,
        actor.permission,
        target_uid,
        &body,
        mutation,
    )
    .await
}

async fn api_admin_user_mutation(
    state: AppState,
    headers: HeaderMap,
    target_uid: i64,
    body: Bytes,
    mutation: AdminUserMutation,
) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_scope("UsersManagement.ReadWrite") {
        return missing_scope();
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    let actor = match database
        .user_profile(&state.config.database.table_prefix, identity.user_id)
        .await
    {
        Ok(Some(user)) if user.permission >= 1 => user,
        Ok(Some(_)) | Ok(None) => return forbidden_action(),
        Err(error) => {
            tracing::error!(%error, "failed to load API user administrator");
            return unavailable();
        }
    };
    apply_admin_user_mutation(
        &state,
        actor.uid,
        actor.permission,
        target_uid,
        &body,
        mutation,
    )
    .await
}

async fn apply_admin_user_mutation(
    state: &AppState,
    actor_uid: i64,
    actor_permission: i32,
    target_uid: i64,
    body: &[u8],
    mutation: AdminUserMutation,
) -> Response {
    let Some(database) = &state.database else {
        return unavailable();
    };
    let target = match database
        .user_profile(&state.config.database.table_prefix, target_uid)
        .await
    {
        Ok(Some(user)) => user,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, target_uid, "failed to load managed user");
            return unavailable();
        }
    };
    if target.uid != actor_uid && target.permission >= actor_permission {
        return admin_user_permission_error(&request_locale(&state));
    }

    match mutation {
        AdminUserMutation::Email => {
            let request = serde_json::from_slice::<serde_json::Value>(body).ok();
            let Some(email) = request
                .as_ref()
                .and_then(|value| value.get("email"))
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
            else {
                return admin_user_validation_error("email", "required", &request_locale(&state));
            };
            if !valid_email_address(email) {
                return admin_user_validation_error("email", "email", &request_locale(&state));
            }
            match database
                .user_email_exists(&state.config.database.table_prefix, email, target_uid)
                .await
            {
                Ok(true) => {
                    return admin_user_validation_error("email", "unique", &request_locale(&state));
                }
                Ok(false) => {}
                Err(error) => {
                    tracing::error!(%error, target_uid, "failed to check user email uniqueness");
                    return unavailable();
                }
            }
            emit_plugin_event(
                state,
                "user.email.updating",
                serde_json::json!({"user_id": target_uid}),
            )
            .await;
            if let Err(error) = database
                .update_user_text(
                    &state.config.database.table_prefix,
                    target_uid,
                    "email",
                    email,
                )
                .await
            {
                tracing::error!(%error, target_uid, "failed to update user email");
                return unavailable();
            }
            emit_plugin_event(
                state,
                "user.email.updated",
                serde_json::json!({"user_id": target_uid}),
            )
            .await;
            emit_plugin_event(
                state,
                "user.profile.updated",
                serde_json::json!({"user_id": target_uid, "action": "email"}),
            )
            .await;
            admin_user_success(AdminUserMutation::Email, &request_locale(&state), None)
        }
        AdminUserMutation::Verification => {
            emit_plugin_event(
                state,
                "user.verification.updating",
                serde_json::json!({"user_id": target_uid}),
            )
            .await;
            if let Err(error) = database
                .toggle_user_verification(&state.config.database.table_prefix, target_uid)
                .await
            {
                tracing::error!(%error, target_uid, "failed to toggle user verification");
                return unavailable();
            }
            emit_plugin_event(
                state,
                "user.verification.updated",
                serde_json::json!({
                    "user_id": target_uid,
                    "previous_verified": target.verified,
                    "verified": !target.verified,
                }),
            )
            .await;
            admin_user_success(
                AdminUserMutation::Verification,
                &request_locale(&state),
                None,
            )
        }
        AdminUserMutation::Nickname => {
            let request = serde_json::from_slice::<serde_json::Value>(body).ok();
            let Some(nickname) = request
                .as_ref()
                .and_then(|value| value.get("nickname"))
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
            else {
                return admin_user_validation_error(
                    "nickname",
                    "required",
                    &request_locale(&state),
                );
            };
            emit_plugin_event(
                state,
                "user.nickname.updating",
                serde_json::json!({"user_id": target_uid, "nickname": nickname}),
            )
            .await;
            if let Err(error) = database
                .update_user_text(
                    &state.config.database.table_prefix,
                    target_uid,
                    "nickname",
                    nickname,
                )
                .await
            {
                tracing::error!(%error, target_uid, "failed to update user nickname");
                return unavailable();
            }
            emit_plugin_event(
                state,
                "user.nickname.updated",
                serde_json::json!({
                    "user_id": target_uid,
                    "previous_nickname": target.nickname,
                    "nickname": nickname,
                }),
            )
            .await;
            emit_plugin_event(
                state,
                "user.profile.updated",
                serde_json::json!({"user_id": target_uid, "action": "nickname"}),
            )
            .await;
            admin_user_success(
                AdminUserMutation::Nickname,
                &request_locale(&state),
                Some(nickname),
            )
        }
        AdminUserMutation::Password => {
            let request = serde_json::from_slice::<serde_json::Value>(body).ok();
            let Some(password) = request
                .as_ref()
                .and_then(|value| value.get("password"))
                .and_then(serde_json::Value::as_str)
            else {
                return admin_user_validation_error(
                    "password",
                    "required",
                    &request_locale(&state),
                );
            };
            if !(8..=16).contains(&password.chars().count()) {
                return admin_user_validation_error("password", "length", &request_locale(&state));
            }
            let Some(hash) = hash_legacy_password(
                password,
                &state.config.password_method,
                &state.config.password_salt,
                state.config.bcrypt_rounds,
            ) else {
                tracing::error!(method = %state.config.password_method, "unsupported configured legacy password method");
                return unavailable();
            };
            let hash = filter_user_password_hash(state, &hash).await;
            emit_plugin_event(
                state,
                "user.password.updating",
                serde_json::json!({"user_id": target_uid}),
            )
            .await;
            if let Err(error) = database
                .update_user_text(
                    &state.config.database.table_prefix,
                    target_uid,
                    "password",
                    &hash,
                )
                .await
            {
                tracing::error!(%error, target_uid, "failed to update user password");
                return unavailable();
            }
            emit_plugin_event(
                state,
                "user.password.updated",
                serde_json::json!({"user_id": target_uid}),
            )
            .await;
            emit_plugin_event(
                state,
                "user.profile.updated",
                serde_json::json!({"user_id": target_uid, "action": "password"}),
            )
            .await;
            admin_user_success(AdminUserMutation::Password, &request_locale(&state), None)
        }
        AdminUserMutation::Score => {
            let request = serde_json::from_slice::<serde_json::Value>(body).ok();
            let Some(score) = request
                .as_ref()
                .and_then(|value| value.get("score"))
                .and_then(|value| request_i64(Some(value)))
            else {
                return admin_user_validation_error("score", "integer", &request_locale(&state));
            };
            emit_plugin_event(
                state,
                "user.score.updating",
                serde_json::json!({"user_id": target_uid, "previous_score": target.score, "score": score}),
            )
            .await;
            if let Err(error) = database
                .update_user_integer(
                    &state.config.database.table_prefix,
                    target_uid,
                    "score",
                    score,
                )
                .await
            {
                tracing::error!(%error, target_uid, "failed to update user score");
                return unavailable();
            }
            emit_plugin_event(
                state,
                "user.score.updated",
                user_score_updated_event(target_uid, target.score, score),
            )
            .await;
            admin_user_success(AdminUserMutation::Score, &request_locale(&state), None)
        }
        AdminUserMutation::Permission => {
            let request = serde_json::from_slice::<serde_json::Value>(body).ok();
            let Some(permission) = request
                .as_ref()
                .and_then(|value| value.get("permission"))
                .and_then(|value| request_i64(Some(value)))
                .filter(|value| matches!(*value, -1 | 0 | 1))
            else {
                return admin_user_validation_error("permission", "in", &request_locale(&state));
            };
            if target_uid == actor_uid || (permission == 1 && actor_permission < 2) {
                return admin_user_permission_error(&request_locale(&state));
            }
            emit_plugin_event(
                state,
                "user.permission.updating",
                serde_json::json!({
                    "user_id": target_uid,
                    "previous_permission": target.permission,
                    "permission": permission,
                }),
            )
            .await;
            if let Err(error) = database
                .update_user_integer(
                    &state.config.database.table_prefix,
                    target_uid,
                    "permission",
                    permission,
                )
                .await
            {
                tracing::error!(%error, target_uid, "failed to update user permission");
                return unavailable();
            }
            if permission == -1 {
                emit_plugin_event(
                    state,
                    "user.banned",
                    serde_json::json!({"user_id": target_uid}),
                )
                .await;
            }
            emit_plugin_event(
                state,
                "user.permission.updated",
                serde_json::json!({
                    "user_id": target_uid,
                    "previous_permission": target.permission,
                    "permission": permission,
                }),
            )
            .await;
            admin_user_success(AdminUserMutation::Permission, &request_locale(&state), None)
        }
        AdminUserMutation::Delete => {
            emit_plugin_event(
                state,
                "user.deleting",
                serde_json::json!({"user_id": target_uid}),
            )
            .await;
            match database
                .delete_user(&state.config.database.table_prefix, target_uid)
                .await
            {
                Ok(true) => {
                    emit_plugin_event(
                        state,
                        "user.deleted",
                        serde_json::json!({"user_id": target_uid}),
                    )
                    .await;
                    admin_user_success(AdminUserMutation::Delete, &request_locale(&state), None)
                }
                Ok(false) => StatusCode::NOT_FOUND.into_response(),
                Err(error) => {
                    tracing::error!(%error, target_uid, "failed to delete user");
                    unavailable()
                }
            }
        }
    }
}

fn admin_user_success(mutation: AdminUserMutation, locale: &str, value: Option<&str>) -> Response {
    let chinese = locale.starts_with("zh");
    let message = match (mutation, chinese) {
        (AdminUserMutation::Email, true) => "邮箱修改成功".to_owned(),
        (AdminUserMutation::Email, false) => "Email changed successfully.".to_owned(),
        (AdminUserMutation::Verification, true) => "用户的邮箱验证状态已修改".to_owned(),
        (AdminUserMutation::Verification, false) => {
            "Account verification status toggled successfully.".to_owned()
        }
        (AdminUserMutation::Nickname, true) => {
            format!("昵称已成功设置为 {}", value.unwrap_or_default())
        }
        (AdminUserMutation::Nickname, false) => "Nickname changed successfully.".to_owned(),
        (AdminUserMutation::Password, true) => "密码修改成功".to_owned(),
        (AdminUserMutation::Password, false) => "Password changed successfully.".to_owned(),
        (AdminUserMutation::Score, true) => "积分修改成功".to_owned(),
        (AdminUserMutation::Score, false) => "Score changed successfully.".to_owned(),
        (AdminUserMutation::Permission, true) => "权限已更改".to_owned(),
        (AdminUserMutation::Permission, false) => "Permission updated.".to_owned(),
        (AdminUserMutation::Delete, true) => "账号已被成功删除".to_owned(),
        (AdminUserMutation::Delete, false) => {
            "The account has been deleted successfully.".to_owned()
        }
    };
    login_result(0, &message, None)
}

fn admin_user_permission_error(locale: &str) -> Response {
    let message = if locale.starts_with("zh") {
        "你无权操作此用户"
    } else {
        "You have no permission to operate this user."
    };
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({ "code": 1, "message": message })),
    )
        .into_response()
}

fn admin_user_validation_error(field: &str, rule: &str, locale: &str) -> Response {
    let chinese = locale.starts_with("zh");
    let message = if chinese {
        "给定数据无效。"
    } else {
        "The given data was invalid."
    };
    let field_error = match (field, rule, chinese) {
        ("email", "required", true) => "邮箱为必填项。",
        ("email", "required", false) => "The email field is required.",
        ("email", "email", true) => "邮箱格式无效。",
        ("email", "email", false) => "The email must be a valid email address.",
        ("email", "unique", true) => "该邮箱已被使用。",
        ("email", "unique", false) => "The email has already been taken.",
        ("nickname", "required", true) => "昵称为必填项。",
        ("nickname", "required", false) => "The nickname field is required.",
        ("password", "required", true) => "密码为必填项。",
        ("password", "required", false) => "The password field is required.",
        ("password", "length", true) => "密码长度必须为 8 至 16 个字符。",
        ("password", "length", false) => "The password must be between 8 and 16 characters.",
        ("score", "integer", true) => "积分必须是整数。",
        ("score", "integer", false) => "The score must be an integer.",
        ("permission", "in", true) => "权限值无效。",
        ("permission", "in", false) => "The selected permission is invalid.",
        _ => "The given field is invalid.",
    };
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(serde_json::json!({ "message": message, "errors": { field: [field_error] } })),
    )
        .into_response()
}

#[derive(Deserialize)]
struct AdminPlayerListQuery {
    q: Option<String>,
    page: Option<i64>,
}

#[derive(Deserialize)]
struct AdminUserListQuery {
    q: Option<String>,
    page: Option<i64>,
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

async fn web_admin_players_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if user.permission < 1 {
        return StatusCode::FORBIDDEN.into_response();
    }
    let site_name = site_name(&state).await;
    let app_dir = state.public_dir.join("app");
    let stylesheet = frontend_entrypoint(&app_dir, "style", "css", &request_app_url(&state)).await;
    let frontend_script =
        frontend_entrypoint(&app_dir, "app", "js", &request_app_url(&state)).await;
    let i18n = load_frontend_translations(&state, &app_dir, &request_locale(&state)).await;
    let frontend_globals_b64 = encode_frontend_globals(
        &state,
        &site_name,
        "admin/players",
        serde_json::json!({}),
        i18n,
    );
    let page = AdminPlayersPage {
        site_name,
        locale: request_locale(&state),
        current_uid: user.uid,
        current_permission: user.permission,
        frontend_style_available: stylesheet.is_some(),
        frontend_stylesheet: stylesheet.unwrap_or_default(),
        frontend_script_available: frontend_script.is_some(),
        frontend_script: frontend_script.unwrap_or_default(),
        frontend_globals_b64,
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to render administrator players page");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn admin_player_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    Query(query): Query<AdminPlayerListQuery>,
) -> Response {
    let Some(user_id) = session_user_id(&state, &headers) else {
        return Redirect::to("/auth/login").into_response();
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let path = format!(
        "{}{}",
        request_app_url(&state).trim_end_matches('/'),
        uri.path()
    );
    match database
        .user_profile(&state.config.database.table_prefix, user_id)
        .await
    {
        Ok(Some(user)) if user.permission >= 1 => {
            admin_players_response(&state, query, &path, uri.query()).await
        }
        Ok(Some(_)) => forbidden_action(),
        Ok(None) => Redirect::to("/auth/login").into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to load player administrator");
            unavailable()
        }
    }
}

async fn api_admin_player_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    Query(query): Query<AdminPlayerListQuery>,
) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_any_scope(&["PlayersManagement.Read", "PlayersManagement.ReadWrite"]) {
        return missing_scope();
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    let path = format!(
        "{}{}",
        request_app_url(&state).trim_end_matches('/'),
        uri.path()
    );
    match database
        .user_profile(&state.config.database.table_prefix, identity.user_id)
        .await
    {
        Ok(Some(user)) if user.permission >= 1 => {
            admin_players_response(&state, query, &path, uri.query()).await
        }
        Ok(Some(_)) | Ok(None) => forbidden_action(),
        Err(error) => {
            tracing::error!(%error, "failed to load API player administrator");
            unavailable()
        }
    }
}
async fn admin_players_response(
    state: &AppState,
    query: AdminPlayerListQuery,
    path: &str,
    raw_query: Option<&str>,
) -> Response {
    let Some(database) = &state.database else {
        return unavailable();
    };
    let page = query.page.unwrap_or(1).max(1);
    let per_page = 10_i64;
    let offset = page.saturating_sub(1).saturating_mul(per_page);
    let (players, total) = match database
        .admin_players(
            &state.config.database.table_prefix,
            query.q.as_deref(),
            per_page,
            offset,
        )
        .await
    {
        Ok(result) => result,
        Err(error) => {
            tracing::error!(%error, "failed to list managed players");
            return unavailable();
        }
    };
    Json(legacy_paginator_json(
        players, total, page, per_page, path, raw_query,
    ))
    .into_response()
}
#[derive(Clone, Copy)]
enum AdminPlayerMutation {
    Name,
    Owner,
    Texture,
    Delete,
}

macro_rules! define_admin_player_mutation_handlers {
    ($(($web:ident, $api:ident, $kind:ident)),+ $(,)?) => {
        $(
            async fn $web(
                State(state): State<AppState>,
                headers: HeaderMap,
                LegacyRouteId(pid): LegacyRouteId,
                Query(query): Query<BTreeMap<String, String>>,
                body: Bytes,
            ) -> Response {
                let body = legacy_input_body(
                    &query,
                    &body,
                    headers.get(CONTENT_TYPE).and_then(|value| value.to_str().ok()),
                );
                web_admin_player_mutation(state, headers, pid, body, AdminPlayerMutation::$kind).await
            }

            async fn $api(
                State(state): State<AppState>,
                headers: HeaderMap,
                LegacyRouteId(pid): LegacyRouteId,
                Query(query): Query<BTreeMap<String, String>>,
                body: Bytes,
            ) -> Response {
                let body = legacy_input_body(
                    &query,
                    &body,
                    headers.get(CONTENT_TYPE).and_then(|value| value.to_str().ok()),
                );
                api_admin_player_mutation(state, headers, pid, body, AdminPlayerMutation::$kind).await
            }
        )+
    };
}

define_admin_player_mutation_handlers!(
    (web_admin_player_name, api_admin_player_name, Name),
    (web_admin_player_owner, api_admin_player_owner, Owner),
    (web_admin_player_texture, api_admin_player_texture, Texture),
    (web_admin_player_delete, api_admin_player_delete, Delete),
);

async fn web_admin_player_mutation(
    state: AppState,
    headers: HeaderMap,
    pid: i64,
    body: Bytes,
    mutation: AdminPlayerMutation,
) -> Response {
    let Some(actor_uid) = session_user_id(&state, &headers) else {
        return Redirect::to("/auth/login").into_response();
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let actor = match database
        .user_profile(&state.config.database.table_prefix, actor_uid)
        .await
    {
        Ok(Some(user)) if user.permission >= 1 => user,
        Ok(Some(_)) => return forbidden_action(),
        Ok(None) => return Redirect::to("/auth/login").into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to load player administrator");
            return unavailable();
        }
    };
    apply_admin_player_mutation(&state, actor.uid, actor.permission, pid, &body, mutation).await
}

async fn api_admin_player_mutation(
    state: AppState,
    headers: HeaderMap,
    pid: i64,
    body: Bytes,
    mutation: AdminPlayerMutation,
) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_scope("PlayersManagement.ReadWrite") {
        return missing_scope();
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    let actor = match database
        .user_profile(&state.config.database.table_prefix, identity.user_id)
        .await
    {
        Ok(Some(user)) if user.permission >= 1 => user,
        Ok(Some(_)) | Ok(None) => return forbidden_action(),
        Err(error) => {
            tracing::error!(%error, "failed to load API player administrator");
            return unavailable();
        }
    };
    apply_admin_player_mutation(&state, actor.uid, actor.permission, pid, &body, mutation).await
}

async fn apply_admin_player_mutation(
    state: &AppState,
    actor_uid: i64,
    actor_permission: i32,
    pid: i64,
    body: &[u8],
    mutation: AdminPlayerMutation,
) -> Response {
    let Some(database) = &state.database else {
        return unavailable();
    };
    let prefix = &state.config.database.table_prefix;
    let player = match database.admin_player_for_update(prefix, pid).await {
        Ok(Some(player)) => player,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, pid, "failed to load managed player");
            return unavailable();
        }
    };
    if player.uid != actor_uid && player.owner_permission >= actor_permission {
        return admin_player_permission_error(&request_locale(&state));
    }
    match mutation {
        AdminPlayerMutation::Name => {
            let request = serde_json::from_slice::<serde_json::Value>(body).ok();
            let Some(name) = request
                .as_ref()
                .and_then(|value| value.get("player_name"))
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
            else {
                return admin_player_validation_error("player_name", &request_locale(&state));
            };
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
            if !valid_player_name(name, &rule, &custom_rule, min_length, max_length) {
                return admin_player_validation_error("player_name", &request_locale(&state));
            }
            match database.admin_player_name_exists(prefix, name).await {
                Ok(true) => {
                    return admin_player_validation_error("player_name", &request_locale(&state));
                }
                Ok(false) => {}
                Err(error) => {
                    tracing::error!(%error, pid, "failed to check player-name uniqueness");
                    return unavailable();
                }
            }
            emit_plugin_event(
                state,
                "player.renaming",
                serde_json::json!({
                    "user_id": player.uid,
                    "player_id": pid,
                    "previous_name": player.name,
                    "name": name,
                }),
            )
            .await;
            if let Err(error) = database
                .update_admin_player_text(prefix, pid, "name", name)
                .await
            {
                tracing::error!(%error, pid, "failed to rename managed player");
                return unavailable();
            }
            emit_plugin_event(
                state,
                "player.renamed",
                serde_json::json!({
                    "user_id": player.uid,
                    "player_id": pid,
                    "previous_name": player.name,
                    "name": name,
                }),
            )
            .await;
            admin_player_success(
                AdminPlayerMutation::Name,
                &request_locale(&state),
                name,
                None,
            )
        }
        AdminPlayerMutation::Owner => {
            let request = serde_json::from_slice::<serde_json::Value>(body).ok();
            let Some(uid) = request
                .as_ref()
                .and_then(|value| value.get("uid"))
                .and_then(|value| request_i64(Some(value)))
            else {
                return admin_player_validation_error("uid", &request_locale(&state));
            };
            emit_plugin_event(
                state,
                "player.owner.updating",
                serde_json::json!({
                    "player_id": pid,
                    "previous_user_id": player.uid,
                    "user_id": uid,
                }),
            )
            .await;
            let owner = match database.user_profile(prefix, uid).await {
                Ok(Some(owner)) => owner,
                Ok(None) => {
                    return login_result(
                        1,
                        admin_user_missing_message(&request_locale(&state)),
                        None,
                    );
                }
                Err(error) => {
                    tracing::error!(%error, uid, "failed to load new player owner");
                    return unavailable();
                }
            };
            if let Err(error) = database
                .update_admin_player_integer(prefix, pid, "uid", uid)
                .await
            {
                tracing::error!(%error, pid, "failed to transfer player ownership");
                return unavailable();
            }
            emit_plugin_event(
                state,
                "player.owner.updated",
                serde_json::json!({
                    "player_id": pid,
                    "previous_user_id": player.uid,
                    "user_id": uid,
                }),
            )
            .await;
            admin_player_success(
                AdminPlayerMutation::Owner,
                &request_locale(&state),
                &player.name,
                Some(&owner.nickname),
            )
        }
        AdminPlayerMutation::Texture => {
            let request = serde_json::from_slice::<serde_json::Value>(body).ok();
            let Some(tid) = request
                .as_ref()
                .and_then(|value| value.get("tid"))
                .and_then(|value| request_i64(Some(value)))
            else {
                return admin_player_validation_error("tid", &request_locale(&state));
            };
            let Some(texture_type) = request
                .as_ref()
                .and_then(|value| value.get("type"))
                .and_then(serde_json::Value::as_str)
                .filter(|value| matches!(*value, "skin" | "cape"))
            else {
                return admin_player_validation_error("type", &request_locale(&state));
            };
            let previous_tid = if texture_type == "skin" {
                player.tid_skin
            } else {
                player.tid_cape
            };
            emit_plugin_event(
                state,
                "player.texture.updating",
                serde_json::json!({
                    "user_id": player.uid,
                    "player_id": pid,
                    "name": player.name,
                    "type": texture_type,
                    "texture_id": tid,
                }),
            )
            .await;
            if tid != 0 {
                match database.texture_info(prefix, tid).await {
                    Ok(Some(_)) => {}
                    Ok(None) => {
                        let message = admin_texture_missing_message(tid, &request_locale(&state));
                        return login_result(1, &message, None);
                    }
                    Err(error) => {
                        tracing::error!(%error, tid, "failed to check managed texture");
                        return unavailable();
                    }
                }
            }
            let column = if texture_type == "skin" {
                "tid_skin"
            } else {
                "tid_cape"
            };
            if let Err(error) = database
                .update_admin_player_integer(prefix, pid, column, tid)
                .await
            {
                tracing::error!(%error, pid, "failed to update managed player texture");
                return unavailable();
            }
            emit_plugin_event(
                state,
                "player.texture.updated",
                serde_json::json!({
                    "user_id": player.uid,
                    "player_id": pid,
                    "name": player.name,
                    "type": texture_type,
                    "previous_texture_id": previous_tid,
                    "texture_id": tid,
                }),
            )
            .await;
            emit_plugin_event(
                state,
                "player.textures.updated",
                serde_json::json!({
                    "user_id": player.uid,
                    "player_id": pid,
                    "skin_texture_id": if texture_type == "skin" { tid } else { player.tid_skin },
                    "cape_texture_id": if texture_type == "cape" { tid } else { player.tid_cape },
                }),
            )
            .await;
            admin_player_success(
                AdminPlayerMutation::Texture,
                &request_locale(&state),
                &player.name,
                None,
            )
        }
        AdminPlayerMutation::Delete => {
            let event = serde_json::json!({
                "user_id": player.uid,
                "player_id": pid,
                "name": player.name,
            });
            emit_plugin_event(state, "player.deleting", event.clone()).await;
            match database.delete_admin_player(prefix, pid).await {
                Ok(true) => {
                    emit_plugin_event(state, "player.deleted", event).await;
                    admin_player_success(
                        AdminPlayerMutation::Delete,
                        &request_locale(&state),
                        &player.name,
                        None,
                    )
                }
                Ok(false) => StatusCode::NOT_FOUND.into_response(),
                Err(error) => {
                    tracing::error!(%error, pid, "failed to delete managed player");
                    unavailable()
                }
            }
        }
    }
}

fn admin_user_missing_message(locale: &str) -> &'static str {
    if locale.starts_with("zh") {
        "用户不存在"
    } else {
        "No such user."
    }
}

fn admin_texture_missing_message(tid: i64, locale: &str) -> String {
    if locale.starts_with("zh") {
        format!("材质 tid.{tid} 不存在")
    } else {
        format!("No such texture tid.{tid}")
    }
}

fn admin_player_permission_error(locale: &str) -> Response {
    let message = if locale.starts_with("zh") {
        "你无权操作此角色"
    } else {
        "You have no permission to operate this player."
    };
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({"code": 1, "message": message})),
    )
        .into_response()
}

fn admin_player_validation_error(field: &str, locale: &str) -> Response {
    let chinese = locale.starts_with("zh");
    let message = if chinese {
        "给定数据无效。"
    } else {
        "The given data was invalid."
    };
    let field_error = match (field, chinese) {
        ("player_name", true) => "角色名格式或长度无效。",
        ("player_name", false) => "The player name format or length is invalid.",
        ("uid", true) => "UID 必须是整数。",
        ("uid", false) => "The uid field must be an integer.",
        ("tid", true) => "材质 tid 必须是整数。",
        ("tid", false) => "The tid field must be an integer.",
        ("type", true) => "材质类型必须是 skin 或 cape。",
        ("type", false) => "The type field must be skin or cape.",
        _ => "The given field is invalid.",
    };
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(serde_json::json!({"message": message, "errors": {field: [field_error]}})),
    )
        .into_response()
}

fn admin_player_success(
    mutation: AdminPlayerMutation,
    locale: &str,
    player: &str,
    owner: Option<&str>,
) -> Response {
    let message = match (mutation, locale.starts_with("zh")) {
        (AdminPlayerMutation::Name, true) => format!("角色名成功更改为 {player}"),
        (AdminPlayerMutation::Name, false) => format!("Player name has been updated to {player}"),
        (AdminPlayerMutation::Owner, true) => format!(
            "角色 {player} 已被转给用户 {} 。",
            owner.unwrap_or_default()
        ),
        (AdminPlayerMutation::Owner, false) => format!(
            "The player {player} was transferred to user {}.",
            owner.unwrap_or_default()
        ),
        (AdminPlayerMutation::Texture, true) => format!("角色 {player} 的材质修改成功"),
        (AdminPlayerMutation::Texture, false) => {
            format!("The textures of {player} has been updated.")
        }
        (AdminPlayerMutation::Delete, true) => "角色已删除".to_owned(),
        (AdminPlayerMutation::Delete, false) => {
            "The player has been deleted successfully.".to_owned()
        }
    };
    login_result(0, &message, None)
}

async fn web_admin_users_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if user.permission < 1 {
        return StatusCode::FORBIDDEN.into_response();
    }
    let site_name = site_name(&state).await;
    let app_dir = state.public_dir.join("app");
    let stylesheet = frontend_entrypoint(&app_dir, "style", "css", &request_app_url(&state)).await;
    let frontend_script =
        frontend_entrypoint(&app_dir, "app", "js", &request_app_url(&state)).await;
    let i18n = load_frontend_translations(&state, &app_dir, &request_locale(&state)).await;
    let frontend_globals_b64 = encode_frontend_globals(
        &state,
        &site_name,
        "admin/users",
        serde_json::json!({
            "currentUser": {
                "uid": user.uid,
                "permission": user.permission,
            }
        }),
        i18n,
    );
    let page = AdminUsersPage {
        site_name,
        locale: request_locale(&state),
        current_uid: user.uid,
        current_permission: user.permission,
        frontend_style_available: stylesheet.is_some(),
        frontend_stylesheet: stylesheet.unwrap_or_default(),
        frontend_script_available: frontend_script.is_some(),
        frontend_script: frontend_script.unwrap_or_default(),
        frontend_globals_b64,
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to render administrator users page");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn admin_user_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    Query(query): Query<AdminUserListQuery>,
) -> Response {
    let Some(user_id) = session_user_id(&state, &headers) else {
        return Redirect::to("/auth/login").into_response();
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let path = format!(
        "{}{}",
        request_app_url(&state).trim_end_matches('/'),
        uri.path()
    );
    match database
        .user_profile(&state.config.database.table_prefix, user_id)
        .await
    {
        Ok(Some(user)) if user.permission >= 1 => {
            admin_users_response(&state, query, &path, uri.query()).await
        }
        Ok(Some(_)) => forbidden_action(),
        Ok(None) => Redirect::to("/auth/login").into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to load user administrator");
            unavailable()
        }
    }
}

async fn api_admin_user_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    Query(query): Query<AdminUserListQuery>,
) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_any_scope(&["UsersManagement.Read", "UsersManagement.ReadWrite"]) {
        return missing_scope();
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    let path = format!(
        "{}{}",
        request_app_url(&state).trim_end_matches('/'),
        uri.path()
    );
    match database
        .user_profile(&state.config.database.table_prefix, identity.user_id)
        .await
    {
        Ok(Some(user)) if user.permission >= 1 => {
            admin_users_response(&state, query, &path, uri.query()).await
        }
        Ok(Some(_)) | Ok(None) => forbidden_action(),
        Err(error) => {
            tracing::error!(%error, "failed to load API user administrator");
            unavailable()
        }
    }
}
async fn admin_users_response(
    state: &AppState,
    query: AdminUserListQuery,
    path: &str,
    raw_query: Option<&str>,
) -> Response {
    let Some(database) = &state.database else {
        return unavailable();
    };
    let page = query.page.unwrap_or(1).max(1);
    let per_page = 10_i64;
    let offset = page.saturating_sub(1).saturating_mul(per_page);
    let (users, total): (Vec<AdminUserRecord>, i64) = match database
        .admin_users(
            &state.config.database.table_prefix,
            query.q.as_deref(),
            per_page,
            offset,
        )
        .await
    {
        Ok(result) => result,
        Err(error) => {
            tracing::error!(%error, "failed to list users");
            return unavailable();
        }
    };
    Json(legacy_paginator_json(
        users, total, page, per_page, path, raw_query,
    ))
    .into_response()
}
fn forbidden_action() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({ "message": "This action is unauthorized." })),
    )
        .into_response()
}

async fn web_admin_closet_add(
    State(state): State<AppState>,
    headers: HeaderMap,
    LegacyRouteId(uid): LegacyRouteId,
    Query(query): Query<BTreeMap<String, String>>,
    body: Bytes,
) -> Response {
    let Some(actor_uid) = session_user_id(&state, &headers) else {
        return Redirect::to("/auth/login").into_response();
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    match database
        .user_profile(&state.config.database.table_prefix, actor_uid)
        .await
    {
        Ok(Some(user)) if user.permission >= 1 => {
            admin_closet_mutation(&state, uid, &query, &headers, body, false).await
        }
        Ok(Some(_)) => forbidden_action(),
        Ok(None) => Redirect::to("/auth/login").into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to load closet administrator");
            unavailable()
        }
    }
}

async fn web_admin_closet_remove(
    State(state): State<AppState>,
    headers: HeaderMap,
    LegacyRouteId(uid): LegacyRouteId,
    Query(query): Query<BTreeMap<String, String>>,
    body: Bytes,
) -> Response {
    let Some(actor_uid) = session_user_id(&state, &headers) else {
        return Redirect::to("/auth/login").into_response();
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    match database
        .user_profile(&state.config.database.table_prefix, actor_uid)
        .await
    {
        Ok(Some(user)) if user.permission >= 1 => {
            admin_closet_mutation(&state, uid, &query, &headers, body, true).await
        }
        Ok(Some(_)) => forbidden_action(),
        Ok(None) => Redirect::to("/auth/login").into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to load closet administrator");
            unavailable()
        }
    }
}

async fn api_admin_closet_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    LegacyRouteId(uid): LegacyRouteId,
) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_any_scope(&["ClosetManagement.Read", "ClosetManagement.ReadWrite"]) {
        return missing_scope();
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    match database
        .user_profile(&state.config.database.table_prefix, identity.user_id)
        .await
    {
        Ok(Some(user)) if user.permission >= 1 => {}
        Ok(Some(_)) | Ok(None) => return forbidden_action(),
        Err(error) => {
            tracing::error!(%error, "failed to load API closet administrator");
            return unavailable();
        }
    }
    match database
        .admin_closet_user(&state.config.database.table_prefix, uid)
        .await
    {
        Ok(Some(_)) => {}
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, uid, "failed to load managed closet owner");
            return unavailable();
        }
    }
    match database
        .admin_closet_items(&state.config.database.table_prefix, uid)
        .await
    {
        Ok(items) => Json(serde_json::Value::Array(
            items.into_iter().map(admin_closet_texture_json).collect(),
        ))
        .into_response(),
        Err(error) => {
            tracing::error!(%error, uid, "failed to list managed closet");
            unavailable()
        }
    }
}

async fn api_admin_closet_add(
    State(state): State<AppState>,
    headers: HeaderMap,
    LegacyRouteId(uid): LegacyRouteId,
    Query(query): Query<BTreeMap<String, String>>,
    body: Bytes,
) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_scope("ClosetManagement.ReadWrite") {
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
            admin_closet_mutation(&state, uid, &query, &headers, body, false).await
        }
        Ok(Some(_)) | Ok(None) => forbidden_action(),
        Err(error) => {
            tracing::error!(%error, "failed to load API closet administrator");
            unavailable()
        }
    }
}

async fn api_admin_closet_remove(
    State(state): State<AppState>,
    headers: HeaderMap,
    LegacyRouteId(uid): LegacyRouteId,
    Query(query): Query<BTreeMap<String, String>>,
    body: Bytes,
) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_scope("ClosetManagement.ReadWrite") {
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
            admin_closet_mutation(&state, uid, &query, &headers, body, true).await
        }
        Ok(Some(_)) | Ok(None) => forbidden_action(),
        Err(error) => {
            tracing::error!(%error, "failed to load API closet administrator");
            unavailable()
        }
    }
}

async fn admin_closet_mutation(
    state: &AppState,
    uid: i64,
    query: &BTreeMap<String, String>,
    headers: &HeaderMap,
    body: Bytes,
    remove: bool,
) -> Response {
    let Some(database) = &state.database else {
        return unavailable();
    };
    let user = match database
        .admin_closet_user(&state.config.database.table_prefix, uid)
        .await
    {
        Ok(Some(user)) => user,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, uid, "failed to load managed closet owner");
            return unavailable();
        }
    };
    let request = parse_legacy_input_object(
        query,
        &body,
        headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
    )
    .ok()
    .map(serde_json::Value::Object);
    let tid = request
        .as_ref()
        .and_then(|value| value.get("tid"))
        .and_then(|value| request_i64(Some(value)));
    let chinese = request_locale(&state).starts_with("zh");
    let Some(tid) = tid else {
        let message = if remove {
            if chinese {
                "衣柜中不存在此材质"
            } else {
                "The texture does not exist in your closet."
            }
        } else if chinese {
            "该材质不存在"
        } else {
            "We cannot find this texture."
        };
        return login_result(1, message, None);
    };
    if remove {
        emit_plugin_event(
            state,
            "closet.removing",
            serde_json::json!({"user_id": uid, "texture_id": tid}),
        )
        .await;
    } else {
        let texture = match database
            .texture_info(&state.config.database.table_prefix, tid)
            .await
        {
            Ok(Some(texture)) => texture,
            Ok(None) => {
                let message = if chinese {
                    "该材质不存在"
                } else {
                    "We cannot find this texture."
                };
                return login_result(1, message, None);
            }
            Err(error) => {
                tracing::error!(%error, tid, "failed to load texture for managed closet add");
                return unavailable();
            }
        };
        let items = match database
            .admin_closet_items(&state.config.database.table_prefix, uid)
            .await
        {
            Ok(items) => items,
            Err(error) => {
                tracing::error!(%error, uid, "failed to check managed closet membership");
                return unavailable();
            }
        };
        if items.iter().any(|item| item.tid == tid) {
            let message = if chinese {
                "你已经收藏过这个材质啦"
            } else {
                "You have already added this texture."
            };
            return login_result(1, message, None);
        }
        emit_plugin_event(
            state,
            "closet.adding",
            serde_json::json!({"user_id": uid, "texture_id": tid, "item_name": texture.name}),
        )
        .await;
    }
    if remove {
        match database
            .remove_admin_closet_item(&state.config.database.table_prefix, uid, tid)
            .await
        {
            Ok(crate::database::AdminClosetRemoveOutcome::NonExistent) => {
                let message = if chinese {
                    "衣柜中不存在此材质"
                } else {
                    "The texture does not exist in your closet."
                };
                login_result(1, message, None)
            }
            Ok(crate::database::AdminClosetRemoveOutcome::Removed) => {
                emit_plugin_event(
                    state,
                    "closet.removed",
                    serde_json::json!({"user_id": uid, "texture_id": tid}),
                )
                .await;
                let texture = match database
                    .texture_info(&state.config.database.table_prefix, tid)
                    .await
                {
                    Ok(texture) => texture.map(texture_info_json),
                    Err(error) => {
                        tracing::error!(%error, tid, "failed to load removed closet texture");
                        return unavailable();
                    }
                };
                login_result(
                    0,
                    "",
                    Some(serde_json::json!({"user": user, "texture": texture})),
                )
            }
            Err(error) => {
                tracing::error!(%error, uid, tid, "failed to remove admin closet item");
                unavailable()
            }
        }
    } else {
        match database
            .add_admin_closet_item(&state.config.database.table_prefix, uid, tid)
            .await
        {
            Ok(crate::database::AdminClosetAddOutcome::TextureNotFound) => {
                let message = if chinese {
                    "该材质不存在"
                } else {
                    "We cannot find this texture."
                };
                login_result(1, message, None)
            }
            Ok(crate::database::AdminClosetAddOutcome::Repeated) => {
                let message = if chinese {
                    "你已经收藏过这个材质啦"
                } else {
                    "You have already added this texture."
                };
                login_result(1, message, None)
            }
            Ok(crate::database::AdminClosetAddOutcome::Added) => {
                let texture = match database
                    .texture_info(&state.config.database.table_prefix, tid)
                    .await
                {
                    Ok(Some(texture)) => texture,
                    Ok(None) => return unavailable(),
                    Err(error) => {
                        tracing::error!(%error, tid, "failed to load added closet texture");
                        return unavailable();
                    }
                };
                emit_plugin_event(
                    state,
                    "closet.added",
                    serde_json::json!({
                        "user_id": uid,
                        "texture_id": tid,
                        "item_name": texture.name.clone(),
                    }),
                )
                .await;
                let texture_json = texture_info_json(texture);
                login_result(
                    0,
                    "",
                    Some(serde_json::json!({"user": user, "texture": texture_json})),
                )
            }
            Err(error) => {
                tracing::error!(%error, uid, tid, "failed to add admin closet item");
                unavailable()
            }
        }
    }
}

fn admin_closet_texture_json(item: ClosetTextureRecord) -> serde_json::Value {
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
            "item_name": item.item_name,
        }
    })
}

async fn web_admin_reports_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if user.permission < 1 {
        return StatusCode::FORBIDDEN.into_response();
    }
    let site_name = site_name(&state).await;
    let app_dir = state.public_dir.join("app");
    let stylesheet = frontend_entrypoint(&app_dir, "style", "css", &request_app_url(&state)).await;
    let frontend_script =
        frontend_entrypoint(&app_dir, "app", "js", &request_app_url(&state)).await;
    let i18n = load_frontend_translations(&state, &app_dir, &request_locale(&state)).await;
    let frontend_globals_b64 = encode_frontend_globals(
        &state,
        &site_name,
        "admin/reports",
        serde_json::json!({}),
        i18n,
    );
    let page = AdminReportsPage {
        site_name,
        locale: request_locale(&state),
        frontend_style_available: stylesheet.is_some(),
        frontend_stylesheet: stylesheet.unwrap_or_default(),
        frontend_script_available: frontend_script.is_some(),
        frontend_script: frontend_script.unwrap_or_default(),
        frontend_globals_b64,
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to render administrator reports page");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn admin_report_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    Query(query): Query<AdminReportListQuery>,
) -> Response {
    let Some(user_id) = session_user_id(&state, &headers) else {
        return Redirect::to("/auth/login").into_response();
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let path = format!(
        "{}{}",
        request_app_url(&state).trim_end_matches('/'),
        uri.path()
    );
    match database
        .user_profile(&state.config.database.table_prefix, user_id)
        .await
    {
        Ok(Some(user)) if user.permission >= 1 => {
            admin_reports_response(&state, query, &path, uri.query()).await
        }
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
    OriginalUri(uri): OriginalUri,
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
    let path = format!(
        "{}{}",
        request_app_url(&state).trim_end_matches('/'),
        uri.path()
    );
    match database
        .user_profile(&state.config.database.table_prefix, identity.user_id)
        .await
    {
        Ok(Some(user)) if user.permission >= 1 => {
            admin_reports_response(&state, query, &path, uri.query()).await
        }
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
    LegacyRouteId(id): LegacyRouteId,
    Query(query): Query<BTreeMap<String, String>>,
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
            return review_report_action(
                &state,
                id,
                &query,
                &body,
                headers
                    .get(CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok()),
                user.uid,
                user.permission,
            )
            .await;
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
    LegacyRouteId(id): LegacyRouteId,
    Query(query): Query<BTreeMap<String, String>>,
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
            return review_report_action(
                &state,
                id,
                &query,
                &body,
                headers
                    .get(CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok()),
                identity.user_id,
                user.permission,
            )
            .await;
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
    query: &BTreeMap<String, String>,
    body: &[u8],
    content_type: Option<&str>,
    admin_user_id: i64,
    admin_permission: i32,
) -> Response {
    let request = parse_legacy_input_object(query, body, content_type)
        .ok()
        .map(serde_json::Value::Object);
    let Some(action) = request
        .as_ref()
        .and_then(|request| request.get("action"))
        .and_then(serde_json::Value::as_str)
        .filter(|action| matches!(*action, "reject" | "ban" | "delete"))
    else {
        return report_review_validation_error(&request_locale(&state));
    };
    emit_plugin_event(
        state,
        "report.reviewing",
        serde_json::json!({"report_id": id, "admin_user_id": admin_user_id, "action": action}),
    )
    .await;
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
        return delete_reported_texture(state, id, reporter_score_modification, admin_user_id)
            .await;
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
            Ok(value) => legacy_option_integer(value.as_deref(), 0),
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
        Ok(crate::database::ReportReviewOutcome::Rejected) => {
            emit_plugin_event(
                state,
                "report.rejected",
                serde_json::json!({"report_id": id, "admin_user_id": admin_user_id, "action": action, "status": 2}),
            )
            .await;
            emit_plugin_event(
                state,
                "report.reviewed",
                serde_json::json!({"report_id": id, "admin_user_id": admin_user_id, "action": action, "status": 2}),
            )
            .await;
            report_review_success(state, 2)
        }
        Ok(crate::database::ReportReviewOutcome::Resolved) => {
            emit_plugin_event(
                state,
                "report.resolved",
                serde_json::json!({"report_id": id, "admin_user_id": admin_user_id, "action": action, "status": 1}),
            )
            .await;
            emit_plugin_event(
                state,
                "report.reviewed",
                serde_json::json!({"report_id": id, "admin_user_id": admin_user_id, "action": action, "status": 1}),
            )
            .await;
            report_review_success(state, 1)
        }
        Ok(crate::database::ReportReviewOutcome::UploaderBanned(user_id)) => {
            emit_plugin_event(
                state,
                "user.banned",
                serde_json::json!({"user_id": user_id}),
            )
            .await;
            emit_plugin_event(
                state,
                "report.resolved",
                serde_json::json!({"report_id": id, "admin_user_id": admin_user_id, "action": action, "status": 1}),
            )
            .await;
            emit_plugin_event(
                state,
                "report.reviewed",
                serde_json::json!({"report_id": id, "admin_user_id": admin_user_id, "action": action, "status": 1}),
            )
            .await;
            report_review_success(state, 1)
        }

        Ok(crate::database::ReportReviewOutcome::UploaderNotFound) => {
            let message = if request_locale(&state).starts_with("zh") {
                "用户不存在"
            } else {
                "No such user."
            };
            login_result(1, message, None)
        }
        Ok(crate::database::ReportReviewOutcome::UploaderPermissionDenied) => {
            let message = if request_locale(&state).starts_with("zh") {
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
    let message = if request_locale(&state).starts_with("zh") {
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
    admin_user_id: i64,
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
            Ok(crate::database::ReportReviewOutcome::Resolved) => {
                emit_plugin_event(
                    state,
                    "report.resolved",
                    serde_json::json!({"report_id": report_id, "admin_user_id": admin_user_id, "action": "delete", "status": 1}),
                )
                .await;
                emit_plugin_event(
                    state,
                    "report.reviewed",
                    serde_json::json!({"report_id": report_id, "admin_user_id": admin_user_id, "action": "delete", "status": 1}),
                )
                .await;
                login_result(
                    0,
                    if request_locale(&state).starts_with("zh") {
                        "请求的材质已被删除"
                    } else {
                        "The requested texture has been deleted."
                    },
                    Some(serde_json::json!({ "status": 1 })),
                )
            }
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
    let public_cost = match read_score_option(database, prefix, "score_per_storage", 1).await {
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
    emit_plugin_event(
        state,
        "texture.deleting",
        serde_json::json!({"texture_id": texture.tid, "uploader_id": texture.uploader, "hash": texture.hash, "name": texture.name}),
    )
    .await;
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
    emit_plugin_event(
        state,
        "texture.deleted",
        serde_json::json!({"texture_id": texture.tid, "uploader_id": texture.uploader, "hash": texture.hash, "name": texture.name}),
    )
    .await;
    emit_plugin_event(
        state,
        "report.resolved",
        serde_json::json!({"report_id": report_id, "admin_user_id": admin_user_id, "action": "delete", "status": 1}),
    )
    .await;
    emit_plugin_event(
        state,
        "report.reviewed",
        serde_json::json!({"report_id": report_id, "admin_user_id": admin_user_id, "action": "delete", "status": 1}),
    )
    .await;
    report_review_success(state, 1)
}

async fn read_score_option(
    database: &DatabasePool,
    prefix: &str,
    name: &str,
    default: i64,
) -> Result<i64, sqlx::Error> {
    Ok(legacy_option_integer(
        database.option(prefix, name).await?.as_deref(),
        default,
    ))
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

async fn admin_reports_response(
    state: &AppState,
    query: AdminReportListQuery,
    path: &str,
    raw_query: Option<&str>,
) -> Response {
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
            Json(legacy_paginator_json(
                data, total, page, PER_PAGE, path, raw_query,
            ))
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
    OriginalUri(uri): OriginalUri,
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
    let path = format!(
        "{}{}",
        request_app_url(&state).trim_end_matches('/'),
        uri.path()
    );
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
            Json(legacy_paginator_json(
                data,
                total,
                page,
                per_page,
                &path,
                uri.query(),
            ))
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
        self.scopes
            .iter()
            .any(|scope| scope == "*" || scope == required)
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

fn resolve_legacy_home_background(
    configured: Option<String>,
    legacy_jpg_exists: bool,
    webp_exists: bool,
) -> String {
    let configured = configured.unwrap_or_else(|| "./app/bg.webp".to_owned());
    if configured == "./app/bg.jpg" && !legacy_jpg_exists && webp_exists {
        "./app/bg.webp".to_owned()
    } else {
        configured
    }
}

fn legacy_boolean_option_index(value: &str) -> Option<usize> {
    match value.to_ascii_lowercase().as_str() {
        "true" | "(true)" => Some(1),
        "false" | "(false)" => Some(0),
        _ => None,
    }
}

fn copyright_for_preference(preference: Option<&str>) -> Option<&'static str> {
    let key = match preference.and_then(legacy_boolean_option_index) {
        Some(0) => "0",
        Some(1) => "1",
        _ => preference.unwrap_or("0"),
    };
    COPYRIGHTS
        .iter()
        .enumerate()
        .find_map(|(index, copyright)| (key == index.to_string()).then_some(*copyright))
}

async fn build_api_root(database: &DatabasePool, state: &AppState) -> Result<ApiRoot, sqlx::Error> {
    let locale_key = format!("copyright_prefer_{}", request_locale(&state));
    let preference = database
        .option(&state.config.database.table_prefix, &locale_key)
        .await?
        .or(database
            .option(&state.config.database.table_prefix, "copyright_prefer")
            .await?);
    let copyright = copyright_for_preference(preference.as_deref());
    let site_name = database
        .option(&state.config.database.table_prefix, "site_name")
        .await?
        .unwrap_or_else(|| "Blessing Skin".to_owned());

    Ok(ApiRoot {
        blessing_skin: state.config.legacy_app_version.clone(),
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

fn player_banned_message(locale: &str) -> &'static str {
    match locale {
        "de_DE" => "Das Konto dieses Spielers wurde gebannt.",
        "es_ES" => "El dueño de este jugador ha sido baneado.",
        "fr_FR" => "Le propriétaire de ce joueur a été banni.",
        "ko_KR" => "본 사용자가 정지되었습니다.",
        "ru_RU" => "Владелец этого игрока был заблокирован.",
        "zh_CN" => "该角色拥有者已被本站封禁",
        "zh_TW" => "該角色的所有者已被封禁。",
        _ => "The owner of this player has been banned.",
    }
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
        let locale = request_locale(&state);
        return (StatusCode::FORBIDDEN, player_banned_message(&locale)).into_response();
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
    RoutePath(raw_tid): RoutePath<String>,
    request_headers: HeaderMap,
) -> Response {
    let Some(database) = &state.database else {
        return unavailable();
    };
    let allowed = match database
        .option(
            &state.config.database.table_prefix,
            "allow_downloading_texture",
        )
        .await
    {
        Ok(value) => value
            .as_deref()
            .map(|value| legacy_option_bool(Some(value)))
            .unwrap_or(true),
        Err(error) => {
            tracing::error!(%error, "failed to read direct texture download option");
            return unavailable();
        }
    };
    if !allowed {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(tid) = raw_tid.parse::<i64>().ok() else {
        return StatusCode::NOT_FOUND.into_response();
    };

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

#[derive(Debug)]
struct AvatarSource {
    hash: String,
    texture_type: String,
}

async fn preview_by_texture(
    State(state): State<AppState>,
    RoutePath(tid): RoutePath<String>,
    Query(query): Query<HashMap<String, String>>,
    request_headers: HeaderMap,
) -> Response {
    let Some(tid) = tid.parse::<i64>().ok() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    preview_for_texture(&state, tid, &query, &request_headers, true).await
}

async fn preview_by_hash(
    State(state): State<AppState>,
    RoutePath(hash): RoutePath<String>,
    Query(query): Query<HashMap<String, String>>,
    request_headers: HeaderMap,
) -> Response {
    if !valid_texture_hash(&hash) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    let tid = match database
        .texture_id_by_hash(&state.config.database.table_prefix, &hash)
        .await
    {
        Ok(Some(tid)) => tid,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, hash, "failed to find preview texture");
            return unavailable();
        }
    };
    preview_for_texture(&state, tid, &query, &request_headers, false).await
}

async fn preview_for_texture(
    state: &AppState,
    tid: i64,
    query: &HashMap<String, String>,
    request_headers: &HeaderMap,
    http_cache: bool,
) -> Response {
    let Some(database) = &state.database else {
        return unavailable();
    };
    let texture = match database
        .texture_info(&state.config.database.table_prefix, tid)
        .await
    {
        Ok(Some(texture)) => texture,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, tid, "failed to load preview texture metadata");
            return unavailable();
        }
    };
    if !valid_texture_hash(&texture.hash) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let height = legacy_image_dimension(query.get("height").map(String::as_str), 200);
    let use_png = query.contains_key("png");
    let path = state.config.textures_dir.join(&texture.hash);
    let metadata = match tokio::fs::metadata(&path).await {
        Ok(metadata) if metadata.is_file() => metadata,
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    let cache_key = ImageCacheKey::Preview { tid, png: use_png };
    if let Some(cached) = state.image_cache.get(&cache_key) {
        let ttl = cache_ttl(state).await;
        return image_response(
            cached,
            if use_png { "image/png" } else { "image/webp" },
            ttl,
            request_headers,
            http_cache,
        );
    }
    let mut source = match tokio::fs::read(path).await {
        Ok(bytes) => match image::load_from_memory_with_format(&bytes, ImageFormat::Png) {
            Ok(image) => image.to_rgba8(),
            Err(error) => {
                tracing::warn!(%error, tid, "preview source is not a valid PNG");
                return StatusCode::NOT_FOUND.into_response();
            }
        },
        Err(error) => {
            tracing::warn!(%error, tid, "preview source could not be read");
            return StatusCode::NOT_FOUND.into_response();
        }
    };
    let is_cape = texture.texture_type == "cape";
    if is_cape {
        if source.width() < 12 || source.height() < 17 {
            return StatusCode::UNPROCESSABLE_ENTITY.into_response();
        }
    } else if let Some(normalized) = normalize_skin_dimensions(&source, &texture.texture_type) {
        source = normalized;
    } else {
        return StatusCode::UNPROCESSABLE_ENTITY.into_response();
    }
    let format = if use_png {
        ImageFormat::Png
    } else {
        ImageFormat::WebP
    };
    let rendered = if is_cape {
        render_cape_preview(&source, height)
    } else {
        render_skin_preview(&source, texture.texture_type == "alex", height)
    };
    let mut bytes = Vec::new();
    if rendered
        .write_to(&mut Cursor::new(&mut bytes), format)
        .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let body = Bytes::from(bytes);
    let cached = CachedImage {
        etag: content_etag(&body),
        body,
        modified: metadata.modified().ok(),
    };
    let server_cache_ttl = image_response_cache_ttl(state, "enable_preview_cache").await;
    state
        .image_cache
        .insert(cache_key, cached.clone(), server_cache_ttl);
    let ttl = cache_ttl(state).await;
    image_response(
        cached,
        if use_png { "image/png" } else { "image/webp" },
        ttl,
        request_headers,
        http_cache,
    )
}

fn render_skin_preview(skin: &RgbaImage, is_alex: bool, _height: u32) -> DynamicImage {
    crate::skin_renderer::render_preview(skin, is_alex)
}

fn render_cape_preview(cape: &RgbaImage, height: u32) -> DynamicImage {
    // The legacy renderer scales cape texture coordinates by the source HD ratio
    // (width / 64), so a 128x64 cape uses a 20x32 front face starting at (2, 2).
    let hd_ratio = (cape.width() / 64).max(1);
    let crop_x = hd_ratio.min(cape.width().saturating_sub(1));
    let crop_y = hd_ratio.min(cape.height().saturating_sub(1));
    let crop_width = (10 * hd_ratio)
        .min(cape.width().saturating_sub(crop_x))
        .max(1);
    let crop_height = (16 * hd_ratio)
        .min(cape.height().saturating_sub(crop_y))
        .max(1);
    let front = image::imageops::crop_imm(cape, crop_x, crop_y, crop_width, crop_height).to_image();
    let width = (height.saturating_mul(10) / 16).max(1);
    DynamicImage::ImageRgba8(image::imageops::resize(
        &front,
        width,
        height,
        image::imageops::FilterType::Nearest,
    ))
}

async fn avatar_by_player(
    State(state): State<AppState>,
    RoutePath(name): RoutePath<String>,
    Query(query): Query<HashMap<String, String>>,
    request_headers: HeaderMap,
) -> Response {
    let Some(database) = &state.database else {
        return unavailable();
    };
    let profile = match database
        .player_profile(&state.config.database.table_prefix, &name)
        .await
    {
        Ok(Some(profile)) => profile,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, player = %name, "failed to load player avatar");
            return unavailable();
        }
    };
    let source = profile
        .skin_hash
        .zip(profile.skin_type)
        .map(|(hash, texture_type)| AvatarSource { hash, texture_type });
    render_avatar_response(&state, source, &query, &request_headers, true).await
}

async fn avatar_by_user(
    State(state): State<AppState>,
    RoutePath(uid): RoutePath<String>,
    Query(query): Query<HashMap<String, String>>,
    request_headers: HeaderMap,
) -> Response {
    let Some(database) = &state.database else {
        return unavailable();
    };
    let source = match uid.parse::<i64>() {
        Ok(uid) => {
            let user = match database
                .user_profile(&state.config.database.table_prefix, uid)
                .await
            {
                Ok(user) => user,
                Err(error) => {
                    tracing::error!(%error, uid, "failed to load user avatar");
                    return unavailable();
                }
            };
            let texture_id = user.map(|user| user.avatar).filter(|tid| *tid > 0);
            match texture_id {
                Some(tid) => match database
                    .texture_info(&state.config.database.table_prefix, tid)
                    .await
                {
                    Ok(Some(texture)) => Some(AvatarSource {
                        hash: texture.hash,
                        texture_type: texture.texture_type,
                    }),
                    Ok(None) => None,
                    Err(error) => {
                        tracing::error!(%error, tid, "failed to load user avatar texture");
                        return unavailable();
                    }
                },
                None => None,
            }
        }
        Err(_) => None,
    };
    render_avatar_response(&state, source, &query, &request_headers, true).await
}

async fn avatar_by_hash(
    State(state): State<AppState>,
    RoutePath(hash): RoutePath<String>,
    Query(query): Query<HashMap<String, String>>,
    request_headers: HeaderMap,
) -> Response {
    let Some(database) = &state.database else {
        return unavailable();
    };
    let source = if valid_texture_hash(&hash) {
        match database
            .texture_id_by_hash(&state.config.database.table_prefix, &hash)
            .await
        {
            Ok(Some(tid)) => match database
                .texture_info(&state.config.database.table_prefix, tid)
                .await
            {
                Ok(Some(texture)) => Some(AvatarSource {
                    hash: texture.hash,
                    texture_type: texture.texture_type,
                }),
                Ok(None) => None,
                Err(error) => {
                    tracing::error!(%error, tid, "failed to load avatar texture");
                    return unavailable();
                }
            },
            Ok(None) => None,
            Err(error) => {
                tracing::error!(%error, hash, "failed to find avatar texture");
                return unavailable();
            }
        }
    } else {
        None
    };
    render_avatar_response(&state, source, &query, &request_headers, false).await
}

async fn avatar_by_texture(
    State(state): State<AppState>,
    RoutePath(tid): RoutePath<String>,
    Query(query): Query<HashMap<String, String>>,
    request_headers: HeaderMap,
) -> Response {
    let Some(database) = &state.database else {
        return unavailable();
    };
    let source = if let Ok(tid) = tid.parse::<i64>() {
        match database
            .texture_info(&state.config.database.table_prefix, tid)
            .await
        {
            Ok(Some(texture)) => Some(AvatarSource {
                hash: texture.hash,
                texture_type: texture.texture_type,
            }),
            Ok(None) => None,
            Err(error) => {
                tracing::error!(%error, tid, "failed to load avatar texture");
                return unavailable();
            }
        }
    } else {
        None
    };
    render_avatar_response(&state, source, &query, &request_headers, true).await
}

async fn render_avatar_response(
    state: &AppState,
    source: Option<AvatarSource>,
    query: &HashMap<String, String>,
    request_headers: &HeaderMap,
    http_cache: bool,
) -> Response {
    let three_d = query.contains_key("3d");
    let size = legacy_image_dimension(query.get("size").map(String::as_str), 100);
    let use_png = query.contains_key("png");
    let format = if use_png {
        ImageFormat::Png
    } else {
        ImageFormat::WebP
    };
    let mut modified = None;
    let mut source_skin = None;
    let mut cache_key = None;
    if let Some(source) = source {
        if source.texture_type != "steve" && source.texture_type != "alex" {
            return StatusCode::UNPROCESSABLE_ENTITY.into_response();
        }
        if valid_texture_hash(&source.hash) {
            let path = state.config.textures_dir.join(&source.hash);
            if let Ok(metadata) = tokio::fs::metadata(&path).await {
                if metadata.is_file() {
                    modified = metadata.modified().ok();
                    let key = ImageCacheKey::Avatar {
                        texture_hash: source.hash.clone(),
                        texture_type: source.texture_type.clone(),
                        three_d,
                        size,
                        png: use_png,
                    };
                    if let Some(cached) = state.image_cache.get(&key) {
                        let ttl = cache_ttl(state).await;
                        return image_response(
                            cached,
                            if use_png { "image/png" } else { "image/webp" },
                            ttl,
                            request_headers,
                            http_cache,
                        );
                    }
                    if let Ok(bytes) = tokio::fs::read(path).await {
                        source_skin = image::load_from_memory_with_format(&bytes, ImageFormat::Png)
                            .ok()
                            .and_then(|image| {
                                normalize_skin_dimensions(&image.to_rgba8(), &source.texture_type)
                            });
                    }
                    if source_skin.is_some() {
                        cache_key = Some(key);
                    }
                }
            }
        }
    }

    let image = match source_skin {
        Some(skin) => render_skin_avatar(&skin, three_d),
        None => default_avatar(three_d),
    };
    let image = image.resize_exact(size, size, image::imageops::FilterType::Nearest);
    let mut bytes = Vec::new();
    if image
        .write_to(&mut Cursor::new(&mut bytes), format)
        .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let body = Bytes::from(bytes);
    let cached = CachedImage {
        etag: content_etag(&body),
        body,
        modified,
    };
    if let Some(key) = cache_key {
        let server_cache_ttl = image_response_cache_ttl(state, "enable_avatar_cache").await;
        state
            .image_cache
            .insert(key, cached.clone(), server_cache_ttl);
    }
    let ttl = cache_ttl(state).await;
    image_response(
        cached,
        if use_png { "image/png" } else { "image/webp" },
        ttl,
        request_headers,
        http_cache,
    )
}

fn default_avatar(three_d: bool) -> DynamicImage {
    let bytes = if three_d {
        include_bytes!("../resources/misc/textures/avatar3d.png").as_slice()
    } else {
        include_bytes!("../resources/misc/textures/avatar2d.png").as_slice()
    };
    image::load_from_memory_with_format(bytes, ImageFormat::Png).expect("built-in avatar is valid")
}

fn render_skin_avatar(skin: &RgbaImage, three_d: bool) -> DynamicImage {
    if skin.width() < 64 || skin.height() < 32 {
        return default_avatar(three_d);
    }
    crate::skin_renderer::render_avatar(skin, three_d)
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

async fn image_response_cache_ttl(state: &AppState, option_name: &str) -> Duration {
    let enabled = if let Some(database) = &state.database {
        database
            .option(&state.config.database.table_prefix, option_name)
            .await
            .ok()
            .flatten()
            .is_some_and(|value| legacy_option_bool(Some(&value)))
    } else {
        false
    };
    Duration::from_secs(if enabled { 31_536_000 } else { 60 })
}

fn image_response(
    cached: CachedImage,
    content_type: &str,
    ttl: u64,
    request_headers: &HeaderMap,
    http_cache: bool,
) -> Response {
    let CachedImage {
        body,
        etag,
        modified,
    } = cached;
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_str(content_type).unwrap());
    if http_cache {
        headers.insert(ETAG, HeaderValue::from_str(&etag).unwrap());
        headers.insert(
            CACHE_CONTROL,
            HeaderValue::from_str(&format!("public, max-age={ttl}")).unwrap(),
        );
    } else {
        let policy = if modified.is_some() {
            "private, must-revalidate"
        } else {
            "no-cache, private"
        };
        headers.insert(CACHE_CONTROL, HeaderValue::from_static(policy));
    }
    headers.insert(
        CONTENT_LENGTH,
        HeaderValue::from_str(&body.len().to_string()).unwrap(),
    );
    if let Some(modified) = modified {
        headers.insert(
            LAST_MODIFIED,
            HeaderValue::from_str(&httpdate::fmt_http_date(modified)).unwrap(),
        );
    }
    if http_cache
        && ((request_headers.contains_key(IF_NONE_MATCH)
            && header_has_etag(request_headers, &etag))
            || (!request_headers.contains_key(IF_NONE_MATCH)
                && modified.is_some_and(|time| not_modified_since(request_headers, time))))
    {
        let mut response = StatusCode::NOT_MODIFIED.into_response();
        *response.headers_mut() = headers;
        response.headers_mut().remove(CONTENT_TYPE);
        response.headers_mut().remove(CONTENT_LENGTH);
        return response;
    }
    let mut response = Response::new(Body::from(body));
    *response.headers_mut() = headers;
    response
}

fn header_has_etag(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get(IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            let response_tag = etag.strip_prefix("W/").unwrap_or(etag);
            value.split(',').any(|item| {
                let request_tag = item.trim();
                request_tag == "*"
                    || request_tag.strip_prefix("W/").unwrap_or(request_tag) == response_tag
            })
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
    use askama::Template;
    use image::{GenericImageView, ImageFormat};

    use super::{
        AdminPluginsPage, BindEmailPage, EmailVerificationPage, ForgotPage, HomePage,
        PasswordResetPage, PluginConfigurationPage, RegisterPage, Rgba, RgbaImage, content_etag,
        merge_frontend_language_lines, normalize_skin_dimensions, parse_legacy_datetime,
        public_download_ip, render_cape_preview, render_skin_avatar, render_skin_preview,
        resolve_legacy_home_background, router, safe_remote_component_url, valid_texture_hash,
    };

    #[tokio::test]
    async fn unknown_html_page_renders_localized_404_but_api_keeps_plain_404() {
        use axum::{
            body::{Body, to_bytes},
            http::{Request, StatusCode, header::CONTENT_TYPE},
        };
        use sqlx::sqlite::SqliteConnectOptions;
        use std::sync::Arc;
        use tower::ServiceExt;

        let root = std::env::temp_dir().join(format!(
            "blessing-skin-not-found-{}",
            super::setup_csrf_token()
        ));
        let storage_dir = root.join("storage");
        std::fs::create_dir_all(&storage_dir).unwrap();
        std::fs::write(storage_dir.join("install.lock"), b"").unwrap();
        let config = crate::config::Config {
            bind: "127.0.0.1:3000".parse().unwrap(),
            rust_version: "test",
            legacy_app_version: "test".to_owned(),
            locale: "en".to_owned(),
            fallback_locale: "en".to_owned(),
            database: crate::config::DatabaseConfig {
                connection: crate::config::DatabaseConnection::Sqlite(SqliteConnectOptions::new()),
                table_prefix: String::new(),
                driver: "SQLite".to_owned(),
                host: None,
                port: None,
                username: None,
                database: "test.sqlite".to_owned(),
            },
            textures_dir: root.join("textures"),
            plugins_dir: root.join("plugins"),
            wasm_plugin_registry_url: None,
            rust_releases_api_url: None,
            app_url: "http://localhost/skin".to_owned(),
            passport_public_key: None,
            passport_private_key: None,
            password_method: "BCRYPT".to_owned(),
            password_salt: String::new(),
            bcrypt_rounds: 10,
            app_key: None,
            session_lifetime_seconds: 7_200,
            mail: crate::config::MailConfig::default(),
        };
        let state = crate::AppState {
            config: Arc::new(config),
            database: None,
            passport_key: None,
            passport_signing_key: None,
            session_key: None,
            revoked_web_sessions: Default::default(),
            login_failures: Default::default(),
            captcha_challenges: Default::default(),
            mail_limits: Default::default(),
            image_cache: crate::image_cache::ImageCache::shared(),
            storage_dir,
            env_file: root.join(".env"),
            public_dir: root.join("public"),
            wasm_plugins: Vec::new(),
            wasm_plugin_load_failures: Vec::new(),
            wasm_plugin_readmes: Vec::new(),
            wasm_plugin_configurations: Vec::new(),
            wasm_runtime: crate::plugin_runtime::PluginRuntime::shared_empty(),
        };
        let app = router(state.clone());
        let page = app
            .clone()
            .oneshot(
                Request::get("/missing/this/page")
                    .header("accept", "text/html")
                    .header("accept-language", "zh-CN")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(page.status(), StatusCode::NOT_FOUND);
        assert!(
            page.headers()[CONTENT_TYPE]
                .to_str()
                .unwrap()
                .starts_with("text/html")
        );
        let page = String::from_utf8(
            to_bytes(page.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(page.contains(r#"<html lang="zh_CN">"#));
        assert!(page.contains("这里什么都没有哦"));
        assert!(page.contains(r#"name="robots" content="noindex,nofollow""#));

        let api_not_found = app
            .oneshot(
                Request::get("/api/missing")
                    .header("accept", "text/html")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(api_not_found.status(), StatusCode::NOT_FOUND);
        let api_not_found = to_bytes(api_not_found.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(!api_not_found.starts_with(b"<!doctype html>"));

        let error_app = axum::Router::new()
            .route(
                "/denied",
                axum::routing::get(|| async { (StatusCode::FORBIDDEN, "Permission denied") }),
            )
            .route(
                "/api/denied",
                axum::routing::get(|| async { (StatusCode::FORBIDDEN, "Permission denied") }),
            )
            .route(
                "/json-error",
                axum::routing::get(|| async {
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        axum::Json(serde_json::json!({ "status": "not_ready" })),
                    )
                }),
            )
            .route(
                "/unavailable",
                axum::routing::get(|| async {
                    (StatusCode::SERVICE_UNAVAILABLE, "maintenance details")
                }),
            )
            .route(
                "/internal-error",
                axum::routing::get(|| async {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "database password=secret",
                    )
                }),
            )
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                super::render_html_error_page,
            ))
            .with_state(state);
        let denied = error_app
            .clone()
            .oneshot(
                Request::get("/denied")
                    .header("accept", "text/html")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        assert!(
            denied.headers()[CONTENT_TYPE]
                .to_str()
                .unwrap()
                .starts_with("text/html")
        );
        let denied = String::from_utf8(
            to_bytes(denied.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(denied.contains("403 Forbidden"));
        assert!(denied.contains("Permission denied"));

        let api_denied = error_app
            .clone()
            .oneshot(
                Request::get("/api/denied")
                    .header("accept", "text/html")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(api_denied.status(), StatusCode::FORBIDDEN);
        assert!(
            api_denied.headers()[CONTENT_TYPE]
                .to_str()
                .unwrap()
                .starts_with("text/plain")
        );

        let json_error = error_app
            .clone()
            .oneshot(
                Request::get("/json-error")
                    .header("accept", "text/html")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(json_error.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            json_error.headers()[CONTENT_TYPE]
                .to_str()
                .unwrap()
                .starts_with("application/json")
        );

        let unavailable = error_app
            .clone()
            .oneshot(
                Request::get("/unavailable")
                    .header("accept", "text/html")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(unavailable.headers()["cache-control"], "no-store");
        let unavailable = String::from_utf8(
            to_bytes(unavailable.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(unavailable.contains("503 Service Unavailable"));
        assert!(!unavailable.contains("maintenance details"));

        let internal_error = error_app
            .oneshot(
                Request::get("/internal-error")
                    .header("accept", "text/html")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(internal_error.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let internal_error = String::from_utf8(
            to_bytes(internal_error.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(internal_error.contains("500 Internal Server Error"));
        assert!(!internal_error.contains("database password=secret"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn old_default_home_background_uses_the_available_webp_asset() {
        assert_eq!(
            resolve_legacy_home_background(Some("./app/bg.jpg".to_owned()), false, true),
            "./app/bg.webp"
        );
        assert_eq!(
            resolve_legacy_home_background(Some("./app/bg.jpg".to_owned()), true, true),
            "./app/bg.jpg"
        );
        assert_eq!(
            resolve_legacy_home_background(Some("/uploads/custom.jpg".to_owned()), false, true),
            "/uploads/custom.jpg"
        );
        assert_eq!(
            resolve_legacy_home_background(None, false, true),
            "./app/bg.webp"
        );
    }

    #[test]
    fn plugin_inventory_reports_startup_failures_in_both_locales() {
        assert_eq!(
            super::admin_plugin_description(false, true, true, true, false),
            "Failed to load; check service logs"
        );
        assert_eq!(
            super::admin_plugin_description(false, true, true, true, true),
            "加载失败；请查看服务日志"
        );
        assert_eq!(
            super::admin_plugin_description(false, false, true, true, false),
            "Enabled; will load on next startup"
        );
    }

    #[tokio::test]
    async fn malformed_protected_route_ids_reach_authentication_before_resource_lookup() {
        use axum::{
            Router,
            body::Body,
            http::{Request, StatusCode},
            response::IntoResponse,
            routing::get,
        };
        use tower::ServiceExt;

        let app = Router::new().route(
            "/{id}",
            get(
                |headers: super::HeaderMap, route_id: super::LegacyRouteId| async move {
                    if !headers.contains_key("authorization") {
                        return StatusCode::UNAUTHORIZED.into_response();
                    }
                    if route_id.0 == i64::MIN {
                        return StatusCode::NOT_FOUND.into_response();
                    }
                    StatusCode::OK.into_response()
                },
            ),
        );

        let unauthenticated = app
            .clone()
            .oneshot(Request::get("/not-a-number").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

        let authenticated_invalid = app
            .clone()
            .oneshot(
                Request::get("/not-a-number")
                    .header("authorization", "Bearer test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authenticated_invalid.status(), StatusCode::NOT_FOUND);

        let authenticated_valid = app
            .oneshot(
                Request::get("/42")
                    .header("authorization", "Bearer test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authenticated_valid.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn client_ip_prefers_valid_proxy_headers_then_uses_the_socket_peer() {
        use axum::{
            Router,
            body::{Body, to_bytes},
            extract::ConnectInfo,
            http::{HeaderMap, Request},
            routing::get,
        };
        use tower::ServiceExt;

        let app = Router::new()
            .route(
                "/ip",
                get(|headers: HeaderMap| async move { super::registration_client_ip(&headers) }),
            )
            .layer(axum::middleware::from_fn(super::infer_peer_client_ip));
        let peer: std::net::SocketAddr = "203.0.113.17:43120".parse().unwrap();

        let direct = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/ip")
                    .extension(ConnectInfo(peer))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let direct = to_bytes(direct.into_body(), usize::MAX).await.unwrap();
        assert_eq!(direct.as_ref(), b"203.0.113.17");

        let proxied = app
            .oneshot(
                Request::builder()
                    .uri("/ip")
                    .header("x-real-ip", "198.51.100.9")
                    .extension(ConnectInfo(peer))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let proxied = to_bytes(proxied.into_body(), usize::MAX).await.unwrap();
        assert_eq!(proxied.as_ref(), b"198.51.100.9");
    }

    #[test]
    fn legacy_locale_aliases_and_accept_language_quality_are_resolved() {
        assert_eq!(super::normalize_locale("zh-HANS-CN"), Some("zh_CN"));
        assert_eq!(super::normalize_locale("en_US"), Some("en"));
        assert_eq!(super::normalize_locale("ru"), Some("ru_RU"));
        for locale in [
            "de_DE", "el_GR", "en", "es_ES", "fr_FR", "it_IT", "ja_JP", "ko_KR", "nl_NL", "pt_PT",
            "ru_RU", "zh_CN", "zh_TW",
        ] {
            assert_eq!(super::normalize_locale(locale), Some(locale), "{locale}");
        }
        assert_eq!(super::normalize_locale("fr"), Some("fr_FR"));
        assert_eq!(super::normalize_locale("zh-Hant"), Some("zh_TW"));
        assert_eq!(super::normalize_locale("fr-CA"), None);

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "accept-language",
            axum::http::HeaderValue::from_static("fr-CA;q=1, en-US;q=0.7, ru;q=0.9"),
        );
        assert_eq!(super::browser_preferred_locale(&headers), Some("ru_RU"));
        assert_eq!(
            super::body_locale(br#"{"lang":"zh_TW"}"#, "application/json"),
            Some("zh_TW".to_owned())
        );
        assert_eq!(
            super::body_locale(b"lang=en&lang=zh_TW", "application/x-www-form-urlencoded"),
            Some("zh_TW".to_owned())
        );
        assert_eq!(
            super::body_locale(br#"{"lang":""}"#, "application/json"),
            None
        );
    }
    #[test]
    fn database_frontend_translations_override_static_lines_with_locale_fallback() {
        let mut translations = serde_json::json!({
            "auth": { "login": "Log In" },
            "nav": { "home": "Home" }
        });

        merge_frontend_language_lines(
            &mut translations,
            "fr",
            vec![
                (
                    "nav.home".to_owned(),
                    r#"{"en":"Home","fr":"Accueil"}"#.to_owned(),
                ),
                ("auth.login".to_owned(), r#"{"en":"Sign in"}"#.to_owned()),
                ("broken".to_owned(), "not-json".to_owned()),
            ],
        );

        assert_eq!(translations["nav"]["home"], "Accueil");
        assert_eq!(translations["auth"]["login"], "Sign in");
        assert!(translations.get("broken").is_none());
    }
    async fn login_page_too_many_fails(app: &axum::Router, ip: &str) -> bool {
        use axum::{
            body::{Body, to_bytes},
            http::{Request, StatusCode},
        };
        use base64::Engine as _;
        use tower::ServiceExt;

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/auth/login")
                    .header("x-real-ip", ip)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let html = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(html.to_vec()).unwrap();
        let encoded = html
            .split("atob('")
            .nth(1)
            .unwrap()
            .split("')")
            .next()
            .unwrap();
        let globals = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        let globals: serde_json::Value = serde_json::from_slice(&globals).unwrap();
        globals["extra"]["tooManyFails"].as_bool().unwrap()
    }

    async fn test_web_csrf_credentials(app: &axum::Router, cookie: &str) -> (String, String) {
        use axum::{
            body::{Body, to_bytes},
            http::Request,
        };
        use tower::ServiceExt;

        let mut request = Request::get("/");
        if !cookie.is_empty() {
            request = request.header("cookie", cookie);
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            response.headers().get("cache-control").unwrap(),
            "private, no-store"
        );
        let html = String::from_utf8(
            to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        let token = html
            .split("name=\"csrf-token\" content=\"")
            .nth(1)
            .and_then(|value| value.split('\"').next())
            .unwrap_or_default()
            .to_owned();
        assert!(html.contains("window.fetch=(input,init)=>"));
        if !token.is_empty() {
            assert!(html.contains(&format!("name=\"csrf-token\" content=\"{token}\"")));
        }
        let cookie = if cookie
            .split(';')
            .any(|part| part.trim().starts_with("blessing_skin_csrf="))
        {
            cookie.to_owned()
        } else if cookie.is_empty() {
            format!("blessing_skin_csrf={token}")
        } else {
            format!("{cookie}; blessing_skin_csrf={token}")
        };
        (cookie, token)
    }

    async fn submit_test_registration(
        app: &axum::Router,
        cookie: &str,
        captcha: &str,
        email: &str,
        player_name: &str,
        ip: &str,
    ) -> axum::response::Response {
        use axum::body::Body;
        use tower::ServiceExt;

        let (cookie, csrf_token) = test_web_csrf_credentials(app, cookie).await;
        let body = form_urlencoded::Serializer::new(String::new())
            .append_pair("email", email)
            .append_pair("password", "secure pass 123")
            .append_pair("player_name", player_name)
            .append_pair("captcha", captcha)
            .finish();
        app.clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/auth/register?lang=en")
                    .header("cookie", cookie)
                    .header("x-csrf-token", csrf_token)
                    .header("x-real-ip", ip)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    async fn login_test_account(
        app: &axum::Router,
        email: &str,
        password: &str,
        ip: &str,
    ) -> String {
        use axum::{
            body::{Body, to_bytes},
            http::{Request, StatusCode, header::SET_COOKIE},
        };
        use tower::ServiceExt;

        let (cookie, csrf_token) = test_web_csrf_credentials(app, "").await;
        if !csrf_token.is_empty() {
            let rejected = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/auth/login")
                        .header("cookie", &cookie)
                        .header("accept", "application/json")
                        .header("content-type", "application/json")
                        .body(Body::from(
                            r#"{"identification":"alex@example.test","password":"correct horse"}"#,
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(rejected.status(), StatusCode::from_u16(419).unwrap());
            let body: serde_json::Value =
                serde_json::from_slice(&to_bytes(rejected.into_body(), usize::MAX).await.unwrap())
                    .unwrap();
            assert_eq!(body["message"], "CSRF token mismatched.");

            let browser_rejected = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/auth/login")
                        .header("cookie", &cookie)
                        .header("accept", "text/html")
                        .header("content-type", "application/x-www-form-urlencoded")
                        .body(Body::from("identification=alex%40example.test"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                browser_rejected.status(),
                StatusCode::from_u16(419).unwrap()
            );
            assert!(
                browser_rejected
                    .headers()
                    .get("content-type")
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .starts_with("text/html")
            );
            let browser_error = String::from_utf8(
                to_bytes(browser_rejected.into_body(), usize::MAX)
                    .await
                    .unwrap()
                    .to_vec(),
            )
            .unwrap();
            assert!(browser_error.contains("Page Expired"));

            let signature_char = csrf_token.as_bytes()[49];
            let replacement = if signature_char == b'0' { "1" } else { "0" };
            let forged_csrf_token = format!("{}{replacement}", &csrf_token[..49]);
            let forged = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/auth/login")
                        .header("cookie", format!("blessing_skin_csrf={forged_csrf_token}"))
                        .header("x-csrf-token", forged_csrf_token)
                        .header("accept", "application/json")
                        .header("content-type", "application/json")
                        .body(Body::from(
                            r#"{"identification":"alex@example.test","password":"correct horse"}"#,
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(forged.status(), StatusCode::from_u16(419).unwrap());
        }
        let body = form_urlencoded::Serializer::new(String::new())
            .append_pair("identification", email)
            .append_pair("password", password)
            .append_pair("keep", "on")
            .finish();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/login?lang=en")
                    .header("cookie", cookie)
                    .header("x-csrf-token", csrf_token)
                    .header("x-real-ip", ip)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let set_cookie = response
            .headers()
            .get(SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(set_cookie.contains(&format!("Max-Age={}", super::LEGACY_REMEMBER_TTL_SECONDS)));
        let cookie = set_cookie.split(';').next().unwrap().to_owned();
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(body["code"], 0);
        cookie
    }

    async fn session_request(
        app: &axum::Router,
        cookie: &str,
        method: &str,
        uri: &str,
        body: Option<&str>,
    ) -> axum::response::Response {
        use axum::body::Body;
        use tower::ServiceExt;

        let (cookie, csrf_token) = test_web_csrf_credentials(app, cookie).await;
        let mut builder = axum::http::Request::builder()
            .method(method)
            .uri(uri)
            .header("cookie", cookie)
            .header("x-csrf-token", csrf_token)
            .header("accept", "application/json");
        let body = if let Some(body) = body {
            builder = builder.header("content-type", "application/json");
            Body::from(body.to_owned())
        } else {
            Body::empty()
        };
        app.clone()
            .oneshot(builder.body(body).unwrap())
            .await
            .unwrap()
    }

    async fn issue_test_captcha(
        app: &axum::Router,
        challenges: &std::sync::Arc<
            std::sync::Mutex<std::collections::HashMap<String, (String, std::time::Instant)>>,
        >,
    ) -> (String, String) {
        use axum::{
            body::{Body, to_bytes},
            http::{Request, header::SET_COOKIE},
        };
        use tower::ServiceExt;

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/auth/captcha")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "image/jpeg");
        let set_cookie = response
            .headers()
            .get(SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        let cookie = set_cookie.split(';').next().unwrap().to_owned();
        let jpeg = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert!(jpeg.starts_with(&[0xff, 0xd8]));
        let id = cookie.split_once('=').unwrap().1.to_owned();
        let answer = challenges.lock().unwrap().get(&id).unwrap().0.clone();
        (cookie, answer)
    }

    #[test]
    fn wasm_plugin_registry_v1_validates_metadata_urls_hashes_and_unique_names() {
        let good_entry = serde_json::json!({
            "name": "demo-plugin",
            "version": "1.2.3",
            "title": "Demo plugin",
            "description": "A test plugin.",
            "author": "Blessing Skin",
            "download_url": "https://plugins.example.com/releases/demo-plugin.wasm",
            "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        });
        let manifest = |plugins: Vec<serde_json::Value>| {
            serde_json::json!({ "schema_version": 1, "plugins": plugins }).to_string()
        };
        assert_eq!(
            super::parse_wasm_plugin_registry(manifest(vec![good_entry.clone()]).as_bytes())
                .unwrap()
                .len(),
            1
        );
        assert!(
            super::parse_wasm_plugin_registry(
                manifest(vec![good_entry.clone(), good_entry.clone()]).as_bytes()
            )
            .is_err()
        );

        let mut bad_hash = good_entry.clone();
        bad_hash["sha256"] = serde_json::json!("not-a-hash");
        assert!(super::parse_wasm_plugin_registry(manifest(vec![bad_hash]).as_bytes()).is_err());

        let mut unsafe_url = good_entry.clone();
        unsafe_url["download_url"] =
            serde_json::json!("https://127.0.0.1/releases/demo-plugin.wasm");
        assert!(super::parse_wasm_plugin_registry(manifest(vec![unsafe_url]).as_bytes()).is_err());

        let mut mismatched_name = good_entry;
        mismatched_name["download_url"] =
            serde_json::json!("https://plugins.example.com/releases/other.wasm");
        assert!(
            super::parse_wasm_plugin_registry(manifest(vec![mismatched_name]).as_bytes()).is_err()
        );

        let unsupported_version = serde_json::json!({ "schema_version": 2, "plugins": [] });
        assert!(
            super::parse_wasm_plugin_registry(unsupported_version.to_string().as_bytes()).is_err()
        );
    }
    #[test]
    fn replaces_wasm_market_component_without_leaving_partial_files() {
        let directory = std::env::temp_dir().join(format!(
            "blessing-wasm-market-update-{}",
            super::setup_csrf_token()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let destination = directory.join("demo-plugin.wasm");
        std::fs::write(&destination, b"old component").unwrap();

        super::replace_component_file(&directory, "demo-plugin", &destination, b"new component")
            .unwrap();
        assert_eq!(std::fs::read(&destination).unwrap(), b"new component");
        let remaining = std::fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(
            remaining,
            vec![std::ffi::OsString::from("demo-plugin.wasm")]
        );

        super::write_wasm_plugin_market_metadata(
            &directory,
            "demo-plugin",
            "1.2.3",
            &"a".repeat(64),
        )
        .unwrap();
        let metadata = std::fs::read(super::wasm_plugin_market_metadata_path(
            &directory,
            "demo-plugin",
        ))
        .unwrap();
        let metadata: super::WasmPluginMarketMetadata = serde_json::from_slice(&metadata).unwrap();
        assert_eq!(metadata.version, "1.2.3");
        assert_eq!(metadata.sha256, "a".repeat(64));

        std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn remote_wasm_download_requires_public_https_urls() {
        for raw in [
            "http://example.com/plugin.wasm",
            "https://localhost/plugin.wasm",
            "https://plugin.local/plugin.wasm",
            "https://127.0.0.1/plugin.wasm",
            "https://example.com:8443/plugin.wasm",
            "https://user@example.com/plugin.wasm",
            "https://example.com/plugin.wasm#fragment",
        ] {
            assert!(
                !safe_remote_component_url(&reqwest::Url::parse(raw).unwrap()),
                "accepted unsafe component URL: {raw}"
            );
        }
        assert!(safe_remote_component_url(
            &reqwest::Url::parse("https://example.com/releases/plugin.wasm").unwrap()
        ));
    }

    #[test]
    fn remote_wasm_download_blocks_non_public_addresses() {
        for raw in [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "192.0.0.1",
            "192.168.1.1",
            "198.18.0.1",
            "203.0.113.1",
            "240.0.0.1",
            "::1",
            "::ffff:127.0.0.1",
            "2001:db8::1",
            "2002::1",
            "fc00::1",
            "fe80::1",
        ] {
            assert!(
                !public_download_ip(raw.parse().unwrap()),
                "accepted non-public address: {raw}"
            );
        }
        assert!(public_download_ip("1.1.1.1".parse().unwrap()));
        assert!(public_download_ip("2606:4700:4700::1111".parse().unwrap()));
    }
    #[test]
    fn forgot_password_failure_includes_legacy_diagnostic() {
        assert_eq!(
            super::forgot_password_failure_message("en", &"A fake exception."),
            "Failed to send verification mail. A fake exception."
        );
        assert_eq!(
            super::forgot_password_failure_message("zh_CN", &"A fake exception."),
            "邮件发送失败，详细信息：A fake exception."
        );
    }

    #[test]
    fn verification_email_failure_includes_legacy_diagnostic() {
        assert_eq!(
            super::verification_email_failure_message("en", &"A fake exception."),
            "We failed to send you the verification link. Detailed message A fake exception."
        );
        assert_eq!(
            super::verification_email_failure_message("zh_CN", &"A fake exception."),
            "邮件发送失败，详细信息：A fake exception."
        );
    }

    #[test]
    fn banned_player_message_uses_legacy_translations() {
        let translations = [
            ("de_DE", "Das Konto dieses Spielers wurde gebannt."),
            ("es_ES", "El dueño de este jugador ha sido baneado."),
            ("fr_FR", "Le propriétaire de ce joueur a été banni."),
            ("ko_KR", "본 사용자가 정지되었습니다."),
            ("ru_RU", "Владелец этого игрока был заблокирован."),
            ("zh_CN", "该角色拥有者已被本站封禁"),
            ("zh_TW", "該角色的所有者已被封禁。"),
        ];
        for (locale, expected) in translations {
            assert_eq!(super::player_banned_message(locale), expected, "{locale}");
        }
        assert_eq!(
            super::player_banned_message("unsupported"),
            "The owner of this player has been banned."
        );
    }

    #[test]
    fn api_root_copyright_matches_php_array_key_lookup() {
        assert_eq!(
            super::copyright_for_preference(None),
            Some(super::COPYRIGHTS[0])
        );
        assert_eq!(
            super::copyright_for_preference(Some("0")),
            Some(super::COPYRIGHTS[0])
        );
        assert_eq!(
            super::copyright_for_preference(Some("6")),
            Some(super::COPYRIGHTS[6])
        );
        assert_eq!(
            super::copyright_for_preference(Some("true")),
            Some(super::COPYRIGHTS[1])
        );
        assert_eq!(
            super::copyright_for_preference(Some("(TRUE)")),
            Some(super::COPYRIGHTS[1])
        );
        assert_eq!(
            super::copyright_for_preference(Some("false")),
            Some(super::COPYRIGHTS[0])
        );
        assert_eq!(
            super::copyright_for_preference(Some("(FALSE)")),
            Some(super::COPYRIGHTS[0])
        );
        for invalid in ["7", "01", "-1", "1.0", "invalid", ""] {
            assert_eq!(
                super::copyright_for_preference(Some(invalid)),
                None,
                "{invalid}"
            );
        }
    }

    #[test]
    fn plugin_head_links_are_rendered_with_attribute_escaping() {
        let html = super::add_plugin_head_links_to_html(
            "<html><head></head><body></body></html>",
            &serde_json::json!([{
                "rel": "stylesheet",
                "href": "https://cdn.example.test/a&b.css?x=\"quoted\"",
                "crossorigin": "anonymous"
            }]),
        );
        assert!(html.contains("<link rel=\"stylesheet\" href=\"https://cdn.example.test/a&amp;b.css?x=&quot;quoted&quot;\" crossorigin=\"anonymous\" />"));
        assert!(html.contains("</head>"));
    }

    #[test]
    fn plugin_configuration_page_preserves_app_subpaths_and_escapes_values() {
        let page = PluginConfigurationPage {
            locale: "zh_CN".to_owned(),
            base_url: "https://example.test/skin".to_owned(),
            plugin_name: "demo-plugin".to_owned(),
            heading: "插件设置".to_owned(),
            configuration_label: "JSON 配置".to_owned(),
            description: "设置说明".to_owned(),
            configuration: r#"{"unsafe":"</textarea><script>alert(1)</script>"}"#.to_owned(),
            message: String::new(),
            save_label: "保存".to_owned(),
            back_label: "返回插件管理".to_owned(),
        };
        let html = super::add_web_csrf_to_html(&page.render().unwrap(), "a".repeat(48).as_str());

        assert!(
            html.contains("action=\"https://example.test/skin/admin/plugins/config/demo-plugin\"")
        );
        assert!(html.contains(
            r#"<form method="post" action="https://example.test/skin/admin/plugins/config/demo-plugin"><input type="hidden" name="_token" value=""#
        ));
        assert!(html.contains("href=\"https://example.test/skin/admin/plugins/manage\""));
        assert!(html.contains("JSON 配置"));
        assert!(!html.contains("<script>alert(1)</script>"));
    }

    #[test]
    fn home_page_keeps_public_links_without_a_frontend_bundle() {
        let page = HomePage {
            site_name: "Example Skin".to_owned(),
            locale: "en".to_owned(),
            title: "Skin Server".to_owned(),
            login: "Log in".to_owned(),
            browse_skinlib: "Browse skin library".to_owned(),
            favicon: String::new(),
            theme_color: "#17a2b8",
            meta_keywords: String::new(),
            meta_description: String::new(),
            meta_extras: String::new(),
            cdn_address: String::new(),
            home_css_available: false,
            home_stylesheet: String::new(),
            frontend_style_available: false,
            frontend_stylesheet: String::new(),
            frontend_script_available: false,
            frontend_script: String::new(),
            home_script_available: false,
            home_script: String::new(),
            custom_css: String::new(),
            custom_js: String::new(),
            frontend_globals_b64: String::new(),
        };
        let html = page.render().unwrap();

        assert!(html.contains("id=\"home-app\""));
        assert!(html.contains("href=\"/auth/login\""));
        assert!(html.contains("Browse skin library"));
        assert!(html.contains("href=\"/skinlib\""));
        assert!(!html.contains("window.blessing"));
    }

    #[test]
    fn database_setup_env_writer_preserves_existing_values_and_escapes_credentials() {
        let path = std::env::temp_dir().join(format!(
            "blessing-skin-setup-env-{}.env",
            super::setup_csrf_token()
        ));
        std::fs::write(
            &path,
            "# retained comment\nAPP_URL=\"https://skin.example.test\"\nDB_CONNECTION=mysql\nDB_PASSWORD=old\n",
        )
        .unwrap();
        let password = r#"two words; "quoted" \ #value"#;
        super::write_env_file(
            &path,
            &[
                ("DB_CONNECTION", "pgsql".to_owned()),
                ("DB_PASSWORD", password.to_owned()),
                ("DB_PREFIX", "bs_".to_owned()),
            ],
        )
        .unwrap();
        let parsed = dotenvy::from_path_iter(&path)
            .unwrap()
            .collect::<Result<std::collections::HashMap<_, _>, _>>()
            .unwrap();
        assert_eq!(parsed.get("APP_URL").unwrap(), "https://skin.example.test");
        assert_eq!(parsed.get("DB_CONNECTION").unwrap(), "pgsql");
        assert_eq!(parsed.get("DB_PASSWORD").unwrap(), password);
        assert_eq!(parsed.get("DB_PREFIX").unwrap(), "bs_");
        std::fs::remove_file(path).unwrap();
    }

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
    fn legacy_api_rate_limit_is_sixty_per_key_and_resets_after_a_minute() {
        let limiter = super::ApiRateLimiter::default();
        let start = std::time::Instant::now();
        let key = "user:42".to_owned();
        for attempt in 1..=super::LEGACY_API_RATE_LIMIT {
            let decision = limiter.hit(key.clone(), start);
            assert!(decision.allowed);
            assert_eq!(decision.remaining, super::LEGACY_API_RATE_LIMIT - attempt);
        }
        let denied = limiter.hit(key.clone(), start);
        assert!(!denied.allowed);
        assert_eq!(denied.remaining, 0);
        assert_eq!(denied.retry_after, super::LEGACY_API_RATE_WINDOW);
        assert!(limiter.hit("ip:192.0.2.1".to_owned(), start).allowed);
        assert!(
            limiter
                .hit(key, start + super::LEGACY_API_RATE_WINDOW)
                .allowed
        );
    }

    #[tokio::test]
    async fn legacy_api_throttle_returns_headers_and_limits_each_ip() {
        use axum::{
            Router,
            body::{Body, to_bytes},
            extract::ConnectInfo,
            http::{Request, StatusCode},
            routing::{any, get},
        };
        use tower::ServiceExt;

        let app = Router::new()
            .route("/api", any(|| async { StatusCode::OK }))
            .route("/health/live", get(|| async { StatusCode::OK }));
        let app = super::legacy_api_throttle_layer(app, None);
        let address: std::net::SocketAddr = "192.0.2.7:3210".parse().unwrap();
        for expected_remaining in (0..super::LEGACY_API_RATE_LIMIT).rev() {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/api")
                        .extension(ConnectInfo(address))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response
                    .headers()
                    .get("x-ratelimit-limit")
                    .unwrap()
                    .to_str()
                    .unwrap(),
                "60"
            );
            assert_eq!(
                response
                    .headers()
                    .get("x-ratelimit-remaining")
                    .unwrap()
                    .to_str()
                    .unwrap(),
                expected_remaining.to_string()
            );
        }

        let blocked = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api")
                    .extension(ConnectInfo(address))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);
        let retry_after = blocked
            .headers()
            .get("retry-after")
            .unwrap()
            .to_str()
            .unwrap()
            .parse::<u64>()
            .unwrap();
        assert!((1..=60).contains(&retry_after));
        assert!(blocked.headers().get("x-ratelimit-reset").is_some());
        let body = to_bytes(blocked.into_body(), usize::MAX).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["message"], "Too Many Attempts.");

        let other_address: std::net::SocketAddr = "192.0.2.8:3210".parse().unwrap();
        let other_client = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api")
                    .extension(ConnectInfo(other_address))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(other_client.status(), StatusCode::OK);

        let unrelated = app
            .oneshot(
                Request::builder()
                    .uri("/health/live")
                    .extension(ConnectInfo(address))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unrelated.status(), StatusCode::OK);
        assert!(unrelated.headers().get("x-ratelimit-limit").is_none());
    }

    #[test]
    fn legacy_integer_options_match_php_option_and_int_casts() {
        assert_eq!(super::legacy_option_integer(None, 17), 17);
        assert_eq!(super::legacy_option_integer(Some("true"), 17), 1);
        assert_eq!(super::legacy_option_integer(Some("(TRUE)"), 17), 1);
        assert_eq!(super::legacy_option_integer(Some("false"), 17), 0);
        assert_eq!(super::legacy_option_integer(Some("(null)"), 17), 0);
        assert_eq!(super::legacy_option_integer(Some("1.9"), 17), 1);
        assert_eq!(super::legacy_option_integer(Some("1e2"), 17), 100);
        assert_eq!(super::legacy_option_integer(Some("1.2e2"), 17), 120);
        assert_eq!(super::legacy_option_integer(Some("1e2 items"), 17), 100);
        assert_eq!(super::legacy_option_integer(Some("1e+"), 17), 1);
        assert_eq!(super::legacy_option_integer(Some(" -12.5 items"), 17), -12);
        assert_eq!(super::legacy_option_integer(Some("invalid"), 17), 0);
    }

    #[test]
    fn legacy_image_dimensions_preserve_php_integer_casts_with_safe_bounds() {
        assert_eq!(super::legacy_image_dimension(None, 200), 200);
        assert_eq!(super::legacy_image_dimension(Some("50px"), 100), 50);
        assert_eq!(super::legacy_image_dimension(Some(" 50.9 pixels"), 100), 50);
        assert_eq!(super::legacy_image_dimension(Some("1e2 items"), 100), 100);
        assert_eq!(super::legacy_image_dimension(Some("invalid"), 100), 100);
        assert_eq!(super::legacy_image_dimension(Some("0"), 100), 100);
        assert_eq!(super::legacy_image_dimension(Some("-4"), 100), 100);
        assert_eq!(super::legacy_image_dimension(Some("1025px"), 100), 100);
    }
    #[test]
    fn skinlib_paginator_preserves_query_and_builds_page_window() {
        let paginator = super::legacy_paginator_json(
            Vec::<serde_json::Value>::new(),
            2_000,
            50,
            20,
            "https://skin.example/skinlib/list",
            Some("filter=skin&keyword=white+fox&page=50"),
        );
        assert_eq!(
            paginator["first_page_url"],
            "https://skin.example/skinlib/list?filter=skin&keyword=white+fox&page=1"
        );
        assert_eq!(paginator["last_page"], 100);
        let links = paginator["links"].as_array().unwrap();
        assert_eq!(links.len(), 13);
        assert_eq!(links[0]["label"], "&laquo; Previous");
        assert_eq!(links[2]["label"], "...");
        assert_eq!(links[3]["label"], "47");
        assert_eq!(links[6]["label"], "50");
        assert_eq!(links[6]["active"], true);
        assert_eq!(links[10]["label"], "...");
        assert_eq!(links[11]["label"], "100");
        assert_eq!(links[12]["label"], "Next &raquo;");
    }
    #[test]
    fn texture_width_option_preserves_php_boolean_and_numeric_comparisons() {
        let (default_limit, default_label) = super::legacy_texture_width_limit(None);
        assert_eq!(default_limit, 8192.0);
        assert_eq!(default_label, "8192");

        let (true_limit, true_label) = super::legacy_texture_width_limit(Some("(TRUE)"));
        assert!(!(64.0 > true_limit));
        assert_eq!(true_label, "1");

        let (false_limit, false_label) = super::legacy_texture_width_limit(Some("false"));
        assert!(64.0 > false_limit);
        assert!(false_label.is_empty());

        let (null_limit, null_label) = super::legacy_texture_width_limit(Some("(null)"));
        assert!(64.0 > null_limit);
        assert!(null_label.is_empty());

        let (numeric_limit, numeric_label) = super::legacy_texture_width_limit(Some("64.5"));
        assert!(!(64.0 > numeric_limit));
        assert!(65.0 > numeric_limit);
        assert_eq!(numeric_label, "64.5");

        let (invalid_limit, invalid_label) = super::legacy_texture_width_limit(Some("invalid"));
        assert_eq!(invalid_limit, 8192.0);
        assert_eq!(invalid_label, "8192");
    }

    #[test]
    fn parses_legacy_boolean_options() {
        assert!(super::legacy_option_bool(Some("true")));
        assert!(super::legacy_option_bool(Some("(true)")));
        assert!(!super::legacy_option_bool(Some("false")));
        assert!(!super::legacy_option_bool(Some("(false)")));
        assert!(!super::legacy_option_bool(Some("0")));
        assert!(!super::legacy_option_bool(Some("")));
        assert!(super::legacy_option_bool(Some("no")));
        assert!(!super::legacy_option_bool(None));
    }
    #[test]
    fn legacy_input_object_merges_query_json_and_form_fields() {
        use std::collections::BTreeMap;

        let query = BTreeMap::from([("tid".to_owned(), "7".to_owned())]);
        let form = super::parse_legacy_input_object(
            &query,
            b"tid=8&name=My+Texture",
            Some("application/x-www-form-urlencoded"),
        )
        .unwrap();
        assert_eq!(form["tid"], "8");
        assert_eq!(form["name"], "My Texture");

        let json = super::parse_legacy_input_object(
            &query,
            br#"{"tid":9,"name":"JSON Texture"}"#,
            Some("application/json"),
        )
        .unwrap();
        assert_eq!(json["tid"], 9);
        assert_eq!(json["name"], "JSON Texture");
    }

    #[test]
    fn player_name_inputs_read_query_json_and_form_values() {
        use std::collections::BTreeMap;

        let query = BTreeMap::from([("name".to_owned(), "QueryName".to_owned())]);
        assert_eq!(
            super::parse_player_name_request(
                &query,
                br#"{"name":"JsonName"}"#,
                Some("application/json"),
            )
            .unwrap()
            .name
            .as_deref(),
            Some("JsonName")
        );
        assert_eq!(
            super::parse_player_name_request(
                &BTreeMap::new(),
                b"name=FormName",
                Some("application/x-www-form-urlencoded"),
            )
            .unwrap()
            .name
            .as_deref(),
            Some("FormName")
        );
        assert_eq!(
            super::parse_player_name_request(&query, b"", None)
                .unwrap()
                .name
                .as_deref(),
            Some("QueryName")
        );
    }
    #[test]
    fn player_texture_input_ids_read_query_json_and_form_inputs() {
        use std::collections::BTreeMap;

        let query = BTreeMap::from([
            ("skin".to_owned(), "12".to_owned()),
            ("cape".to_owned(), "13".to_owned()),
        ]);
        assert_eq!(
            super::player_texture_input_ids(
                &query,
                br#"{"skin":14,"cape":null}"#,
                Some("application/json"),
            ),
            (Some(14), None)
        );
        assert_eq!(
            super::player_texture_input_ids(
                &BTreeMap::new(),
                b"skin=21&cape=22",
                Some("application/x-www-form-urlencoded"),
            ),
            (Some(21), Some(22))
        );
        assert_eq!(
            super::player_texture_input_ids(&query, b"", None),
            (Some(12), Some(13))
        );
    }
    #[test]
    fn player_texture_clear_flags_read_query_json_and_form_inputs() {
        use std::collections::BTreeMap;

        let query = BTreeMap::from([("skin".to_owned(), "true".to_owned())]);
        assert_eq!(
            super::player_texture_clear_flags(
                &query,
                br#"{"type":["cape"]}"#,
                Some("application/json")
            ),
            (true, true)
        );
        assert_eq!(
            super::player_texture_clear_flags(
                &BTreeMap::new(),
                b"type%5B%5D=skin&cape=false",
                Some("application/x-www-form-urlencoded"),
            ),
            (true, true)
        );
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
    fn serializes_score_changes_for_plugin_events() {
        assert_eq!(
            super::user_score_updated_event(7, 5, 15),
            serde_json::json!({
                "user_id": 7,
                "previous_score": 5,
                "score": 15,
            })
        );
    }

    #[test]
    fn legacy_sign_eligibility_matches_the_database_cutoff() {
        assert!(super::legacy_sign_is_eligible("", "2026-10-05 00:00:00"));
        assert!(super::legacy_sign_is_eligible(
            "2026-10-04 23:59:59",
            "2026-10-05 00:00:00"
        ));
        assert!(!super::legacy_sign_is_eligible(
            "2026-10-05 00:00:01",
            "2026-10-05 00:00:00"
        ));
    }

    #[test]
    fn user_sign_filter_only_rejects_the_rejection_object() {
        assert_eq!(
            super::plugin_filter_rejection(&serde_json::json!(true)),
            None
        );
        assert_eq!(
            super::plugin_filter_rejection(&serde_json::json!(false)),
            None
        );
        assert_eq!(
            super::plugin_filter_rejection(&serde_json::json!({
                "rejection": "sign-in is disabled"
            })),
            Some("sign-in is disabled")
        );
    }

    #[test]
    fn user_sign_plugin_events_report_the_reward_not_the_total_score() {
        assert_eq!(
            super::user_sign_plugin_event(7, 10),
            serde_json::json!({ "user_id": 7, "score": 10 })
        );
    }

    #[test]
    fn password_reset_plugin_event_matches_profile_update_contract() {
        assert_eq!(
            super::password_reset_plugin_event(7),
            serde_json::json!({"user_id": 7, "action": "password"})
        );
    }
    #[test]
    fn validates_legacy_texture_name_rules() {
        assert!(super::valid_texture_name("skin_01", ""));
        assert!(super::valid_texture_name("Skin 01", "0"));
        assert!(super::valid_texture_name("Skin 01", "false"));
        assert!(super::valid_texture_name("Skin 01", "(false)"));
        assert!(!super::valid_texture_name("", ""));
        assert!(super::valid_texture_name("skin_01", "^[a-z0-9_]+$"));
        assert!(!super::valid_texture_name("Skin 01", "^[a-z0-9_]+$"));
        assert!(super::valid_texture_name(
            "A_skin1",
            "/^(?=.*[A-Z])[A-Za-z0-9_]+$/"
        ));
        assert!(super::valid_texture_name("skinskin", r"/^(skin)\1$/"));
        assert!(super::valid_texture_name("skin\n", "/^skin$/"));
        assert!(super::valid_texture_name("foo/bar", r"/^foo\/bar$/"));
        assert!(super::valid_texture_name("SKIN", "/^skin$/i"));
        assert!(super::valid_texture_name("皮肤", "/^皮肤$/u"));
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
    fn admin_plugin_market_page_keeps_fallback_and_frontend_mount() {
        let page = super::AdminPluginMarketPage {
            site_name: "Blessing Skin".to_owned(),
            locale: "en".to_owned(),
            base_url: "https://example.test/skin".to_owned(),
            frontend_style_available: false,
            frontend_stylesheet: String::new(),
            frontend_script_available: false,
            frontend_script: String::new(),
            frontend_globals_b64: String::new(),
        };
        let html = page.render().unwrap();
        assert!(html.contains("id=\"plugin-market\""));
        assert!(html.contains("data-base-url=\"https://example.test/skin\""));
        assert!(html.contains("/admin/plugins/market/list"));
        assert!(html.contains("/admin/plugins/market/download"));
        assert!(!html.contains("window.blessing = JSON.parse"));

        let bundled_page = super::AdminPluginMarketPage {
            site_name: "Blessing Skin".to_owned(),
            locale: "zh_CN".to_owned(),
            base_url: "https://example.test/skin".to_owned(),
            frontend_style_available: true,
            frontend_stylesheet: "https://example.test/skin/app/style.css".to_owned(),
            frontend_script_available: true,
            frontend_script: "https://example.test/skin/app/app.js".to_owned(),
            frontend_globals_b64: "eyJyb3V0ZSI6ImFkbWluL3BsdWdpbnMvbWFya2V0In0=".to_owned(),
        };
        let html = bundled_page.render().unwrap();
        assert!(html.contains("WASM 插件市场"));
        assert!(html.contains(r#"class="content"><div class="container-fluid"></div>"#));
        assert!(html.contains("https://example.test/skin/app/app.js"));
        assert!(html.contains("window.blessing = JSON.parse"));
    }
    #[test]
    fn admin_plugins_page_keeps_inline_fallback_without_frontend_bundle() {
        let page = AdminPluginsPage {
            site_name: "Blessing Skin".to_owned(),
            locale: "en".to_owned(),
            base_url: "https://example.test/skin".to_owned(),
            can_upload: true,
            frontend_style_available: false,
            frontend_stylesheet: String::new(),
            frontend_script_available: false,
            frontend_script: String::new(),
            frontend_globals_b64: String::new(),
        };
        let html = page.render().unwrap();

        assert!(html.contains(r#"id="admin-plugins" data-can-upload="true""#));
        assert!(html.contains("href=\"https://example.test/skin/admin/plugins/market\""));
        assert!(html.contains("fetch('/admin/plugins/data'"));
        assert!(html.contains("plugin-migrate"));
        assert!(html.contains("id=\"download-form\""));
        assert!(html.contains("/admin/plugins/wget"));
        assert!(!html.contains("window.blessing = JSON.parse"));
    }

    #[test]
    fn email_verification_page_keeps_inline_fallback_without_frontend_bundle() {
        let page = EmailVerificationPage {
            site_name: "Blessing Skin".to_owned(),
            locale: "en".to_owned(),
            title: "Email Verification".to_owned(),
            prompt: "Enter your account email address.".to_owned(),
            action_url: "/auth/verify/7?signature=abc".to_owned(),
            email_label: "Email".to_owned(),
            submit_label: "Verify email".to_owned(),
            frontend_style_available: false,
            frontend_stylesheet: String::new(),
            frontend_script_available: false,
            frontend_script: String::new(),
            frontend_globals_b64: String::new(),
        };
        let html = page.render().unwrap();

        assert!(html.contains(r#"id="verify-form""#));
        assert!(html.contains("action=\"/auth/verify/7?signature=abc\""));
        assert!(!html.contains("window.blessing = JSON.parse"));
    }

    #[test]
    fn bind_email_page_keeps_inline_fallback_without_frontend_bundle() {
        let page = BindEmailPage {
            site_name: "Blessing Skin".to_owned(),
            locale: "en".to_owned(),
            frontend_style_available: false,
            frontend_stylesheet: String::new(),
            frontend_script_available: false,
            frontend_script: String::new(),
            frontend_globals_b64: String::new(),
        };
        let html = page.render().unwrap();

        assert!(html.contains(r#"id="bind-form""#));
        assert!(html.contains("/auth/bind"));
        assert!(html.contains("Email address"));
        assert!(!html.contains("window.blessing = JSON.parse"));
    }

    #[test]
    fn password_reset_page_keeps_inline_fallback_without_frontend_bundle() {
        let page = PasswordResetPage {
            site_name: "Blessing Skin".to_owned(),
            locale: "en".to_owned(),
            title: "Reset Password".to_owned(),
            prompt: "Reset your password here.".to_owned(),
            action_url: "/auth/reset/7?expires=123&signature=abc".to_owned(),
            password_label: "New password".to_owned(),
            submit_label: "Reset password".to_owned(),
            frontend_style_available: false,
            frontend_stylesheet: String::new(),
            frontend_script_available: false,
            frontend_script: String::new(),
            frontend_globals_b64: String::new(),
        };
        let html = page.render().unwrap();

        assert!(html.contains(r#"id="reset-form""#));
        assert!(html.contains("expires=123"));
        assert!(html.contains("signature=abc"));
        assert!(html.contains("Unable to reset password."));
        assert!(!html.contains("window.blessing = JSON.parse"));
    }

    #[test]
    fn forgot_page_keeps_inline_fallback_without_frontend_bundle() {
        let page = ForgotPage {
            site_name: "Blessing Skin".to_owned(),
            locale: "en".to_owned(),
            title: "Forgot Password".to_owned(),
            prompt: "Enter your account email.".to_owned(),
            email_label: "Email".to_owned(),
            captcha_label: "CAPTCHA".to_owned(),
            submit_label: "Send reset email".to_owned(),
            use_recaptcha: false,
            recaptcha_sitekey: String::new(),
            frontend_style_available: false,
            frontend_stylesheet: String::new(),
            frontend_script_available: false,
            frontend_script: String::new(),
            frontend_globals_b64: String::new(),
        };
        let html = page.render().unwrap();

        assert!(html.contains(r#"id="forgot-form""#));
        assert!(html.contains("/auth/captcha"));
        assert!(!html.contains("window.blessing = JSON.parse"));
    }

    #[test]
    fn registration_plugin_events_match_legacy_success_order_and_payloads() {
        let player = crate::database::PlayerRecord {
            pid: 11,
            uid: 7,
            name: "Alex".to_owned(),
            tid_skin: 0,
            tid_cape: 0,
            last_modified: "2026-10-05 12:00:00".to_owned(),
        };
        assert_eq!(
            super::registration_plugin_events(7, Some(&player)),
            vec![
                (
                    "auth.registration.completed",
                    serde_json::json!({"user_id": 7}),
                ),
                ("user.registered", serde_json::json!({"user_id": 7})),
                (
                    "player.added",
                    serde_json::json!({"user_id": 7, "player_id": 11, "name": "Alex"}),
                ),
                ("auth.login.ready", serde_json::json!({"user_id": 7})),
                ("auth.login.succeeded", serde_json::json!({"user_id": 7})),
                ("user.logged-in", serde_json::json!({"user_id": 7})),
            ]
        );
        assert_eq!(
            super::registration_plugin_events(7, None),
            vec![
                (
                    "auth.registration.completed",
                    serde_json::json!({"user_id": 7}),
                ),
                ("user.registered", serde_json::json!({"user_id": 7})),
                ("auth.login.ready", serde_json::json!({"user_id": 7})),
                ("auth.login.succeeded", serde_json::json!({"user_id": 7})),
                ("user.logged-in", serde_json::json!({"user_id": 7})),
            ]
        );
    }

    #[test]
    fn registration_page_keeps_inline_fallback_without_frontend_bundle() {
        let mut page = RegisterPage {
            site_name: "Blessing Skin".to_owned(),
            locale: "en".to_owned(),
            title: "Register".to_owned(),
            prompt: "Create an account.".to_owned(),
            email_label: "Email".to_owned(),
            account_label: "Player name".to_owned(),
            password_label: "Password".to_owned(),
            captcha_label: "CAPTCHA".to_owned(),
            submit_label: "Register".to_owned(),
            player_name_registration: true,
            use_recaptcha: false,
            recaptcha_sitekey: String::new(),
            rows: vec![
                "auth.rows.register.notice".to_owned(),
                "auth.rows.register.form".to_owned(),
            ],
            show_form: true,
            frontend_style_available: false,
            frontend_stylesheet: String::new(),
            frontend_script_available: false,
            frontend_script: String::new(),
            frontend_globals_b64: String::new(),
        };
        let html = page.render().unwrap();

        assert!(html.contains(r#"id="register-form""#));
        assert!(html.contains("/auth/captcha"));
        assert!(html.contains("Player name"));
        assert!(!html.contains("window.blessing = JSON.parse"));

        page.rows = vec![
            "auth.rows.register.form".to_owned(),
            "auth.rows.register.notice".to_owned(),
        ];
        let reordered = page.render().unwrap();
        assert!(
            reordered.find("id=\"register-form\"").unwrap()
                < reordered.find("Create an account.").unwrap()
        );

        page.rows = vec!["auth.rows.register.notice".to_owned()];
        page.show_form = false;
        let without_form = page.render().unwrap();
        assert!(without_form.contains("Create an account."));
        assert!(!without_form.contains("id=\"register-form\""));
        assert!(!without_form.contains("const form ="));
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
    fn normalizes_hd_skin_dimensions_for_preview_and_avatar_rendering() {
        for (texture_type, height) in [("steve", 32), ("steve", 64), ("alex", 64)] {
            let base = RgbaImage::from_fn(64, height, |x, y| {
                Rgba([(x * 3) as u8, (y * 5) as u8, (x + y) as u8, 255])
            });
            let hd = image::imageops::resize(
                &base,
                128,
                height * 2,
                image::imageops::FilterType::Nearest,
            );
            assert_eq!(
                normalize_skin_dimensions(&hd, texture_type).as_ref(),
                Some(&base)
            );
        }
        assert!(normalize_skin_dimensions(&RgbaImage::new(128, 96), "steve").is_none());
    }

    #[test]
    fn renders_square_skin_and_aspect_preserving_cape_previews() {
        let skin = RgbaImage::from_pixel(64, 64, Rgba([40, 80, 120, 255]));
        let skin_preview = render_skin_preview(&skin, true, 200);
        assert!(skin_preview.width() > 300 && skin_preview.height() > 300);
        assert!(skin_preview.pixels().any(|(_, _, pixel)| pixel[3] > 0));

        let mut cape = RgbaImage::from_pixel(64, 32, Rgba([0, 0, 0, 255]));
        for y in 1..17 {
            for x in 1..11 {
                cape.put_pixel(x, y, Rgba([10, 120, 30, 255]));
            }
        }
        let cape_preview = render_cape_preview(&cape, 160);
        assert_eq!((cape_preview.width(), cape_preview.height()), (100, 160));
        assert_eq!(cape_preview.get_pixel(0, 0), Rgba([10, 120, 30, 255]));

        let cape_hd = image::imageops::resize(&cape, 128, 64, image::imageops::FilterType::Nearest);
        let cape_hd_preview = render_cape_preview(&cape_hd, 160);
        assert_eq!(cape_preview, cape_hd_preview);
    }

    #[test]
    fn invalid_skin_avatar_uses_the_legacy_default_image() {
        let skin = RgbaImage::new(8, 8);
        for three_d in [false, true] {
            assert_eq!(
                render_skin_avatar(&skin, three_d).to_rgba8(),
                super::default_avatar(three_d).to_rgba8()
            );
        }
    }

    #[test]
    fn renders_skin_face_and_isometric_avatar_layers() {
        let mut skin = RgbaImage::from_pixel(64, 64, Rgba([0, 0, 0, 0]));
        for y in 0..16 {
            for x in 0..32 {
                skin.put_pixel(x, y, Rgba([220, 30, 40, 255]));
            }
        }
        let flat = render_skin_avatar(&skin, false);
        assert!(flat.width() > 100 && flat.height() > 100);
        assert!(flat.pixels().any(|(_, _, pixel)| pixel[0] >= 150
            && pixel[1] < 100
            && pixel[2] < 100
            && pixel[3] > 0));

        let isometric = render_skin_avatar(&skin, true);
        assert!(isometric.width() > 100 && isometric.height() > 100);
        assert!(isometric.pixels().any(|(_, _, pixel)| pixel[0] >= 150
            && pixel[1] < 100
            && pixel[2] < 100
            && pixel[3] > 0));
        assert!(isometric.pixels().any(|(_, _, pixel)| pixel[3] > 0));
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

    #[test]
    fn weak_if_none_match_values_match_legacy_image_etags() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::IF_NONE_MATCH,
            axum::http::HeaderValue::from_static("\"older\", W/\"current\""),
        );
        assert!(super::header_has_etag(&headers, "\"current\""));

        headers.insert(
            axum::http::header::IF_NONE_MATCH,
            axum::http::HeaderValue::from_static("W/\"older\""),
        );
        assert!(!super::header_has_etag(&headers, "\"current\""));
        headers.insert(
            axum::http::header::IF_NONE_MATCH,
            axum::http::HeaderValue::from_static("*"),
        );
        assert!(super::header_has_etag(&headers, "\"current\""));
    }

    #[tokio::test]
    async fn api_user_rejects_requests_without_a_bearer_token() {
        use axum::{
            body::{Body, to_bytes},
            http::{
                Request, StatusCode,
                header::{CACHE_CONTROL, CONTENT_TYPE, ETAG, IF_NONE_MATCH, SET_COOKIE},
            },
        };
        use base64::Engine as _;
        use sqlx::sqlite::SqliteConnectOptions;
        use std::{path::PathBuf, sync::Arc};
        use tower::ServiceExt;

        let config = crate::config::Config {
            bind: "127.0.0.1:3000".parse().unwrap(),
            rust_version: "test",
            legacy_app_version: "test".to_owned(),
            locale: "en".to_owned(),
            fallback_locale: "en".to_owned(),
            database: crate::config::DatabaseConfig {
                connection: crate::config::DatabaseConnection::Sqlite(SqliteConnectOptions::new()),
                table_prefix: String::new(),
                driver: "SQLite".to_owned(),
                host: None,
                port: None,
                username: None,
                database: "test.sqlite".to_owned(),
            },
            textures_dir: PathBuf::new(),
            plugins_dir: PathBuf::new(),
            wasm_plugin_registry_url: None,
            rust_releases_api_url: None,
            app_url: "http://localhost".to_owned(),
            passport_public_key: None,
            passport_private_key: None,
            password_method: "BCRYPT".to_owned(),
            password_salt: String::new(),
            bcrypt_rounds: 10,
            app_key: None,
            session_lifetime_seconds: 7_200,
            mail: crate::config::MailConfig::default(),
        };
        let setup_token = super::setup_csrf_token();
        let setup_storage = std::env::temp_dir().join(format!("blessing-skin-setup-{setup_token}"));
        let setup_env = std::env::temp_dir().join(format!("blessing-skin-env-{setup_token}"));
        let setup_database_file =
            std::env::temp_dir().join(format!("blessing-skin-db-{setup_token}.sqlite"));
        let app = router(crate::AppState {
            config: Arc::new(config.clone()),
            database: None,
            passport_key: None,
            passport_signing_key: None,
            session_key: None,
            revoked_web_sessions: Default::default(),
            login_failures: Default::default(),
            captcha_challenges: Default::default(),
            mail_limits: Default::default(),
            image_cache: crate::image_cache::ImageCache::shared(),
            storage_dir: setup_storage,
            env_file: setup_env.clone(),
            public_dir: {
                let path = std::env::temp_dir().join(format!("blessing-skin-public-{setup_token}"));
                std::fs::create_dir_all(path.join("app")).unwrap();
                std::fs::write(path.join("app/main.012abcd.js"), b"window.fixture = true;")
                    .unwrap();
                std::fs::write(path.join("app/app.012abcd.js"), b"window.app = true;").unwrap();
                path
            },
            wasm_plugins: Vec::new(),
            wasm_plugin_load_failures: Vec::new(),
            wasm_plugin_readmes: Vec::new(),
            wasm_plugin_configurations: Vec::new(),
            wasm_runtime: crate::plugin_runtime::PluginRuntime::shared_empty(),
        });
        let login_before_install = app
            .clone()
            .oneshot(Request::get("/auth/login").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(login_before_install.status(), StatusCode::FOUND);
        assert_eq!(
            login_before_install
                .headers()
                .get(axum::http::header::LOCATION)
                .unwrap(),
            "/setup"
        );
        let welcome_page = app
            .clone()
            .oneshot(Request::get("/setup").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(welcome_page.status(), StatusCode::OK);
        let welcome_html = String::from_utf8(
            to_bytes(welcome_page.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(welcome_html.contains("Welcome"));
        assert!(welcome_html.contains("http://localhost/app/app.012abcd.js"));
        let encoded_welcome_globals = welcome_html
            .split("atob('")
            .nth(1)
            .unwrap()
            .split("')")
            .next()
            .unwrap();
        let welcome_globals_bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded_welcome_globals)
            .unwrap();
        let welcome_globals: serde_json::Value =
            serde_json::from_slice(&welcome_globals_bytes).unwrap();
        assert_eq!(welcome_globals["route"], "setup");
        assert_eq!(welcome_globals["extra"]["setup_welcome"]["version"], "test");
        let asset = app
            .clone()
            .oneshot(
                Request::get("/app/main.012abcd.js")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(asset.status(), StatusCode::OK);
        assert_eq!(
            asset.headers().get(CONTENT_TYPE).unwrap(),
            "application/javascript; charset=utf-8"
        );
        assert_eq!(
            asset.headers().get(CACHE_CONTROL).unwrap(),
            "public, max-age=31536000, immutable"
        );
        let asset_etag = asset
            .headers()
            .get(ETAG)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(
            to_bytes(asset.into_body(), usize::MAX)
                .await
                .unwrap()
                .as_ref(),
            b"window.fixture = true;"
        );
        let cached_asset = app
            .clone()
            .oneshot(
                Request::get("/app/main.012abcd.js")
                    .header(IF_NONE_MATCH, &asset_etag)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cached_asset.status(), StatusCode::NOT_MODIFIED);
        let unsafe_asset = app
            .clone()
            .oneshot(
                Request::get("/app/%2e%2e/Cargo.toml")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(unsafe_asset.status(), StatusCode::OK);
        let database_page = app
            .clone()
            .oneshot(Request::get("/setup/database").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(database_page.status(), StatusCode::OK);
        let setup_cookie = database_page
            .headers()
            .get(SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let database_page_html = String::from_utf8(
            to_bytes(database_page.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(database_page_html.contains("id=\"setup-database-app\""));
        assert!(database_page_html.contains("http://localhost/app/app.012abcd.js"));
        let encoded_database_globals = database_page_html
            .split("atob('")
            .nth(1)
            .unwrap()
            .split("')")
            .next()
            .unwrap();
        let database_globals_bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded_database_globals)
            .unwrap();
        let database_globals: serde_json::Value =
            serde_json::from_slice(&database_globals_bytes).unwrap();
        assert_eq!(database_globals["route"], "setup/database");
        assert_eq!(
            database_globals["extra"]["setup_database"]["driver"],
            "sqlite"
        );
        assert_eq!(
            database_globals["extra"]["setup_database"]["csrf"],
            setup_cookie.split_once('=').unwrap().1
        );
        let second_database_page = app
            .clone()
            .oneshot(
                Request::get("/setup/database")
                    .header("cookie", &setup_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let second_setup_cookie = second_database_page
            .headers()
            .get(SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        assert_eq!(second_setup_cookie, setup_cookie);
        let database_form = form_urlencoded::Serializer::new(String::new())
            .append_pair("csrf", setup_cookie.split_once('=').unwrap().1)
            .append_pair("type", "sqlite")
            .append_pair("host", "")
            .append_pair("port", "")
            .append_pair("username", "")
            .append_pair("password", "")
            .append_pair("db", setup_database_file.to_str().unwrap())
            .append_pair("prefix", "setup_")
            .finish();
        let database_saved = app
            .clone()
            .oneshot(
                Request::post("/setup/database")
                    .header("cookie", &setup_cookie)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(database_form.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(database_saved.status(), StatusCode::OK);
        let database_saved_html = String::from_utf8(
            to_bytes(database_saved.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(database_saved_html.contains("connection succeeded"));
        let database_updated_with_put = app
            .clone()
            .oneshot(
                Request::put(format!("/setup/database?{database_form}"))
                    .header("cookie", &setup_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(database_updated_with_put.status(), StatusCode::OK);
        let database_updated_html = String::from_utf8(
            to_bytes(database_updated_with_put.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(database_updated_html.contains("connection succeeded"));
        let saved_settings = dotenvy::from_path_iter(&setup_env)
            .unwrap()
            .collect::<Result<std::collections::HashMap<_, _>, _>>()
            .unwrap();
        assert_eq!(saved_settings.get("DB_CONNECTION").unwrap(), "sqlite");
        assert_eq!(saved_settings.get("DB_PREFIX").unwrap(), "setup_");
        assert_eq!(
            saved_settings.get("DB_DATABASE").unwrap(),
            setup_database_file.to_str().unwrap()
        );
        let missing_csrf = app
            .clone()
            .oneshot(
                Request::post("/setup/finish")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("csrf=missing&email=admin%40example.test&nickname=Admin&password=correct%20horse&password_confirmation=correct%20horse&site_name=Test"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing_csrf.status(), StatusCode::FORBIDDEN);
        let info_before_restart = app
            .clone()
            .oneshot(Request::get("/setup/info").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(info_before_restart.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            info_before_restart
                .headers()
                .get(axum::http::header::LOCATION)
                .unwrap(),
            "/setup/database"
        );
        std::fs::remove_file(&setup_env).unwrap();
        std::fs::remove_file(&setup_database_file).unwrap();
        std::fs::remove_dir_all(
            std::env::temp_dir().join(format!("blessing-skin-public-{setup_token}")),
        )
        .unwrap();

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
        let users_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/admin/users")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(users_response.status(), StatusCode::UNAUTHORIZED);
        let closet_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/admin/closet/7")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(closet_response.status(), StatusCode::UNAUTHORIZED);
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

        let finish_token = super::setup_csrf_token();
        let finish_database_file =
            std::env::temp_dir().join(format!("blessing-skin-finish-db-{finish_token}.sqlite"));
        let finish_storage =
            std::env::temp_dir().join(format!("blessing-skin-finish-storage-{finish_token}"));
        let finish_public =
            std::env::temp_dir().join(format!("blessing-skin-finish-public-{finish_token}"));
        std::fs::create_dir_all(finish_public.join("app")).unwrap();
        std::fs::write(
            finish_public.join("app/app.012abcd.js"),
            b"window.setup = true;",
        )
        .unwrap();
        let finish_env =
            std::env::temp_dir().join(format!("blessing-skin-finish-env-{finish_token}"));
        let mut finish_config = config.clone();
        finish_config.database = crate::config::DatabaseConfig::from_setup(
            "sqlite",
            "",
            "",
            "",
            "",
            finish_database_file.to_str().unwrap(),
            "web_",
        )
        .unwrap();
        finish_config.app_key = None;
        finish_config.passport_public_key = None;
        finish_config.passport_private_key = None;
        let finish_database =
            crate::database::DatabasePool::connect_for_install(&finish_config.database)
                .await
                .unwrap();
        let finish_app = router(crate::AppState {
            config: Arc::new(finish_config.clone()),
            database: Some(finish_database.clone()),
            passport_key: None,
            passport_signing_key: None,
            session_key: None,
            revoked_web_sessions: Default::default(),
            login_failures: Default::default(),
            captcha_challenges: Default::default(),
            mail_limits: Default::default(),
            image_cache: crate::image_cache::ImageCache::shared(),
            storage_dir: finish_storage.clone(),
            env_file: finish_env.clone(),
            public_dir: finish_public.clone(),
            wasm_plugins: Vec::new(),
            wasm_plugin_load_failures: Vec::new(),
            wasm_plugin_readmes: Vec::new(),
            wasm_plugin_configurations: Vec::new(),
            wasm_runtime: crate::plugin_runtime::PluginRuntime::shared_empty(),
        });
        let finish_page = finish_app
            .clone()
            .oneshot(Request::get("/setup/info").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(finish_page.status(), StatusCode::OK);
        let finish_cookie = finish_page
            .headers()
            .get(SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let finish_page_html = String::from_utf8(
            to_bytes(finish_page.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(finish_page_html.contains("id=\"setup-info-app\""));
        assert!(finish_page_html.contains("http://localhost/app/app.012abcd.js"));
        let encoded_finish_globals = finish_page_html
            .split("atob('")
            .nth(1)
            .unwrap()
            .split("')")
            .next()
            .unwrap();
        let finish_globals_bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded_finish_globals)
            .unwrap();
        let finish_globals: serde_json::Value =
            serde_json::from_slice(&finish_globals_bytes).unwrap();
        assert_eq!(finish_globals["route"], "setup/info");
        assert_eq!(
            finish_globals["extra"]["setup_info"]["csrf"],
            finish_cookie.split_once('=').unwrap().1
        );
        let invalid_finish_form = form_urlencoded::Serializer::new(String::new())
            .append_pair("csrf", finish_cookie.split_once('=').unwrap().1)
            .append_pair("email", "first-admin@example.test")
            .append_pair("nickname", "First admin")
            .append_pair("password", "correct horse")
            .append_pair("password_confirmation", "different horse")
            .append_pair("site_name", "Rust Skin")
            .finish();
        let invalid_finish = finish_app
            .clone()
            .oneshot(
                Request::post("/setup/finish")
                    .header("cookie", &finish_cookie)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(invalid_finish_form))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(invalid_finish.status(), StatusCode::BAD_REQUEST);
        let invalid_finish_html = String::from_utf8(
            to_bytes(invalid_finish.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(invalid_finish_html.contains("The passwords do not match."));
        assert!(invalid_finish_html.contains("http://localhost/app/app.012abcd.js"));
        let invalid_finish_globals = invalid_finish_html
            .split("atob('")
            .nth(1)
            .unwrap()
            .split("')")
            .next()
            .unwrap();
        let invalid_finish_globals = base64::engine::general_purpose::STANDARD
            .decode(invalid_finish_globals)
            .unwrap();
        let invalid_finish_globals: serde_json::Value =
            serde_json::from_slice(&invalid_finish_globals).unwrap();
        assert_eq!(invalid_finish_globals["route"], "setup/info");
        assert_eq!(
            invalid_finish_globals["extra"]["setup_info"]["error"],
            "The passwords do not match."
        );
        let finish_form = form_urlencoded::Serializer::new(String::new())
            .append_pair("csrf", finish_cookie.split_once('=').unwrap().1)
            .append_pair("nickname", "First admin")
            .append_pair("password", "correct horse")
            .append_pair("password_confirmation", "correct horse")
            .append_pair("site_name", "Rust Skin")
            .finish();
        let installed = finish_app
            .clone()
            .oneshot(
                Request::post("/setup/finish?email=first-admin%40example.test")
                    .header("cookie", &finish_cookie)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(finish_form))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(installed.status(), StatusCode::OK);
        let installed_html = String::from_utf8(
            to_bytes(installed.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(installed_html.contains("Installation complete"));
        assert!(installed_html.contains("id=\"setup-finish-app\""));
        assert!(installed_html.contains("http://localhost/app/app.012abcd.js"));
        let encoded_installed_globals = installed_html
            .split("atob('")
            .nth(1)
            .unwrap()
            .split("')")
            .next()
            .unwrap();
        let installed_globals_bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded_installed_globals)
            .unwrap();
        let installed_globals: serde_json::Value =
            serde_json::from_slice(&installed_globals_bytes).unwrap();
        assert_eq!(installed_globals["route"], "setup/finish");
        assert_eq!(installed_globals["extra"], serde_json::json!({}));
        assert!(finish_storage.join("install.lock").exists());
        let installed_admin = match &finish_database {
            crate::database::DatabasePool::Sqlite(pool) => {
                sqlx::query_as::<_, (String, String, i64, bool, String)>(
                    "SELECT email, nickname, permission, verified, password FROM web_users LIMIT 1",
                )
                .fetch_one(pool)
                .await
                .unwrap()
            }
            _ => unreachable!(),
        };
        assert_eq!(installed_admin.0, "first-admin@example.test");
        assert_eq!(installed_admin.1, "First admin");
        assert_eq!(installed_admin.2, 2);
        assert!(installed_admin.3);
        assert!(crate::auth::verify_legacy_password(
            "correct horse",
            &installed_admin.4,
            "BCRYPT",
            ""
        ));
        assert!(finish_storage.join("oauth-private.key").exists());
        assert!(finish_storage.join("oauth-public.key").exists());
        assert!(finish_storage.join("app.key").exists());
        drop(finish_app);
        if let crate::database::DatabasePool::Sqlite(pool) = finish_database {
            pool.close().await;
        }
        std::fs::remove_dir_all(&finish_storage).unwrap();
        std::fs::remove_dir_all(&finish_public).unwrap();
        std::fs::remove_file(&finish_database_file).unwrap();
        if finish_env.exists() {
            std::fs::remove_file(&finish_env).unwrap();
        }
    }

    #[test]
    fn public_user_plugin_context_excludes_private_account_fields() {
        let user = super::UserProfile {
            uid: 7,
            email: "private@example.test".to_owned(),
            nickname: "Alex".to_owned(),
            locale: Some("en".to_owned()),
            score: 12,
            avatar: 9,
            permission: 1,
            last_sign_at: String::new(),
            register_at: String::new(),
            verified: true,
            is_dark_mode: false,
        };
        let context = super::public_user_plugin_context(&user);
        assert_eq!(
            context["user"],
            serde_json::json!({
                "uid": 7,
                "nickname": "Alex",
                "score": 12,
                "avatar": 9,
                "permission": 1,
                "verified": true
            })
        );
        assert_eq!(context["user"].as_object().unwrap().len(), 6);
    }

    #[tokio::test]
    async fn login_issues_a_session_that_opens_the_user_dashboard() {
        use axum::{
            body::{Body, to_bytes},
            http::{
                Method, Request, StatusCode,
                header::{
                    CONTENT_LENGTH, CONTENT_TYPE, ETAG, IF_NONE_MATCH, LAST_MODIFIED, LOCATION,
                    SET_COOKIE,
                },
            },
        };
        use base64::Engine as _;
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
        sqlx::query("CREATE TABLE language_lines (id INTEGER PRIMARY KEY AUTOINCREMENT, \"group\" TEXT NOT NULL, \"key\" TEXT NOT NULL, text TEXT NOT NULL, created_at TEXT, updated_at TEXT, UNIQUE(\"group\", \"key\"))")
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
        sqlx::query("CREATE TABLE notifications (id TEXT PRIMARY KEY, type TEXT NOT NULL, notifiable_type TEXT NOT NULL, notifiable_id INTEGER NOT NULL, data TEXT NOT NULL, read_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)")
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
        let unbound_password = bcrypt::hash("correct horse", 4).unwrap();
        sqlx::query("INSERT INTO users (uid,email,nickname,locale,score,avatar,password,permission,last_sign_at,register_at,verified,is_dark_mode) VALUES (9,'','Unbound','en',0,0,?,0,'','',1,0)")
            .bind(unbound_password)
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

        let texture_test_dir = std::env::temp_dir().join(format!(
            "blessing-skin-rs-preview-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&texture_test_dir).unwrap();
        let preview_skin_hash = "a".repeat(64);
        let preview_cape_hash = "b".repeat(64);
        for (hash, width, height, color) in [
            (&preview_skin_hash, 64, 64, Rgba([40, 80, 120, 255])),
            (&preview_cape_hash, 64, 32, Rgba([10, 120, 30, 255])),
        ] {
            let mut image_bytes = Vec::new();
            image::DynamicImage::ImageRgba8(RgbaImage::from_pixel(width, height, color))
                .write_to(
                    &mut std::io::Cursor::new(&mut image_bytes),
                    ImageFormat::Png,
                )
                .unwrap();
            std::fs::write(texture_test_dir.join(hash), image_bytes).unwrap();
        }

        let secret = "a test APP_KEY with enough entropy".to_owned();
        let config = crate::config::Config {
            bind: "127.0.0.1:3000".parse().unwrap(),
            rust_version: "0.1.0-test",
            legacy_app_version: "6.0.2".to_owned(),
            locale: "en".to_owned(),
            fallback_locale: "en".to_owned(),
            database: crate::config::DatabaseConfig {
                connection: crate::config::DatabaseConnection::Sqlite(
                    sqlx::sqlite::SqliteConnectOptions::new(),
                ),
                table_prefix: String::new(),
                driver: "SQLite".to_owned(),
                host: None,
                port: None,
                username: None,
                database: "test.sqlite".to_owned(),
            },
            textures_dir: texture_test_dir.clone(),
            plugins_dir: PathBuf::new(),
            wasm_plugin_registry_url: None,
            rust_releases_api_url: None,
            app_url: "http://localhost".to_owned(),
            passport_public_key: None,
            passport_private_key: None,
            password_method: "BCRYPT".to_owned(),
            password_salt: String::new(),
            bcrypt_rounds: 10,
            app_key: Some(secret.clone()),
            session_lifetime_seconds: 7_200,
            mail: crate::config::MailConfig {
                mailer: "array".to_owned(),
                ..crate::config::MailConfig::default()
            },
        };
        let captcha_challenges = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let setup_storage = std::env::temp_dir().join(format!(
            "blessing-skin-setup-test-{}",
            super::setup_csrf_token()
        ));
        std::fs::create_dir_all(&setup_storage).unwrap();
        std::fs::write(setup_storage.join("install.lock"), b"").unwrap();
        let public_dir = std::env::temp_dir().join(format!(
            "blessing-skin-login-public-{}",
            super::setup_csrf_token()
        ));
        std::fs::create_dir_all(public_dir.join("app/i18n")).unwrap();
        std::fs::create_dir_all(public_dir.join("uploads")).unwrap();
        std::fs::create_dir_all(public_dir.join("storage")).unwrap();
        std::fs::write(public_dir.join("uploads/banner.svg"), b"<svg>banner</svg>").unwrap();
        std::fs::write(public_dir.join("index.php"), b"<?php").unwrap();
        std::fs::write(public_dir.join(".env"), b"SECRET=private").unwrap();
        std::fs::write(public_dir.join("storage/private.png"), b"private").unwrap();
        std::fs::write(
            public_dir.join("app/app.012abcd.js"),
            "window.fixture = true;",
        )
        .unwrap();
        std::fs::write(
            public_dir.join("app/style.012abcd.css"),
            "body { color: black; }",
        )
        .unwrap();
        std::fs::write(
            public_dir.join("app/home-css.012abcd.css"),
            "body { font-size: 16px; }",
        )
        .unwrap();
        std::fs::write(
            public_dir.join("app/home.012abcd.js"),
            "window.homeFixture = true;",
        )
        .unwrap();
        std::fs::write(
            public_dir.join("app/home-css.012abcd.css"),
            "body { font-size: 16px; }",
        )
        .unwrap();
        std::fs::write(
            public_dir.join("app/home.012abcd.js"),
            "window.homeFixture = true;",
        )
        .unwrap();
        std::fs::write(
            public_dir.join("app/i18n/en.json"),
            r#"{"auth":{"login":"Log In"}}"#,
        )
        .unwrap();
        let database = crate::database::DatabasePool::Sqlite(pool.clone());
        database
            .ensure_web_session_revocations_schema("")
            .await
            .unwrap();
        let revoked_web_sessions =
            Arc::new(std::sync::RwLock::new(std::collections::HashMap::new()));
        let app = router(crate::AppState {
            config: Arc::new(config),
            database: Some(database.clone()),
            passport_key: None,
            passport_signing_key: None,
            session_key: Some(jsonwebtoken::EncodingKey::from_secret(secret.as_bytes())),
            revoked_web_sessions: revoked_web_sessions.clone(),
            login_failures: Default::default(),
            captcha_challenges: captcha_challenges.clone(),
            mail_limits: Default::default(),
            image_cache: crate::image_cache::ImageCache::shared(),
            storage_dir: setup_storage.clone(),
            env_file: std::path::PathBuf::from(".env"),
            public_dir: public_dir.clone(),
            wasm_plugins: Vec::new(),
            wasm_plugin_load_failures: Vec::new(),
            wasm_plugin_readmes: Vec::new(),
            wasm_plugin_configurations: Vec::new(),
            wasm_runtime: crate::plugin_runtime::PluginRuntime::shared_empty(),
        });
        let (test_csrf_cookie, test_csrf_token) = test_web_csrf_credentials(&app, "").await;
        let api_root_response = app
            .clone()
            .oneshot(Request::get("/api").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(api_root_response.status(), StatusCode::OK);
        let api_root: serde_json::Value = serde_json::from_slice(
            &to_bytes(api_root_response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(api_root["blessing_skin"], "6.0.2");

        let public_upload = app
            .clone()
            .oneshot(
                Request::get("/uploads/banner.svg")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(public_upload.status(), StatusCode::OK);
        assert_eq!(public_upload.headers()[CONTENT_TYPE], "image/svg+xml");
        let public_upload_etag = public_upload.headers()[ETAG].clone();
        assert!(public_upload.headers().contains_key(LAST_MODIFIED));
        assert_eq!(
            to_bytes(public_upload.into_body(), usize::MAX)
                .await
                .unwrap()
                .as_ref(),
            b"<svg>banner</svg>"
        );
        let public_upload_head = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::HEAD)
                    .uri("/uploads/banner.svg")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(public_upload_head.status(), StatusCode::OK);
        assert_eq!(public_upload_head.headers()[CONTENT_LENGTH], "17");
        assert!(
            to_bytes(public_upload_head.into_body(), usize::MAX)
                .await
                .unwrap()
                .is_empty()
        );
        let cached_public_upload = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/uploads/banner.svg")
                    .header(IF_NONE_MATCH, public_upload_etag)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cached_public_upload.status(), StatusCode::NOT_MODIFIED);
        for uri in [
            "/index.php",
            "/.env",
            "/storage/private.png",
            "/uploads/%2e%2e/index.php",
        ] {
            let protected_public_path = app
                .clone()
                .oneshot(Request::get(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_ne!(protected_public_path.status(), StatusCode::OK, "{uri}");
        }

        let query_locale_page = app
            .clone()
            .oneshot(
                Request::get("/?lang=zh_TW")
                    .header("accept-language", "ru")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(query_locale_page.status(), StatusCode::OK);
        assert!(
            query_locale_page
                .headers()
                .get_all(SET_COOKIE)
                .iter()
                .any(|cookie| cookie.to_str().unwrap().starts_with("locale=zh_TW;"))
        );
        let query_locale_html = String::from_utf8(
            to_bytes(query_locale_page.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(query_locale_html.contains("<html lang=\"zh_TW\">"));

        let cookie_locale_page = app
            .clone()
            .oneshot(
                Request::get("/auth/login")
                    .header(
                        "cookie",
                        format!("{}; {}", "locale=en_US", test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .header("accept-language", "ru")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cookie_locale_page.status(), StatusCode::OK);
        let cookie_locale_html = String::from_utf8(
            to_bytes(cookie_locale_page.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(cookie_locale_html.contains("<html lang=\"en\">"));

        let browser_locale_page = app
            .clone()
            .oneshot(
                Request::get("/auth/login")
                    .header("accept-language", "fr-CA;q=1, ru;q=0.9, en;q=0.5")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(browser_locale_page.status(), StatusCode::OK);
        let browser_locale_html = String::from_utf8(
            to_bytes(browser_locale_page.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(browser_locale_html.contains("<html lang=\"ru_RU\">"));

        let invalid_locale_page = app
            .clone()
            .oneshot(
                Request::get("/auth/login?lang=fr-CA")
                    .header("accept-language", "ru")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(invalid_locale_page.status(), StatusCode::OK);
        assert!(
            invalid_locale_page
                .headers()
                .get_all(SET_COOKIE)
                .iter()
                .any(|cookie| cookie.to_str().unwrap().starts_with("locale=en;"))
        );
        let invalid_locale_html = String::from_utf8(
            to_bytes(invalid_locale_page.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(invalid_locale_html.contains("<html lang=\"en\">"));

        let api_locale_response = app
            .clone()
            .oneshot(Request::get("/api?lang=zh_TW").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert!(
            !api_locale_response
                .headers()
                .get_all(SET_COOKIE)
                .iter()
                .any(|cookie| cookie.to_str().unwrap().starts_with("locale="))
        );

        let setup_page = app
            .clone()
            .oneshot(Request::get("/setup").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(setup_page.status(), StatusCode::OK);
        let setup_html = String::from_utf8(
            to_bytes(setup_page.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(setup_html.contains("Already installed"));
        let change_password = app
            .clone()
            .oneshot(
                Request::get("/.well-known/change-password")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(change_password.status(), StatusCode::FOUND);
        assert_eq!(
            change_password.headers().get(LOCATION).unwrap(),
            "/user/profile"
        );
        let now = jsonwebtoken::get_current_timestamp();
        let unbound_claims = crate::auth::WebSessionClaims {
            jti: None,
            sub: "9".to_owned(),
            iat: now,
            exp: now + 3600,
            remember: false,
        };
        let unbound_token = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
            &unbound_claims,
            &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();
        let unbound_cookie = format!("blessing_skin_session={unbound_token}");
        let bind_page = session_request(&app, &unbound_cookie, "GET", "/auth/bind", None).await;
        assert_eq!(bind_page.status(), StatusCode::OK);
        let bind_html = String::from_utf8(
            to_bytes(bind_page.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(bind_html.contains("Bind your email"));
        assert!(bind_html.contains("http://localhost/app/style.012abcd.css"));
        assert!(bind_html.contains("http://localhost/app/app.012abcd.js"));
        let encoded_bind_globals = bind_html
            .split("atob('")
            .nth(1)
            .unwrap()
            .split("')")
            .next()
            .unwrap();
        let bind_globals_bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded_bind_globals)
            .unwrap();
        let bind_globals: serde_json::Value = serde_json::from_slice(&bind_globals_bytes).unwrap();
        assert_eq!(bind_globals["route"], "auth/bind");
        let duplicate_email = session_request(
            &app,
            &unbound_cookie,
            "POST",
            "/auth/bind",
            Some(r#"{"email":"alex@example.test"}"#),
        )
        .await;
        assert_eq!(duplicate_email.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let duplicate_email: serde_json::Value = serde_json::from_slice(
            &to_bytes(duplicate_email.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            duplicate_email["errors"]["email"][0],
            "The email has already been taken."
        );
        let bind_response = session_request(
            &app,
            &unbound_cookie,
            "POST",
            "/auth/bind",
            Some(r#"{"email":"new-account@example.test"}"#),
        )
        .await;
        assert_eq!(bind_response.status(), StatusCode::OK);
        let bind_response: serde_json::Value = serde_json::from_slice(
            &to_bytes(bind_response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(bind_response["data"]["redirectTo"], "/user");
        let bound_email: String = sqlx::query_scalar("SELECT email FROM users WHERE uid = 9")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(bound_email, "new-account@example.test");
        let bound_verified: bool = sqlx::query_scalar("SELECT verified FROM users WHERE uid = 9")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(bound_verified);
        let bound_page = session_request(&app, &unbound_cookie, "GET", "/user/profile", None).await;
        assert_eq!(bound_page.status(), StatusCode::OK);
        let already_bound = session_request(&app, &unbound_cookie, "GET", "/auth/bind", None).await;
        assert_eq!(already_bound.status(), StatusCode::SEE_OTHER);
        assert_eq!(already_bound.headers().get("location").unwrap(), "/user");

        let locale_change = app
            .clone()
            .oneshot(
                Request::get("/user/profile?lang=zh_TW")
                    .header(
                        "cookie",
                        format!("{}; {}", &unbound_cookie, test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(locale_change.status(), StatusCode::OK);
        assert!(
            locale_change
                .headers()
                .get_all(SET_COOKIE)
                .iter()
                .any(|cookie| cookie.to_str().unwrap().starts_with("locale=zh_TW;"))
        );
        assert_eq!(
            crate::database::DatabasePool::Sqlite(pool.clone())
                .user_locale("", 9)
                .await
                .unwrap()
                .as_deref(),
            Some("zh_TW")
        );

        let body_locale_change = session_request(
            &app,
            &unbound_cookie,
            "POST",
            "/user/profile?lang=en",
            Some(r#"{"action":"unsupported","lang":"zh_TW"}"#),
        )
        .await;
        assert_eq!(body_locale_change.status(), StatusCode::OK);
        assert!(
            body_locale_change
                .headers()
                .get_all(SET_COOKIE)
                .iter()
                .any(|cookie| cookie.to_str().unwrap().starts_with("locale=zh_TW;"))
        );
        assert_eq!(
            crate::database::DatabasePool::Sqlite(pool.clone())
                .user_locale("", 9)
                .await
                .unwrap()
                .as_deref(),
            Some("zh_TW")
        );

        let stored_user_locale = app
            .clone()
            .oneshot(
                Request::get("/user/profile")
                    .header(
                        "cookie",
                        format!(
                            "{}; {}",
                            format!("{unbound_cookie}; locale=en"),
                            test_csrf_cookie
                        ),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .header("accept-language", "en")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(stored_user_locale.status(), StatusCode::OK);
        let stored_user_locale_html = String::from_utf8(
            to_bytes(stored_user_locale.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(stored_user_locale_html.contains("<html lang=\"zh_TW\">"));
        let homepage = app
            .clone()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(homepage.status(), StatusCode::OK);
        let homepage_html = to_bytes(homepage.into_body(), usize::MAX).await.unwrap();
        let homepage_html = String::from_utf8(homepage_html.to_vec()).unwrap();
        assert!(homepage_html.contains("Skin Server"));
        assert!(homepage_html.contains("/skinlib"));

        let avatar = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/avatar/user/7?png&size=16")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(avatar.status(), StatusCode::OK);
        assert_eq!(
            avatar
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap(),
            "image/png"
        );
        assert!(
            avatar
                .headers()
                .get(axum::http::header::CACHE_CONTROL)
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("public, max-age=")
        );
        let avatar_etag = avatar
            .headers()
            .get(axum::http::header::ETAG)
            .unwrap()
            .clone();
        let avatar_bytes = to_bytes(avatar.into_body(), usize::MAX).await.unwrap();
        let decoded_avatar =
            image::load_from_memory_with_format(&avatar_bytes, ImageFormat::Png).unwrap();
        assert_eq!((decoded_avatar.width(), decoded_avatar.height()), (16, 16));
        let cached_avatar = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/avatar/user/7?png&size=16")
                    .header(axum::http::header::IF_NONE_MATCH, avatar_etag)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cached_avatar.status(), StatusCode::NOT_MODIFIED);

        let avatar_webp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/avatar/player/Alex?3d&size=24")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(avatar_webp.status(), StatusCode::OK);
        assert_eq!(
            avatar_webp
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap(),
            "image/webp"
        );
        let avatar_webp = to_bytes(avatar_webp.into_body(), usize::MAX).await.unwrap();
        let decoded_avatar = image::load_from_memory(&avatar_webp).unwrap();
        assert_eq!((decoded_avatar.width(), decoded_avatar.height()), (24, 24));

        sqlx::query("UPDATE users SET permission = -1 WHERE uid = 7")
            .execute(&pool)
            .await
            .unwrap();
        let banned_player_avatar = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/avatar/player/Alex")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(banned_player_avatar.status(), StatusCode::OK);
        sqlx::query("UPDATE users SET permission = 1 WHERE uid = 7")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO options (option_name,option_value) VALUES ('recaptcha_invisible','(true)')")
            .execute(&pool)
            .await
            .unwrap();
        let login_page = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/auth/login?redirect_to=%2Fskinlib")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login_page.status(), StatusCode::OK);
        let login_html = to_bytes(login_page.into_body(), usize::MAX).await.unwrap();
        let login_html = String::from_utf8(login_html.to_vec()).unwrap();
        assert!(login_html.contains("Email or player name"));
        assert!(login_html.contains("id=\"login-app\""));
        assert!(login_html.contains("http://localhost/app/style.012abcd.css"));
        assert!(login_html.contains("http://localhost/app/app.012abcd.js"));
        let encoded_globals = login_html
            .split("atob('")
            .nth(1)
            .unwrap()
            .split("')")
            .next()
            .unwrap();
        let globals_bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded_globals)
            .unwrap();
        let globals: serde_json::Value = serde_json::from_slice(&globals_bytes).unwrap();
        assert_eq!(globals["route"], "auth/login");
        assert_eq!(globals["base_url"], "http://localhost");
        assert_eq!(globals["extra"]["redirectTo"], "/skinlib");
        assert_eq!(globals["extra"]["invisible"], true);
        assert_eq!(globals["i18n"]["auth"]["login"], "Log In");

        for (method, path, body) in [
            ("GET", "/auth/login", None),
            ("GET", "/auth/register", None),
            ("GET", "/auth/forgot", None),
            ("GET", "/auth/reset/7?signature=expired", None),
            ("POST", "/auth/login", Some("{}")),
            ("POST", "/auth/register", Some("{}")),
            ("POST", "/auth/forgot", Some("{}")),
            ("POST", "/auth/reset/7?signature=expired", Some("{}")),
        ] {
            let response = session_request(&app, &unbound_cookie, method, path, body).await;
            assert_eq!(response.status(), StatusCode::FOUND, "{method} {path}");
            assert_eq!(response.headers().get(LOCATION).unwrap(), "/user");
        }
        let stale_now = jsonwebtoken::get_current_timestamp();
        let stale_claims = crate::auth::WebSessionClaims {
            jti: None,
            sub: "999".to_owned(),
            iat: stale_now,
            exp: stale_now + 3600,
            remember: false,
        };
        let stale_token = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
            &stale_claims,
            &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();
        let stale_cookie = format!("blessing_skin_session={stale_token}");
        let stale_session_login =
            session_request(&app, &stale_cookie, "GET", "/auth/login", None).await;
        assert_eq!(stale_session_login.status(), StatusCode::OK);

        let forgot_page = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/auth/forgot")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(forgot_page.status(), StatusCode::OK);
        let forgot_page = String::from_utf8(
            to_bytes(forgot_page.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(forgot_page.contains("http://localhost/app/style.012abcd.css"));
        assert!(forgot_page.contains("http://localhost/app/app.012abcd.js"));
        let encoded_forgot_globals = forgot_page
            .split("atob('")
            .nth(1)
            .unwrap()
            .split("')")
            .next()
            .unwrap();
        let forgot_globals_bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded_forgot_globals)
            .unwrap();
        let forgot_globals: serde_json::Value =
            serde_json::from_slice(&forgot_globals_bytes).unwrap();
        assert_eq!(forgot_globals["route"], "auth/forgot");
        assert_eq!(forgot_globals["extra"]["invisible"], true);

        let register_page = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/auth/register")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(register_page.status(), StatusCode::OK);
        let register_html = to_bytes(register_page.into_body(), usize::MAX)
            .await
            .unwrap();
        let register_html = String::from_utf8(register_html.to_vec()).unwrap();
        assert!(register_html.contains("http://localhost/app/style.012abcd.css"));
        assert!(register_html.contains("http://localhost/app/app.012abcd.js"));
        let encoded_register_globals = register_html
            .split("atob('")
            .nth(1)
            .unwrap()
            .split("')")
            .next()
            .unwrap();
        let register_globals_bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded_register_globals)
            .unwrap();
        let register_globals: serde_json::Value =
            serde_json::from_slice(&register_globals_bytes).unwrap();
        assert_eq!(register_globals["route"], "auth/register");
        assert_eq!(register_globals["extra"]["player"], true);
        assert_eq!(register_globals["extra"]["invisible"], true);
        sqlx::query("INSERT INTO options (option_name,option_value) VALUES ('register_with_player_name','true'), ('user_initial_score','73'), ('regs_per_ip','2')")
            .execute(&pool)
            .await
            .unwrap();

        let (captcha_cookie, captcha_answer) = issue_test_captcha(&app, &captcha_challenges).await;
        let registration = submit_test_registration(
            &app,
            &captcha_cookie,
            &captcha_answer,
            "first@example.test",
            "NewGuy",
            "203.0.113.40",
        )
        .await;
        assert_eq!(registration.status(), StatusCode::OK);
        let registered_cookie = registration
            .headers()
            .get(SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let registration_body: serde_json::Value = serde_json::from_slice(
            &to_bytes(registration.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(registration_body["code"], 0);
        let registered_user: (i64, String, i64, String, i32, bool, i64, String, String) =
            sqlx::query_as("SELECT uid,nickname,score,ip,permission,verified,avatar,last_sign_at,register_at FROM users WHERE email = 'first@example.test'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(registered_user.1, "NewGuy");
        assert_eq!(
            crate::database::DatabasePool::Sqlite(pool.clone())
                .user_locale("", registered_user.0)
                .await
                .unwrap()
                .as_deref(),
            Some("en")
        );
        assert_eq!(registered_user.2, 73);
        assert_eq!(registered_user.3, "203.0.113.40");
        assert_eq!(registered_user.4, 0);
        assert!(!registered_user.5);
        assert_eq!(registered_user.6, 0);
        assert!(registered_user.7 < registered_user.8);
        let registered_player: (i64, String, i64, i64) =
            sqlx::query_as("SELECT uid,name,tid_skin,tid_cape FROM players WHERE name = 'NewGuy'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            registered_player,
            (registered_user.0, "NewGuy".to_owned(), 0, 0)
        );
        let registered_password: String =
            sqlx::query_scalar("SELECT password FROM users WHERE uid = ?")
                .bind(registered_user.0)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(crate::auth::verify_legacy_password(
            "secure pass 123",
            &registered_password,
            "BCRYPT",
            ""
        ));
        sqlx::query("INSERT INTO notifications (id,type,notifiable_type,notifiable_id,data,read_at,created_at,updated_at) VALUES (?,'App\\Notifications\\SiteMessage','App\\Models\\User',?,?,NULL,'2026-10-02 14:00:00','2026-10-02 14:00:00')")
            .bind("welcome-1")
            .bind(registered_user.0)
            .bind(r#"{"title":"Welcome note","content":"**Hello**"}"#)
            .execute(&pool)
            .await
            .unwrap();
        let registered_dashboard = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/user")
                    .header(
                        "cookie",
                        format!("{}; {}", registered_cookie.clone(), test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(registered_dashboard.status(), StatusCode::OK);
        let renewed_cookie = registered_dashboard
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find(|value| value.starts_with("blessing_skin_session="))
            .expect("authenticated web request should slide the legacy idle session");
        assert!(renewed_cookie.contains("Max-Age=7200"));
        let renewed_token = renewed_cookie
            .split(';')
            .next()
            .unwrap()
            .split_once('=')
            .unwrap()
            .1;
        let renewed_claims = jsonwebtoken::decode::<crate::auth::WebSessionClaims>(
            renewed_token,
            &jsonwebtoken::DecodingKey::from_secret(secret.as_bytes()),
            &jsonwebtoken::Validation::default(),
        )
        .unwrap()
        .claims;
        let registered_token = registered_cookie.split_once('=').unwrap().1;
        let registered_claims = jsonwebtoken::decode::<crate::auth::WebSessionClaims>(
            registered_token,
            &jsonwebtoken::DecodingKey::from_secret(secret.as_bytes()),
            &jsonwebtoken::Validation::default(),
        )
        .unwrap()
        .claims;
        assert_eq!(renewed_claims.jti, registered_claims.jti);
        assert_eq!(renewed_claims.sub, registered_claims.sub);
        assert!(!renewed_claims.remember);
        let registered_dashboard = String::from_utf8(
            to_bytes(registered_dashboard.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(registered_dashboard.contains("Welcome note"));
        assert!(registered_dashboard.contains("/user/reports"));
        assert!(registered_dashboard.contains("/user/profile"));
        assert!(registered_dashboard.contains("/user/oauth/manage"));
        assert!(registered_dashboard.contains(r#"href="/skinlib""#));
        assert!(registered_dashboard.contains("Skin library"));
        assert!(!registered_dashboard.contains(r#"href="/admin""#));

        let non_admin_dashboard =
            session_request(&app, &registered_cookie, "GET", "/admin", None).await;
        assert_eq!(non_admin_dashboard.status(), StatusCode::FORBIDDEN);
        let non_admin_chart =
            session_request(&app, &registered_cookie, "GET", "/admin/chart", None).await;
        assert_eq!(non_admin_chart.status(), StatusCode::FORBIDDEN);
        let admin_now = jsonwebtoken::get_current_timestamp();
        let admin_claims = crate::auth::WebSessionClaims {
            jti: None,
            sub: "7".to_owned(),
            iat: admin_now,
            exp: admin_now + 3600,
            remember: false,
        };
        let admin_token = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
            &admin_claims,
            &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();
        let admin_cookie = format!("blessing_skin_session={admin_token}");
        sqlx::query("UPDATE users SET email = '' WHERE uid = 7")
            .execute(&pool)
            .await
            .unwrap();
        let bound_email = session_request(
            &app,
            &admin_cookie,
            "POST",
            "/auth/bind?email=bound%40example.test",
            None,
        )
        .await;
        assert_eq!(bound_email.status(), StatusCode::SEE_OTHER);
        let bound_email: String = sqlx::query_scalar("SELECT email FROM users WHERE uid = 7")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(bound_email, "bound@example.test");
        sqlx::query("UPDATE users SET email = 'alex@example.test' WHERE uid = 7")
            .execute(&pool)
            .await
            .unwrap();
        let denied_translation_page =
            session_request(&app, &registered_cookie, "GET", "/admin/i18n", None).await;
        assert_eq!(denied_translation_page.status(), StatusCode::FORBIDDEN);
        let denied_status_page =
            session_request(&app, &registered_cookie, "GET", "/admin/status", None).await;
        assert_eq!(denied_status_page.status(), StatusCode::FORBIDDEN);
        let denied_users_page =
            session_request(&app, &registered_cookie, "GET", "/admin/users", None).await;
        assert_eq!(denied_users_page.status(), StatusCode::FORBIDDEN);
        let denied_update_page =
            session_request(&app, &registered_cookie, "GET", "/admin/update", None).await;
        assert_eq!(denied_update_page.status(), StatusCode::FORBIDDEN);

        let denied_update_admin_page =
            session_request(&app, &admin_cookie, "GET", "/admin/update", None).await;
        assert_eq!(denied_update_admin_page.status(), StatusCode::FORBIDDEN);
        let denied_update_admin_download =
            session_request(&app, &admin_cookie, "POST", "/admin/update/download", None).await;
        assert_eq!(denied_update_admin_download.status(), StatusCode::FORBIDDEN);

        let users_page = session_request(&app, &admin_cookie, "GET", "/admin/users", None).await;
        assert_eq!(users_page.status(), StatusCode::OK);
        let users_html = String::from_utf8(
            to_bytes(users_page.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(users_html.contains("User management"));
        assert!(users_html.contains(r#"class="container-fluid""#));
        assert!(users_html.contains("http://localhost/app/style.012abcd.css"));
        assert!(users_html.contains("http://localhost/app/app.012abcd.js"));
        assert!(users_html.contains("data-current-permission=\"1\""));
        let encoded_users_globals = users_html
            .split("atob('")
            .nth(1)
            .unwrap()
            .split("')")
            .next()
            .unwrap();
        let users_globals_bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded_users_globals)
            .unwrap();
        let users_globals: serde_json::Value =
            serde_json::from_slice(&users_globals_bytes).unwrap();
        assert_eq!(users_globals["route"], "admin/users");
        assert_eq!(users_globals["extra"]["currentUser"]["uid"], 7);
        assert_eq!(users_globals["extra"]["currentUser"]["permission"], 1);
        assert_eq!(users_globals["i18n"]["auth"]["login"], "Log In");
        let denied_players_page =
            session_request(&app, &registered_cookie, "GET", "/admin/players", None).await;
        assert_eq!(denied_players_page.status(), StatusCode::FORBIDDEN);
        let players_page =
            session_request(&app, &admin_cookie, "GET", "/admin/players", None).await;
        assert_eq!(players_page.status(), StatusCode::OK);
        let players_html = String::from_utf8(
            to_bytes(players_page.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(players_html.contains("Player management"));
        assert!(players_html.contains(r#"class="container-fluid""#));
        assert!(players_html.contains("http://localhost/app/style.012abcd.css"));
        assert!(players_html.contains("http://localhost/app/app.012abcd.js"));
        let encoded_players_globals = players_html
            .split("atob('")
            .nth(1)
            .unwrap()
            .split("')")
            .next()
            .unwrap();
        let players_globals_bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded_players_globals)
            .unwrap();
        let players_globals: serde_json::Value =
            serde_json::from_slice(&players_globals_bytes).unwrap();
        assert_eq!(players_globals["route"], "admin/players");
        assert_eq!(players_globals["extra"], serde_json::json!({}));
        assert_eq!(players_globals["i18n"]["auth"]["login"], "Log In");
        let denied_reports_page =
            session_request(&app, &registered_cookie, "GET", "/admin/reports", None).await;
        assert_eq!(denied_reports_page.status(), StatusCode::FORBIDDEN);
        let reports_page =
            session_request(&app, &admin_cookie, "GET", "/admin/reports", None).await;
        assert_eq!(reports_page.status(), StatusCode::OK);
        let reports_html = String::from_utf8(
            to_bytes(reports_page.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(reports_html.contains("Report management"));
        assert!(reports_html.contains(r#"class="container-fluid""#));
        assert!(reports_html.contains("http://localhost/app/style.012abcd.css"));
        assert!(reports_html.contains("http://localhost/app/app.012abcd.js"));
        let encoded_reports_globals = reports_html
            .split("atob('")
            .nth(1)
            .unwrap()
            .split("')")
            .next()
            .unwrap();
        let reports_globals_bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded_reports_globals)
            .unwrap();
        let reports_globals: serde_json::Value =
            serde_json::from_slice(&reports_globals_bytes).unwrap();
        assert_eq!(reports_globals["route"], "admin/reports");
        assert_eq!(reports_globals["extra"], serde_json::json!({}));
        assert_eq!(reports_globals["i18n"]["auth"]["login"], "Log In");

        let denied_plugins_page = session_request(
            &app,
            &registered_cookie,
            "GET",
            "/admin/plugins/manage",
            None,
        )
        .await;
        assert_eq!(denied_plugins_page.status(), StatusCode::FORBIDDEN);
        let plugins_page =
            session_request(&app, &admin_cookie, "GET", "/admin/plugins/manage", None).await;
        assert_eq!(plugins_page.status(), StatusCode::OK);
        let plugins_html = String::from_utf8(
            to_bytes(plugins_page.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        let normalized_plugins_html = plugins_html
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(normalized_plugins_html.contains("WASM plugin management"));
        assert!(plugins_html.contains(r#"class="content"><div class="container-fluid""#));
        assert!(plugins_html.contains("http://localhost/app/app.012abcd.js"));
        let encoded_plugins_globals = plugins_html
            .split("atob('")
            .nth(1)
            .unwrap()
            .split("')")
            .next()
            .unwrap();
        let plugins_globals_bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded_plugins_globals)
            .unwrap();
        let plugins_globals: serde_json::Value =
            serde_json::from_slice(&plugins_globals_bytes).unwrap();
        assert_eq!(plugins_globals["route"], "admin/plugins/manage");
        assert_eq!(plugins_globals["extra"]["wasm_plugins"], true);
        assert_eq!(plugins_globals["extra"]["can_upload"], false);
        let invalid_form_report = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/skinlib/report?tid=not-an-id")
                    .header(
                        "cookie",
                        format!("{}; {}", admin_cookie.clone(), test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("reason=source+form"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            invalid_form_report.status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let invalid_form_report: serde_json::Value = serde_json::from_slice(
            &to_bytes(invalid_form_report.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(invalid_form_report["errors"]["tid"].is_array());
        let invalid_texture_name = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/texture/2/name")
                    .header(
                        "cookie",
                        format!("{}; {}", admin_cookie.clone(), test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("name="))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            invalid_texture_name.status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let invalid_texture_name: serde_json::Value = serde_json::from_slice(
            &to_bytes(invalid_texture_name.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(invalid_texture_name["errors"]["name"].is_array());
        let invalid_texture_type = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/texture/2/type?type=invalid")
                    .header(
                        "cookie",
                        format!("{}; {}", admin_cookie.clone(), test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            invalid_texture_type.status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let invalid_texture_type: serde_json::Value = serde_json::from_slice(
            &to_bytes(invalid_texture_type.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(invalid_texture_type["errors"]["type"].is_array());
        let plugin_manage = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/plugins/manage?name=bad%20plugin")
                    .header(
                        "cookie",
                        format!("{}; {}", admin_cookie.clone(), test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("action=enable"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(plugin_manage.status(), StatusCode::OK);
        let plugin_manage: serde_json::Value = serde_json::from_slice(
            &to_bytes(plugin_manage.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(plugin_manage["code"], 1);
        assert_eq!(plugin_manage["message"], "Invalid plugin name.");
        sqlx::query("UPDATE users SET permission = 2 WHERE uid = 7")
            .execute(&pool)
            .await
            .unwrap();
        let plugin_market_download = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/plugins/market/download?name=bad%20plugin")
                    .header(
                        "cookie",
                        format!("{}; {}", admin_cookie.clone(), test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(plugin_market_download.status(), StatusCode::OK);
        let plugin_market_download: serde_json::Value = serde_json::from_slice(
            &to_bytes(plugin_market_download.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(plugin_market_download["code"], 1);
        assert_eq!(plugin_market_download["message"], "Invalid plugin name.");
        sqlx::query("UPDATE users SET permission = 1 WHERE uid = 7")
            .execute(&pool)
            .await
            .unwrap();
        let denied_plugin_market =
            session_request(&app, &admin_cookie, "GET", "/admin/plugins/market", None).await;
        assert_eq!(denied_plugin_market.status(), StatusCode::FORBIDDEN);
        let plugin_data =
            session_request(&app, &admin_cookie, "GET", "/admin/plugins/data", None).await;
        assert_eq!(plugin_data.status(), StatusCode::OK);
        let plugin_data: serde_json::Value =
            serde_json::from_slice(&to_bytes(plugin_data.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert!(plugin_data.is_array());
        let denied_plugin_config = session_request(
            &app,
            &registered_cookie,
            "PATCH",
            "/admin/plugins/config/unavailable-plugin",
            None,
        )
        .await;
        assert_eq!(denied_plugin_config.status(), StatusCode::FORBIDDEN);
        let unavailable_plugin_config = session_request(
            &app,
            &admin_cookie,
            "PATCH",
            "/admin/plugins/config/unavailable-plugin",
            None,
        )
        .await;
        assert_eq!(unavailable_plugin_config.status(), StatusCode::NOT_FOUND);
        let missing_native_form_csrf = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/plugins/config/unavailable-plugin")
                    .header(
                        "cookie",
                        format!("{}; {}", admin_cookie.clone(), test_csrf_cookie),
                    )
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("configuration=%7B%7D"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            missing_native_form_csrf.status(),
            StatusCode::from_u16(419).unwrap()
        );
        assert!(
            missing_native_form_csrf
                .headers()
                .get("content-type")
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("text/html")
        );
        let native_form_csrf = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/plugins/config/unavailable-plugin")
                    .header(
                        "cookie",
                        format!("{}; {}", admin_cookie.clone(), test_csrf_cookie),
                    )
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(format!(
                        "configuration=%7B%7D&_token={test_csrf_token}"
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(native_form_csrf.status(), StatusCode::NOT_FOUND);
        let boundary = "blessing-wasm-upload-test";
        let upload_body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"broken.wasm\"\r\nContent-Type: application/wasm\r\n\r\nnot wasm\r\n--{boundary}--\r\n"
        );
        let denied_plugin_upload = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/plugins/upload")
                    .header(
                        "cookie",
                        format!("{}; {}", admin_cookie.clone(), test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .header(
                        "content-type",
                        format!("multipart/form-data; boundary={boundary}"),
                    )
                    .body(Body::from(upload_body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied_plugin_upload.status(), StatusCode::FORBIDDEN);
        let denied_plugin_wget = session_request(
            &app,
            &admin_cookie,
            "POST",
            "/admin/plugins/wget",
            Some(r#"{"url":"https://example.com/component.wasm"}"#),
        )
        .await;
        assert_eq!(denied_plugin_wget.status(), StatusCode::FORBIDDEN);
        sqlx::query("UPDATE users SET permission = 2 WHERE uid = 7")
            .execute(&pool)
            .await
            .unwrap();
        let update_page = session_request(&app, &admin_cookie, "GET", "/admin/update", None).await;
        assert_eq!(update_page.status(), StatusCode::OK);
        let update_html = String::from_utf8(
            to_bytes(update_page.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(update_html.contains("Rust service releases"));
        assert!(update_html.contains("Current version"));
        let normalized_update_html = update_html.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(normalized_update_html.contains("Release checks are disabled."));
        assert!(update_html.contains("https://github.com/HELPMEEADICE/blessing-skin-rs/releases"));
        assert!(update_html.contains("storage"));
        let update_download =
            session_request(&app, &admin_cookie, "POST", "/admin/update/download", None).await;
        assert_eq!(update_download.status(), StatusCode::OK);
        let update_download: serde_json::Value = serde_json::from_slice(
            &to_bytes(update_download.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(update_download["code"], 1);
        assert!(
            update_download["message"]
                .as_str()
                .unwrap()
                .contains("standalone")
        );

        let market_page =
            session_request(&app, &admin_cookie, "GET", "/admin/plugins/market", None).await;
        assert_eq!(market_page.status(), StatusCode::OK);
        let market_html = String::from_utf8(
            to_bytes(market_page.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        let normalized_market_html = market_html.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(normalized_market_html.contains("WASM plugin market"));
        assert!(market_html.contains(r#"class="content"><div class="container-fluid"></div>"#));
        let encoded_market_globals = market_html
            .split("atob('")
            .nth(1)
            .unwrap()
            .split("')")
            .next()
            .unwrap();
        let market_globals_bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded_market_globals)
            .unwrap();
        let market_globals: serde_json::Value =
            serde_json::from_slice(&market_globals_bytes).unwrap();
        assert_eq!(market_globals["route"], "admin/plugins/market");
        assert_eq!(market_globals["extra"]["wasm_plugins"], true);
        let market_list = session_request(
            &app,
            &admin_cookie,
            "GET",
            "/admin/plugins/market/list",
            None,
        )
        .await;
        assert_eq!(market_list.status(), StatusCode::OK);
        let market_list: serde_json::Value =
            serde_json::from_slice(&to_bytes(market_list.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(
            market_list,
            serde_json::json!({ "configured": false, "plugins": [] })
        );
        let invalid_plugin_upload = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/plugins/upload")
                    .header(
                        "cookie",
                        format!("{}; {}", admin_cookie.clone(), test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .header(
                        "content-type",
                        format!("multipart/form-data; boundary={boundary}"),
                    )
                    .body(Body::from(upload_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(invalid_plugin_upload.status(), StatusCode::OK);
        let invalid_plugin_upload: serde_json::Value = serde_json::from_slice(
            &to_bytes(invalid_plugin_upload.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(invalid_plugin_upload["code"], 1);
        assert!(
            invalid_plugin_upload["message"]
                .as_str()
                .unwrap()
                .contains("valid Blessing Skin WASM component")
        );
        let rejected_plugin_wget = session_request(
            &app,
            &admin_cookie,
            "POST",
            "/admin/plugins/wget",
            Some(r#"{"url":"http://127.0.0.1/component.wasm"}"#),
        )
        .await;
        assert_eq!(rejected_plugin_wget.status(), StatusCode::OK);
        let rejected_plugin_wget: serde_json::Value = serde_json::from_slice(
            &to_bytes(rejected_plugin_wget.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(rejected_plugin_wget["code"], 1);
        assert!(
            rejected_plugin_wget["message"]
                .as_str()
                .unwrap()
                .contains("HTTPS")
        );
        sqlx::query("UPDATE users SET permission = 1 WHERE uid = 7")
            .execute(&pool)
            .await
            .unwrap();

        let status_page = session_request(&app, &admin_cookie, "GET", "/admin/status", None).await;
        assert_eq!(status_page.status(), StatusCode::OK);
        let status_html = String::from_utf8(
            to_bytes(status_page.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(status_html.contains("System status"));
        assert!(status_html.contains("Rust / Axum / Tokio"));
        assert!(status_html.contains("SQLite"));
        assert!(status_html.contains("No WASM plugins loaded"));
        assert!(status_html.contains("http://localhost/app/style.012abcd.css"));
        assert!(status_html.contains("http://localhost/app/app.012abcd.js"));
        let encoded_status_globals = status_html
            .split("atob('")
            .nth(1)
            .unwrap()
            .split("')")
            .next()
            .unwrap();
        let status_globals_bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded_status_globals)
            .unwrap();
        let status_globals: serde_json::Value =
            serde_json::from_slice(&status_globals_bytes).unwrap();
        assert_eq!(status_globals["route"], "admin/status");
        assert_eq!(
            status_globals["extra"]["admin_status"]["groups"][2]["fields"][0]["value"],
            "SQLite"
        );
        assert_eq!(
            status_globals["extra"]["admin_status"]["wasm_plugins"],
            serde_json::json!([])
        );
        assert_eq!(
            status_globals["extra"]["admin_status"]["page_widgets"],
            serde_json::json!(["system_info", "plugins"])
        );

        let translation_page =
            session_request(&app, &admin_cookie, "GET", "/admin/i18n", None).await;
        assert_eq!(translation_page.status(), StatusCode::OK);
        let translation_html = String::from_utf8(
            to_bytes(translation_page.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(translation_html.contains("Translation entries"));
        assert!(translation_html.contains("action=\"/admin/i18n\""));
        assert!(translation_html.contains(r#"id="table""#));
        assert!(translation_html.contains("http://localhost/app/style.012abcd.css"));
        assert!(translation_html.contains("http://localhost/app/app.012abcd.js"));
        let encoded_translation_globals = translation_html
            .split("atob('")
            .nth(1)
            .unwrap()
            .split("')")
            .next()
            .unwrap();
        let translation_globals_bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded_translation_globals)
            .unwrap();
        let translation_globals: serde_json::Value =
            serde_json::from_slice(&translation_globals_bytes).unwrap();
        assert_eq!(translation_globals["route"], "admin/i18n");
        assert_eq!(translation_globals["extra"], serde_json::json!({}));
        assert_eq!(translation_globals["i18n"]["auth"]["login"], "Log In");

        let create_body = form_urlencoded::Serializer::new(String::new())
            .append_pair("key", "nav.home")
            .append_pair("text", "Home")
            .finish();
        let created = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/i18n?group=front-end")
                    .header(
                        "cookie",
                        format!("{}; {}", admin_cookie.clone(), test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(create_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::SEE_OTHER);
        assert_eq!(created.headers()["location"], "/admin/i18n?added=1");

        let list_response =
            session_request(&app, &admin_cookie, "GET", "/admin/i18n/list?page=1", None).await;
        assert_eq!(list_response.status(), StatusCode::OK);
        let list: serde_json::Value = serde_json::from_slice(
            &to_bytes(list_response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(list["total"], 1);
        assert_eq!(list["data"][0]["group"], "front-end");
        assert_eq!(list["data"][0]["key"], "nav.home");
        assert_eq!(list["per_page"], 10);
        assert!(list["path"].as_str().unwrap().ends_with("/admin/i18n/list"));
        assert!(
            list["first_page_url"]
                .as_str()
                .unwrap()
                .ends_with("/admin/i18n/list?page=1")
        );
        assert!(list["links"].as_array().is_some());
        let line_id = list["data"][0]["id"].as_i64().unwrap();
        sqlx::query(
            "UPDATE language_lines SET text = '{\"en\":\"Home\",\"fr\":\"Accueil\"}' WHERE id = ?",
        )
        .bind(line_id)
        .execute(&pool)
        .await
        .unwrap();

        let updated = session_request(
            &app,
            &admin_cookie,
            "PUT",
            &format!("/admin/i18n/{line_id}?text=Homepage"),
            None,
        )
        .await;
        assert_eq!(updated.status(), StatusCode::OK);
        let updated: serde_json::Value =
            serde_json::from_slice(&to_bytes(updated.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(updated["code"], 0);
        let list_response =
            session_request(&app, &admin_cookie, "GET", "/admin/i18n/list?page=1", None).await;
        let list: serde_json::Value = serde_json::from_slice(
            &to_bytes(list_response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(list["data"][0]["text"]["en"], "Homepage");
        assert_eq!(list["data"][0]["text"]["fr"], "Accueil");

        let translated_page =
            session_request(&app, &admin_cookie, "GET", "/admin/i18n", None).await;
        assert_eq!(translated_page.status(), StatusCode::OK);
        let translated_html = String::from_utf8(
            to_bytes(translated_page.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        let encoded_globals = translated_html
            .split("atob('")
            .nth(1)
            .unwrap()
            .split("')")
            .next()
            .unwrap();
        let globals_bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded_globals)
            .unwrap();
        let globals: serde_json::Value = serde_json::from_slice(&globals_bytes).unwrap();
        assert_eq!(globals["i18n"]["nav"]["home"], "Homepage");

        let deleted = session_request(
            &app,
            &admin_cookie,
            "DELETE",
            &format!("/admin/i18n/{line_id}"),
            None,
        )
        .await;
        assert_eq!(deleted.status(), StatusCode::OK);
        let deleted: serde_json::Value =
            serde_json::from_slice(&to_bytes(deleted.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(deleted["code"], 0);
        let list_response =
            session_request(&app, &admin_cookie, "GET", "/admin/i18n/list?page=1", None).await;
        let list: serde_json::Value = serde_json::from_slice(
            &to_bytes(list_response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(list["total"], 0);
        let admin_dashboard = session_request(&app, &admin_cookie, "GET", "/admin", None).await;
        assert_eq!(admin_dashboard.status(), StatusCode::OK);
        let admin_dashboard = String::from_utf8(
            to_bytes(admin_dashboard.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(admin_dashboard.contains(r#"id="admin-dashboard-app""#));
        assert!(admin_dashboard.contains("http://localhost/app/style.012abcd.css"));
        assert!(admin_dashboard.contains("http://localhost/app/app.012abcd.js"));
        let encoded_admin_globals = admin_dashboard
            .split("atob('")
            .nth(1)
            .unwrap()
            .split("')")
            .next()
            .unwrap();
        let admin_globals_bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded_admin_globals)
            .unwrap();
        let admin_globals: serde_json::Value =
            serde_json::from_slice(&admin_globals_bytes).unwrap();
        assert_eq!(admin_globals["route"], "admin");
        assert_eq!(admin_globals["extra"]["dashboard_stats"]["users"], 4);
        assert_eq!(admin_globals["extra"]["dashboard_stats"]["players"], 2);
        assert_eq!(admin_globals["extra"]["dashboard_stats"]["textures"], 1);
        assert_eq!(admin_globals["extra"]["dashboard_stats"]["storage"], 8);
        assert_eq!(
            admin_globals["extra"]["page_widgets"],
            serde_json::json!(["usage", "notification", "chart"])
        );
        assert_eq!(
            admin_globals["extra"]["side_menu"],
            serde_json::json!([
                {"label": "Users", "link": "/admin/users"},
                {"label": "Players", "link": "/admin/players"},
                {"label": "Reports", "link": "/admin/reports"},
                {"label": "Internationalization", "link": "/admin/i18n"},
                {"label": "Site settings", "link": "/admin/options"},
                {"label": "System status", "link": "/admin/status"},
                {"label": "Plugins", "link": "/admin/plugins/manage"},
                {"label": "Updates", "link": "/admin/update"},
            ])
        );
        let admin_chart = session_request(&app, &admin_cookie, "GET", "/admin/chart", None).await;
        assert_eq!(admin_chart.status(), StatusCode::OK);
        let admin_chart: serde_json::Value =
            serde_json::from_slice(&to_bytes(admin_chart.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(admin_chart["labels"][0], "User Registration");
        assert_eq!(admin_chart["labels"][1], "Texture Uploads");
        assert_eq!(admin_chart["xAxis"].as_array().unwrap().len(), 31);
        assert_eq!(admin_chart["data"][0].as_array().unwrap().len(), 31);
        assert_eq!(admin_chart["data"][1].as_array().unwrap().len(), 31);
        assert_eq!(
            admin_chart["data"][0]
                .as_array()
                .unwrap()
                .iter()
                .map(|count| count.as_i64().unwrap())
                .sum::<i64>(),
            1
        );
        assert_eq!(
            admin_chart["data"][1]
                .as_array()
                .unwrap()
                .iter()
                .map(|count| count.as_i64().unwrap())
                .sum::<i64>(),
            1
        );
        let admin_user_dashboard = session_request(&app, &admin_cookie, "GET", "/user", None).await;
        assert_eq!(admin_user_dashboard.status(), StatusCode::OK);
        let admin_user_dashboard = String::from_utf8(
            to_bytes(admin_user_dashboard.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(admin_user_dashboard.contains(r#"href="/admin""#));
        assert!(admin_user_dashboard.contains(r#"id="usage-box""#));
        assert!(admin_user_dashboard.contains(r#"class="account-menu""#));
        assert!(admin_user_dashboard.contains("User Center"));
        assert!(admin_user_dashboard.contains("Web CLI"));
        assert!(admin_user_dashboard.contains(r#"srcset="/avatar/0?size=36" type="image/webp""#));
        assert!(admin_user_dashboard.contains(r#"src="/avatar/0?size=36&#38;png""#));
        assert!(admin_user_dashboard.contains(r#"class="account-badge bg-primary""#));
        assert!(admin_user_dashboard.contains("STAFF"));
        assert!(admin_user_dashboard.contains("http://localhost/app/style.012abcd.css"));
        assert!(admin_user_dashboard.contains("http://localhost/app/app.012abcd.js"));
        let encoded_dashboard_globals = admin_user_dashboard
            .split("atob('")
            .nth(1)
            .unwrap()
            .split("')")
            .next()
            .unwrap();
        let dashboard_globals_bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded_dashboard_globals)
            .unwrap();
        let dashboard_globals: serde_json::Value =
            serde_json::from_slice(&dashboard_globals_bytes).unwrap();
        assert_eq!(dashboard_globals["route"], "user");
        assert_eq!(dashboard_globals["base_url"], "http://localhost");
        assert_eq!(dashboard_globals["extra"]["unverified"], false);
        assert_eq!(
            dashboard_globals["extra"]["page_widgets"],
            serde_json::json!(["email_verification", "usage", "announcement"])
        );
        assert_eq!(
            dashboard_globals["extra"]["side_menu"],
            serde_json::json!({
                "user": [
                    {"label": "Manage players", "link": "/user/player"},
                    {"label": "Manage closet", "link": "/user/closet"},
                    {"label": "My reports", "link": "/user/reports"},
                    {"label": "Account settings", "link": "/user/profile"},
                    {"label": "OAuth apps", "link": "/user/oauth/manage"},
                ],
                "explore": [{"label": "Skin library", "link": "/skinlib"}],
            })
        );
        assert!(admin_user_dashboard.contains("Announcement"));
        assert_eq!(dashboard_globals["i18n"]["auth"]["login"], "Log In");
        let profile_page =
            session_request(&app, &registered_cookie, "GET", "/user/profile", None).await;
        assert_eq!(profile_page.status(), StatusCode::OK);
        let profile_html = String::from_utf8(
            to_bytes(profile_page.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(profile_html.contains(r#"id="profile-app""#));
        assert!(profile_html.contains("http://localhost/app/style.012abcd.css"));
        assert!(profile_html.contains("http://localhost/app/app.012abcd.js"));
        let encoded_profile_globals = profile_html
            .split("atob('")
            .nth(1)
            .unwrap()
            .split("')")
            .next()
            .unwrap();
        let profile_globals_bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded_profile_globals)
            .unwrap();
        let profile_globals: serde_json::Value =
            serde_json::from_slice(&profile_globals_bytes).unwrap();
        assert_eq!(profile_globals["route"], "user/profile");
        assert_eq!(
            profile_globals["extra"]["profile"]["email"],
            "first@example.test"
        );
        assert_eq!(
            profile_globals["extra"]["page_widgets"],
            serde_json::json!(["avatar", "password", "nickname", "email", "delete_account"])
        );
        let oauth_page =
            session_request(&app, &registered_cookie, "GET", "/user/oauth/manage", None).await;
        assert_eq!(oauth_page.status(), StatusCode::OK);
        let oauth_html = String::from_utf8(
            to_bytes(oauth_page.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(oauth_html.contains(r#"class="container-fluid""#));
        assert!(oauth_html.contains("http://localhost/app/style.012abcd.css"));
        assert!(oauth_html.contains("http://localhost/app/app.012abcd.js"));
        let encoded_oauth_globals = oauth_html
            .split("atob('")
            .nth(1)
            .unwrap()
            .split("')")
            .next()
            .unwrap();
        let oauth_globals_bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded_oauth_globals)
            .unwrap();
        let oauth_globals: serde_json::Value =
            serde_json::from_slice(&oauth_globals_bytes).unwrap();
        assert_eq!(oauth_globals["route"], "user/oauth/manage");
        assert_eq!(oauth_globals["extra"], serde_json::json!({}));
        assert_eq!(oauth_globals["i18n"]["auth"]["login"], "Log In");
        let read_notification = session_request(
            &app,
            &registered_cookie,
            "POST",
            "/user/notifications/welcome-1",
            None,
        )
        .await;
        assert_eq!(read_notification.status(), StatusCode::OK);
        let read_notification: serde_json::Value = serde_json::from_slice(
            &to_bytes(read_notification.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(read_notification["title"], "Welcome note");
        assert!(
            read_notification["content"]
                .as_str()
                .unwrap()
                .contains("<strong>Hello</strong>")
        );
        let reread_notification = session_request(
            &app,
            &registered_cookie,
            "POST",
            "/user/notifications/welcome-1",
            None,
        )
        .await;
        assert_eq!(reread_notification.status(), StatusCode::NOT_FOUND);

        let (forgot_captcha_cookie, forgot_captcha_answer) =
            issue_test_captcha(&app, &captcha_challenges).await;
        let forgot_request = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/forgot")
                    .header(
                        "cookie",
                        format!("{}; {}", forgot_captcha_cookie, test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .header("x-real-ip", "203.0.113.41")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "email": "first@example.test",
                            "captcha": forgot_captcha_answer
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(forgot_request.status(), StatusCode::OK);
        let forgot_body: serde_json::Value = serde_json::from_slice(
            &to_bytes(forgot_request.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(forgot_body["code"], 0);

        sqlx::query("INSERT INTO options (option_name,option_value) VALUES ('require_verification','true'), ('score_per_player','10'), ('return_score','true')")
            .execute(&pool)
            .await
            .unwrap();
        let verification_dashboard =
            session_request(&app, &registered_cookie, "GET", "/user", None).await;
        let verification_dashboard = String::from_utf8(
            to_bytes(verification_dashboard.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(verification_dashboard.contains("id=\"send-verification\""));
        let sent_verification = session_request(
            &app,
            &registered_cookie,
            "POST",
            "/user/email-verification",
            None,
        )
        .await;
        let sent_verification: serde_json::Value = serde_json::from_slice(
            &to_bytes(sent_verification.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(sent_verification["code"], 0);
        let repeated_verification = session_request(
            &app,
            &registered_cookie,
            "POST",
            "/user/email-verification",
            None,
        )
        .await;
        let repeated_verification: serde_json::Value = serde_json::from_slice(
            &to_bytes(repeated_verification.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(repeated_verification["code"], 1);

        let second_verification_session = login_test_account(
            &app,
            "first@example.test",
            "secure pass 123",
            "203.0.113.42",
        )
        .await;
        let sent_from_second_session = session_request(
            &app,
            &second_verification_session,
            "POST",
            "/user/email-verification",
            None,
        )
        .await;
        let sent_from_second_session: serde_json::Value = serde_json::from_slice(
            &to_bytes(sent_from_second_session.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(sent_from_second_session["code"], 0);
        let repeated_second_session = session_request(
            &app,
            &second_verification_session,
            "POST",
            "/user/email-verification",
            None,
        )
        .await;
        let repeated_second_session: serde_json::Value = serde_json::from_slice(
            &to_bytes(repeated_second_session.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(repeated_second_session["code"], 1);

        let unverified_player_page =
            session_request(&app, &registered_cookie, "GET", "/user/player", None).await;
        assert_eq!(unverified_player_page.status(), StatusCode::FORBIDDEN);
        let unverified_upload_page =
            session_request(&app, &registered_cookie, "GET", "/skinlib/upload", None).await;
        assert_eq!(unverified_upload_page.status(), StatusCode::FORBIDDEN);
        let verification_path = format!("/auth/verify/{}", registered_user.0);
        let verification_signature = super::signature_hex(&secret, &verification_path).unwrap();
        let verification_uri = format!("{verification_path}?signature={verification_signature}");
        let verification_page = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&verification_uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(verification_page.status(), StatusCode::OK);
        let verification_html = String::from_utf8(
            to_bytes(verification_page.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(verification_html.contains("Email Verification"));
        assert!(verification_html.contains("http://localhost/app/style.012abcd.css"));
        assert!(verification_html.contains("http://localhost/app/app.012abcd.js"));
        let encoded_verification_globals = verification_html
            .split("atob('")
            .nth(1)
            .unwrap()
            .split("')")
            .next()
            .unwrap();
        let verification_globals_bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded_verification_globals)
            .unwrap();
        let verification_globals: serde_json::Value =
            serde_json::from_slice(&verification_globals_bytes).unwrap();
        assert_eq!(
            verification_globals["route"],
            format!("auth/verify/{}", registered_user.0)
        );
        let tampered_verification = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("{verification_uri}&extra=changed"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(tampered_verification.status(), StatusCode::FORBIDDEN);
        let verified = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&verification_uri)
                    .header("cookie", test_csrf_cookie.clone())
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({"email":"first@example.test"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let verified: serde_json::Value =
            serde_json::from_slice(&to_bytes(verified.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(verified["code"], 0);
        let verified_state: bool = sqlx::query_scalar("SELECT verified FROM users WHERE uid = ?")
            .bind(registered_user.0)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(verified_state);
        sqlx::query("INSERT INTO reports (tid,uploader,reporter,reason,status,report_at) VALUES (999,?,?, 'my tracked report',0,'2026-10-02 16:00:00'), (999,?,9999,'another user private report',2,'2026-10-02 15:00:00')")
            .bind(registered_user.0)
            .bind(registered_user.0)
            .bind(registered_user.0)
            .execute(&pool)
            .await
            .unwrap();
        let tracked_reports =
            session_request(&app, &registered_cookie, "GET", "/user/reports", None).await;
        assert_eq!(tracked_reports.status(), StatusCode::OK);
        let tracked_reports = String::from_utf8(
            to_bytes(tracked_reports.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(tracked_reports.contains(r#"id="reports-list""#));
        assert!(tracked_reports.contains("http://localhost/app/style.012abcd.css"));
        assert!(tracked_reports.contains("http://localhost/app/app.012abcd.js"));
        let encoded_report_globals = tracked_reports
            .split("atob('")
            .nth(1)
            .unwrap()
            .split("')")
            .next()
            .unwrap();
        let report_globals_bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded_report_globals)
            .unwrap();
        let report_globals: serde_json::Value =
            serde_json::from_slice(&report_globals_bytes).unwrap();
        assert_eq!(report_globals["route"], "user/reports");
        assert_eq!(report_globals["i18n"]["auth"]["login"], "Log In");

        let tracked_report_list = session_request(
            &app,
            &registered_cookie,
            "GET",
            "/user/reports/list?page=1",
            None,
        )
        .await;
        assert_eq!(tracked_report_list.status(), StatusCode::OK);
        let tracked_report_list: serde_json::Value = serde_json::from_slice(
            &to_bytes(tracked_report_list.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(tracked_report_list["total"], 1);
        assert_eq!(tracked_report_list["data"][0]["tid"], 999);
        assert_eq!(
            tracked_report_list["data"][0]["reason"],
            "my tracked report"
        );
        assert_eq!(tracked_report_list["data"][0]["status"], 0);
        assert_eq!(
            tracked_report_list["data"][0]["texture_name"],
            serde_json::Value::Null
        );
        assert_eq!(tracked_report_list["data"].as_array().unwrap().len(), 1);
        assert_eq!(tracked_report_list["per_page"], 10);
        assert!(
            tracked_report_list["path"]
                .as_str()
                .unwrap()
                .ends_with("/user/reports/list")
        );
        assert!(
            tracked_report_list["first_page_url"]
                .as_str()
                .unwrap()
                .ends_with("/user/reports/list?page=1")
        );
        assert!(tracked_report_list["links"].as_array().is_some());
        sqlx::query("DELETE FROM reports WHERE reason IN ('my tracked report','another user private report')")
            .execute(&pool)
            .await
            .unwrap();

        let non_admin_settings =
            session_request(&app, &registered_cookie, "GET", "/admin/options", None).await;
        assert_eq!(non_admin_settings.status(), StatusCode::FORBIDDEN);
        sqlx::query("UPDATE users SET permission = 2 WHERE uid = ?")
            .bind(registered_user.0)
            .execute(&pool)
            .await
            .unwrap();
        let settings_page =
            session_request(&app, &registered_cookie, "GET", "/admin/options", None).await;
        assert_eq!(settings_page.status(), StatusCode::OK);
        let settings_html = String::from_utf8(
            to_bytes(settings_page.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(settings_html.contains("data-section=\"general\""));
        assert!(settings_html.contains("http://localhost/app/style.012abcd.css"));
        assert!(settings_html.contains("http://localhost/app/app.012abcd.js"));
        let encoded_settings_globals = settings_html
            .split("atob('")
            .nth(1)
            .unwrap()
            .split("')")
            .next()
            .unwrap();
        let settings_globals_bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded_settings_globals)
            .unwrap();
        let settings_globals: serde_json::Value =
            serde_json::from_slice(&settings_globals_bytes).unwrap();
        assert_eq!(settings_globals["route"], "admin/options");
        assert_eq!(settings_globals["extra"]["settings"]["section"], "general");
        assert!(
            settings_globals["extra"]["settings"]["fields"]
                .as_array()
                .unwrap()
                .iter()
                .any(|field| field["key"] == "site_name")
        );
        for (settings_path, section) in [
            ("/admin/score", "score"),
            ("/admin/customize", "customize"),
            ("/admin/resource", "resource"),
        ] {
            let section_page =
                session_request(&app, &registered_cookie, "GET", settings_path, None).await;
            assert_eq!(section_page.status(), StatusCode::OK, "{settings_path}");
            let section_html = String::from_utf8(
                to_bytes(section_page.into_body(), usize::MAX)
                    .await
                    .unwrap()
                    .to_vec(),
            )
            .unwrap();
            assert!(section_html.contains(r#"id="admin-settings-app""#));
            let encoded = section_html
                .split("atob('")
                .nth(1)
                .unwrap()
                .split("')")
                .next()
                .unwrap();
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .unwrap();
            let globals: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
            assert_eq!(globals["route"], format!("admin/{section}"));
            assert_eq!(globals["extra"]["settings"]["section"], section);
        }
        let legacy_color_form = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/admin/customize?action=color")
                    .header(
                        "cookie",
                        format!("{}; {}", &registered_cookie, test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "navbar=orange&sidebar=light-olive&submit_color=Submit",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(legacy_color_form.status(), StatusCode::OK);
        let legacy_color_html = String::from_utf8(
            to_bytes(legacy_color_form.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(legacy_color_html.contains("data-section=\"customize\""));
        let saved_navbar_color: String = sqlx::query_scalar(
            "SELECT option_value FROM options WHERE option_name = 'navbar_color'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let saved_sidebar_color: String = sqlx::query_scalar(
            "SELECT option_value FROM options WHERE option_name = 'sidebar_color'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(saved_navbar_color, "orange");
        assert_eq!(saved_sidebar_color, "light-olive");
        sqlx::query("DELETE FROM options WHERE option_name IN ('navbar_color', 'sidebar_color')")
            .execute(&pool)
            .await
            .unwrap();
        let original_meta_keywords: Option<String> = sqlx::query_scalar(
            "SELECT option_value FROM options WHERE option_name = 'meta_keywords'",
        )
        .fetch_optional(&pool)
        .await
        .unwrap();
        let original_site_name: Option<String> = sqlx::query_scalar(
            "SELECT option_value FROM options WHERE option_name = 'site_name_en'",
        )
        .fetch_optional(&pool)
        .await
        .unwrap();
        let legacy_settings_form = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/admin/options")
                    .header(
                        "cookie",
                        format!("{}; {}", &registered_cookie, test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .header(
                        CONTENT_TYPE,
                        "application/x-www-form-urlencoded; charset=UTF-8",
                    )
                    .body(Body::from(
                        "option=meta&meta_keywords=legacy+form+keywords&site_name=must+be+ignored",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(legacy_settings_form.status(), StatusCode::OK);
        let legacy_settings_html = String::from_utf8(
            to_bytes(legacy_settings_form.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(legacy_settings_html.contains("data-section=\"general\""));
        let saved_meta_keywords: String = sqlx::query_scalar(
            "SELECT option_value FROM options WHERE option_name = 'meta_keywords'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let unchanged_site_name: Option<String> = sqlx::query_scalar(
            "SELECT option_value FROM options WHERE option_name = 'site_name_en'",
        )
        .fetch_optional(&pool)
        .await
        .unwrap();
        assert_eq!(saved_meta_keywords, "legacy form keywords");
        assert_eq!(unchanged_site_name, original_site_name);
        if let Some(original) = original_meta_keywords {
            sqlx::query("UPDATE options SET option_value = ? WHERE option_name = 'meta_keywords'")
                .bind(original)
                .execute(&pool)
                .await
                .unwrap();
        } else {
            sqlx::query("DELETE FROM options WHERE option_name = 'meta_keywords'")
                .execute(&pool)
                .await
                .unwrap();
        }
        let saved_settings = session_request(
            &app,
            &registered_cookie,
            "POST",
            "/admin/options",
            Some(r#"{"values":{"site_name":"Settings Integration","require_verification":true}}"#),
        )
        .await;
        assert_eq!(saved_settings.status(), StatusCode::OK);
        let saved_settings: serde_json::Value = serde_json::from_slice(
            &to_bytes(saved_settings.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(saved_settings["code"], 0);
        let localized_site_name: String = sqlx::query_scalar(
            "SELECT option_value FROM options WHERE option_name = 'site_name_en'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(localized_site_name, "Settings Integration");
        for method in ["PUT", "PATCH", "DELETE", "OPTIONS"] {
            let settings_fallback = session_request(
                &app,
                &registered_cookie,
                method,
                "/admin/options",
                Some(r#"{"values":{"site_name":"must not be saved"}}"#),
            )
            .await;
            assert_eq!(settings_fallback.status(), StatusCode::OK, "{method}");
            let settings_fallback_html = String::from_utf8(
                to_bytes(settings_fallback.into_body(), usize::MAX)
                    .await
                    .unwrap()
                    .to_vec(),
            )
            .unwrap();
            assert!(settings_fallback_html.contains(r#"data-section="general""#));
        }
        let localized_site_name_after_fallbacks: String = sqlx::query_scalar(
            "SELECT option_value FROM options WHERE option_name = 'site_name_en'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(localized_site_name_after_fallbacks, "Settings Integration");
        let localized_home = session_request(&app, &registered_cookie, "GET", "/", None).await;
        let localized_home = String::from_utf8(
            to_bytes(localized_home.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(localized_home.contains("Settings Integration"));

        sqlx::query(r#"INSERT OR REPLACE INTO options (option_name,option_value) VALUES ('site_description_en','Legacy site description'), ('home_pic_url','/uploads/home.webp'), ('fixed_bg','(true)'), ('hide_intro','(false)'), ('transparent_navbar','(true)'), ('navbar_color','purple'), ('favicon_url','/favicon.png'), ('meta_keywords','minecraft,skins'), ('meta_description','Legacy SEO summary'), ('meta_extras','<meta name="author" content="legacy"><script>alert(1)</script>'), ('custom_css','body { color: red; }'), ('custom_js','window.homeCustom = true;'), ('copyright_prefer_en','2'), ('copyright_text_en','For {site_name} at {site_url}')"#)
            .execute(&pool)
            .await
            .unwrap();
        let customized_home = session_request(&app, &registered_cookie, "GET", "/", None).await;
        assert_eq!(customized_home.status(), StatusCode::OK);
        let customized_home = String::from_utf8(
            to_bytes(customized_home.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(customized_home.contains(r#"content="Legacy SEO summary""#));
        assert!(customized_home.contains("http://localhost/favicon.png"));
        assert!(customized_home.contains(r#"name="author" content="legacy""#));
        assert!(!customized_home.contains("<script>alert(1)</script>"));
        assert!(customized_home.contains("window.homeCustom = true;"));
        assert!(customized_home.contains("http://localhost/app/home-css.012abcd.css"));
        assert!(customized_home.contains("http://localhost/app/home.012abcd.js"));
        let encoded_home_globals = customized_home
            .split("atob('")
            .nth(1)
            .unwrap()
            .split("')")
            .next()
            .unwrap();
        let home_globals_bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded_home_globals)
            .unwrap();
        let home_globals: serde_json::Value = serde_json::from_slice(&home_globals_bytes).unwrap();
        assert_eq!(home_globals["route"], "home");
        assert_eq!(home_globals["site_name"], "Settings Integration");
        assert_eq!(home_globals["extra"]["home"]["fixed_bg"], true);
        assert_eq!(home_globals["extra"]["home"]["hide_intro"], false);
        assert_eq!(home_globals["extra"]["home"]["navbar_color"], "purple");
        assert_eq!(
            home_globals["extra"]["home"]["description"],
            "Legacy site description"
        );
        assert_eq!(
            home_globals["extra"]["home"]["background"],
            "/uploads/home.webp"
        );
        sqlx::query("UPDATE options SET option_value = '0' WHERE option_name = 'home_pic_url'")
            .execute(&pool)
            .await
            .unwrap();
        let falsey_background_home =
            session_request(&app, &registered_cookie, "GET", "/", None).await;
        assert_eq!(falsey_background_home.status(), StatusCode::OK);
        let falsey_background_home = String::from_utf8(
            to_bytes(falsey_background_home.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        let encoded_falsey_background_globals = falsey_background_home
            .split("atob('")
            .nth(1)
            .unwrap()
            .split("')")
            .next()
            .unwrap();
        let falsey_background_globals = base64::engine::general_purpose::STANDARD
            .decode(encoded_falsey_background_globals)
            .unwrap();
        let falsey_background_globals: serde_json::Value =
            serde_json::from_slice(&falsey_background_globals).unwrap();
        assert_eq!(
            falsey_background_globals["extra"]["home"]["background"],
            "./app/bg.webp"
        );
        assert_eq!(home_globals["extra"]["home"]["user_label"], "NewGuy");
        assert_eq!(home_globals["extra"]["transparent_navbar"], true);
        let invalid_setting = session_request(
            &app,
            &registered_cookie,
            "POST",
            "/admin/options",
            Some(r#"{"values":{"arbitrary_database_key":"unsafe"}}"#),
        )
        .await;
        assert_eq!(invalid_setting.status(), StatusCode::UNPROCESSABLE_ENTITY);
        sqlx::query("UPDATE users SET permission = 0 WHERE uid = ?")
            .bind(registered_user.0)
            .execute(&pool)
            .await
            .unwrap();

        let reset_path = format!("/auth/reset/{}", registered_user.0);
        let reset_expiry = super::unix_timestamp() + 3600;
        let reset_unsigned = format!("{reset_path}?expires={reset_expiry}");
        let reset_signature = super::signature_hex(&secret, &reset_unsigned).unwrap();
        let reset_uri = format!("{reset_unsigned}&signature={reset_signature}");
        let reset_page = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&reset_uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(reset_page.status(), StatusCode::OK);
        let reset_html = String::from_utf8(
            to_bytes(reset_page.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(reset_html.contains("reset your password here"));
        assert!(reset_html.contains("http://localhost/app/style.012abcd.css"));
        assert!(reset_html.contains("http://localhost/app/app.012abcd.js"));
        let encoded_reset_globals = reset_html
            .split("atob('")
            .nth(1)
            .unwrap()
            .split("')")
            .next()
            .unwrap();
        let reset_globals_bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded_reset_globals)
            .unwrap();
        let reset_globals: serde_json::Value =
            serde_json::from_slice(&reset_globals_bytes).unwrap();
        assert_eq!(
            reset_globals["route"],
            format!("auth/reset/{}", registered_user.0)
        );
        let reset = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&reset_uri)
                    .header("cookie", test_csrf_cookie.clone())
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({"password":"new secure password"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let reset: serde_json::Value =
            serde_json::from_slice(&to_bytes(reset.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(reset["code"], 0);
        let reset_hash: String = sqlx::query_scalar("SELECT password FROM users WHERE uid = ?")
            .bind(registered_user.0)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(crate::auth::verify_legacy_password(
            "new secure password",
            &reset_hash,
            "BCRYPT",
            ""
        ));
        let expired = super::unix_timestamp().saturating_sub(1);
        let expired_unsigned = format!("{reset_path}?expires={expired}");
        let expired_signature = super::signature_hex(&secret, &expired_unsigned).unwrap();
        let expired_reset = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("{expired_unsigned}&signature={expired_signature}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(expired_reset.status(), StatusCode::FORBIDDEN);

        let player_page =
            session_request(&app, &registered_cookie, "GET", "/user/player", None).await;
        assert_eq!(player_page.status(), StatusCode::OK);
        let player_page = to_bytes(player_page.into_body(), usize::MAX).await.unwrap();
        let player_page = String::from_utf8(player_page.to_vec()).unwrap();
        assert!(player_page.contains(r#"id="players-list""#));
        assert!(player_page.contains(r#"id="previewer""#));
        assert!(player_page.contains("http://localhost/app/style.012abcd.css"));
        assert!(player_page.contains("http://localhost/app/app.012abcd.js"));
        let encoded_player_globals = player_page
            .split("atob('")
            .nth(1)
            .unwrap()
            .split("')")
            .next()
            .unwrap();
        let player_globals_bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded_player_globals)
            .unwrap();
        let player_globals: serde_json::Value =
            serde_json::from_slice(&player_globals_bytes).unwrap();
        assert_eq!(player_globals["route"], "user/player");
        assert_eq!(player_globals["extra"]["count"], 1);
        assert!(player_globals["extra"]["score"].is_number());
        assert!(player_globals["extra"]["cost"].is_number());
        assert!(player_globals["extra"]["rule"].is_string());
        assert!(player_globals["extra"]["length"].is_string());

        let player_list =
            session_request(&app, &registered_cookie, "GET", "/user/player/list", None).await;
        assert_eq!(player_list.status(), StatusCode::OK);
        let player_list: serde_json::Value =
            serde_json::from_slice(&to_bytes(player_list.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert!(
            player_list
                .as_array()
                .unwrap()
                .iter()
                .any(|player| { player["name"] == "NewGuy" && player["uid"] == registered_user.0 })
        );

        let forbidden_player = session_request(
            &app,
            &registered_cookie,
            "PUT",
            "/user/player/3/name",
            Some(r#"{"name":"NotMine"}"#),
        )
        .await;
        assert_eq!(forbidden_player.status(), StatusCode::FORBIDDEN);

        let added_player = session_request(
            &app,
            &registered_cookie,
            "POST",
            "/user/player",
            Some(r#"{"name":"WebPlayer"}"#),
        )
        .await;
        assert_eq!(added_player.status(), StatusCode::OK);
        let added_player: serde_json::Value = serde_json::from_slice(
            &to_bytes(added_player.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(added_player["code"], 0);
        let added_pid = added_player["data"]["pid"].as_i64().unwrap();

        let duplicate_player = session_request(
            &app,
            &registered_cookie,
            "POST",
            "/user/player",
            Some(r#"{"name":"Alex"}"#),
        )
        .await;
        assert_eq!(duplicate_player.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let renamed_player = session_request(
            &app,
            &registered_cookie,
            "PUT",
            &format!("/user/player/{added_pid}/name"),
            Some(r#"{"name":"WebRenamed"}"#),
        )
        .await;
        let renamed_player: serde_json::Value = serde_json::from_slice(
            &to_bytes(renamed_player.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(renamed_player["code"], 0);
        assert_eq!(renamed_player["data"]["name"], "WebRenamed");

        sqlx::query(
            "INSERT INTO user_closet (user_uid,texture_tid,item_name) VALUES (?,2,'Reported skin')",
        )
        .bind(registered_user.0)
        .execute(&pool)
        .await
        .unwrap();
        let applied_texture = session_request(
            &app,
            &registered_cookie,
            "PUT",
            &format!("/user/player/{added_pid}/textures"),
            Some(r#"{"skin":2}"#),
        )
        .await;
        let applied_texture: serde_json::Value = serde_json::from_slice(
            &to_bytes(applied_texture.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(applied_texture["code"], 0);
        assert_eq!(applied_texture["data"]["tid_skin"], 2);

        let cleared_texture = session_request(
            &app,
            &registered_cookie,
            "DELETE",
            &format!("/user/player/{added_pid}/textures?skin=true&cape=true"),
            None,
        )
        .await;
        let cleared_texture: serde_json::Value = serde_json::from_slice(
            &to_bytes(cleared_texture.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(cleared_texture["code"], 0);
        assert_eq!(cleared_texture["data"]["tid_skin"], 0);
        assert_eq!(cleared_texture["data"]["tid_cape"], 0);

        let reapplied_texture = session_request(
            &app,
            &registered_cookie,
            "PUT",
            &format!("/user/player/{added_pid}/textures"),
            Some(r#"{"skin":2}"#),
        )
        .await;
        assert_eq!(reapplied_texture.status(), StatusCode::OK);
        let cleared_texture_from_body = session_request(
            &app,
            &registered_cookie,
            "DELETE",
            &format!("/user/player/{added_pid}/textures"),
            Some(r#"{"type":["skin"]}"#),
        )
        .await;
        let cleared_texture_from_body: serde_json::Value = serde_json::from_slice(
            &to_bytes(cleared_texture_from_body.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(cleared_texture_from_body["code"], 0);
        assert_eq!(cleared_texture_from_body["data"]["tid_skin"], 0);

        let deleted_player = session_request(
            &app,
            &registered_cookie,
            "DELETE",
            &format!("/user/player/{added_pid}"),
            None,
        )
        .await;
        let deleted_player: serde_json::Value = serde_json::from_slice(
            &to_bytes(deleted_player.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(deleted_player["code"], 0);
        let refunded_score: i64 = sqlx::query_scalar("SELECT score FROM users WHERE uid = ?")
            .bind(registered_user.0)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(refunded_score, 73);

        let closet_page =
            session_request(&app, &registered_cookie, "GET", "/user/closet", None).await;
        assert_eq!(closet_page.status(), StatusCode::OK);
        let closet_page = String::from_utf8(
            to_bytes(closet_page.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(closet_page.contains("Closet"));
        assert!(closet_page.contains(r#"id="closet-list""#));
        assert!(closet_page.contains(r#"id="previewer""#));
        assert!(closet_page.contains("http://localhost/app/style.012abcd.css"));
        assert!(closet_page.contains("http://localhost/app/app.012abcd.js"));
        let encoded_closet_globals = closet_page
            .split("atob('")
            .nth(1)
            .unwrap()
            .split("')")
            .next()
            .unwrap();
        let closet_globals_bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded_closet_globals)
            .unwrap();
        let closet_globals: serde_json::Value =
            serde_json::from_slice(&closet_globals_bytes).unwrap();
        assert_eq!(closet_globals["route"], "user/closet");
        assert_eq!(closet_globals["extra"]["unverified"], false);
        assert_eq!(closet_globals["i18n"]["auth"]["login"], "Log In");
        sqlx::query("INSERT INTO textures (tid,name,type,hash,size,uploader,public,upload_at,likes) VALUES (20,'Closet texture','steve','0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',8,?,1,'2026-10-02 14:00:00',0)")
            .bind(registered_user.0)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO options (option_name,option_value) VALUES ('score_per_closet_item','5'), ('score_award_per_like','0')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE options SET option_value = 'true' WHERE option_name = 'return_score'")
            .execute(&pool)
            .await
            .unwrap();

        let initial_closet_ids =
            session_request(&app, &registered_cookie, "GET", "/user/closet/ids", None).await;
        let initial_closet_ids: serde_json::Value = serde_json::from_slice(
            &to_bytes(initial_closet_ids.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(initial_closet_ids, serde_json::json!([2]));

        let added_closet_item = session_request(
            &app,
            &registered_cookie,
            "POST",
            "/user/closet",
            Some(r#"{"tid":20,"name":"Closet item"}"#),
        )
        .await;
        let added_closet_item: serde_json::Value = serde_json::from_slice(
            &to_bytes(added_closet_item.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(added_closet_item["code"], 0);

        let closet_list = session_request(
            &app,
            &registered_cookie,
            "GET",
            "/user/closet/list?category=skin&q=Closet&page=1&perPage=6",
            None,
        )
        .await;
        assert_eq!(closet_list.status(), StatusCode::OK);
        let closet_list: serde_json::Value =
            serde_json::from_slice(&to_bytes(closet_list.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(closet_list["total"], 1);
        assert_eq!(closet_list["data"][0]["pivot"]["item_name"], "Closet item");
        assert_eq!(
            closet_list["data"][0]["hash"],
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );

        assert_eq!(closet_list["per_page"], 6);
        assert!(
            closet_list["path"]
                .as_str()
                .unwrap()
                .ends_with("/user/closet/list")
        );
        assert!(
            closet_list["first_page_url"]
                .as_str()
                .unwrap()
                .ends_with("/user/closet/list?category=skin&q=Closet&page=1&perPage=6")
        );
        assert!(closet_list["links"].as_array().is_some());
        let all_closet_ids =
            session_request(&app, &registered_cookie, "GET", "/user/closet/ids", None).await;
        let all_closet_ids: serde_json::Value = serde_json::from_slice(
            &to_bytes(all_closet_ids.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(all_closet_ids, serde_json::json!([2, 20]));

        let renamed_closet_item = session_request(
            &app,
            &registered_cookie,
            "PUT",
            "/user/closet/20",
            Some(r#"{"name":"Renamed closet item"}"#),
        )
        .await;
        let renamed_closet_item: serde_json::Value = serde_json::from_slice(
            &to_bytes(renamed_closet_item.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(renamed_closet_item["code"], 0);

        let removed_closet_item =
            session_request(&app, &registered_cookie, "DELETE", "/user/closet/20", None).await;
        let removed_closet_item: serde_json::Value = serde_json::from_slice(
            &to_bytes(removed_closet_item.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(removed_closet_item["code"], 0);
        let closet_refunded_score: i64 =
            sqlx::query_scalar("SELECT score FROM users WHERE uid = ?")
                .bind(registered_user.0)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(closet_refunded_score, 73);
        sqlx::query("UPDATE options SET option_value = 'false' WHERE option_name = 'return_score'")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE options SET option_value = '0' WHERE option_name = 'score_per_closet_item'",
        )
        .execute(&pool)
        .await
        .unwrap();

        let skinlib_page = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/skinlib")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(skinlib_page.status(), StatusCode::OK);
        let skinlib_page = String::from_utf8(
            to_bytes(skinlib_page.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(skinlib_page.contains(r#"class="content-wrapper""#));
        assert!(skinlib_page.contains("http://localhost/app/style.012abcd.css"));
        assert!(skinlib_page.contains("http://localhost/app/app.012abcd.js"));
        let encoded_skinlib_globals = skinlib_page
            .split("atob('")
            .nth(1)
            .unwrap()
            .split("')")
            .next()
            .unwrap();
        let skinlib_globals_bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded_skinlib_globals)
            .unwrap();
        let skinlib_globals: serde_json::Value =
            serde_json::from_slice(&skinlib_globals_bytes).unwrap();
        assert_eq!(skinlib_globals["route"], "skinlib");
        assert_eq!(
            skinlib_globals["extra"]["currentUid"],
            serde_json::Value::Null
        );
        assert_eq!(skinlib_globals["i18n"]["auth"]["login"], "Log In");

        let skinlib_list = session_request(
            &app,
            &registered_cookie,
            "GET",
            "/skinlib/list?filter=skin&sort=time&page=1",
            None,
        )
        .await;
        assert_eq!(skinlib_list.status(), StatusCode::OK);
        let skinlib_list: serde_json::Value = serde_json::from_slice(
            &to_bytes(skinlib_list.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(
            skinlib_list["data"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["tid"] == 20 && item["nickname"] == "NewGuy")
        );

        assert_eq!(skinlib_list["per_page"], 20);
        assert_eq!(
            skinlib_list["path"]
                .as_str()
                .unwrap()
                .ends_with("/skinlib/list"),
            true
        );
        assert!(
            skinlib_list["first_page_url"]
                .as_str()
                .unwrap()
                .ends_with("/skinlib/list?filter=skin&sort=time&page=1")
        );
        assert!(skinlib_list["links"].as_array().is_some());
        let invalid_uploader_list = session_request(
            &app,
            &registered_cookie,
            "GET",
            "/skinlib/list?uploader=not-a-number",
            None,
        )
        .await;
        assert_eq!(invalid_uploader_list.status(), StatusCode::OK);
        let invalid_uploader_list: serde_json::Value = serde_json::from_slice(
            &to_bytes(invalid_uploader_list.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(invalid_uploader_list["data"], serde_json::json!([]));
        assert_eq!(invalid_uploader_list["total"], 0);
        let skinlib_show =
            session_request(&app, &registered_cookie, "GET", "/skinlib/show/20", None).await;
        assert_eq!(skinlib_show.status(), StatusCode::OK);
        let skinlib_show = String::from_utf8(
            to_bytes(skinlib_show.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(skinlib_show.contains(r#"id="previewer""#));
        assert!(skinlib_show.contains(r#"id="side""#));
        assert!(skinlib_show.contains("http://localhost/app/style.012abcd.css"));
        assert!(skinlib_show.contains("http://localhost/app/app.012abcd.js"));
        let encoded_show_globals = skinlib_show
            .split("atob('")
            .nth(1)
            .unwrap()
            .split("')")
            .next()
            .unwrap();
        let show_globals_bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded_show_globals)
            .unwrap();
        let show_globals: serde_json::Value = serde_json::from_slice(&show_globals_bytes).unwrap();
        assert_eq!(show_globals["route"], "skinlib/show/20");
        assert_eq!(show_globals["extra"]["nickname"], "NewGuy");
        assert_eq!(show_globals["extra"]["uploaderExists"], true);
        assert_eq!(show_globals["extra"]["currentUid"], registered_user.0);
        assert_eq!(show_globals["extra"]["admin"], false);
        assert_eq!(show_globals["extra"]["inCloset"], false);
        assert_eq!(show_globals["i18n"]["auth"]["login"], "Log In");

        let upload_page =
            session_request(&app, &registered_cookie, "GET", "/skinlib/upload", None).await;
        assert_eq!(upload_page.status(), StatusCode::OK);
        let upload_page = String::from_utf8(
            to_bytes(upload_page.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(upload_page.contains(r#"id="file-input""#));
        assert!(upload_page.contains(r#"id="previewer""#));
        assert!(upload_page.contains("http://localhost/app/style.012abcd.css"));
        assert!(upload_page.contains("http://localhost/app/app.012abcd.js"));
        assert!(upload_page.contains("</title><style>"));
        let encoded_upload_globals = upload_page
            .split("atob('")
            .nth(1)
            .unwrap()
            .split("')")
            .next()
            .unwrap();
        let upload_globals_bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded_upload_globals)
            .unwrap();
        let upload_globals: serde_json::Value =
            serde_json::from_slice(&upload_globals_bytes).unwrap();
        assert_eq!(upload_globals["route"], "skinlib/upload");
        assert!(!upload_globals["extra"]["rule"].as_str().unwrap().is_empty());
        assert!(upload_globals["extra"]["score"].as_i64().is_some());
        assert_eq!(
            upload_globals["extra"]["scorePublic"].as_i64().is_some(),
            true
        );
        assert_eq!(
            upload_globals["extra"]["scorePrivate"].as_i64().is_some(),
            true
        );
        assert_eq!(
            upload_globals["extra"]["closetItemCost"].as_i64().is_some(),
            true
        );
        assert!(upload_globals["extra"]["award"].as_i64().is_some());
        assert!(upload_globals["extra"]["privacyNotice"].is_string());
        assert!(upload_globals["extra"]["contentPolicy"].is_string());
        assert_eq!(upload_globals["i18n"]["auth"]["login"], "Log In");

        sqlx::query("INSERT INTO textures (tid,name,type,hash,size,uploader,public,upload_at,likes) VALUES (21,'Private texture','steve','private-hash',8,8,0,'2026-10-02 15:00:00',0)")
            .execute(&pool)
            .await
            .unwrap();
        let hidden_texture =
            session_request(&app, &registered_cookie, "GET", "/skinlib/show/21", None).await;
        assert_eq!(hidden_texture.status(), StatusCode::FORBIDDEN);
        sqlx::query("INSERT OR REPLACE INTO options (option_name, option_value) VALUES ('status_code_for_private', '410')")
            .execute(&pool)
            .await
            .unwrap();
        let hidden_texture =
            session_request(&app, &registered_cookie, "GET", "/skinlib/show/21", None).await;
        assert_eq!(hidden_texture.status(), StatusCode::FORBIDDEN);
        let hidden_texture_info =
            session_request(&app, &registered_cookie, "GET", "/skinlib/info/21", None).await;
        assert_eq!(hidden_texture_info.status(), StatusCode::FORBIDDEN);

        sqlx::query(
            "UPDATE options SET option_value = '404' WHERE option_name = 'status_code_for_private'",
        )
        .execute(&pool)
        .await
        .unwrap();
        let deleted_texture =
            session_request(&app, &registered_cookie, "GET", "/skinlib/show/21", None).await;
        assert_eq!(deleted_texture.status(), StatusCode::NOT_FOUND);
        let deleted_texture_info =
            session_request(&app, &registered_cookie, "GET", "/skinlib/info/21", None).await;
        assert_eq!(deleted_texture_info.status(), StatusCode::NOT_FOUND);

        sqlx::query(
            "UPDATE options SET option_value = '100' WHERE option_name = 'score_per_player'",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("UPDATE options SET option_value = 'false' WHERE option_name = 'return_score'")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE options SET option_value = 'true' WHERE option_name = 'require_verification'",
        )
        .execute(&pool)
        .await
        .unwrap();

        let (second_captcha_cookie, second_captcha_answer) =
            issue_test_captcha(&app, &captcha_challenges).await;
        let second_registration = submit_test_registration(
            &app,
            &second_captcha_cookie,
            &second_captcha_answer,
            "second@example.test",
            "NewGuy2",
            "203.0.113.40",
        )
        .await;
        let second_registration: serde_json::Value = serde_json::from_slice(
            &to_bytes(second_registration.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(second_registration["code"], 0);
        let second_user_verified: bool =
            sqlx::query_scalar("SELECT verified FROM users WHERE email = 'second@example.test'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(!second_user_verified);
        sqlx::query(
            "UPDATE options SET option_value = 'false' WHERE option_name = 'require_verification'",
        )
        .execute(&pool)
        .await
        .unwrap();
        let (third_captcha_cookie, third_captcha_answer) =
            issue_test_captcha(&app, &captcha_challenges).await;
        let limited_registration = submit_test_registration(
            &app,
            &third_captcha_cookie,
            &third_captcha_answer,
            "third@example.test",
            "NewGuy3",
            "203.0.113.40",
        )
        .await;
        let limited_registration: serde_json::Value = serde_json::from_slice(
            &to_bytes(limited_registration.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(limited_registration["code"], 1);
        assert!(
            limited_registration["message"]
                .as_str()
                .unwrap()
                .contains("2 accounts")
        );

        let login_ip = "198.51.100.41";
        for expected_failures in 1..=4 {
            let failed_login = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/auth/login")
                        .header("cookie", test_csrf_cookie.clone())
                        .header("x-csrf-token", test_csrf_token.as_str())
                        .header("x-real-ip", login_ip)
                        .header("content-type", "application/json")
                        .body(Body::from(
                            r#"{"identification":"alex@example.test","password":"incorrect horse"}"#,
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            let failed_login: serde_json::Value = serde_json::from_slice(
                &to_bytes(failed_login.into_body(), usize::MAX)
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(failed_login["data"]["login_fails"], expected_failures);
        }
        let captcha_required = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/login")
                    .header("cookie", test_csrf_cookie.clone())
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .header("x-real-ip", login_ip)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"identification":"different-account@example.test","password":"correct horse","keep":true}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let captcha_required: serde_json::Value = serde_json::from_slice(
            &to_bytes(captcha_required.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(captcha_required["code"], 1);
        assert_eq!(captcha_required["data"]["login_fails"], 4);
        assert!(login_page_too_many_fails(&app, login_ip).await);
        assert!(!login_page_too_many_fails(&app, "198.51.100.42").await);

        let isolated_failure = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/login")
                    .header("cookie", test_csrf_cookie.clone())
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .header("x-real-ip", "198.51.100.42")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"identification":"alex@example.test","password":"incorrect horse"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let isolated_failure: serde_json::Value = serde_json::from_slice(
            &to_bytes(isolated_failure.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(isolated_failure["data"]["login_fails"], 1);

        let (captcha_cookie, captcha_answer) = issue_test_captcha(&app, &captcha_challenges).await;
        let login = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/login?lang=en")
                    .header("x-real-ip", "198.51.100.41")
                    .header(
                        "cookie",
                        format!("{}; {}", captcha_cookie, test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "identification": "alex@example.test",
                            "password": "correct horse",
                            "keep": true,
                            "captcha": captcha_answer,
                            "redirect_to": "/skinlib",
                            "lang": "zh_TW"
                        })
                        .to_string(),
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
                .contains("Max-Age=34560000")
        );
        let body = to_bytes(login.into_body(), usize::MAX).await.unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["code"], 0);
        assert_eq!(result["data"]["redirectTo"], "/skinlib");
        assert_eq!(
            sqlx::query_scalar::<_, Option<String>>("SELECT locale FROM users WHERE uid = 7")
                .fetch_one(&pool)
                .await
                .unwrap()
                .as_deref(),
            Some("zh_TW")
        );
        let restore_login_locale =
            session_request(&app, &cookie, "GET", "/user/profile?lang=en", None).await;
        assert_eq!(restore_login_locale.status(), StatusCode::OK);

        let dashboard = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/user")
                    .header(
                        "cookie",
                        format!("{}; {}", cookie.clone(), test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
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
        sqlx::query("INSERT INTO options (option_name,option_value) VALUES ('score_per_storage','2'), ('score_per_player','100'), ('sign_after_zero','false'), ('sign_gap_time','24'), ('sign_score','10,10')")
            .execute(&pool)
            .await
            .unwrap();
        let score_info = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/user/score-info")
                    .header(
                        "cookie",
                        format!("{}; {}", cookie.clone(), test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(score_info.status(), StatusCode::OK);
        let score_info: serde_json::Value =
            serde_json::from_slice(&to_bytes(score_info.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(score_info["user"]["score"], 5);
        assert_eq!(score_info["user"]["lastSignAt"], "");
        assert_eq!(score_info["rate"]["storage"], 2);
        assert_eq!(score_info["rate"]["players"], 100);
        assert_eq!(score_info["usage"]["players"], 1);
        sqlx::query(
            "UPDATE options SET option_value = 'false' WHERE option_name = 'score_per_storage'",
        )
        .execute(&pool)
        .await
        .unwrap();
        let false_score_info = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/user/score-info")
                    .header(
                        "cookie",
                        format!("{}; {}", cookie.clone(), test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let false_score_info: serde_json::Value = serde_json::from_slice(
            &to_bytes(false_score_info.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(false_score_info["rate"]["storage"], 0);
        sqlx::query(
            "UPDATE options SET option_value = '2' WHERE option_name = 'score_per_storage'",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(score_info["usage"]["storage"], 8);
        let sign = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/user/sign")
                    .header(
                        "cookie",
                        format!("{}; {}", cookie.clone(), test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let sign: serde_json::Value =
            serde_json::from_slice(&to_bytes(sign.into_body(), usize::MAX).await.unwrap()).unwrap();
        assert_eq!(sign["code"], 0);
        assert_eq!(sign["data"]["score"], 15);
        let duplicate_sign = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/user/sign")
                    .header(
                        "cookie",
                        format!("{}; {}", cookie.clone(), test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let duplicate_sign: serde_json::Value = serde_json::from_slice(
            &to_bytes(duplicate_sign.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(duplicate_sign["code"], 1);
        let yesterday = super::shanghai_now()
            .date()
            .pred_opt()
            .unwrap()
            .and_hms_opt(23, 59, 59)
            .unwrap()
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        sqlx::query("UPDATE users SET last_sign_at = ? WHERE uid = 7")
            .bind(yesterday)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE options SET option_value = 'true' WHERE option_name = 'sign_after_zero'",
        )
        .execute(&pool)
        .await
        .unwrap();
        let daily_sign = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/user/sign")
                    .header(
                        "cookie",
                        format!("{}; {}", cookie.clone(), test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let daily_sign: serde_json::Value =
            serde_json::from_slice(&to_bytes(daily_sign.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(daily_sign["code"], 0);
        let duplicate_daily_sign = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/user/sign")
                    .header(
                        "cookie",
                        format!("{}; {}", cookie.clone(), test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let duplicate_daily_sign: serde_json::Value = serde_json::from_slice(
            &to_bytes(duplicate_daily_sign.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(duplicate_daily_sign["code"], 1);
        sqlx::query("UPDATE users SET score = 5, last_sign_at = '' WHERE uid = 7")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE options SET option_value = 'false' WHERE option_name = 'sign_after_zero'",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("UPDATE options SET option_value = '0' WHERE option_name IN ('score_per_storage', 'score_per_player')")
            .execute(&pool)
            .await
            .unwrap();

        for nickname in ["Changed nickname", "Alex User"] {
            let encoded_nickname = nickname.replace(' ', "+");
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/user/profile")
                        .header(
                            "cookie",
                            format!("{}; {}", cookie.clone(), test_csrf_cookie),
                        )
                        .header("x-csrf-token", test_csrf_token.as_str())
                        .header("content-type", "application/x-www-form-urlencoded")
                        .body(Body::from(format!(
                            "action=nickname&new_nickname={encoded_nickname}"
                        )))
                        .unwrap(),
                )
                .await
                .unwrap();
            let body: serde_json::Value =
                serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                    .unwrap();
            assert_eq!(body["code"], 0);
        }
        let changed_password = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/user/profile")
                    .header("cookie", format!("{}; {}", cookie.clone(), test_csrf_cookie))
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"action":"password","current_password":"correct horse","new_password":"new secure password"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            changed_password
                .headers()
                .get(SET_COOKIE)
                .unwrap()
                .to_str()
                .unwrap()
                .contains("Max-Age=0")
        );
        let changed_password: serde_json::Value = serde_json::from_slice(
            &to_bytes(changed_password.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(changed_password["code"], 0);
        let stale_password_cookie = cookie.clone();
        let cookie =
            login_test_account(&app, "alex@example.test", "new secure password", login_ip).await;
        let stale_password_session =
            session_request(&app, &stale_password_cookie, "GET", "/user", None).await;
        assert_eq!(stale_password_session.status(), StatusCode::SEE_OTHER);
        let restored_password = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/user/profile")
                    .header("cookie", format!("{}; {}", cookie.clone(), test_csrf_cookie))
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"action":"password","current_password":"new secure password","new_password":"correct horse"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let restored_password: serde_json::Value = serde_json::from_slice(
            &to_bytes(restored_password.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(restored_password["code"], 0);
        let cookie = login_test_account(&app, "alex@example.test", "correct horse", login_ip).await;
        let stored_password: String =
            sqlx::query_scalar("SELECT password FROM users WHERE uid = 7")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(crate::auth::verify_legacy_password(
            "correct horse",
            &stored_password,
            "BCRYPT",
            ""
        ));

        let stale_email_cookie = cookie.clone();
        let changed_email = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/user/profile")
                    .header("cookie", format!("{}; {}", cookie.clone(), test_csrf_cookie))
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"action":"email","email":"changed@example.test","password":"correct horse"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            changed_email
                .headers()
                .get(SET_COOKIE)
                .unwrap()
                .to_str()
                .unwrap()
                .contains("Max-Age=0")
        );
        let changed_email: serde_json::Value = serde_json::from_slice(
            &to_bytes(changed_email.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(changed_email["code"], 0);
        let changed_email_state: (String, bool) =
            sqlx::query_as("SELECT email,verified FROM users WHERE uid = 7")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            changed_email_state,
            ("changed@example.test".to_owned(), false)
        );
        let stale_email_session =
            session_request(&app, &stale_email_cookie, "GET", "/user", None).await;
        assert_eq!(stale_email_session.status(), StatusCode::SEE_OTHER);
        let cookie =
            login_test_account(&app, "changed@example.test", "correct horse", login_ip).await;
        let restored_email = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/user/profile")
                    .header("cookie", format!("{}; {}", cookie.clone(), test_csrf_cookie))
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"action":"email","email":"alex@example.test","password":"correct horse"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let restored_email: serde_json::Value = serde_json::from_slice(
            &to_bytes(restored_email.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(restored_email["code"], 0);
        let cookie = login_test_account(&app, "alex@example.test", "correct horse", login_ip).await;
        sqlx::query("UPDATE users SET verified = 1 WHERE uid = 7")
            .execute(&pool)
            .await
            .unwrap();

        let set_avatar = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/user/profile/avatar?tid=2")
                    .header(
                        "cookie",
                        format!("{}; {}", cookie.clone(), test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let set_avatar: serde_json::Value =
            serde_json::from_slice(&to_bytes(set_avatar.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(set_avatar["code"], 0);
        let avatar: i64 = sqlx::query_scalar("SELECT avatar FROM users WHERE uid = 7")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(avatar, 2);
        let reset_avatar = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/user/profile/avatar")
                    .header(
                        "cookie",
                        format!("{}; {}", cookie.clone(), test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"tid":0}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(reset_avatar.status(), StatusCode::OK);

        for expected_dark_mode in [true, false] {
            let dark_mode = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("PUT")
                        .uri("/user/dark-mode")
                        .header(
                            "cookie",
                            format!("{}; {}", cookie.clone(), test_csrf_cookie),
                        )
                        .header("x-csrf-token", test_csrf_token.as_str())
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(dark_mode.status(), StatusCode::NO_CONTENT);
            let is_dark_mode: bool =
                sqlx::query_scalar("SELECT is_dark_mode FROM users WHERE uid = 7")
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            assert_eq!(is_dark_mode, expected_dark_mode);
        }
        let refused_admin_deletion = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/user/profile")
                    .header(
                        "cookie",
                        format!("{}; {}", cookie.clone(), test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"action":"delete","password":"correct horse"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let refused_admin_deletion: serde_json::Value = serde_json::from_slice(
            &to_bytes(refused_admin_deletion.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(refused_admin_deletion["code"], 1);

        let clients_before = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/oauth/clients")
                    .header(
                        "cookie",
                        format!("{}; {}", cookie.clone(), test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
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
                    .header(
                        "cookie",
                        format!("{}; {}", cookie.clone(), test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
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
                    .header(
                        "cookie",
                        format!("{}; {}", cookie.clone(), test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
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
                    .header(
                        "cookie",
                        format!("{}; {}", cookie.clone(), test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
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
                    .header(
                        "cookie",
                        format!("{}; {}", cookie.clone(), test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
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

        let managed_players = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/admin/players/list?q=name%3AAlex&page=1")
                    .header(
                        "cookie",
                        format!("{}; {}", cookie.clone(), test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(managed_players.status(), StatusCode::OK);
        let managed_players: serde_json::Value = serde_json::from_slice(
            &to_bytes(managed_players.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(managed_players["total"], 1);
        assert_eq!(managed_players["data"][0]["pid"], 3);
        assert_eq!(managed_players["data"][0]["uid"], 7);
        assert_eq!(managed_players["per_page"], 10);
        assert!(
            managed_players["path"]
                .as_str()
                .unwrap()
                .ends_with("/admin/players/list")
        );
        assert!(
            managed_players["first_page_url"]
                .as_str()
                .unwrap()
                .ends_with("/admin/players/list?q=name%3AAlex&page=1")
        );
        assert!(managed_players["links"].as_array().is_some());

        sqlx::query("INSERT INTO textures (tid,name,type,hash,size,uploader,public,upload_at,likes) VALUES (13,'Admin texture','alex','admin-hash',8,7,1,'2026-10-01 10:05:00',0)")
            .execute(&pool)
            .await
            .unwrap();
        for (uri, body, content_type) in [
            (
                "/admin/players/3/name",
                "player_name=AlexRenamed",
                "application/x-www-form-urlencoded",
            ),
            (
                "/admin/players/3/owner?uid=8",
                "",
                "application/x-www-form-urlencoded",
            ),
            (
                "/admin/players/3/textures",
                r#"{"type":"skin","tid":13}"#,
                "application/json",
            ),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("PUT")
                        .uri(uri)
                        .header(
                            "cookie",
                            format!("{}; {}", cookie.clone(), test_csrf_cookie),
                        )
                        .header("x-csrf-token", test_csrf_token.as_str())
                        .header("content-type", content_type)
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{uri}");
            let response: serde_json::Value =
                serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                    .unwrap();
            assert_eq!(response["code"], 0, "{uri}");
        }
        let managed_player: (i64, String, i64, i64) =
            sqlx::query_as("SELECT uid,name,tid_skin,tid_cape FROM players WHERE pid = 3")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(managed_player, (8, "AlexRenamed".to_owned(), 13, 0));
        let removed_player = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/admin/players/3")
                    .header(
                        "cookie",
                        format!("{}; {}", cookie.clone(), test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(removed_player.status(), StatusCode::OK);
        let player_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM players WHERE pid = 3")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(player_count, 0);

        let managed_closet_add = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/closet/8?tid=2")
                    .header(
                        "cookie",
                        format!("{}; {}", cookie.clone(), test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(managed_closet_add.status(), StatusCode::OK);
        let managed_closet_add: serde_json::Value = serde_json::from_slice(
            &to_bytes(managed_closet_add.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(managed_closet_add["code"], 0);
        assert_eq!(managed_closet_add["message"], "");
        assert_eq!(managed_closet_add["data"]["user"]["uid"], 8);
        assert_eq!(managed_closet_add["data"]["user"]["ip"], "");
        assert_eq!(managed_closet_add["data"]["texture"]["tid"], 2);
        let closet_row: (String,) = sqlx::query_as(
            "SELECT item_name FROM user_closet WHERE user_uid = 8 AND texture_tid = 2",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(closet_row.0, "Reported skin");
        let admin_closet_items = crate::database::DatabasePool::Sqlite(pool.clone())
            .admin_closet_items("", 8)
            .await
            .unwrap();
        assert_eq!(admin_closet_items.len(), 1);
        assert_eq!(
            admin_closet_items[0].item_name.as_deref(),
            Some("Reported skin")
        );

        let repeated_closet_add = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/closet/8")
                    .header(
                        "cookie",
                        format!("{}; {}", cookie.clone(), test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"tid":2}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let repeated_closet_add: serde_json::Value = serde_json::from_slice(
            &to_bytes(repeated_closet_add.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(repeated_closet_add["code"], 1);

        let managed_closet_remove = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/admin/closet/8")
                    .header(
                        "cookie",
                        format!("{}; {}", cookie.clone(), test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("tid=2"))
                    .unwrap(),
            )
            .await
            .unwrap();
        let managed_closet_remove: serde_json::Value = serde_json::from_slice(
            &to_bytes(managed_closet_remove.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(managed_closet_remove["code"], 0);
        assert_eq!(managed_closet_remove["message"], "");
        assert_eq!(managed_closet_remove["data"]["user"]["uid"], 8);
        assert_eq!(managed_closet_remove["data"]["texture"]["tid"], 2);
        let closet_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM user_closet WHERE user_uid = 8 AND texture_tid = 2",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(closet_count, 0);

        let users = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/admin/users/list?q=alex&page=1")
                    .header(
                        "cookie",
                        format!("{}; {}", cookie.clone(), test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(users.status(), StatusCode::OK);
        let users: serde_json::Value =
            serde_json::from_slice(&to_bytes(users.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(users["current_page"], 1);
        assert_eq!(users["last_page"], 1);
        assert_eq!(users["total"], 1);
        assert_eq!(users["data"][0]["uid"], 7);
        assert_eq!(users["data"][0]["email"], "alex@example.test");
        assert_eq!(users["data"][0]["ip"], "");
        assert!(users["data"][0].get("password").is_none());
        assert_eq!(users["per_page"], 10);
        assert!(
            users["path"]
                .as_str()
                .unwrap()
                .ends_with("/admin/users/list")
        );
        assert!(
            users["first_page_url"]
                .as_str()
                .unwrap()
                .ends_with("/admin/users/list?q=alex&page=1")
        );
        assert!(users["links"].as_array().is_some());

        let combined_user_filter = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/admin/users/list?q=email%3Aalex%40example.test%20or%20uid%3A8&page=1")
                    .header(
                        "cookie",
                        format!("{}; {}", cookie.clone(), test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(combined_user_filter.status(), StatusCode::OK);
        let combined_user_filter: serde_json::Value = serde_json::from_slice(
            &to_bytes(combined_user_filter.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(combined_user_filter["total"], 2);
        assert_eq!(combined_user_filter["data"][0]["uid"], 7);
        assert_eq!(combined_user_filter["data"][1]["uid"], 8);
        assert!(
            combined_user_filter["first_page_url"]
                .as_str()
                .unwrap()
                .ends_with("/admin/users/list?q=email%3Aalex%40example.test+or+uid%3A8&page=1")
        );

        let reports = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/admin/reports/list?q=status%3A0%20sort%3A-report_at")
                    .header(
                        "cookie",
                        format!("{}; {}", cookie.clone(), test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
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
        assert_eq!(report_page["per_page"], 9);
        assert!(
            report_page["path"]
                .as_str()
                .unwrap()
                .ends_with("/admin/reports/list")
        );
        assert!(
            report_page["first_page_url"]
                .as_str()
                .unwrap()
                .ends_with("/admin/reports/list?q=status%3A0+sort%3A-report_at&page=1")
        );
        assert!(report_page["links"].as_array().is_some());

        let invalid_review_query = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/admin/reports/1?action=invalid")
                    .header(
                        "cookie",
                        format!("{}; {}", cookie.clone(), test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            invalid_review_query.status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let invalid_review_query: serde_json::Value = serde_json::from_slice(
            &to_bytes(invalid_review_query.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(invalid_review_query["errors"]["action"].is_array());

        let rejected = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/admin/reports/1")
                    .header(
                        "cookie",
                        format!("{}; {}", cookie.clone(), test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("action=reject"))
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
                    .header(
                        "cookie",
                        format!("{}; {}", cookie.clone(), test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
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
                    .header(
                        "cookie",
                        format!("{}; {}", cookie.clone(), test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
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
                    .header(
                        "cookie",
                        format!("{}; {}", cookie.clone(), test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
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

        let duplicate_email = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/admin/users/8/email")
                    .header(
                        "cookie",
                        format!("{}; {}", cookie.clone(), test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"email":"alex@example.test"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(duplicate_email.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let duplicate_body = to_bytes(duplicate_email.into_body(), usize::MAX)
            .await
            .unwrap();
        let duplicate_body: serde_json::Value = serde_json::from_slice(&duplicate_body).unwrap();
        assert!(duplicate_body["errors"]["email"].is_array());

        for (uri, body, content_type, expected) in [
            (
                "/admin/users/8/email",
                "email=uploader2%40example.test",
                "application/x-www-form-urlencoded",
                "Email changed successfully.",
            ),
            (
                "/admin/users/8/nickname?nickname=Target%20User",
                "",
                "application/x-www-form-urlencoded",
                "Nickname changed successfully.",
            ),
            (
                "/admin/users/8/score",
                r#"{"score":17}"#,
                "application/json",
                "Score changed successfully.",
            ),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("PUT")
                        .uri(uri)
                        .header(
                            "cookie",
                            format!("{}; {}", cookie.clone(), test_csrf_cookie),
                        )
                        .header("x-csrf-token", test_csrf_token.as_str())
                        .header("content-type", content_type)
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let response: serde_json::Value =
                serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                    .unwrap();
            assert_eq!(response["code"], 0);
            assert_eq!(response["message"], expected);
        }

        let promoted = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/admin/users/8/permission")
                    .header(
                        "cookie",
                        format!("{}; {}", cookie.clone(), test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"permission":1}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(promoted.status(), StatusCode::FORBIDDEN);
        let self_role_change = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/admin/users/7/permission")
                    .header(
                        "cookie",
                        format!("{}; {}", cookie.clone(), test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"permission":0}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(self_role_change.status(), StatusCode::FORBIDDEN);

        let verified_before: bool = sqlx::query_scalar("SELECT verified FROM users WHERE uid = 8")
            .fetch_one(&pool)
            .await
            .unwrap();
        let verification = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/admin/users/8/verification")
                    .header(
                        "cookie",
                        format!("{}; {}", cookie.clone(), test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(verification.status(), StatusCode::OK);
        let verified_after: bool = sqlx::query_scalar("SELECT verified FROM users WHERE uid = 8")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(verified_after, !verified_before);

        let password_change = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/admin/users/8/password")
                    .header(
                        "cookie",
                        format!("{}; {}", cookie.clone(), test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"password":"NewPass123"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(password_change.status(), StatusCode::OK);
        let changed_hash: String = sqlx::query_scalar("SELECT password FROM users WHERE uid = 8")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(crate::auth::verify_legacy_password(
            "NewPass123",
            &changed_hash,
            "BCRYPT",
            ""
        ));

        let set_permission = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/admin/users/8/permission")
                    .header(
                        "cookie",
                        format!("{}; {}", cookie.clone(), test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"permission":0}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(set_permission.status(), StatusCode::OK);
        let user_eight_player = sqlx::query(
            "INSERT INTO players (pid,uid,name,tid_skin,tid_cape,last_modified) VALUES (99,8,'Uploader player',0,0,'2026-10-02 12:00:00')",
        );
        user_eight_player.execute(&pool).await.unwrap();
        let removed_user = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/admin/users/8")
                    .header(
                        "cookie",
                        format!("{}; {}", cookie.clone(), test_csrf_cookie),
                    )
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(removed_user.status(), StatusCode::OK);
        let removed_body: serde_json::Value = serde_json::from_slice(
            &to_bytes(removed_user.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(removed_body["code"], 0);
        let deleted_users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE uid = 8")
            .fetch_one(&pool)
            .await
            .unwrap();
        let deleted_players: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM players WHERE uid = 8")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(deleted_users, 0);
        assert_eq!(deleted_players, 0);

        sqlx::query("INSERT INTO textures (tid,name,type,hash,size,uploader,public,upload_at,likes) VALUES (900001,'Preview skin','alex',?,4096,7,1,'2026-10-02 12:00:00',0),(900002,'Preview cape','cape',?,4096,7,1,'2026-10-02 12:00:00',0)")
            .bind(&preview_skin_hash)
            .bind(&preview_cape_hash)
            .execute(&pool)
            .await
            .unwrap();
        let raw_invalid_id = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/raw/not-a-number")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(raw_invalid_id.status(), StatusCode::NOT_FOUND);
        let raw_default = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/raw/900001")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(raw_default.status(), StatusCode::OK);
        sqlx::query("INSERT INTO options (option_name, option_value) VALUES ('allow_downloading_texture', 'no')")
            .execute(&pool)
            .await
            .unwrap();
        let raw_legacy_truthy = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/raw/900001")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(raw_legacy_truthy.status(), StatusCode::OK);
        sqlx::query("UPDATE options SET option_value = '(false)' WHERE option_name = 'allow_downloading_texture'")
            .execute(&pool)
            .await
            .unwrap();
        let raw_legacy_false = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/raw/900001")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(raw_legacy_false.status(), StatusCode::FORBIDDEN);
        let raw_invalid_id_when_disabled = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/raw/not-a-number")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(raw_invalid_id_when_disabled.status(), StatusCode::FORBIDDEN);
        sqlx::query("UPDATE options SET option_value = 'true' WHERE option_name = 'allow_downloading_texture'")
            .execute(&pool)
            .await
            .unwrap();
        let skin_preview = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/preview/900001?png")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(skin_preview.status(), StatusCode::OK);
        assert_eq!(
            skin_preview
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap(),
            "image/png"
        );
        let skin_preview_etag = skin_preview
            .headers()
            .get(axum::http::header::ETAG)
            .unwrap()
            .clone();
        let skin_preview_bytes = to_bytes(skin_preview.into_body(), usize::MAX)
            .await
            .unwrap();
        let decoded_skin_preview =
            image::load_from_memory_with_format(&skin_preview_bytes, ImageFormat::Png).unwrap();
        assert!(
            decoded_skin_preview.width() > 400 && decoded_skin_preview.height() > 400,
            "expected the PHP-compatible two-view skin preview canvas"
        );
        let cached_skin_preview = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/preview/900001?png")
                    .header(axum::http::header::IF_NONE_MATCH, skin_preview_etag)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cached_skin_preview.status(), StatusCode::NOT_MODIFIED);

        let cape_preview_uri = format!("/preview/hash/{preview_cape_hash}?png&height=160");
        let cape_preview = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&cape_preview_uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cape_preview.status(), StatusCode::OK);
        assert_eq!(
            cape_preview
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap(),
            "image/png"
        );
        assert!(
            cape_preview
                .headers()
                .get(axum::http::header::ETAG)
                .is_none()
        );
        assert!(
            !cape_preview
                .headers()
                .get(axum::http::header::CACHE_CONTROL)
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("public")
        );
        assert!(
            cape_preview
                .headers()
                .contains_key(axum::http::header::LAST_MODIFIED)
        );
        let cape_preview_bytes = to_bytes(cape_preview.into_body(), usize::MAX)
            .await
            .unwrap();
        let decoded_cape_preview =
            image::load_from_memory_with_format(&cape_preview_bytes, ImageFormat::Png).unwrap();
        assert_eq!(
            (decoded_cape_preview.width(), decoded_cape_preview.height()),
            (100, 160)
        );
        let repeated_cape_preview = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&cape_preview_uri)
                    .header(axum::http::header::IF_NONE_MATCH, "*")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(repeated_cape_preview.status(), StatusCode::OK);
        let avatar_by_hash = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/avatar/hash/{preview_skin_hash}?png&size=64"))
                    .header(axum::http::header::IF_NONE_MATCH, "*")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(avatar_by_hash.status(), StatusCode::OK);
        assert!(
            avatar_by_hash
                .headers()
                .get(axum::http::header::ETAG)
                .is_none()
        );
        assert_eq!(
            avatar_by_hash
                .headers()
                .get(axum::http::header::CACHE_CONTROL)
                .unwrap(),
            "private, must-revalidate"
        );
        assert!(
            avatar_by_hash
                .headers()
                .get(axum::http::header::LAST_MODIFIED)
                .is_some()
        );
        for uri in [
            "/avatar/not-an-id?png&size=32",
            "/avatar/user/not-an-id?png&size=32",
        ] {
            let invalid_avatar_id = app
                .clone()
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(invalid_avatar_id.status(), StatusCode::OK, "{uri}");
            assert_eq!(
                invalid_avatar_id
                    .headers()
                    .get(axum::http::header::CONTENT_TYPE)
                    .unwrap(),
                "image/png"
            );
        }
        std::fs::remove_dir_all(&texture_test_dir).unwrap();

        let admin_notice = session_request(
            &app,
            &admin_cookie,
            "POST",
            "/admin/notifications/send",
            Some(r#"{"receiver":"uid","uid":7,"title":"Rust notice","content":"Maintenance starts tonight."}"#),
        )
        .await;
        let admin_notice_status = admin_notice.status();
        let admin_notice_body = to_bytes(admin_notice.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            admin_notice_status,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&admin_notice_body)
        );
        let admin_notice: serde_json::Value = serde_json::from_slice(&admin_notice_body).unwrap();
        assert_eq!(admin_notice["code"], 0);
        let saved_notice: String = sqlx::query_scalar(
            "SELECT data FROM notifications WHERE notifiable_id = 7 AND data LIKE '%Rust notice%' LIMIT 1",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let saved_notice: serde_json::Value = serde_json::from_str(&saved_notice).unwrap();
        assert_eq!(saved_notice["title"], "Rust notice");
        assert_eq!(saved_notice["content"], "Maintenance starts tonight.");
        let query_notice = session_request(
            &app,
            &admin_cookie,
            "POST",
            "/admin/notifications/send?receiver=uid&uid=7&title=Query+notice&content=Settings+saved",
            None,
        )
        .await;
        assert_eq!(query_notice.status(), StatusCode::SEE_OTHER);
        let saved_query_notice: String = sqlx::query_scalar(
            "SELECT data FROM notifications WHERE notifiable_id = 7 AND data LIKE '%Query notice%' LIMIT 1",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let saved_query_notice: serde_json::Value =
            serde_json::from_str(&saved_query_notice).unwrap();
        assert_eq!(saved_query_notice["content"], "Settings saved");
        let denied_notice = session_request(
            &app,
            &registered_cookie,
            "POST",
            "/admin/notifications/send",
            Some(r#"{"receiver":"all","title":"Unauthorized notice"}"#),
        )
        .await;
        assert_eq!(denied_notice.status(), StatusCode::FORBIDDEN);
        sqlx::query("INSERT OR REPLACE INTO options (option_name,option_value) VALUES ('auto_detect_asset_url','false'), ('site_url','http://legacy.example.test'), ('force_ssl','true')")
            .execute(&pool)
            .await
            .unwrap();
        let forced_url_page = app
            .clone()
            .oneshot(Request::get("/auth/login").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(forced_url_page.status(), StatusCode::OK);
        let forced_url_page = String::from_utf8(
            to_bytes(forced_url_page.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(forced_url_page.contains("https://legacy.example.test/app/style.012abcd.css"));
        let encoded_forced_url_globals = forced_url_page
            .split("atob('")
            .nth(1)
            .unwrap()
            .split("')")
            .next()
            .unwrap();
        let forced_url_globals_bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded_forced_url_globals)
            .unwrap();
        let forced_url_globals: serde_json::Value =
            serde_json::from_slice(&forced_url_globals_bytes).unwrap();
        assert_eq!(
            forced_url_globals["base_url"],
            "https://legacy.example.test"
        );

        let secure_captcha = app
            .clone()
            .oneshot(Request::get("/auth/captcha").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(secure_captcha.status(), StatusCode::OK);
        assert!(
            secure_captcha
                .headers()
                .get_all(SET_COOKIE)
                .iter()
                .any(
                    |cookie| cookie.to_str().unwrap().contains("blessing_skin_captcha=")
                        && cookie.to_str().unwrap().contains("; Secure")
                )
        );

        sqlx::query(
            "UPDATE options SET option_value = 'true' WHERE option_name = 'auto_detect_asset_url'",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("UPDATE options SET option_value = 'false' WHERE option_name = 'force_ssl'")
            .execute(&pool)
            .await
            .unwrap();
        let detected_url_page = app
            .clone()
            .oneshot(
                Request::get("/auth/login")
                    .header("host", "skins.auto.example.test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(detected_url_page.status(), StatusCode::OK);
        let detected_url_page = String::from_utf8(
            to_bytes(detected_url_page.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        let encoded_detected_url_globals = detected_url_page
            .split("atob('")
            .nth(1)
            .unwrap()
            .split("')")
            .next()
            .unwrap();
        let detected_url_globals_bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded_detected_url_globals)
            .unwrap();
        let detected_url_globals: serde_json::Value =
            serde_json::from_slice(&detected_url_globals_bytes).unwrap();
        assert_eq!(
            detected_url_globals["base_url"],
            "http://skins.auto.example.test"
        );

        let proxied_https_page = app
            .clone()
            .oneshot(
                Request::get("/auth/login")
                    .header("host", "skins.auto.example.test")
                    .header("x-forwarded-proto", "https")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let proxied_https_page = String::from_utf8(
            to_bytes(proxied_https_page.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(
            proxied_https_page.contains("https://skins.auto.example.test/app/style.012abcd.css")
        );

        let anonymous_logout = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/logout")
                    .header("cookie", test_csrf_cookie.clone())
                    .header("x-csrf-token", test_csrf_token.as_str())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(anonymous_logout.status(), StatusCode::FOUND);
        assert_eq!(anonymous_logout.headers()[LOCATION], "/auth/login");

        let logout = session_request(&app, &registered_cookie, "POST", "/auth/logout", None).await;
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
        let persisted_revocations = database
            .active_web_session_revocations(
                "",
                i64::try_from(jsonwebtoken::get_current_timestamp()).unwrap(),
            )
            .await
            .unwrap();
        revoked_web_sessions.write().unwrap().clear();
        let cross_instance_replay =
            session_request(&app, &registered_cookie, "GET", "/user", None).await;
        assert_eq!(cross_instance_replay.status(), StatusCode::SEE_OTHER);
        assert_eq!(cross_instance_replay.headers()[LOCATION], "/auth/login");
        let registered_token = registered_cookie.split_once('=').unwrap().1;
        let registered_hash = super::web_session_fingerprint(registered_token);
        assert!(
            revoked_web_sessions
                .read()
                .unwrap()
                .contains_key(&registered_hash)
        );

        let mut restored_revocations = revoked_web_sessions.write().unwrap();
        restored_revocations.clear();
        restored_revocations.extend(persisted_revocations);
        drop(restored_revocations);
        let replayed_logout_session =
            session_request(&app, &registered_cookie, "GET", "/user", None).await;
        assert_eq!(replayed_logout_session.status(), StatusCode::SEE_OTHER);
        assert_eq!(replayed_logout_session.headers()[LOCATION], "/auth/login");

        let legacy_now = jsonwebtoken::get_current_timestamp();
        let legacy_claims = crate::auth::WebSessionClaims {
            jti: None,
            sub: "7".to_owned(),
            iat: legacy_now,
            exp: legacy_now + 3600,
            remember: false,
        };
        let legacy_token = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
            &legacy_claims,
            &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();
        let legacy_cookie = format!("blessing_skin_session={legacy_token}");
        let legacy_logout =
            session_request(&app, &legacy_cookie, "POST", "/auth/logout", None).await;
        assert_eq!(legacy_logout.status(), StatusCode::OK);
        let legacy_replay = session_request(&app, &legacy_cookie, "GET", "/user", None).await;
        assert_eq!(legacy_replay.status(), StatusCode::SEE_OTHER);
        assert_eq!(legacy_replay.headers()[LOCATION], "/auth/login");

        std::fs::remove_dir_all(&setup_storage).unwrap();
        std::fs::remove_dir_all(&public_dir).unwrap();
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
        assert!(valid_player_name("a\u{00a0}b", "utf8", "", 3, 16));
        for whitespace in ['\t', '\n', '\u{000b}', '\u{000c}', '\r', ' '] {
            let name = format!("ab{whitespace}c");
            assert!(!valid_player_name(&name, "utf8", "", 3, 16));
        }
        assert!(valid_player_name(
            "玩家 @!",
            "unknown-legacy-rule",
            "",
            3,
            16
        ));
        assert!(valid_player_name("ABC", "custom", "/^[a-z]+$/i", 3, 16));
        assert!(!valid_player_name("ABC1", "custom", "/^[a-z]+$/i", 3, 16));
        assert!(valid_player_name("a/b", "custom", "/^[a-z\\/]+$/", 3, 16));

        assert!(valid_player_name(
            "Abc1",
            "custom",
            "~^(?=.*[A-Z])(?=.*\\d)[A-Za-z\\d]+$~",
            3,
            16
        ));
        assert!(!valid_player_name(
            "abc1",
            "custom",
            "~^(?=.*[A-Z])(?=.*\\d)[A-Za-z\\d]+$~",
            3,
            16
        ));
        assert!(valid_player_name(
            "Ab-Ab",
            "custom",
            "{^([A-Z]+)-\\1$}i",
            3,
            16
        ));
        assert!(valid_player_name("a/b", "custom", "#^[a-z/]+$#i", 3, 16));
        assert!(!valid_player_name("abc", "custom", "^[a-z]+$", 3, 16));
        assert!(valid_player_name("anything", "custom", "0", 3, 16));
        assert!(valid_player_name("anything", "custom", "(false)", 3, 16));
        assert!(valid_player_name("abc\n", "custom", "/^[a-z]+$/", 3, 16));
        assert!(!valid_player_name("abc\n", "custom", "/^[a-z]+$/D", 3, 16));
        assert!(!valid_player_name("é", "custom", "/^\\w+$/", 1, 16));
        assert!(!valid_player_name("é", "custom", "/^.$/", 1, 16));
        assert!(valid_player_name("é", "custom", "/^..$/", 1, 16));
        assert!(valid_player_name("é", "custom", "/^.$/u", 1, 16));
        assert!(valid_player_name("é", "custom", "/^\\w+$/u", 1, 16));
    }
    #[test]
    fn missing_site_description_and_copyright_use_legacy_defaults() {
        assert_eq!(
            super::legacy_site_description(None),
            "Open-source PHP Minecraft Skin Hosting Service"
        );
        assert_eq!(
            super::legacy_copyright_text(None, "Blessing Skin", "https://skin.example"),
            "<b>Copyright &copy; {year} <a href=\"https://skin.example\">Blessing Skin</a>.</b> All rights reserved."
        );
        assert_eq!(
            super::legacy_copyright_text(
                Some("For {site_name} at {site_url}".to_owned()),
                "Blessing Skin",
                "https://skin.example"
            ),
            "For Blessing Skin at https://skin.example"
        );
    }
}
