use std::{
    collections::{BTreeMap, HashMap},
    time::{SystemTime, UNIX_EPOCH},
};

use askama::Template;
use axum::{
    Json,
    body::Bytes,
    extract::{Path, RawQuery, State},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{CACHE_CONTROL, PRAGMA},
    },
    response::{Html, IntoResponse, Redirect, Response},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{DateTime, SecondsFormat, Utc};
use hmac::{Hmac, Mac};
use jsonwebtoken::{Algorithm, Header, encode};
use rand::{
    RngCore,
    distributions::{Alphanumeric, DistString},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::{AppState, database::OAuthGrantClientRecord, defuse};

const ACCESS_TOKEN_TTL: u64 = 365 * 24 * 60 * 60;
const REFRESH_TOKEN_TTL: u64 = 365 * 24 * 60 * 60;
const DEFAULT_SCOPE_DESCRIPTIONS: &[(&str, &str)] = &[
    ("User.Read", "auth.oauth.scope.user.read"),
    ("Notification.Read", "auth.oauth.scope.notification.read"),
    (
        "Notification.ReadWrite",
        "auth.oauth.scope.notification.readwrite",
    ),
    ("Player.Read", "auth.oauth.scope.player.read"),
    ("Player.ReadWrite", "auth.oauth.scope.player.readwrite"),
    ("Closet.Read", "auth.oauth.scope.closet.read"),
    ("Closet.ReadWrtie", "auth.oauth.scope.closet.readwrite"),
    (
        "UsersManagement.Read",
        "auth.oauth.scope.users-management.read",
    ),
    (
        "UsersManagement.ReadWrite",
        "auth.oauth.scope.users-management.readwrite",
    ),
    (
        "PlayersManagement.Read",
        "auth.oauth.scope.players-management.read",
    ),
    (
        "PlayersManagement.ReadWrite",
        "auth.oauth.scope.players-management.readwrite",
    ),
    (
        "ClosetManagement.Read",
        "auth.oauth.scope.closet-management.read",
    ),
    (
        "ClosetManagement.ReadWrite",
        "auth.oauth.scope.closet-management.readwrite",
    ),
    (
        "ReportsManagement.Read",
        "auth.oauth.scope.reports-management.read",
    ),
    (
        "ReportsManagement.ReadWrite",
        "auth.oauth.scope.reports-management.readwrite",
    ),
];

const KNOWN_SCOPES: &[&str] = &[
    "User.Read",
    "Notification.Read",
    "Notification.ReadWrite",
    "Player.Read",
    "Player.ReadWrite",
    "Closet.Read",
    "Closet.ReadWrite",
    "Closet.ReadWrtie",
    "UsersManagement.Read",
    "UsersManagement.ReadWrite",
    "PlayersManagement.Read",
    "PlayersManagement.ReadWrite",
    "ClosetManagement.Read",
    "ClosetManagement.ReadWrite",
    "ReportsManagement.Read",
    "ReportsManagement.ReadWrite",
];

#[derive(Default)]
struct TokenRequest {
    fields: HashMap<String, String>,
}

#[derive(Deserialize)]
struct PassportAuthorizationCodePayload {
    client_id: serde_json::Value,
    redirect_uri: Option<String>,
    auth_code_id: String,
    scopes: Vec<String>,
    user_id: serde_json::Value,
    expire_time: u64,
    #[serde(default)]
    code_challenge: Option<String>,
    #[serde(default)]
    code_challenge_method: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct OAuthAuthorizationFormClaims {
    user_id: i64,
    client_id: i64,
    redirect_uri: Option<String>,
    callback_uri: String,
    scopes: Vec<String>,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    exp: u64,
}

#[derive(Template)]
#[template(path = "oauth_authorize.html")]
struct OAuthAuthorizePage {
    site_name: String,
    locale: String,
    client_name: String,
    scopes: Vec<String>,
    auth_token: String,
    client_id: i64,
}
#[derive(Serialize)]
struct PassportAccessTokenClaims {
    aud: String,
    exp: u64,
    iat: u64,
    jti: String,
    nbf: u64,
    scopes: Vec<String>,
    sub: String,
}

fn login_redirect_url(return_to: &str) -> String {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("redirect_to", return_to);
    format!("/auth/login?{}", serializer.finish())
}

pub async fn authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
) -> Response {
    let return_to = raw_query
        .as_deref()
        .map(|query| format!("/oauth/authorize?{query}"))
        .unwrap_or_else(|| "/oauth/authorize".to_owned());
    let login_url = login_redirect_url(&return_to);
    let Some(user_id) = crate::http::session_user_id(&state, &headers) else {
        return Redirect::to(&login_url).into_response();
    };
    if let Err(response) = crate::http::authenticated_web_user(&state, &headers).await {
        return response;
    }
    let Some(raw_query) = raw_query else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "The authorization request is invalid.",
        );
    };
    let request = match TokenRequest::parse(raw_query.as_bytes()) {
        Ok(request) => request,
        Err(()) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "The authorization request is invalid.",
            );
        }
    };
    if request.fields.get("response_type").map(String::as_str) != Some("code") {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_response_type",
            "The response_type must be code.",
        );
    }
    let Some(client_id) = request
        .fields
        .get("client_id")
        .and_then(|value| value.parse::<i64>().ok())
    else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "The client_id field is required.",
        );
    };
    let Some(database) = &state.database else {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "The authorization service is unavailable.",
        );
    };
    let prefix = &state.config.database.table_prefix;
    let client = match database.oauth_authorization_client(prefix, client_id).await {
        Ok(Some(client)) if !client.revoked && !client.personal_access_client => client,
        Ok(_) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_client",
                "The OAuth client is invalid.",
            );
        }
        Err(error) => {
            tracing::error!(%error, "failed to load OAuth authorization client");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "The authorization service is unavailable.",
            );
        }
    };
    let registered_redirects = client.redirect.split(',').collect::<Vec<_>>();
    let requested_redirect = request.fields.get("redirect_uri").cloned();
    let callback_uri = match requested_redirect.as_deref() {
        Some(redirect) if registered_redirects.contains(&redirect) => redirect.to_owned(),
        Some(_) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "The redirect_uri does not match the registered URI.",
            );
        }
        None if registered_redirects.len() == 1 => registered_redirects[0].to_owned(),
        None => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "The redirect_uri field is required.",
            );
        }
    };
    let known_scopes = load_known_scopes(database, prefix).await;
    let scopes = match parse_scopes(
        request.fields.get("scope").map(String::as_str),
        None,
        &known_scopes,
    ) {
        Ok(scopes) => scopes,
        Err(()) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_scope",
                "The requested scope is invalid.",
            );
        }
    };
    let code_challenge = request
        .fields
        .get("code_challenge")
        .filter(|value| !value.is_empty())
        .cloned();
    let code_challenge_method = request.fields.get("code_challenge_method").cloned();
    if let Some(challenge) = code_challenge.as_deref() {
        if !valid_pkce_verifier(challenge) {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "The code_challenge is invalid.",
            );
        }
        if !matches!(
            code_challenge_method.as_deref().unwrap_or("plain"),
            "plain" | "S256"
        ) {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "The code_challenge_method is invalid.",
            );
        }
    } else if code_challenge_method.is_some() {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "A code_challenge_method requires a code_challenge.",
        );
    } else if client.secret.as_deref().is_none_or(str::is_empty) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Public clients must use PKCE.",
        );
    }
    if request
        .fields
        .get("state")
        .is_some_and(|state| state.len() > 2048)
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "The state parameter is too long.",
        );
    }
    let Some(app_key) = state.config.app_key.as_deref() else {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "The authorization service is unavailable.",
        );
    };
    let claims = OAuthAuthorizationFormClaims {
        user_id,
        client_id,
        redirect_uri: requested_redirect,
        callback_uri,
        scopes: scopes.clone(),
        state: request.fields.get("state").cloned(),
        code_challenge,
        code_challenge_method,
        exp: unix_now().saturating_add(600),
    };
    let auth_token = match sign_authorization_form(&claims, app_key) {
        Some(token) => token,
        None => {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "The authorization service failed.",
            );
        }
    };
    let page = OAuthAuthorizePage {
        site_name: crate::http::site_name(&state).await,
        locale: state.config.locale.clone(),
        client_name: client.name,
        scopes,
        auth_token,
        client_id,
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to render OAuth authorization page");
            oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "The authorization service failed.",
            )
        }
    }
}

pub async fn authorization_decision(
    State(state): State<AppState>,
    headers: HeaderMap,
    method: axum::http::Method,
    body: Bytes,
) -> Response {
    let Some(user_id) = crate::http::session_user_id(&state, &headers) else {
        return Redirect::to("/auth/login").into_response();
    };
    let user = match crate::http::authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let request = match TokenRequest::parse(&body) {
        Ok(request) => request,
        Err(()) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "The authorization decision is invalid.",
            );
        }
    };
    let Some(app_key) = state.config.app_key.as_deref() else {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "The authorization service is unavailable.",
        );
    };
    let Some(auth_token) = request.fields.get("auth_token") else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "The authorization form has expired.",
        );
    };
    let Some(claims) = verify_authorization_form(auth_token, app_key) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "The authorization form has expired.",
        );
    };
    if claims.exp <= unix_now()
        || claims.user_id != user_id
        || claims.user_id != user.uid
        || request
            .fields
            .get("client_id")
            .and_then(|value| value.parse::<i64>().ok())
            != Some(claims.client_id)
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "The authorization form has expired.",
        );
    }
    let denied = method == axum::http::Method::DELETE
        || request
            .fields
            .get("_method")
            .is_some_and(|value| value.eq_ignore_ascii_case("DELETE"));
    let Some(database) = &state.database else {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "The authorization service is unavailable.",
        );
    };
    let prefix = &state.config.database.table_prefix;
    let client = match database
        .oauth_authorization_client(prefix, claims.client_id)
        .await
    {
        Ok(Some(client)) if !client.revoked && !client.personal_access_client => client,
        Ok(_) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_client",
                "The OAuth client is invalid.",
            );
        }
        Err(error) => {
            tracing::error!(%error, "failed to reload OAuth authorization client");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "The authorization service is unavailable.",
            );
        }
    };
    if !client
        .redirect
        .split(',')
        .any(|redirect| redirect == claims.callback_uri)
        || claims
            .redirect_uri
            .as_deref()
            .is_some_and(|redirect| redirect != claims.callback_uri)
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "The redirect_uri no longer matches the registered URI.",
        );
    }
    if denied {
        let mut params = vec![("error", "access_denied".to_owned())];
        if let Some(state) = claims.state.as_deref() {
            params.push(("state", state.to_owned()));
        }
        return redirect_with_query(&claims.callback_uri, &params);
    }
    let known_scopes = load_known_scopes(database, prefix).await;
    if claims
        .scopes
        .iter()
        .any(|scope| !known_scopes.contains(scope))
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "The requested scope is no longer available.",
        );
    }
    let Some(configured_app_key) = state.config.app_key.as_deref() else {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "The Passport encryption key is not configured.",
        );
    };
    let encryption_key = match defuse::laravel_app_key_bytes(configured_app_key) {
        Ok(key) => key,
        Err(()) => {
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "The Passport encryption key is invalid.",
            );
        }
    };
    let auth_code_id = new_uuid();
    let expires_at = unix_now().saturating_add(600);
    let payload = serde_json::json!({
        "client_id": claims.client_id.to_string(),
        "redirect_uri": claims.redirect_uri,
        "auth_code_id": auth_code_id,
        "scopes": claims.scopes,
        "user_id": claims.user_id.to_string(),
        "expire_time": expires_at,
        "code_challenge": claims.code_challenge,
        "code_challenge_method": claims.code_challenge_method
    });
    let serialized = match serde_json::to_vec(&payload) {
        Ok(payload) => payload,
        Err(error) => {
            tracing::error!(%error, "failed to serialize Passport authorization code");
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "The authorization service failed.",
            );
        }
    };
    let code = match defuse::encrypt_with_password(&serialized, &encryption_key) {
        Ok(code) => code,
        Err(()) => {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "The authorization service failed.",
            );
        }
    };
    let scopes_json = match serde_json::to_string(&claims.scopes) {
        Ok(scopes) => scopes,
        Err(error) => {
            tracing::error!(%error, "failed to serialize authorization code scopes");
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "The authorization service failed.",
            );
        }
    };
    if let Err(error) = database
        .create_oauth_auth_code(
            prefix,
            &auth_code_id,
            claims.user_id,
            claims.client_id,
            &scopes_json,
        )
        .await
    {
        tracing::error!(%error, "failed to persist OAuth authorization code");
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "The authorization service is unavailable.",
        );
    }
    let mut params = vec![("code", code)];
    if let Some(state) = claims.state.as_deref() {
        params.push(("state", state.to_owned()));
    }
    redirect_with_query(&claims.callback_uri, &params)
}

fn sign_authorization_form(claims: &OAuthAuthorizationFormClaims, key: &str) -> Option<String> {
    let payload = serde_json::to_vec(claims).ok()?;
    let payload = URL_SAFE_NO_PAD.encode(payload);
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).ok()?;
    mac.update(payload.as_bytes());
    Some(format!(
        "{payload}.{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    ))
}

fn verify_authorization_form(token: &str, key: &str) -> Option<OAuthAuthorizationFormClaims> {
    let (payload, signature) = token.split_once('.')?;
    let signature = URL_SAFE_NO_PAD.decode(signature).ok()?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).ok()?;
    mac.update(payload.as_bytes());
    mac.verify_slice(&signature).ok()?;
    let payload = URL_SAFE_NO_PAD.decode(payload).ok()?;
    serde_json::from_slice(&payload).ok()
}

fn redirect_with_query(uri: &str, params: &[(&str, String)]) -> Response {
    let (without_fragment, fragment) = uri.split_once('#').unwrap_or((uri, ""));
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    for (key, value) in params {
        serializer.append_pair(key, value);
    }
    let query = serializer.finish();
    let separator = if without_fragment.contains('?') {
        if without_fragment.ends_with('?') || without_fragment.ends_with('&') {
            ""
        } else {
            "&"
        }
    } else {
        "?"
    };
    let location = if fragment.is_empty() {
        format!("{without_fragment}{separator}{query}")
    } else {
        format!("{without_fragment}{separator}{query}#{fragment}")
    };
    let Ok(location) = HeaderValue::from_str(&location) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "The redirect_uri is invalid.",
        );
    };
    let mut response = StatusCode::FOUND.into_response();
    response
        .headers_mut()
        .insert(axum::http::header::LOCATION, location);
    response
}
pub async fn list_scopes(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) = crate::http::authenticated_web_user(&state, &headers).await {
        return response;
    }
    let Some(database) = &state.database else {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "The authorization service is unavailable.",
        );
    };
    let mut scopes = DEFAULT_SCOPE_DESCRIPTIONS
        .iter()
        .map(|(name, description)| ((*name).to_owned(), (*description).to_owned()))
        .collect::<BTreeMap<_, _>>();
    match database
        .oauth_scope_descriptions(&state.config.database.table_prefix)
        .await
    {
        Ok(custom) => {
            scopes.extend(
                custom
                    .into_iter()
                    .map(|scope| (scope.name, scope.description)),
            );
        }
        Err(error) => {
            tracing::error!(%error, "failed to load OAuth scope descriptions");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "The authorization service is unavailable.",
            );
        }
    }
    Json(
        scopes
            .into_iter()
            .map(|(id, description)| serde_json::json!({ "id": id, "description": description }))
            .collect::<Vec<_>>(),
    )
    .into_response()
}

pub async fn list_authorized_tokens(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let user = match crate::http::authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Some(database) = &state.database else {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "The authorization service is unavailable.",
        );
    };
    let records = match database
        .oauth_tokens_for_user(&state.config.database.table_prefix, user.uid, false)
        .await
    {
        Ok(records) => records,
        Err(error) => {
            tracing::error!(%error, "failed to list OAuth access tokens");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "The authorization service is unavailable.",
            );
        }
    };
    let tokens = records
        .into_iter()
        .map(|token| {
            let scopes = token.scopes.as_deref().map(decode_stored_scopes);
            serde_json::json!({
                "id": token.id,
                "user_id": token.user_id,
                "client_id": token.client_id,
                "name": token.name,
                "scopes": scopes,
                "revoked": token.revoked,
                "created_at": token.created_at,
                "updated_at": token.updated_at,
                "expires_at": token.expires_at,
                "client": {
                    "id": token.client_id,
                    "user_id": token.client_user_id,
                    "name": token.client_name,
                    "provider": token.client_provider,
                    "redirect": token.client_redirect,
                    "personal_access_client": token.client_personal_access_client,
                    "password_client": token.client_password_client,
                    "revoked": token.client_revoked,
                    "created_at": token.client_created_at,
                    "updated_at": token.client_updated_at
                }
            })
        })
        .collect::<Vec<_>>();
    Json(tokens).into_response()
}

#[derive(Deserialize)]
struct PersonalAccessTokenRequest {
    name: String,
    #[serde(default)]
    scopes: Vec<String>,
}

pub async fn list_personal_access_tokens(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let user = match crate::http::authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Some(database) = &state.database else {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "The authorization service is unavailable.",
        );
    };
    let records = match database
        .oauth_tokens_for_user(&state.config.database.table_prefix, user.uid, true)
        .await
    {
        Ok(records) => records,
        Err(error) => {
            tracing::error!(%error, "failed to list OAuth personal access tokens");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "The authorization service is unavailable.",
            );
        }
    };
    let tokens = records
        .into_iter()
        .map(|token| {
            let scopes = token.scopes.as_deref().map(decode_stored_scopes);
            serde_json::json!({
                "id": token.id,
                "user_id": token.user_id,
                "client_id": token.client_id,
                "name": token.name,
                "scopes": scopes,
                "revoked": token.revoked,
                "created_at": token.created_at,
                "updated_at": token.updated_at,
                "expires_at": token.expires_at,
                "client": {
                    "id": token.client_id,
                    "user_id": token.client_user_id,
                    "name": token.client_name,
                    "provider": token.client_provider,
                    "redirect": token.client_redirect,
                    "personal_access_client": token.client_personal_access_client,
                    "password_client": token.client_password_client,
                    "revoked": token.client_revoked,
                    "created_at": token.client_created_at,
                    "updated_at": token.client_updated_at
                }
            })
        })
        .collect::<Vec<_>>();
    Json(tokens).into_response()
}

pub async fn create_personal_access_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let user = match crate::http::authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let request: PersonalAccessTokenRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => {
            return oauth_validation_error(
                "The given data was invalid.",
                serde_json::json!({
                    "name": ["The name field is required."],
                }),
            );
        }
    };
    if request.name.trim().is_empty() || request.name.chars().count() > 191 {
        return oauth_validation_error(
            "The given data was invalid.",
            serde_json::json!({ "name": ["The name field is required and may not exceed 191 characters."] }),
        );
    }
    let Some(database) = &state.database else {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "The authorization service is unavailable.",
        );
    };
    let prefix = &state.config.database.table_prefix;
    let personal_client_id = match database.oauth_personal_access_client_id(prefix).await {
        Ok(Some(client_id)) => client_id,
        Ok(None) => {
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "The personal access client is not configured.",
            );
        }
        Err(error) => {
            tracing::error!(%error, "failed to load OAuth personal access client");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "The authorization service is unavailable.",
            );
        }
    };
    let known_scopes = load_known_scopes(database, prefix).await;
    let mut scopes = Vec::with_capacity(request.scopes.len());
    for scope in request.scopes {
        if !known_scopes.iter().any(|known| known == &scope) {
            return oauth_validation_error(
                "The given data was invalid.",
                serde_json::json!({ "scopes": [format!("The selected scope {scope} is invalid.")] }),
            );
        }
        if !scopes.contains(&scope) {
            scopes.push(scope);
        }
    }
    let Some(signing_key) = state.passport_signing_key.as_ref() else {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "The authorization service is unavailable.",
        );
    };
    let now = unix_now();
    let expires_at_unix = now.saturating_add(ACCESS_TOKEN_TTL);
    let token_id = new_uuid();
    let claims = PassportAccessTokenClaims {
        aud: personal_client_id.to_string(),
        exp: expires_at_unix,
        iat: now,
        jti: token_id.clone(),
        nbf: now,
        scopes: scopes.clone(),
        sub: user.uid.to_string(),
    };
    let access_token = match encode(&Header::new(Algorithm::RS256), &claims, signing_key) {
        Ok(token) => token,
        Err(error) => {
            tracing::error!(%error, "failed to sign Passport personal access token");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "The authorization service is unavailable.",
            );
        }
    };
    let scopes_json = match serde_json::to_string(&scopes) {
        Ok(scopes) => scopes,
        Err(error) => {
            tracing::error!(%error, "failed to serialize OAuth personal token scopes");
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "The authorization service failed.",
            );
        }
    };
    let created_at = database_datetime(now);
    let expires_at = database_datetime(expires_at_unix);
    if let Err(error) = database
        .issue_oauth_personal_access_token(
            prefix,
            &token_id,
            user.uid,
            personal_client_id,
            &request.name,
            &scopes_json,
            &created_at,
            &expires_at,
        )
        .await
    {
        tracing::error!(%error, "failed to persist OAuth personal access token");
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "The authorization service is unavailable.",
        );
    }
    let created_at_json = DateTime::<Utc>::from_timestamp(now as i64, 0)
        .map(|value| value.to_rfc3339_opts(SecondsFormat::Secs, true));
    let expires_at_json = DateTime::<Utc>::from_timestamp(expires_at_unix as i64, 0)
        .map(|value| value.to_rfc3339_opts(SecondsFormat::Secs, true));
    Json(serde_json::json!({
        "accessToken": access_token,
        "token": {
            "id": token_id,
            "user_id": user.uid,
            "client_id": personal_client_id,
            "name": request.name,
            "scopes": scopes,
            "revoked": false,
            "created_at": created_at_json,
            "updated_at": created_at_json,
            "expires_at": expires_at_json
        }
    }))
    .into_response()
}

fn oauth_json_identifier(value: &serde_json::Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
}

fn valid_pkce_verifier(verifier: &str) -> bool {
    (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}

fn verify_pkce_challenge(verifier: &str, challenge: &str, method: &str) -> bool {
    let expected = match method {
        "plain" => verifier.to_owned(),
        "S256" => URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())),
        _ => return false,
    };
    bool::from(expected.as_bytes().ct_eq(challenge.as_bytes()))
}

fn oauth_validation_error(message: &str, errors: serde_json::Value) -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(serde_json::json!({ "message": message, "errors": errors })),
    )
        .into_response()
}

pub async fn revoke_access_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(token_id): Path<String>,
) -> Response {
    let user = match crate::http::authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Some(database) = &state.database else {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "The authorization service is unavailable.",
        );
    };
    match database
        .revoke_oauth_access_token(&state.config.database.table_prefix, user.uid, &token_id)
        .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to revoke OAuth access token");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "The authorization service is unavailable.",
            )
        }
    }
}

pub async fn token(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let request = match TokenRequest::parse(&body) {
        Ok(request) => request,
        Err(()) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "The request body is invalid.",
            );
        }
    };
    let grant_type = request
        .fields
        .get("grant_type")
        .map(String::as_str)
        .unwrap_or("");
    if !matches!(
        grant_type,
        "password" | "refresh_token" | "authorization_code"
    ) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "The authorization grant type is not supported.",
        );
    }

    let (client_id, client_secret) = match client_credentials(&headers, &request.fields) {
        Ok(credentials) => credentials,
        Err(response) => return response,
    };
    let Some(database) = &state.database else {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "The authorization service is unavailable.",
        );
    };
    let prefix = &state.config.database.table_prefix;
    let client = match database.oauth_grant_client(prefix, client_id).await {
        Ok(Some(client)) if !client.revoked => client,
        Ok(_) => {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "Client authentication failed.",
            );
        }
        Err(error) => {
            tracing::error!(%error, "failed to load OAuth client");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "The authorization service is unavailable.",
            );
        }
    };
    if !verify_client_secret(&client, client_secret.as_deref()) {
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "Client authentication failed.",
        );
    }

    let signing_key = match &state.passport_signing_key {
        Some(key) => key,
        None => {
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "The Passport private key is not configured.",
            );
        }
    };

    let (user_id, scopes, rotate_refresh, consume_auth_code) = match grant_type {
        "password" => {
            if !client.password_client {
                return oauth_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_client",
                    "This client is not authorized for the password grant.",
                );
            }
            let Some(username) = request
                .fields
                .get("username")
                .filter(|value| !value.is_empty())
            else {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "The username field is required.",
                );
            };
            let Some(password) = request
                .fields
                .get("password")
                .filter(|value| !value.is_empty())
            else {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "The password field is required.",
                );
            };
            let credential = if username.contains('@') {
                database.credentials_by_email(prefix, username).await
            } else {
                database.credentials_by_player_name(prefix, username).await
            };
            let credential = match credential {
                Ok(Some(credential)) => credential,
                Ok(None) => {
                    return oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_grant",
                        "The user credentials were incorrect.",
                    );
                }
                Err(error) => {
                    tracing::error!(%error, "failed to load OAuth password credential");
                    return oauth_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "server_error",
                        "The authorization service is unavailable.",
                    );
                }
            };
            if !crate::auth::verify_legacy_password(
                password,
                &credential.password,
                &state.config.password_method,
                &state.config.password_salt,
            ) {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "The user credentials were incorrect.",
                );
            }
            let known_scopes = load_known_scopes(database, prefix).await;
            let scopes = match parse_scopes(
                request.fields.get("scope").map(String::as_str),
                None,
                &known_scopes,
            ) {
                Ok(scopes) => scopes,
                Err(()) => {
                    return oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_scope",
                        "The requested scope is invalid.",
                    );
                }
            };
            (credential.uid, scopes, None, None)
        }
        "authorization_code" => {
            let Some(code) = request.fields.get("code").filter(|value| !value.is_empty()) else {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "The code field is required.",
                );
            };
            let Some(configured_app_key) = state.config.app_key.as_deref() else {
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "The Passport encryption key is not configured.",
                );
            };
            let encryption_key = match defuse::laravel_app_key_bytes(configured_app_key) {
                Ok(key) => key,
                Err(()) => {
                    tracing::error!("configured Laravel APP_KEY cannot be decoded");
                    return oauth_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "server_error",
                        "The Passport encryption key is invalid.",
                    );
                }
            };
            let payload = match defuse::decrypt_with_password(code, &encryption_key)
                .ok()
                .and_then(|plaintext| {
                    serde_json::from_slice::<PassportAuthorizationCodePayload>(&plaintext).ok()
                }) {
                Some(payload) => payload,
                None => {
                    return oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_grant",
                        "The authorization code is invalid.",
                    );
                }
            };
            let payload_client_id = match oauth_json_identifier(&payload.client_id) {
                Some(id) => id,
                None => {
                    return oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_grant",
                        "The authorization code is invalid.",
                    );
                }
            };
            let Some(user_id) = oauth_json_identifier(&payload.user_id) else {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "The authorization code is invalid.",
                );
            };
            if payload_client_id != client.id || payload.expire_time <= unix_now() {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "The authorization code is invalid or expired.",
                );
            }
            if request.fields.get("redirect_uri") != payload.redirect_uri.as_ref() {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "The redirect_uri does not match the authorization request.",
                );
            }
            let code_verifier = request.fields.get("code_verifier").map(String::as_str);
            match payload
                .code_challenge
                .as_deref()
                .filter(|value| !value.is_empty())
            {
                Some(challenge) => {
                    let Some(verifier) = code_verifier else {
                        return oauth_error(
                            StatusCode::BAD_REQUEST,
                            "invalid_request",
                            "The code_verifier field is required.",
                        );
                    };
                    if !valid_pkce_verifier(verifier) {
                        return oauth_error(
                            StatusCode::BAD_REQUEST,
                            "invalid_request",
                            "The code_verifier is invalid.",
                        );
                    }
                    let method = payload.code_challenge_method.as_deref().unwrap_or("plain");
                    if !verify_pkce_challenge(verifier, challenge, method) {
                        return oauth_error(
                            StatusCode::BAD_REQUEST,
                            "invalid_grant",
                            "The code_verifier could not be verified.",
                        );
                    }
                }
                None if code_verifier.is_some() => {
                    return oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        "A code_verifier was received for an authorization code without PKCE.",
                    );
                }
                None => {}
            }

            let known_scopes = load_known_scopes(database, prefix).await;
            let mut scopes = Vec::with_capacity(payload.scopes.len());
            for scope in payload.scopes {
                if !known_scopes.iter().any(|known| known == &scope) {
                    return oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_scope",
                        "The authorization code contains an invalid scope.",
                    );
                }
                if !scopes.contains(&scope) {
                    scopes.push(scope);
                }
            }
            let code_record = match database
                .oauth_auth_code(prefix, &payload.auth_code_id)
                .await
            {
                Ok(Some(record)) => record,
                Ok(None) => {
                    return oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_grant",
                        "The authorization code is invalid or has already been used.",
                    );
                }
                Err(error) => {
                    tracing::error!(%error, "failed to load OAuth authorization code");
                    return oauth_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "server_error",
                        "The authorization service is unavailable.",
                    );
                }
            };
            let mut persisted_scopes = decode_stored_scopes(&code_record.scopes);
            let mut payload_scopes = scopes.clone();
            persisted_scopes.sort();
            payload_scopes.sort();
            if code_record.revoked
                || code_record.client_id != client.id
                || code_record.user_id != Some(user_id)
                || persisted_scopes != payload_scopes
            {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "The authorization code is invalid or has already been used.",
                );
            }
            (
                user_id,
                scopes,
                None,
                Some((payload.auth_code_id, user_id, client.id)),
            )
        }
        "refresh_token" => {
            let Some(refresh_id) = request
                .fields
                .get("refresh_token")
                .filter(|value| !value.is_empty())
            else {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "The refresh_token field is required.",
                );
            };
            let previous = match database.oauth_refresh_token(prefix, refresh_id).await {
                Ok(Some(previous)) => previous,
                Ok(None) => {
                    return oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_grant",
                        "The refresh token is invalid or expired.",
                    );
                }
                Err(error) => {
                    tracing::error!(%error, "failed to load OAuth refresh token");
                    return oauth_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "server_error",
                        "The authorization service is unavailable.",
                    );
                }
            };
            if previous.user_id.is_none() || previous.client_id != client.id {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "The refresh token is invalid for this client.",
                );
            }
            let old_scopes = decode_stored_scopes(&previous.scopes);
            let known_scopes = load_known_scopes(database, prefix).await;
            let scopes = match parse_scopes(
                request.fields.get("scope").map(String::as_str),
                Some(&old_scopes),
                &known_scopes,
            ) {
                Ok(scopes) => scopes,
                Err(()) => {
                    return oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_scope",
                        "The requested scope is invalid.",
                    );
                }
            };
            if scopes
                .iter()
                .any(|scope| !old_scopes.iter().any(|old| old == scope))
            {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_scope",
                    "A refresh token cannot grant additional scopes.",
                );
            }
            (
                previous.user_id.unwrap(),
                scopes,
                Some(refresh_id.clone()),
                None,
            )
        }
        _ => unreachable!(),
    };

    let now = unix_now();
    let access_expires = now.saturating_add(ACCESS_TOKEN_TTL);
    let refresh_expires = now.saturating_add(REFRESH_TOKEN_TTL);
    let access_id = new_uuid();
    let refresh_id = Alphanumeric.sample_string(&mut rand::thread_rng(), 80);
    let claims = PassportAccessTokenClaims {
        aud: client.id.to_string(),
        exp: access_expires,
        iat: now,
        jti: access_id.clone(),
        nbf: now,
        scopes: scopes.clone(),
        sub: user_id.to_string(),
    };
    let access_token = match encode(&Header::new(Algorithm::RS256), &claims, signing_key) {
        Ok(token) => token,
        Err(error) => {
            tracing::error!(%error, "failed to sign Passport access token");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "The authorization service is unavailable.",
            );
        }
    };
    let scopes_json = match serde_json::to_string(&scopes) {
        Ok(scopes) => scopes,
        Err(error) => {
            tracing::error!(%error, "failed to serialize OAuth scopes");
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "The authorization service failed.",
            );
        }
    };
    let stored = match database
        .issue_oauth_token_pair(
            prefix,
            &access_id,
            user_id,
            client.id,
            &scopes_json,
            &database_datetime(access_expires),
            &refresh_id,
            &database_datetime(refresh_expires),
            rotate_refresh.as_deref(),
            consume_auth_code
                .as_ref()
                .map(|(id, user_id, client_id)| (id.as_str(), *user_id, *client_id)),
        )
        .await
    {
        Ok(stored) => stored,
        Err(error) => {
            tracing::error!(%error, "failed to persist Passport access and refresh tokens");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "The authorization service is unavailable.",
            );
        }
    };
    if !stored {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "The refresh token has already been used.",
        );
    }

    let mut response = Json(serde_json::json!({
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_TTL,
        "access_token": access_token,
        "refresh_token": refresh_id,
        "scope": scopes.join(" "),
    }))
    .into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

impl TokenRequest {
    fn parse(body: &[u8]) -> Result<Self, ()> {
        let mut fields = HashMap::new();
        for (key, value) in form_urlencoded::parse(body) {
            if fields
                .insert(key.into_owned(), value.into_owned())
                .is_some()
            {
                return Err(());
            }
        }
        Ok(Self { fields })
    }
}

fn client_credentials(
    headers: &HeaderMap,
    fields: &HashMap<String, String>,
) -> Result<(i64, Option<String>), Response> {
    let basic = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    if let Some(header) = basic.filter(|header| {
        header
            .get(..6)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("Basic "))
    }) {
        if fields.contains_key("client_id") || fields.contains_key("client_secret") {
            return Err(oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Client credentials must be sent in one place.",
            ));
        }
        let decoded = STANDARD.decode(&header[6..]).map_err(|_| {
            oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "Client authentication failed.",
            )
        })?;
        let decoded = String::from_utf8(decoded).map_err(|_| {
            oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "Client authentication failed.",
            )
        })?;
        let (id, secret) = decoded.split_once(':').ok_or_else(|| {
            oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "Client authentication failed.",
            )
        })?;
        let id = id.parse().map_err(|_| {
            oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "Client authentication failed.",
            )
        })?;
        return Ok((id, Some(secret.to_owned())));
    }
    let id = fields
        .get("client_id")
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| {
            oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "The client_id field is required.",
            )
        })?;
    Ok((id, fields.get("client_secret").cloned()))
}

fn verify_client_secret(client: &OAuthGrantClientRecord, supplied: Option<&str>) -> bool {
    let Some(expected) = client.secret.as_deref() else {
        return true;
    };
    let Some(supplied) = supplied else {
        return false;
    };
    if expected.starts_with("$2") || expected.starts_with("$argon2") {
        return crate::auth::verify_legacy_password(supplied, expected, "PHP_PASSWORD_HASH", "");
    }
    bool::from(expected.as_bytes().ct_eq(supplied.as_bytes()))
}

async fn load_known_scopes(database: &crate::database::DatabasePool, prefix: &str) -> Vec<String> {
    let mut scopes: Vec<String> = KNOWN_SCOPES
        .iter()
        .map(|scope| (*scope).to_owned())
        .collect();
    match database.oauth_scopes(prefix).await {
        Ok(custom) => scopes.extend(custom),
        Err(error) => {
            tracing::warn!(%error, "could not load custom Passport scopes; using built-in scopes")
        }
    }
    scopes.sort();
    scopes.dedup();
    scopes
}

fn parse_scopes(
    requested: Option<&str>,
    defaults: Option<&[String]>,
    known_scopes: &[String],
) -> Result<Vec<String>, ()> {
    let scopes: Vec<String> = match requested.filter(|value| !value.trim().is_empty()) {
        Some(value) => value.split_ascii_whitespace().map(str::to_owned).collect(),
        None => defaults
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| vec!["User.Read".to_owned()]),
    };
    if scopes
        .iter()
        .any(|scope| !known_scopes.iter().any(|known| known == scope))
    {
        return Err(());
    }
    let mut unique = Vec::with_capacity(scopes.len());
    for scope in scopes {
        if !unique.contains(&scope) {
            unique.push(scope);
        }
    }
    Ok(unique)
}

fn decode_stored_scopes(stored: &str) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(stored).unwrap_or_else(|_| {
        stored
            .split([',', ' '])
            .filter(|scope| !scope.is_empty())
            .map(str::to_owned)
            .collect()
    })
}

fn new_uuid() -> String {
    let mut bytes = [0_u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn database_datetime(timestamp: u64) -> String {
    DateTime::<Utc>::from_timestamp(timestamp as i64, 0)
        .unwrap_or_else(|| DateTime::<Utc>::from_timestamp(0, 0).unwrap())
        .format("%Y-%m-%d %H:%M:%S")
        .to_string()
}

fn oauth_error(status: StatusCode, error: &str, message: &str) -> Response {
    let mut response = (
        status,
        Json(serde_json::json!({
            "error": error,
            "error_description": message,
            "message": message,
        })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

#[cfg(test)]
mod tests {
    use super::{KNOWN_SCOPES, TokenRequest, decode_stored_scopes, new_uuid, parse_scopes};

    fn known_scopes() -> Vec<String> {
        KNOWN_SCOPES
            .iter()
            .map(|scope| (*scope).to_owned())
            .collect()
    }

    #[test]
    fn parses_form_encoded_oauth_requests_and_rejects_duplicates() {
        let parsed = TokenRequest::parse(
            b"grant_type=password&username=alex%40example.test&scope=User.Read+Player.Read",
        )
        .unwrap();
        assert_eq!(
            parsed.fields.get("username").map(String::as_str),
            Some("alex@example.test")
        );
        assert_eq!(
            parsed.fields.get("scope").map(String::as_str),
            Some("User.Read Player.Read")
        );
        assert!(TokenRequest::parse(b"grant_type=password&grant_type=refresh_token").is_err());
    }

    #[test]
    fn applies_default_and_requested_scope_rules() {
        assert_eq!(
            parse_scopes(None, None, &known_scopes()).unwrap(),
            vec!["User.Read"]
        );
        assert_eq!(
            parse_scopes(
                Some("Player.Read User.Read Player.Read"),
                None,
                &known_scopes()
            )
            .unwrap(),
            vec!["Player.Read", "User.Read"]
        );
        assert!(parse_scopes(Some("Unknown.Read"), None, &known_scopes()).is_err());
        assert_eq!(
            parse_scopes(None, Some(&["Player.Read".to_owned()]), &known_scopes()).unwrap(),
            vec!["Player.Read"]
        );
    }

    #[test]
    fn accepts_passport_json_and_legacy_scope_storage() {
        assert_eq!(
            decode_stored_scopes("[\"User.Read\",\"Player.Read\"]"),
            vec!["User.Read", "Player.Read"]
        );
        assert_eq!(
            decode_stored_scopes("User.Read,Player.Read"),
            vec!["User.Read", "Player.Read"]
        );
    }

    #[test]
    fn creates_uuid_formatted_token_identifiers() {
        let id = new_uuid();
        assert_eq!(id.len(), 36);
        assert_eq!(id.as_bytes()[8], b'-');
        assert_eq!(id.as_bytes()[13], b'-');
        assert_eq!(id.as_bytes()[18], b'-');
        assert_eq!(id.as_bytes()[23], b'-');
    }
}
#[cfg(test)]
mod integration_tests {
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, encode};
    use serde_json::Value;
    use sha2::{Digest, Sha256};
    use sqlx::sqlite::SqlitePoolOptions;
    use std::{path::PathBuf, sync::Arc};
    use tower::ServiceExt;

    use super::unix_now;

    use crate::{
        AppState,
        config::{Config, DatabaseConfig, DatabaseConnection, MailConfig},
        database::DatabasePool,
        defuse, http,
    };

    fn form(fields: &[(&str, &str)]) -> String {
        let mut serializer = form_urlencoded::Serializer::new(String::new());
        for (key, value) in fields {
            serializer.append_pair(key, value);
        }
        serializer.finish()
    }

    fn hidden_input_value(html: &str, name: &str) -> String {
        let marker = format!("name=\"{name}\" value=\"");
        html.split_once(&marker)
            .unwrap()
            .1
            .split_once('"')
            .unwrap()
            .0
            .to_owned()
    }

    fn redirect_parameter(location: &str, name: &str) -> Option<String> {
        let query = location.split_once('?')?.1.split('#').next()?;
        form_urlencoded::parse(query.as_bytes())
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
    }
    async fn response_json(response: axum::response::Response) -> Value {
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn session_cookie(user_id: i64, secret: &str) -> String {
        let now = jsonwebtoken::get_current_timestamp();
        let claims = crate::auth::WebSessionClaims {
            sub: user_id.to_string(),
            iat: now,
            exp: now + 3600,
        };
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();
        format!("blessing_skin_session={token}")
    }

    #[tokio::test]
    async fn passport_password_and_refresh_grants_issue_compatible_tokens() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query("CREATE TABLE users (uid INTEGER PRIMARY KEY, email TEXT NOT NULL, nickname TEXT NOT NULL DEFAULT '', locale TEXT, score INTEGER NOT NULL DEFAULT 0, avatar INTEGER NOT NULL DEFAULT 0, password TEXT NOT NULL, ip TEXT NOT NULL DEFAULT '', permission INTEGER NOT NULL, last_sign_at TEXT NOT NULL DEFAULT '', register_at TEXT NOT NULL DEFAULT '', verified BOOLEAN NOT NULL DEFAULT 1, is_dark_mode BOOLEAN NOT NULL DEFAULT 0)")
            .execute(&pool).await.unwrap();
        sqlx::query("CREATE TABLE options (id INTEGER PRIMARY KEY, option_name TEXT NOT NULL, option_value TEXT NOT NULL)")
            .execute(&pool).await.unwrap();
        sqlx::query("CREATE TABLE players (pid INTEGER PRIMARY KEY, uid INTEGER NOT NULL, name TEXT NOT NULL)")
            .execute(&pool).await.unwrap();
        sqlx::query("CREATE TABLE scopes (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, description TEXT NOT NULL)")
            .execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO scopes (id,name,description) VALUES (1,'Plugin.Custom','Custom plugin capability')")
            .execute(&pool).await.unwrap();
        sqlx::query("CREATE TABLE oauth_clients (id INTEGER PRIMARY KEY, user_id INTEGER, name TEXT NOT NULL, secret TEXT, provider TEXT, redirect TEXT NOT NULL, personal_access_client BOOLEAN NOT NULL, password_client BOOLEAN NOT NULL, revoked BOOLEAN NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)")
            .execute(&pool).await.unwrap();
        sqlx::query("CREATE TABLE oauth_access_tokens (id TEXT PRIMARY KEY, user_id INTEGER, client_id INTEGER NOT NULL, name TEXT, scopes TEXT, revoked BOOLEAN NOT NULL, created_at TEXT, updated_at TEXT, expires_at TEXT)")
            .execute(&pool).await.unwrap();
        sqlx::query("CREATE TABLE oauth_refresh_tokens (id TEXT PRIMARY KEY, access_token_id TEXT NOT NULL, revoked BOOLEAN NOT NULL, expires_at TEXT)")
            .execute(&pool).await.unwrap();
        sqlx::query("CREATE TABLE oauth_auth_codes (id TEXT PRIMARY KEY, user_id INTEGER, client_id INTEGER NOT NULL, scopes TEXT NOT NULL, revoked BOOLEAN NOT NULL)")
            .execute(&pool).await.unwrap();
        let password = bcrypt::hash("correct horse", 4).unwrap();
        sqlx::query(
            "INSERT INTO users (uid,email,nickname,password,permission) VALUES (7,'alex@example.test','Alex',?,1),(8,'other@example.test','Other','unused',0)",
        )
        .bind(password)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO oauth_clients (id,name,secret,provider,redirect,personal_access_client,password_client,revoked,created_at,updated_at) VALUES (2,'Game client','client-secret',NULL,'http://localhost',FALSE,TRUE,FALSE,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)")
            .execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO oauth_clients (id,user_id,name,secret,provider,redirect,personal_access_client,password_client,revoked,created_at,updated_at) VALUES (3,7,'Third-party app','never-return-this-secret',NULL,'https://example.test/callback',FALSE,FALSE,FALSE,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)")
            .execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO oauth_clients (id,name,secret,provider,redirect,personal_access_client,password_client,revoked,created_at,updated_at) VALUES (4,'Personal Access Client','personal-secret',NULL,'http://localhost',TRUE,FALSE,FALSE,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)")
            .execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO oauth_access_tokens (id,user_id,client_id,name,scopes,revoked,created_at,updated_at,expires_at) VALUES ('authorized-third-party',7,3,'Browser','[\"User.Read\"]',FALSE,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)")
            .execute(&pool).await.unwrap();

        let private_key = include_bytes!("../tests/fixtures/oauth-test-private.pem");
        let public_key = include_bytes!("../tests/fixtures/oauth-test-public.pem");
        let session_secret = "test web session signing secret";
        let config = Config {
            bind: "127.0.0.1:3000".parse().unwrap(),
            version: "test",
            locale: "en".to_owned(),
            database: DatabaseConfig {
                connection: DatabaseConnection::Sqlite(sqlx::sqlite::SqliteConnectOptions::new()),
                table_prefix: String::new(),
            },
            textures_dir: PathBuf::new(),
            plugins_dir: PathBuf::new(),
            app_url: "https://skin.example.test".to_owned(),
            passport_public_key: Some(public_key.to_vec()),
            passport_private_key: Some(private_key.to_vec()),
            password_method: "BCRYPT".to_owned(),
            password_salt: String::new(),
            app_key: Some(session_secret.to_owned()),
            mail: MailConfig::default(),
        };
        let app = http::router(AppState {
            config: Arc::new(config),
            database: Some(DatabasePool::Sqlite(pool.clone())),
            passport_key: Some(DecodingKey::from_rsa_pem(public_key).unwrap()),
            passport_signing_key: Some(EncodingKey::from_rsa_pem(private_key).unwrap()),
            session_key: Some(EncodingKey::from_secret(session_secret.as_bytes())),
            login_failures: Default::default(),
            captcha_challenges: Default::default(),
            mail_limits: Default::default(),
        });

        let password_body = form(&[
            ("grant_type", "password"),
            ("client_id", "2"),
            ("client_secret", "client-secret"),
            ("username", "alex@example.test"),
            ("password", "correct horse"),
            ("scope", "User.Read Player.Read Plugin.Custom"),
        ]);
        let response = app
            .clone()
            .oneshot(
                Request::post("/oauth/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(password_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
        let issued: Value = response_json(response).await;
        assert_eq!(issued["expires_in"], 365 * 24 * 60 * 60);
        let first_access = issued["access_token"].as_str().unwrap();
        let first_refresh = issued["refresh_token"].as_str().unwrap();
        let claims = crate::auth::decode_access_token(
            first_access,
            &DecodingKey::from_rsa_pem(public_key).unwrap(),
        )
        .unwrap();
        assert_eq!(claims.sub, "7");
        assert_eq!(claims.aud.unwrap(), "2");
        assert_eq!(
            claims.scopes,
            vec!["User.Read", "Player.Read", "Plugin.Custom"]
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM oauth_access_tokens WHERE id = ? AND revoked = FALSE"
            )
            .bind(&claims.jti)
            .fetch_one(&pool)
            .await
            .unwrap(),
            1
        );

        let auth_code_id = "php-issued-code";
        let code_verifier = "A".repeat(43);
        let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
        let code_scopes = vec!["User.Read", "Plugin.Custom"];
        sqlx::query(
            "INSERT INTO oauth_auth_codes (id,user_id,client_id,scopes,revoked) VALUES (?,?,?, ?,FALSE)",
        )
        .bind(auth_code_id)
        .bind(7_i64)
        .bind(3_i64)
        .bind(serde_json::to_string(&code_scopes).unwrap())
        .execute(&pool)
        .await
        .unwrap();
        let code_payload = serde_json::json!({
            "client_id": "3",
            "redirect_uri": "https://example.test/callback",
            "auth_code_id": auth_code_id,
            "scopes": code_scopes,
            "user_id": "7",
            "expire_time": unix_now() + 600,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256"
        });
        let encrypted_code = defuse::encrypt_with_password(
            serde_json::to_string(&code_payload).unwrap().as_bytes(),
            session_secret.as_bytes(),
        )
        .unwrap();
        let wrong_code_request = form(&[
            ("grant_type", "authorization_code"),
            ("client_id", "3"),
            ("client_secret", "never-return-this-secret"),
            ("code", &encrypted_code),
            ("redirect_uri", "https://example.test/callback"),
            ("code_verifier", &"B".repeat(43)),
        ]);
        let rejected_code = app
            .clone()
            .oneshot(
                Request::post("/oauth/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(wrong_code_request))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rejected_code.status(), StatusCode::BAD_REQUEST);
        let rejected_code: Value = response_json(rejected_code).await;
        assert_eq!(rejected_code["error"], "invalid_grant");
        assert_eq!(
            sqlx::query_scalar::<_, bool>("SELECT revoked FROM oauth_auth_codes WHERE id = ?",)
                .bind(auth_code_id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            false
        );

        let valid_code_request = form(&[
            ("grant_type", "authorization_code"),
            ("client_id", "3"),
            ("client_secret", "never-return-this-secret"),
            ("code", &encrypted_code),
            ("redirect_uri", "https://example.test/callback"),
            ("code_verifier", &code_verifier),
        ]);
        let code_response = app
            .clone()
            .oneshot(
                Request::post("/oauth/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(valid_code_request.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(code_response.status(), StatusCode::OK);
        assert_eq!(
            code_response.headers().get("cache-control").unwrap(),
            "no-store"
        );
        let code_tokens: Value = response_json(code_response).await;
        let code_claims = crate::auth::decode_access_token(
            code_tokens["access_token"].as_str().unwrap(),
            &DecodingKey::from_rsa_pem(public_key).unwrap(),
        )
        .unwrap();
        assert_eq!(code_claims.sub, "7");
        assert_eq!(code_claims.aud.unwrap(), "3");
        assert_eq!(code_claims.scopes, vec!["User.Read", "Plugin.Custom"]);
        assert_eq!(
            sqlx::query_scalar::<_, bool>("SELECT revoked FROM oauth_auth_codes WHERE id = ?",)
                .bind(auth_code_id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            true
        );
        let replayed_code = app
            .clone()
            .oneshot(
                Request::post("/oauth/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(valid_code_request))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(replayed_code.status(), StatusCode::BAD_REQUEST);
        let replayed_code: Value = response_json(replayed_code).await;
        assert_eq!(replayed_code["error"], "invalid_grant");

        let browser_verifier = "C".repeat(43);
        let browser_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(browser_verifier.as_bytes()));
        let authorize_path = format!(
            "/oauth/authorize?response_type=code&client_id=3&scope=User.Read+Plugin.Custom&state=browser-state&code_challenge={browser_challenge}&code_challenge_method=S256"
        );
        let guest_authorize = app
            .clone()
            .oneshot(Request::get(&authorize_path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(guest_authorize.status(), StatusCode::SEE_OTHER);
        let login_location = guest_authorize
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        assert!(login_location.starts_with("/auth/login?redirect_to="));
        let login_page = app
            .clone()
            .oneshot(Request::get(&login_location).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(login_page.status(), StatusCode::OK);
        let login_html = String::from_utf8(
            to_bytes(login_page.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(login_html.contains("id=\"redirect-to\" type=\"hidden\""));
        let login_response = app
            .clone()
            .oneshot(
                Request::post("/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::json!({
                        "identification": "alex@example.test",
                        "password": "correct horse",
                        "redirect_to": format!("/oauth/authorize?response_type=code&client_id=3&scope=User.Read+Plugin.Custom&state=browser-state&code_challenge={browser_challenge}&code_challenge_method=S256")
                    }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login_response.status(), StatusCode::OK);
        let login_result: Value = response_json(login_response).await;
        assert_eq!(login_result["data"]["redirectTo"], authorize_path);
        let authorize_page = app
            .clone()
            .oneshot(
                Request::get(&authorize_path)
                    .header("cookie", session_cookie(7, session_secret))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authorize_page.status(), StatusCode::OK);
        let page_html = String::from_utf8(
            to_bytes(authorize_page.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(page_html.contains("Third-party app"));
        assert!(page_html.contains("Plugin.Custom"));
        let authorize_token = hidden_input_value(&page_html, "auth_token");
        let authorize_form = form(&[
            ("auth_token", &authorize_token),
            ("client_id", "3"),
            ("decision", "approve"),
        ]);
        let authorize_response = app
            .clone()
            .oneshot(
                Request::post("/oauth/authorize")
                    .header("cookie", session_cookie(7, session_secret))
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(authorize_form))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authorize_response.status(), StatusCode::FOUND);
        let authorize_location = authorize_response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        assert!(authorize_location.starts_with("https://example.test/callback?code="));
        assert_eq!(
            redirect_parameter(&authorize_location, "state").as_deref(),
            Some("browser-state")
        );
        let browser_code = redirect_parameter(&authorize_location, "code").unwrap();
        let browser_exchange = form(&[
            ("grant_type", "authorization_code"),
            ("client_id", "3"),
            ("client_secret", "never-return-this-secret"),
            ("code", &browser_code),
            ("code_verifier", &browser_verifier),
        ]);
        let browser_tokens = app
            .clone()
            .oneshot(
                Request::post("/oauth/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(browser_exchange))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(browser_tokens.status(), StatusCode::OK);
        let browser_tokens: Value = response_json(browser_tokens).await;
        let browser_claims = crate::auth::decode_access_token(
            browser_tokens["access_token"].as_str().unwrap(),
            &DecodingKey::from_rsa_pem(public_key).unwrap(),
        )
        .unwrap();
        assert_eq!(browser_claims.sub, "7");
        assert_eq!(browser_claims.scopes, vec!["User.Read", "Plugin.Custom"]);

        let deny_page = app
            .clone()
            .oneshot(
                Request::get("/oauth/authorize?response_type=code&client_id=3&scope=User.Read&state=deny-state")
                    .header("cookie", session_cookie(7, session_secret))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(deny_page.status(), StatusCode::OK);
        let deny_html = String::from_utf8(
            to_bytes(deny_page.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        let deny_token = hidden_input_value(&deny_html, "auth_token");
        let deny_form = form(&[
            ("auth_token", &deny_token),
            ("client_id", "3"),
            ("_method", "DELETE"),
        ]);
        let denied = app
            .clone()
            .oneshot(
                Request::post("/oauth/authorize")
                    .header("cookie", session_cookie(7, session_secret))
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(deny_form))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::FOUND);
        let deny_location = denied.headers().get("location").unwrap().to_str().unwrap();
        assert_eq!(
            redirect_parameter(deny_location, "error").as_deref(),
            Some("access_denied")
        );
        assert_eq!(
            redirect_parameter(deny_location, "state").as_deref(),
            Some("deny-state")
        );
        let refresh_body = form(&[
            ("grant_type", "refresh_token"),
            ("client_id", "2"),
            ("client_secret", "client-secret"),
            ("refresh_token", first_refresh),
            ("scope", "User.Read"),
        ]);
        let response = app
            .clone()
            .oneshot(
                Request::post("/oauth/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(refresh_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let refreshed: Value = response_json(response).await;
        let second_refresh = refreshed["refresh_token"].as_str().unwrap();
        assert_ne!(first_refresh, second_refresh);
        assert_eq!(
            sqlx::query_scalar::<_, bool>("SELECT revoked FROM oauth_refresh_tokens WHERE id = ?")
                .bind(first_refresh)
                .fetch_one(&pool)
                .await
                .unwrap(),
            true
        );

        let scopes = app
            .clone()
            .oneshot(
                Request::get("/oauth/scopes")
                    .header("cookie", session_cookie(7, session_secret))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(scopes.status(), StatusCode::OK);
        let scopes: Value = response_json(scopes).await;
        assert!(scopes.as_array().unwrap().iter().any(|scope| {
            scope["id"] == "User.Read" && scope["description"] == "auth.oauth.scope.user.read"
        }));
        assert!(scopes.as_array().unwrap().iter().any(|scope| {
            scope["id"] == "Plugin.Custom" && scope["description"] == "Custom plugin capability"
        }));

        let listed = app
            .clone()
            .oneshot(
                Request::get("/oauth/tokens")
                    .header("cookie", session_cookie(7, session_secret))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(listed.status(), StatusCode::OK);
        let listed: Value = response_json(listed).await;
        assert_eq!(listed.as_array().unwrap().len(), 3);
        assert!(
            listed
                .as_array()
                .unwrap()
                .iter()
                .any(|token| token["id"] == "authorized-third-party")
        );
        let listed_code_token = listed
            .as_array()
            .unwrap()
            .iter()
            .find(|token| token["id"] == code_claims.jti)
            .unwrap();
        assert_eq!(listed_code_token["scopes"][0], "User.Read");
        assert_eq!(listed_code_token["client"]["name"], "Third-party app");
        assert!(listed_code_token["client"].get("secret").is_none());

        let personal_created = app
            .clone()
            .oneshot(
                Request::post("/oauth/personal-access-tokens")
                    .header("cookie", session_cookie(7, session_secret))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"name":"CLI token","scopes":["User.Read"]}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(personal_created.status(), StatusCode::OK);
        let personal_created: Value = response_json(personal_created).await;
        assert_eq!(personal_created["token"]["name"], "CLI token");
        let personal_access = personal_created["accessToken"].as_str().unwrap();
        let personal_claims = crate::auth::decode_access_token(
            personal_access,
            &DecodingKey::from_rsa_pem(public_key).unwrap(),
        )
        .unwrap();
        assert_eq!(personal_created["token"]["id"], personal_claims.jti);
        let personal_use = app
            .clone()
            .oneshot(
                Request::get("/api/user")
                    .header("authorization", format!("Bearer {personal_access}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(personal_use.status(), StatusCode::OK);
        let personal_list = app
            .clone()
            .oneshot(
                Request::get("/oauth/personal-access-tokens")
                    .header("cookie", session_cookie(7, session_secret))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(personal_list.status(), StatusCode::OK);
        let personal_list: Value = response_json(personal_list).await;
        assert_eq!(personal_list.as_array().unwrap().len(), 1);
        assert_eq!(personal_list[0]["id"], personal_claims.jti);
        let personal_revoke = app
            .clone()
            .oneshot(
                Request::delete(format!(
                    "/oauth/personal-access-tokens/{}",
                    personal_claims.jti
                ))
                .header("cookie", session_cookie(7, session_secret))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(personal_revoke.status(), StatusCode::NO_CONTENT);
        let revoked_use = app
            .clone()
            .oneshot(
                Request::get("/api/user")
                    .header("authorization", format!("Bearer {personal_access}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(revoked_use.status(), StatusCode::UNAUTHORIZED);

        let second_access = refreshed["access_token"].as_str().unwrap();
        let second_claims = crate::auth::decode_access_token(
            second_access,
            &DecodingKey::from_rsa_pem(public_key).unwrap(),
        )
        .unwrap();
        let path = format!("/oauth/tokens/{}", second_claims.jti);
        let other_owner = app
            .clone()
            .oneshot(
                Request::delete(&path)
                    .header("cookie", session_cookie(8, session_secret))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(other_owner.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            sqlx::query_scalar::<_, bool>("SELECT revoked FROM oauth_access_tokens WHERE id = ?")
                .bind(&second_claims.jti)
                .fetch_one(&pool)
                .await
                .unwrap(),
            false
        );

        let revoked = app
            .clone()
            .oneshot(
                Request::delete(&path)
                    .header("cookie", session_cookie(7, session_secret))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(revoked.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            sqlx::query_scalar::<_, bool>("SELECT revoked FROM oauth_access_tokens WHERE id = ?")
                .bind(&second_claims.jti)
                .fetch_one(&pool)
                .await
                .unwrap(),
            true
        );
        assert_eq!(
            sqlx::query_scalar::<_, bool>("SELECT revoked FROM oauth_refresh_tokens WHERE id = ?")
                .bind(second_refresh)
                .fetch_one(&pool)
                .await
                .unwrap(),
            true
        );

        let reused_body = form(&[
            ("grant_type", "refresh_token"),
            ("client_id", "2"),
            ("client_secret", "client-secret"),
            ("refresh_token", second_refresh),
        ]);
        let response = app
            .oneshot(
                Request::post("/oauth/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(reused_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let error: Value = response_json(response).await;
        assert_eq!(error["error"], "invalid_grant");
    }
}
