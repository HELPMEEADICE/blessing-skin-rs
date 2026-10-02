use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Json,
    body::Bytes,
    extract::{Path, State},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{CACHE_CONTROL, PRAGMA},
    },
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, Header, encode};
use rand::{
    RngCore,
    distributions::{Alphanumeric, DistString},
};
use serde::Serialize;
use subtle::ConstantTimeEq;

use crate::{AppState, database::OAuthGrantClientRecord};

const ACCESS_TOKEN_TTL: u64 = 365 * 24 * 60 * 60;
const REFRESH_TOKEN_TTL: u64 = 365 * 24 * 60 * 60;
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
        .oauth_authorized_tokens_for_user(&state.config.database.table_prefix, user.uid)
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
    if !matches!(grant_type, "password" | "refresh_token") {
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

    let (user_id, scopes, rotate_refresh) = match grant_type {
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
            (credential.uid, scopes, None)
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
            (previous.user_id.unwrap(), scopes, Some(refresh_id.clone()))
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
    use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, encode};
    use serde_json::Value;
    use sqlx::sqlite::SqlitePoolOptions;
    use std::{path::PathBuf, sync::Arc};
    use tower::ServiceExt;

    use crate::{
        AppState,
        config::{Config, DatabaseConfig, DatabaseConnection, MailConfig},
        database::DatabasePool,
        http,
    };

    fn form(fields: &[(&str, &str)]) -> String {
        let mut serializer = form_urlencoded::Serializer::new(String::new());
        for (key, value) in fields {
            serializer.append_pair(key, value);
        }
        serializer.finish()
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
        assert_eq!(listed.as_array().unwrap().len(), 1);
        assert_eq!(listed[0]["id"], "authorized-third-party");
        assert_eq!(listed[0]["scopes"][0], "User.Read");
        assert_eq!(listed[0]["client"]["name"], "Third-party app");
        assert!(listed[0]["client"].get("secret").is_none());

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
