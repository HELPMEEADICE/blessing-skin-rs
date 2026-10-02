use axum::http::{HeaderMap, header::AUTHORIZATION};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
pub struct PassportClaims {
    pub jti: String,
    pub sub: String,
    pub exp: u64,
    #[serde(default)]
    pub scopes: Vec<String>,
    pub aud: Option<Value>,
}

pub fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let authorization = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = authorization.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Bearer")
        || token.is_empty()
        || token.chars().any(char::is_whitespace)
    {
        return None;
    }
    Some(token)
}

pub fn decode_access_token(token: &str, key: &DecodingKey) -> Option<PassportClaims> {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_aud = false;
    decode::<PassportClaims>(token, key, &validation)
        .ok()
        .map(|data| data.claims)
}

pub fn has_scope(claims: &PassportClaims, required: &str) -> bool {
    claims.scopes.iter().any(|scope| scope == required)
}

pub fn audience_matches(audience: Option<&Value>, client_id: i64) -> bool {
    let expected = client_id.to_string();
    match audience {
        Some(Value::String(value)) => value == &expected,
        Some(Value::Array(values)) => values.iter().any(|value| value.as_str() == Some(&expected)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{PassportClaims, audience_matches, bearer_token, has_scope};
    use axum::http::{HeaderMap, HeaderValue, header::AUTHORIZATION};
    use serde_json::json;

    #[test]
    fn extracts_only_well_formed_bearer_credentials() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer legacy-token"),
        );
        assert_eq!(bearer_token(&headers), Some("legacy-token"));
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Basic legacy-token"),
        );
        assert_eq!(bearer_token(&headers), None);
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer two tokens"));
        assert_eq!(bearer_token(&headers), None);
    }

    #[test]
    fn checks_string_and_array_passport_audiences() {
        assert!(audience_matches(Some(&json!("3")), 3));
        assert!(audience_matches(Some(&json!(["1", "3"])), 3));
        assert!(!audience_matches(Some(&json!("30")), 3));
    }

    #[test]
    fn enforces_scopes_by_exact_name() {
        let claims = PassportClaims {
            jti: "token".to_owned(),
            sub: "7".to_owned(),
            exp: u64::MAX,
            scopes: vec!["User.Read".to_owned()],
            aud: None,
        };
        assert!(has_scope(&claims, "User.Read"));
        assert!(!has_scope(&claims, "Player.Read"));
    }
}
