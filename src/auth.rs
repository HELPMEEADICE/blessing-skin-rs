use argon2::password_hash::{PasswordHash, PasswordHasher, SaltString};
use argon2::{Algorithm as ArgonAlgorithm, Argon2, Params, PasswordVerifier, Version};
use axum::http::{HeaderMap, header::AUTHORIZATION};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Sha256, Sha512};
use subtle::ConstantTimeEq;

#[derive(Debug, Serialize, Deserialize)]
pub struct WebSessionClaims {
    #[serde(default)]
    pub jti: Option<String>,
    pub sub: String,
    pub iat: u64,
    pub exp: u64,
    #[serde(default)]
    pub remember: bool,
}

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

pub fn decode_web_session(token: &str, secret: &str) -> Option<WebSessionClaims> {
    let key = DecodingKey::from_secret(secret.as_bytes());
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_aud = false;
    decode::<WebSessionClaims>(token, &key, &validation)
        .ok()
        .map(|data| data.claims)
}

pub fn has_scope(claims: &PassportClaims, required: &str) -> bool {
    claims
        .scopes
        .iter()
        .any(|scope| scope == "*" || scope == required)
}

pub fn audience_matches(audience: Option<&Value>, client_id: i64) -> bool {
    let expected = client_id.to_string();
    match audience {
        Some(Value::String(value)) => value == &expected,
        Some(Value::Array(values)) => values.iter().any(|value| value.as_str() == Some(&expected)),
        _ => false,
    }
}

pub fn verify_legacy_password(password: &str, encoded: &str, method: &str, salt: &str) -> bool {
    match method.to_ascii_uppercase().as_str() {
        "BCRYPT" => verify_bcrypt(password, encoded),
        "ARGON2I" => verify_argon2(password, encoded),
        "PHP_PASSWORD_HASH" => {
            if encoded.starts_with("$2") {
                verify_bcrypt(password, encoded)
            } else if encoded.starts_with("$argon2") {
                verify_argon2(password, encoded)
            } else {
                false
            }
        }
        "MD5" => constant_time_equal(encoded, &format!("{:x}", Md5::digest(password.as_bytes()))),
        "SALTED2MD5" => {
            let first = format!("{:x}", Md5::digest(password.as_bytes()));
            constant_time_equal(
                encoded,
                &format!("{:x}", Md5::digest(format!("{first}{salt}"))),
            )
        }
        "SHA256" => constant_time_equal(
            encoded,
            &format!("{:x}", Sha256::digest(password.as_bytes())),
        ),
        "SALTED2SHA256" => {
            let first = format!("{:x}", Sha256::digest(password.as_bytes()));
            constant_time_equal(
                encoded,
                &format!("{:x}", Sha256::digest(format!("{first}{salt}"))),
            )
        }
        "SHA512" => constant_time_equal(
            encoded,
            &format!("{:x}", Sha512::digest(password.as_bytes())),
        ),
        "SALTED2SHA512" => {
            let first = format!("{:x}", Sha512::digest(password.as_bytes()));
            constant_time_equal(
                encoded,
                &format!("{:x}", Sha512::digest(format!("{first}{salt}"))),
            )
        }
        _ => false,
    }
}

pub fn hash_legacy_password(
    password: &str,
    method: &str,
    salt: &str,
    bcrypt_rounds: u32,
) -> Option<String> {
    match method.to_ascii_uppercase().as_str() {
        "BCRYPT" | "PHP_PASSWORD_HASH" => bcrypt::hash(password, bcrypt_rounds).ok(),
        "ARGON2I" => {
            let argon = Argon2::new(ArgonAlgorithm::Argon2i, Version::V0x13, Params::default());
            let salt = SaltString::generate(&mut rand::thread_rng());
            argon
                .hash_password(password.as_bytes(), &salt)
                .ok()
                .map(|hash| hash.to_string())
        }
        "MD5" => Some(format!("{:x}", Md5::digest(password.as_bytes()))),
        "SALTED2MD5" => {
            let first = format!("{:x}", Md5::digest(password.as_bytes()));
            Some(format!("{:x}", Md5::digest(format!("{first}{salt}"))))
        }
        "SHA256" => Some(format!("{:x}", Sha256::digest(password.as_bytes()))),
        "SALTED2SHA256" => {
            let first = format!("{:x}", Sha256::digest(password.as_bytes()));
            Some(format!("{:x}", Sha256::digest(format!("{first}{salt}"))))
        }
        "SHA512" => Some(format!("{:x}", Sha512::digest(password.as_bytes()))),
        "SALTED2SHA512" => {
            let first = format!("{:x}", Sha512::digest(password.as_bytes()));
            Some(format!("{:x}", Sha512::digest(format!("{first}{salt}"))))
        }
        _ => None,
    }
}

fn verify_bcrypt(password: &str, encoded: &str) -> bool {
    let normalized;
    let encoded = if let Some(rest) = encoded.strip_prefix("$2y$") {
        normalized = format!("$2b${rest}");
        normalized.as_str()
    } else {
        encoded
    };
    bcrypt::verify(password, encoded).unwrap_or(false)
}

fn verify_argon2(password: &str, encoded: &str) -> bool {
    let Ok(hash) = PasswordHash::new(encoded) else {
        return false;
    };
    let algorithm = match hash.algorithm.as_str() {
        "argon2i" => ArgonAlgorithm::Argon2i,
        "argon2id" => ArgonAlgorithm::Argon2id,
        "argon2d" => ArgonAlgorithm::Argon2d,
        _ => return false,
    };
    Argon2::new(algorithm, Version::V0x13, Params::default())
        .verify_password(password.as_bytes(), &hash)
        .is_ok()
}

fn constant_time_equal(actual: &str, expected: &str) -> bool {
    actual.as_bytes().ct_eq(expected.as_bytes()).into()
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
        let wildcard = PassportClaims {
            scopes: vec!["*".to_owned()],
            ..claims
        };
        assert!(has_scope(&wildcard, "Player.Read"));
    }

    #[test]
    fn verifies_php_bcrypt_2y_hashes() {
        let hash = bcrypt::hash("password", 4)
            .unwrap()
            .replacen("$2b$", "$2y$", 1);
        assert!(super::verify_legacy_password(
            "password", &hash, "BCRYPT", ""
        ));
        assert!(!super::verify_legacy_password("wrong", &hash, "BCRYPT", ""));
    }

    #[test]
    fn verifies_legacy_digest_and_salted_digest_formats() {
        assert!(super::verify_legacy_password(
            "password",
            "5f4dcc3b5aa765d61d8327deb882cf99",
            "MD5",
            ""
        ));
        assert!(super::verify_legacy_password(
            "password",
            "1931a728dc5e84865a8b465882510799",
            "SALTED2MD5",
            "pepper"
        ));
        assert!(super::verify_legacy_password(
            "password",
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
            "SHA256",
            ""
        ));
        assert!(super::verify_legacy_password(
            "password",
            "af9c6750ff1ee6fcf123a7962108d4819701976528db91faf65821af04148ee3",
            "SALTED2SHA256",
            "pepper"
        ));
    }

    #[test]
    fn verifies_php_password_hash_argon2i_phc_strings() {
        use argon2::password_hash::SaltString;
        use argon2::{Algorithm, Argon2, Params, PasswordHasher, Version};

        let salt = SaltString::from_b64("c2FsdHlzYWx0").unwrap();
        let hasher = Argon2::new(Algorithm::Argon2i, Version::V0x13, Params::default());
        let hash = hasher
            .hash_password(b"password", &salt)
            .unwrap()
            .to_string();
        assert!(super::verify_legacy_password(
            "password", &hash, "ARGON2I", ""
        ));
        assert!(!super::verify_legacy_password(
            "wrong", &hash, "ARGON2I", ""
        ));
    }

    #[test]
    fn verifies_sha512_and_salted_sha512_legacy_hashes() {
        assert!(super::verify_legacy_password(
            "password",
            "b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86",
            "SHA512",
            ""
        ));
        assert!(super::verify_legacy_password(
            "password",
            "7ab78923e29b98e49adc97c3885cc8d8b1c3baefd4521b81da6704fed4f4822d8f449bf1c9862a144a34472046c702bd1a18c4ea81987cd4d8575cef58851e5c",
            "SALTED2SHA512",
            "pepper"
        ));
    }

    #[test]
    fn hashes_new_passwords_in_configured_legacy_formats() {
        let bcrypt = super::hash_legacy_password("correct horse", "BCRYPT", "", 4).unwrap();
        assert_eq!(bcrypt.split('$').nth(2), Some("04"));
        assert!(super::verify_legacy_password(
            "correct horse",
            &bcrypt,
            "BCRYPT",
            ""
        ));
        let argon = super::hash_legacy_password("correct horse", "ARGON2I", "", 10).unwrap();
        assert!(argon.starts_with("$argon2i$"));
        assert!(super::verify_legacy_password(
            "correct horse",
            &argon,
            "ARGON2I",
            ""
        ));
        for method in [
            "MD5",
            "SALTED2MD5",
            "SHA256",
            "SALTED2SHA256",
            "SHA512",
            "SALTED2SHA512",
        ] {
            let hash =
                super::hash_legacy_password("correct horse", method, "legacy-salt", 10).unwrap();
            assert!(
                super::verify_legacy_password("correct horse", &hash, method, "legacy-salt"),
                "{method}"
            );
        }
        assert!(super::hash_legacy_password("x", "UNKNOWN", "", 10).is_none());
    }
}
