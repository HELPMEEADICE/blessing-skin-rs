use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::{Digest, Sha256};

type Aes256Ctr = ctr::Ctr128BE<Aes256>;
type HmacSha256 = Hmac<Sha256>;

const VERSION: &[u8; 4] = b"\xDE\xF5\x02\x00";
const HEADER_SIZE: usize = 4;
const SALT_SIZE: usize = 32;
const IV_SIZE: usize = 16;
const MAC_SIZE: usize = 32;
const MIN_CIPHERTEXT_SIZE: usize = HEADER_SIZE + SALT_SIZE + IV_SIZE + MAC_SIZE;
const MAX_CIPHERTEXT_SIZE: usize = 16 * 1024;
const PBKDF2_ITERATIONS: u32 = 100_000;
const ENCRYPTION_INFO: &[u8] = b"DefusePHP|V2|KeyForEncryption";
const AUTHENTICATION_INFO: &[u8] = b"DefusePHP|V2|KeyForAuthentication";

pub fn laravel_app_key_bytes(configured: &str) -> Result<Vec<u8>, ()> {
    let bytes = if let Some(encoded) = configured.strip_prefix("base64:") {
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
            .map_err(|_| ())?
    } else {
        configured.as_bytes().to_vec()
    };
    if bytes.is_empty() {
        return Err(());
    }
    Ok(bytes)
}

pub fn encrypt_with_password(plaintext: &[u8], password: &[u8]) -> Result<String, ()> {
    let mut salt = [0_u8; SALT_SIZE];
    let mut iv = [0_u8; IV_SIZE];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut iv);
    encrypt_with_password_and_nonce(plaintext, password, &salt, &iv)
}

fn encrypt_with_password_and_nonce(
    plaintext: &[u8],
    password: &[u8],
    salt: &[u8; SALT_SIZE],
    iv: &[u8; IV_SIZE],
) -> Result<String, ()> {
    if plaintext.len() + MIN_CIPHERTEXT_SIZE > MAX_CIPHERTEXT_SIZE {
        return Err(());
    }
    let (encryption_key, authentication_key) = derive_keys(password, salt)?;
    let mut encrypted = plaintext.to_vec();
    let mut cipher = Aes256Ctr::new((&encryption_key).into(), iv.into());
    cipher.apply_keystream(&mut encrypted);

    let mut bytes = Vec::with_capacity(MIN_CIPHERTEXT_SIZE + encrypted.len());
    bytes.extend_from_slice(VERSION);
    bytes.extend_from_slice(salt);
    bytes.extend_from_slice(iv);
    bytes.extend_from_slice(&encrypted);

    let mut mac = HmacSha256::new_from_slice(&authentication_key).map_err(|_| ())?;
    mac.update(&bytes);
    bytes.extend_from_slice(&mac.finalize().into_bytes());

    Ok(hex::encode(bytes))
}

pub fn decrypt_with_password(ciphertext: &str, password: &[u8]) -> Result<Vec<u8>, ()> {
    if ciphertext.len() % 2 != 0
        || ciphertext.len() / 2 < MIN_CIPHERTEXT_SIZE
        || ciphertext.len() / 2 > MAX_CIPHERTEXT_SIZE
    {
        return Err(());
    }
    let bytes = hex::decode(ciphertext).map_err(|_| ())?;
    if bytes.get(..HEADER_SIZE) != Some(VERSION.as_slice()) {
        return Err(());
    }

    let salt: &[u8; SALT_SIZE] = bytes[HEADER_SIZE..HEADER_SIZE + SALT_SIZE]
        .try_into()
        .map_err(|_| ())?;
    let iv_start = HEADER_SIZE + SALT_SIZE;
    let iv: &[u8; IV_SIZE] = bytes[iv_start..iv_start + IV_SIZE]
        .try_into()
        .map_err(|_| ())?;
    let mac_start = bytes.len() - MAC_SIZE;
    let (encryption_key, authentication_key) = derive_keys(password, salt)?;

    let mut mac = HmacSha256::new_from_slice(&authentication_key).map_err(|_| ())?;
    mac.update(&bytes[..mac_start]);
    mac.verify_slice(&bytes[mac_start..]).map_err(|_| ())?;

    let ciphertext_start = iv_start + IV_SIZE;
    let mut plaintext = bytes[ciphertext_start..mac_start].to_vec();
    let mut cipher = Aes256Ctr::new((&encryption_key).into(), iv.into());
    cipher.apply_keystream(&mut plaintext);
    Ok(plaintext)
}

fn derive_keys(password: &[u8], salt: &[u8; SALT_SIZE]) -> Result<([u8; 32], [u8; 32]), ()> {
    let prehash = Sha256::digest(password);
    let mut prekey = [0_u8; 32];
    pbkdf2_hmac::<Sha256>(&prehash, salt, PBKDF2_ITERATIONS, &mut prekey);

    let hkdf = Hkdf::<Sha256>::new(Some(salt), &prekey);
    let mut encryption_key = [0_u8; 32];
    let mut authentication_key = [0_u8; 32];
    hkdf.expand(ENCRYPTION_INFO, &mut encryption_key)
        .map_err(|_| ())?;
    hkdf.expand(AUTHENTICATION_INFO, &mut authentication_key)
        .map_err(|_| ())?;
    Ok((encryption_key, authentication_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PHP_DEFUSE_V2_FIXTURE: &str = "def50200000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000102030405060708090a0b0c0d0e0ff46e52a0a538111a0762efe8f5b2fe9714948d29cfdee971488e5c2b125c196186d87d23dd1431af1b1583557d4c31d28eec465213caeeecdb24f289ebd28f88aea85bae2b1287dcfb0287988184f5dd15c35bf65ad994478f674fd03c0a01f70b4b0740e326e509c82ee68c582c2ae7b0d79b92531bf1eb107be14e8314d4524334ef5736b1bb1e74a76f3a2750da52b5f10737291a82900e40dc3aab7bdf0c515690387e3450e9f3bbb66d509fb735b1a8dc2757128a835d4f1842c54b68776503c553d66c316f56ad9939781d57a801d652cb9c8b8c291e1b68e9893a97a43c4d0aa754e2005389";
    const PASSWORD: &[u8] = b"0123456789abcdef0123456789abcdef";
    const PLAINTEXT: &[u8] = br#"{"client_id":"3","redirect_uri":"https://example.test/callback","auth_code_id":"abc123","scopes":["User.Read"],"user_id":"7","expire_time":1893456000,"code_challenge":null,"code_challenge_method":null}"#;

    #[test]
    fn decrypts_php_defuse_v2_authorization_code_fixture() {
        assert_eq!(
            decrypt_with_password(PHP_DEFUSE_V2_FIXTURE, PASSWORD).unwrap(),
            PLAINTEXT
        );
    }

    #[test]
    fn emits_a_php_compatible_defuse_v2_ciphertext() {
        let salt: [u8; SALT_SIZE] = std::array::from_fn(|index| index as u8);
        let iv: [u8; IV_SIZE] = std::array::from_fn(|index| index as u8);
        assert_eq!(
            encrypt_with_password_and_nonce(PLAINTEXT, PASSWORD, &salt, &iv).unwrap(),
            PHP_DEFUSE_V2_FIXTURE
        );
    }

    #[test]
    fn decodes_laravel_base64_app_keys_to_their_raw_bytes() {
        let raw = b"0123456789abcdef0123456789abcdef";
        let configured = format!(
            "base64:{}",
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, raw)
        );
        assert_eq!(laravel_app_key_bytes(&configured).unwrap(), raw);
        assert_eq!(laravel_app_key_bytes("plain-key").unwrap(), b"plain-key");
        assert!(laravel_app_key_bytes("base64:invalid").is_err());
    }

    #[test]
    fn rejects_modified_or_truncated_ciphertexts() {
        assert!(decrypt_with_password("def50200", PASSWORD).is_err());
        let mut modified = PHP_DEFUSE_V2_FIXTURE.to_owned();
        modified.replace_range(100..101, if &modified[100..101] == "0" { "1" } else { "0" });
        assert!(decrypt_with_password(&modified, PASSWORD).is_err());
    }
}
