use std::{env, net::SocketAddr, path::PathBuf};

use sqlx::{mysql::MySqlConnectOptions, postgres::PgConnectOptions, sqlite::SqliteConnectOptions};
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct Config {
    pub bind: SocketAddr,
    pub version: &'static str,
    pub locale: String,
    pub database: DatabaseConfig,
    pub textures_dir: PathBuf,
    pub plugins_dir: PathBuf,
    pub app_url: String,
    pub passport_public_key: Option<Vec<u8>>,
    pub passport_private_key: Option<Vec<u8>>,
    pub password_method: String,
    pub password_salt: String,
    pub app_key: Option<String>,
    pub mail: MailConfig,
}

#[derive(Clone, Debug)]
pub struct MailConfig {
    pub mailer: String,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub encryption: String,
    pub from_address: String,
    pub from_name: String,
}

impl Default for MailConfig {
    fn default() -> Self {
        Self {
            mailer: String::new(),
            host: String::new(),
            port: 465,
            username: None,
            password: None,
            encryption: String::new(),
            from_address: "hello@example.com".to_owned(),
            from_name: "Blessing Skin".to_owned(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct DatabaseConfig {
    pub connection: DatabaseConnection,
    pub table_prefix: String,
}

#[derive(Clone, Debug)]
pub enum DatabaseConnection {
    Sqlite(SqliteConnectOptions),
    MySql(MySqlConnectOptions),
    Postgres(PgConnectOptions),
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid BS_LISTEN address: {0}")]
    InvalidListen(#[from] std::net::AddrParseError),
    #[error("invalid DB_CONNECTION; supported values are sqlite, mysql, mariadb, and pgsql")]
    UnsupportedDatabase(String),
    #[error("DB_PREFIX may contain only ASCII letters, digits, and underscores")]
    InvalidTablePrefix,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let bind = env::var("BS_LISTEN")
            .unwrap_or_else(|_| "127.0.0.1:3000".to_owned())
            .parse()?;
        let table_prefix = env::var("DB_PREFIX").unwrap_or_default();
        if !valid_table_prefix(&table_prefix) {
            return Err(ConfigError::InvalidTablePrefix);
        }

        let storage =
            PathBuf::from(env::var("STORAGE_PATH").unwrap_or_else(|_| "storage".to_owned()));
        let textures_dir = env::var_os("TEXTURES_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| storage.join("textures"));
        let passport_public_key = load_passport_public_key(&storage);

        let plugins_dir = env::var_os("PLUGINS_DIR")
            .map(PathBuf::from)
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| storage.join("plugins"));

        Ok(Self {
            bind,
            version: env!("CARGO_PKG_VERSION"),
            locale: env::var("APP_LOCALE").unwrap_or_else(|_| "zh_CN".to_owned()),
            database: DatabaseConfig::from_env(table_prefix)?,
            textures_dir,
            plugins_dir,
            app_url: env::var("APP_URL").unwrap_or_else(|_| "http://localhost".to_owned()),
            passport_public_key,
            passport_private_key: load_passport_key(
                &storage,
                "PASSPORT_PRIVATE_KEY",
                "oauth-private.key",
            ),
            password_method: env::var("PWD_METHOD").unwrap_or_else(|_| "BCRYPT".to_owned()),
            password_salt: env::var("SALT").unwrap_or_default(),
            app_key: env::var("APP_KEY")
                .ok()
                .filter(|value| !value.is_empty())
                .or_else(|| std::fs::read_to_string(storage.join("app.key")).ok())
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty()),
            mail: MailConfig::from_env(),
        })
    }
}

impl MailConfig {
    fn from_env() -> Self {
        Self {
            mailer: env::var("MAIL_MAILER").unwrap_or_else(|_| "smtp".to_owned()),
            host: env::var("MAIL_HOST").unwrap_or_default(),
            port: parse_port("MAIL_PORT", 465),
            username: env::var("MAIL_USERNAME")
                .ok()
                .filter(|value| !value.is_empty()),
            password: env::var("MAIL_PASSWORD")
                .ok()
                .filter(|value| !value.is_empty()),
            encryption: env::var("MAIL_ENCRYPTION").unwrap_or_default(),
            from_address: env::var("MAIL_FROM_ADDRESS")
                .unwrap_or_else(|_| "hello@example.com".to_owned()),
            from_name: env::var("MAIL_FROM_NAME").unwrap_or_else(|_| "Blessing Skin".to_owned()),
        }
    }
}

impl DatabaseConfig {
    fn from_env(table_prefix: String) -> Result<Self, ConfigError> {
        let driver = env::var("DB_CONNECTION").unwrap_or_else(|_| "mysql".to_owned());
        let connection = match driver.to_ascii_lowercase().as_str() {
            "sqlite" => {
                let filename = env::var("DB_DATABASE")
                    .unwrap_or_else(|_| "storage/database.sqlite".to_owned());
                let mut options = SqliteConnectOptions::new()
                    .filename(filename)
                    .create_if_missing(false);
                if env::var("DB_FOREIGN_KEYS").is_ok_and(|value| value == "false" || value == "0") {
                    options = options.foreign_keys(false);
                }
                DatabaseConnection::Sqlite(options)
            }
            "mysql" | "mariadb" => {
                let options = MySqlConnectOptions::new()
                    .host(&env::var("DB_HOST").unwrap_or_else(|_| "127.0.0.1".to_owned()))
                    .port(parse_port("DB_PORT", 3306))
                    .username(&env::var("DB_USERNAME").unwrap_or_else(|_| "forge".to_owned()))
                    .password(&env::var("DB_PASSWORD").unwrap_or_default())
                    .database(&env::var("DB_DATABASE").unwrap_or_else(|_| "forge".to_owned()));
                DatabaseConnection::MySql(options)
            }
            "pgsql" | "postgres" | "postgresql" => {
                let options = PgConnectOptions::new()
                    .host(&env::var("DB_HOST").unwrap_or_else(|_| "127.0.0.1".to_owned()))
                    .port(parse_port("DB_PORT", 5432))
                    .username(&env::var("DB_USERNAME").unwrap_or_else(|_| "forge".to_owned()))
                    .password(&env::var("DB_PASSWORD").unwrap_or_default())
                    .database(&env::var("DB_DATABASE").unwrap_or_else(|_| "forge".to_owned()));
                DatabaseConnection::Postgres(options)
            }
            _ => return Err(ConfigError::UnsupportedDatabase(driver)),
        };

        Ok(Self {
            connection,
            table_prefix,
        })
    }
}

fn parse_port(name: &str, default: u16) -> u16 {
    env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn valid_table_prefix(prefix: &str) -> bool {
    prefix
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

#[cfg(test)]
mod tests {
    use super::valid_table_prefix;

    #[test]
    fn accepts_empty_and_simple_prefixes() {
        assert!(valid_table_prefix(""));
        assert!(valid_table_prefix("bs_"));
        assert!(valid_table_prefix("skin2026_"));
    }

    #[test]
    fn rejects_sql_identifiers_with_special_characters() {
        assert!(!valid_table_prefix("x; DROP TABLE users"));
        assert!(!valid_table_prefix("bs-skin_"));
    }
}
fn load_passport_public_key(storage: &std::path::Path) -> Option<Vec<u8>> {
    load_passport_key(storage, "PASSPORT_PUBLIC_KEY", "oauth-public.key")
}

fn load_passport_key(
    storage: &std::path::Path,
    environment_variable: &str,
    default_filename: &str,
) -> Option<Vec<u8>> {
    if let Ok(configured) = env::var(environment_variable) {
        if let Some(path) = configured.strip_prefix("file://") {
            return std::fs::read(path).ok();
        }
        return Some(configured.replace("\\n", "\n").into_bytes());
    }

    std::fs::read(storage.join(default_filename)).ok()
}
