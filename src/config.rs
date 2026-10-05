use std::{env, ffi::OsString, net::SocketAddr, path::PathBuf};

use sqlx::{mysql::MySqlConnectOptions, postgres::PgConnectOptions, sqlite::SqliteConnectOptions};
use thiserror::Error;

const LEGACY_SQLITE_DATABASE_PATH: &str = "database/database.sqlite";
const DEFAULT_RUST_RELEASES_API_URL: &str =
    "https://api.github.com/repos/HELPMEEADICE/blessing-skin-rs/releases/latest";
const DEFAULT_LEGACY_APP_VERSION: &str = "6.0.2";

/// Read an environment value using Laravel's reserved `.env` value semantics.
/// Laravel's `Env::get` converts `null` and `(null)` to `None`, and `empty` and
/// `(empty)` to an empty string. Rust's dotenv loader leaves these as strings.
pub(crate) fn legacy_env(name: &str) -> Option<String> {
    env::var(name).ok().and_then(parse_legacy_env_value)
}

fn legacy_env_os(name: &str) -> Option<OsString> {
    env::var_os(name).and_then(parse_legacy_env_os)
}

fn parse_legacy_env_os(value: OsString) -> Option<OsString> {
    match value.into_string() {
        Ok(value) => parse_legacy_env_value(value).map(OsString::from),
        Err(value) => Some(value),
    }
}

fn parse_legacy_env_value(value: String) -> Option<String> {
    match value.to_ascii_lowercase().as_str() {
        "null" | "(null)" => None,
        "empty" | "(empty)" => Some(String::new()),
        _ => Some(value),
    }
}

fn is_legacy_false(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "false" | "(false)" | "0"
    )
}

#[derive(Clone, Debug)]
pub struct Config {
    pub bind: SocketAddr,
    pub rust_version: &'static str,
    pub legacy_app_version: String,
    pub locale: String,
    pub fallback_locale: String,
    pub database: DatabaseConfig,
    pub textures_dir: PathBuf,
    pub plugins_dir: PathBuf,
    pub wasm_plugin_registry_url: Option<String>,
    pub rust_releases_api_url: Option<String>,
    pub app_url: String,
    pub passport_public_key: Option<Vec<u8>>,
    pub passport_private_key: Option<Vec<u8>>,
    pub password_method: String,
    pub password_salt: String,
    pub bcrypt_rounds: u32,
    pub app_key: Option<String>,
    pub mail: MailConfig,
}

#[derive(Clone, Debug)]
pub struct MailConfig {
    pub mailer: String,
    pub url: Option<String>,
    pub sendmail_path: String,
    pub mailgun_domain: Option<String>,
    pub mailgun_secret: Option<String>,
    pub mailgun_endpoint: String,
    pub postmark_token: Option<String>,
    pub postmark_message_stream: Option<String>,
    pub ses_access_key: Option<String>,
    pub ses_secret_key: Option<String>,
    pub ses_session_token: Option<String>,
    pub ses_region: String,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub encryption: String,
    pub local_domain: Option<String>,
    pub from_address: String,
    pub from_name: String,
}

impl Default for MailConfig {
    fn default() -> Self {
        Self::from_values(|_| None)
    }
}

#[derive(Clone, Debug)]
pub struct DatabaseConfig {
    pub connection: DatabaseConnection,
    pub table_prefix: String,
    pub driver: String,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub database: String,
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
    #[error("invalid database setup value")]
    InvalidSetupValue,
    #[error("invalid DATABASE_URL for the selected DB_CONNECTION")]
    InvalidDatabaseUrl,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let bind = legacy_env("BS_LISTEN")
            .unwrap_or_else(|| "127.0.0.1:3000".to_owned())
            .parse()?;
        let table_prefix = legacy_env("DB_PREFIX").unwrap_or_default();
        if !valid_table_prefix(&table_prefix) {
            return Err(ConfigError::InvalidTablePrefix);
        }

        let storage =
            PathBuf::from(legacy_env("STORAGE_PATH").unwrap_or_else(|| "storage".to_owned()));
        let textures_dir = legacy_env_os("TEXTURES_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| storage.join("textures"));
        let passport_public_key = load_passport_public_key(&storage);

        let plugins_dir = legacy_env_os("PLUGINS_DIR")
            .map(PathBuf::from)
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| storage.join("plugins"));

        Ok(Self {
            bind,
            rust_version: env!("CARGO_PKG_VERSION"),
            legacy_app_version: legacy_app_version(legacy_env("BS_LEGACY_APP_VERSION")),
            locale: legacy_env("APP_LOCALE").unwrap_or_else(|| "zh_CN".to_owned()),
            fallback_locale: legacy_env("APP_FALLBACK_LOCALE").unwrap_or_else(|| "en".to_owned()),
            database: DatabaseConfig::from_env(table_prefix)?,
            textures_dir,
            plugins_dir,
            wasm_plugin_registry_url: legacy_env("WASM_PLUGIN_REGISTRY_URL")
                .filter(|value| !value.trim().is_empty()),
            rust_releases_api_url: match legacy_env("RUST_RELEASES_API_URL") {
                Some(value) if value.is_empty() => None,
                Some(value) => Some(value),
                None => Some(DEFAULT_RUST_RELEASES_API_URL.to_owned()),
            },
            app_url: legacy_env("APP_URL").unwrap_or_else(|| "http://localhost".to_owned()),
            passport_public_key,
            passport_private_key: load_passport_key(
                &storage,
                "PASSPORT_PRIVATE_KEY",
                "oauth-private.key",
            ),
            password_method: legacy_env("PWD_METHOD").unwrap_or_else(|| "BCRYPT".to_owned()),
            password_salt: legacy_env("SALT").unwrap_or_default(),
            bcrypt_rounds: parse_bcrypt_rounds(legacy_env("BCRYPT_ROUNDS")),
            app_key: legacy_env("APP_KEY")
                .filter(|value| !value.is_empty())
                .or_else(|| std::fs::read_to_string(storage.join("app.key")).ok())
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty()),
            mail: MailConfig::from_env(),
        })
    }
}

fn legacy_app_version(value: Option<String>) -> String {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_LEGACY_APP_VERSION.to_owned())
}

impl MailConfig {
    fn from_env() -> Self {
        Self::from_values(legacy_env)
    }

    fn from_values(mut value: impl FnMut(&str) -> Option<String>) -> Self {
        Self {
            mailer: value("MAIL_MAILER").unwrap_or_else(|| "smtp".to_owned()),
            url: value("MAIL_URL").filter(|value| !value.trim().is_empty()),
            sendmail_path: value("MAIL_SENDMAIL_PATH")
                .unwrap_or_else(|| "/usr/sbin/sendmail -bs -i".to_owned()),
            mailgun_domain: value("MAILGUN_DOMAIN").filter(|value| !value.trim().is_empty()),
            mailgun_secret: value("MAILGUN_SECRET").filter(|value| !value.trim().is_empty()),
            mailgun_endpoint: value("MAILGUN_ENDPOINT")
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "api.mailgun.net".to_owned()),
            postmark_token: value("POSTMARK_TOKEN").filter(|value| !value.trim().is_empty()),
            postmark_message_stream: value("POSTMARK_MESSAGE_STREAM_ID")
                .filter(|value| !value.trim().is_empty()),
            ses_access_key: value("AWS_ACCESS_KEY_ID").filter(|value| !value.trim().is_empty()),
            ses_secret_key: value("AWS_SECRET_ACCESS_KEY").filter(|value| !value.trim().is_empty()),
            ses_session_token: value("AWS_SESSION_TOKEN").filter(|value| !value.trim().is_empty()),
            ses_region: value("AWS_DEFAULT_REGION")
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "us-east-1".to_owned()),
            host: value("MAIL_HOST").unwrap_or_else(|| "smtp.mailgun.org".to_owned()),
            port: parse_port_value(value("MAIL_PORT"), 587),
            username: value("MAIL_USERNAME").filter(|value| !value.is_empty()),
            password: value("MAIL_PASSWORD").filter(|value| !value.is_empty()),
            encryption: value("MAIL_ENCRYPTION").unwrap_or_else(|| "tls".to_owned()),
            local_domain: value("MAIL_EHLO_DOMAIN").filter(|value| !value.is_empty()),
            from_address: value("MAIL_FROM_ADDRESS")
                .unwrap_or_else(|| "hello@example.com".to_owned()),
            from_name: value("MAIL_FROM_NAME").unwrap_or_else(|| "Example".to_owned()),
        }
    }
}

impl DatabaseConfig {
    pub fn from_setup(
        driver: &str,
        host: &str,
        port: &str,
        username: &str,
        password: &str,
        database: &str,
        table_prefix: &str,
    ) -> Result<Self, ConfigError> {
        if !valid_table_prefix(table_prefix) {
            return Err(ConfigError::InvalidTablePrefix);
        }
        if [driver, host, port, username, password, database]
            .iter()
            .any(|value| value.chars().any(char::is_control))
        {
            return Err(ConfigError::InvalidSetupValue);
        }
        let driver = driver.trim().to_ascii_lowercase();
        let table_prefix = table_prefix.to_owned();
        match driver.as_str() {
            "sqlite" => {
                if database.trim().is_empty() || database.trim() == ":memory:" {
                    return Err(ConfigError::InvalidSetupValue);
                }
                let options = SqliteConnectOptions::new()
                    .filename(database)
                    .create_if_missing(false);
                Ok(Self {
                    connection: DatabaseConnection::Sqlite(options),
                    table_prefix,
                    driver: "SQLite".to_owned(),
                    host: None,
                    port: None,
                    username: None,
                    database: database.to_owned(),
                })
            }
            "mysql" | "mariadb" => {
                if host.trim().is_empty()
                    || username.trim().is_empty()
                    || database.trim().is_empty()
                {
                    return Err(ConfigError::InvalidSetupValue);
                }
                let port = parse_setup_port(port, 3306)?;
                let options = MySqlConnectOptions::new()
                    .host(host)
                    .port(port)
                    .username(username)
                    .password(password)
                    .database(database);
                let options =
                    with_mysql_ssl_ca(options, legacy_env("MYSQL_ATTR_SSL_CA").as_deref());
                Ok(Self {
                    connection: DatabaseConnection::MySql(options),
                    table_prefix,
                    driver: "MySQL/MariaDB".to_owned(),
                    host: Some(host.to_owned()),
                    port: Some(port),
                    username: Some(username.to_owned()),
                    database: database.to_owned(),
                })
            }
            "pgsql" | "postgres" | "postgresql" => {
                if host.trim().is_empty()
                    || username.trim().is_empty()
                    || database.trim().is_empty()
                {
                    return Err(ConfigError::InvalidSetupValue);
                }
                let port = parse_setup_port(port, 5432)?;
                let options = PgConnectOptions::new()
                    .host(host)
                    .port(port)
                    .username(username)
                    .password(password)
                    .database(database);
                Ok(Self {
                    connection: DatabaseConnection::Postgres(options),
                    table_prefix,
                    driver: "PostgreSQL".to_owned(),
                    host: Some(host.to_owned()),
                    port: Some(port),
                    username: Some(username.to_owned()),
                    database: database.to_owned(),
                })
            }
            _ => Err(ConfigError::UnsupportedDatabase(driver)),
        }
    }

    fn from_url(
        driver: &str,
        table_prefix: String,
        url: &str,
        sqlite_foreign_keys: Option<&str>,
        mysql_ssl_ca: Option<&str>,
    ) -> Result<Self, ConfigError> {
        if !valid_table_prefix(&table_prefix) {
            return Err(ConfigError::InvalidTablePrefix);
        }

        match driver.to_ascii_lowercase().as_str() {
            "sqlite" => {
                let mut options = url
                    .parse::<SqliteConnectOptions>()
                    .map_err(|_| ConfigError::InvalidDatabaseUrl)?
                    .create_if_missing(false);
                if sqlite_foreign_keys.is_some_and(is_legacy_false) {
                    options = options.foreign_keys(false);
                }
                let database = options.get_filename().to_string_lossy().into_owned();
                Ok(Self {
                    connection: DatabaseConnection::Sqlite(options),
                    table_prefix,
                    driver: "SQLite".to_owned(),
                    host: None,
                    port: None,
                    username: None,
                    database,
                })
            }
            "mysql" | "mariadb" => {
                let options = url
                    .parse::<MySqlConnectOptions>()
                    .map_err(|_| ConfigError::InvalidDatabaseUrl)?;
                let options = with_mysql_ssl_ca(options, mysql_ssl_ca);
                let host = options.get_host().to_owned();
                let port = options.get_port();
                let username = options.get_username().to_owned();
                let database = options.get_database().unwrap_or_default().to_owned();
                Ok(Self {
                    connection: DatabaseConnection::MySql(options),
                    table_prefix,
                    driver: "MySQL/MariaDB".to_owned(),
                    host: Some(host),
                    port: Some(port),
                    username: Some(username),
                    database,
                })
            }
            "pgsql" | "postgres" | "postgresql" => {
                let options = url
                    .parse::<PgConnectOptions>()
                    .map_err(|_| ConfigError::InvalidDatabaseUrl)?;
                let host = options.get_host().to_owned();
                let port = options.get_port();
                let username = options.get_username().to_owned();
                let database = options.get_database().unwrap_or_default().to_owned();
                Ok(Self {
                    connection: DatabaseConnection::Postgres(options),
                    table_prefix,
                    driver: "PostgreSQL".to_owned(),
                    host: Some(host),
                    port: Some(port),
                    username: Some(username),
                    database,
                })
            }
            _ => Err(ConfigError::UnsupportedDatabase(driver.to_owned())),
        }
    }

    fn from_env(table_prefix: String) -> Result<Self, ConfigError> {
        let driver = legacy_env("DB_CONNECTION").unwrap_or_else(|| "mysql".to_owned());
        if let Some(url) = legacy_env("DATABASE_URL").filter(|value| !value.trim().is_empty()) {
            let foreign_keys = legacy_env("DB_FOREIGN_KEYS");
            let mysql_ssl_ca = legacy_env("MYSQL_ATTR_SSL_CA");
            return Self::from_url(
                &driver,
                table_prefix,
                &url,
                foreign_keys.as_deref(),
                mysql_ssl_ca.as_deref(),
            );
        }
        let (connection, display_driver, host, port, username, database) =
            match driver.to_ascii_lowercase().as_str() {
                "sqlite" => {
                    let database = sqlite_database_path(legacy_env("DB_DATABASE"));
                    let mut options = SqliteConnectOptions::new()
                        .filename(&database)
                        .create_if_missing(false);
                    if legacy_env("DB_FOREIGN_KEYS").is_some_and(|value| is_legacy_false(&value)) {
                        options = options.foreign_keys(false);
                    }
                    (
                        DatabaseConnection::Sqlite(options),
                        "SQLite",
                        None,
                        None,
                        None,
                        database,
                    )
                }
                "mysql" | "mariadb" => {
                    let host = legacy_env("DB_HOST").unwrap_or_else(|| "127.0.0.1".to_owned());
                    let port = parse_port("DB_PORT", 3306);
                    let username = legacy_env("DB_USERNAME").unwrap_or_else(|| "forge".to_owned());
                    let database = legacy_env("DB_DATABASE").unwrap_or_else(|| "forge".to_owned());
                    let options = mysql_connect_options(
                        &host,
                        port,
                        &username,
                        &legacy_env("DB_PASSWORD").unwrap_or_default(),
                        &database,
                        legacy_env("DB_SOCKET").as_deref(),
                    );
                    let options =
                        with_mysql_ssl_ca(options, legacy_env("MYSQL_ATTR_SSL_CA").as_deref());
                    (
                        DatabaseConnection::MySql(options),
                        "MySQL/MariaDB",
                        Some(host),
                        Some(port),
                        Some(username),
                        database,
                    )
                }
                "pgsql" | "postgres" | "postgresql" => {
                    let host = legacy_env("DB_HOST").unwrap_or_else(|| "127.0.0.1".to_owned());
                    let port = parse_port("DB_PORT", 5432);
                    let username = legacy_env("DB_USERNAME").unwrap_or_else(|| "forge".to_owned());
                    let database = legacy_env("DB_DATABASE").unwrap_or_else(|| "forge".to_owned());
                    let options = PgConnectOptions::new()
                        .host(&host)
                        .port(port)
                        .username(&username)
                        .password(&legacy_env("DB_PASSWORD").unwrap_or_default())
                        .database(&database);
                    (
                        DatabaseConnection::Postgres(options),
                        "PostgreSQL",
                        Some(host),
                        Some(port),
                        Some(username),
                        database,
                    )
                }
                _ => return Err(ConfigError::UnsupportedDatabase(driver)),
            };

        Ok(Self {
            connection,
            table_prefix,
            driver: display_driver.to_owned(),
            host,
            port,
            username,
            database,
        })
    }
}

fn mysql_connect_options(
    host: &str,
    port: u16,
    username: &str,
    password: &str,
    database: &str,
    socket: Option<&str>,
) -> MySqlConnectOptions {
    let options = MySqlConnectOptions::new()
        .host(host)
        .port(port)
        .username(username)
        .password(password)
        .database(database);
    match socket.filter(|path| !path.trim().is_empty()) {
        Some(path) => options.socket(path),
        None => options,
    }
}

fn with_mysql_ssl_ca(
    options: MySqlConnectOptions,
    certificate_authority: Option<&str>,
) -> MySqlConnectOptions {
    match certificate_authority.filter(|path| !path.trim().is_empty()) {
        Some(path) => options.ssl_ca(path),
        None => options,
    }
}

fn parse_bcrypt_rounds(value: Option<String>) -> u32 {
    value.and_then(|rounds| rounds.parse().ok()).unwrap_or(10)
}

fn parse_setup_port(value: &str, default: u16) -> Result<u16, ConfigError> {
    if value.trim().is_empty() {
        return Ok(default);
    }
    let port = value
        .parse::<u16>()
        .map_err(|_| ConfigError::InvalidSetupValue)?;
    if port == 0 {
        return Err(ConfigError::InvalidSetupValue);
    }
    Ok(port)
}

fn sqlite_database_path(database: Option<String>) -> String {
    database.unwrap_or_else(|| LEGACY_SQLITE_DATABASE_PATH.to_owned())
}

fn parse_port(name: &str, default: u16) -> u16 {
    parse_port_value(legacy_env(name), default)
}

fn parse_port_value(value: Option<String>, default: u16) -> u16 {
    value
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
    use super::{
        ConfigError, DatabaseConfig, DatabaseConnection, MailConfig, is_legacy_false,
        legacy_app_version, mysql_connect_options, parse_bcrypt_rounds, parse_legacy_env_os,
        parse_legacy_env_value, valid_table_prefix, with_mysql_ssl_ca,
    };
    use sqlx::{ConnectOptions, mysql::MySqlConnectOptions};
    use std::{ffi::OsString, path::Path};

    fn mysql_ssl_ca_path(options: &MySqlConnectOptions) -> Option<String> {
        options
            .to_url_lossy()
            .query_pairs()
            .find(|(name, _)| name == "ssl-ca")
            .map(|(_, value)| value.strip_prefix("file: ").unwrap_or(&value).to_owned())
    }

    #[test]
    fn legacy_application_version_defaults_to_php_and_supports_overrides() {
        assert_eq!(legacy_app_version(None), "6.0.2");
        assert_eq!(legacy_app_version(Some(" 6.1.0 ".to_owned())), "6.1.0");
        assert_eq!(legacy_app_version(Some(String::new())), "6.0.2");
    }

    #[test]
    fn parses_laravel_reserved_environment_values() {
        for value in ["null", "NULL", "(null)", "(NULL)"] {
            assert_eq!(parse_legacy_env_value(value.to_owned()), None);
        }
        for value in ["empty", "EMPTY", "(empty)", "(EMPTY)"] {
            assert_eq!(
                parse_legacy_env_value(value.to_owned()),
                Some(String::new())
            );
        }
        assert_eq!(
            parse_legacy_env_value("/srv/blessing/textures".to_owned()),
            Some("/srv/blessing/textures".to_owned())
        );
        assert_eq!(
            parse_legacy_env_value(" null ".to_owned()),
            Some(" null ".to_owned())
        );
    }

    #[test]
    fn parses_reserved_values_for_path_environment_variables() {
        assert_eq!(parse_legacy_env_os(OsString::from("null")), None);
        assert_eq!(
            parse_legacy_env_os(OsString::from("empty")),
            Some(OsString::new())
        );
        assert_eq!(
            parse_legacy_env_os(OsString::from("/srv/blessing/textures")),
            Some(OsString::from("/srv/blessing/textures"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn preserves_non_utf8_path_environment_values() {
        use std::os::unix::ffi::OsStringExt;

        let path = OsString::from_vec(vec![0xff, b'/', b't']);
        assert_eq!(parse_legacy_env_os(path.clone()), Some(path));
    }

    #[test]
    fn parses_laravel_false_values_for_database_options() {
        assert!(is_legacy_false("false"));
        assert!(is_legacy_false("FALSE"));
        assert!(is_legacy_false("(false)"));
        assert!(is_legacy_false("0"));
        assert!(!is_legacy_false("true"));
        assert!(!is_legacy_false("1"));
    }

    #[test]
    fn mail_configuration_matches_laravel_defaults_when_unset() {
        let mail = MailConfig::from_values(|_| None);
        assert_eq!(mail.mailer, "smtp");
        assert!(mail.url.is_none());
        assert_eq!(mail.sendmail_path, "/usr/sbin/sendmail -bs -i");
        assert!(mail.mailgun_domain.is_none());
        assert!(mail.mailgun_secret.is_none());
        assert_eq!(mail.mailgun_endpoint, "api.mailgun.net");
        assert!(mail.postmark_token.is_none());
        assert!(mail.postmark_message_stream.is_none());
        assert!(mail.ses_access_key.is_none());
        assert!(mail.ses_secret_key.is_none());
        assert!(mail.ses_session_token.is_none());
        assert_eq!(mail.ses_region, "us-east-1");
        assert_eq!(mail.host, "smtp.mailgun.org");
        assert_eq!(mail.port, 587);
        assert_eq!(mail.encryption, "tls");
        assert!(mail.local_domain.is_none());
        assert_eq!(mail.from_address, "hello@example.com");
        assert_eq!(mail.from_name, "Example");
        assert!(mail.username.is_none());
        assert!(mail.password.is_none());
    }

    #[test]
    fn mail_configuration_reads_legacy_provider_environment_values() {
        let mail = MailConfig::from_values(|name| match name {
            "MAILGUN_DOMAIN" => Some("mg.example.test".to_owned()),
            "MAILGUN_SECRET" => Some("mailgun-secret".to_owned()),
            "MAILGUN_ENDPOINT" => Some("api.eu.mailgun.net".to_owned()),
            "POSTMARK_TOKEN" => Some("postmark-token".to_owned()),
            "POSTMARK_MESSAGE_STREAM_ID" => Some("transactional".to_owned()),
            _ => None,
        });
        assert_eq!(mail.mailgun_domain.as_deref(), Some("mg.example.test"));
        assert_eq!(mail.mailgun_secret.as_deref(), Some("mailgun-secret"));
        assert_eq!(mail.mailgun_endpoint, "api.eu.mailgun.net");
        assert_eq!(mail.postmark_token.as_deref(), Some("postmark-token"));
        assert_eq!(
            mail.postmark_message_stream.as_deref(),
            Some("transactional")
        );
    }

    #[test]
    fn mail_configuration_reads_legacy_ses_environment_values() {
        let mail = MailConfig::from_values(|name| match name {
            "AWS_ACCESS_KEY_ID" => Some("access-key".to_owned()),
            "AWS_SECRET_ACCESS_KEY" => Some("secret-key".to_owned()),
            "AWS_SESSION_TOKEN" => Some("session-token".to_owned()),
            "AWS_DEFAULT_REGION" => Some("eu-west-1".to_owned()),
            _ => None,
        });
        assert_eq!(mail.ses_access_key.as_deref(), Some("access-key"));
        assert_eq!(mail.ses_secret_key.as_deref(), Some("secret-key"));
        assert_eq!(mail.ses_session_token.as_deref(), Some("session-token"));
        assert_eq!(mail.ses_region, "eu-west-1");
    }

    #[test]
    fn mail_configuration_keeps_explicit_legacy_smtp_values() {
        let mail = MailConfig::from_values(|name| match name {
            "MAIL_MAILER" => Some("smtp".to_owned()),
            "MAIL_URL" => Some("smtp://url-user:url-pass@smtp-url.example.test:465".to_owned()),
            "MAIL_HOST" => Some("mail.example.test".to_owned()),
            "MAIL_PORT" => Some("2525".to_owned()),
            "MAIL_USERNAME" => Some("blessing".to_owned()),
            "MAIL_PASSWORD" => Some("secret".to_owned()),
            "MAIL_ENCRYPTION" => Some("ssl".to_owned()),
            "MAIL_EHLO_DOMAIN" => Some("smtp.example.test".to_owned()),
            _ => None,
        });
        assert_eq!(
            mail.url.as_deref(),
            Some("smtp://url-user:url-pass@smtp-url.example.test:465")
        );
        assert_eq!(mail.host, "mail.example.test");
        assert_eq!(mail.port, 2525);
        assert_eq!(mail.encryption, "ssl");
        assert_eq!(mail.username.as_deref(), Some("blessing"));
        assert_eq!(mail.password.as_deref(), Some("secret"));
    }

    #[test]
    fn defaults_sqlite_path_to_the_legacy_laravel_database_location() {
        assert_eq!(
            super::sqlite_database_path(None),
            "database/database.sqlite"
        );
        assert_eq!(
            super::sqlite_database_path(Some("storage/custom.sqlite".to_owned())),
            "storage/custom.sqlite"
        );
    }

    #[test]
    fn parses_bcrypt_rounds_with_the_laravel_default() {
        assert_eq!(parse_bcrypt_rounds(None), 10);
        assert_eq!(parse_bcrypt_rounds(Some("12".to_owned())), 12);
        assert_eq!(parse_bcrypt_rounds(Some("not-an-integer".to_owned())), 10);
    }

    #[test]
    fn accepts_empty_and_simple_prefixes() {
        assert!(valid_table_prefix(""));
        assert!(valid_table_prefix("bs_"));
        assert!(valid_table_prefix("skin2026_"));
    }

    #[test]
    fn validates_and_builds_database_settings_from_setup_form() {
        let sqlite =
            DatabaseConfig::from_setup("sqlite", "", "", "", "", "storage/setup.sqlite", "bs_")
                .unwrap();
        assert_eq!(sqlite.driver, "SQLite");
        assert_eq!(sqlite.table_prefix, "bs_");
        assert!(matches!(sqlite.connection, DatabaseConnection::Sqlite(_)));

        let postgres = DatabaseConfig::from_setup(
            "pgsql",
            "db.example.test",
            "5433",
            "blessing",
            "secret",
            "blessing_skin",
            "",
        )
        .unwrap();
        assert_eq!(postgres.port, Some(5433));
        assert!(matches!(
            postgres.connection,
            DatabaseConnection::Postgres(_)
        ));
        assert!(
            DatabaseConfig::from_setup("mysql", "db", "70000", "user", "", "skin", "").is_err()
        );
        assert!(
            DatabaseConfig::from_setup("mysql", "db", "3306", "user", "", "skin", "x;drop")
                .is_err()
        );
        assert!(DatabaseConfig::from_setup("sqlite", "", "", "", "", ":memory:", "").is_err());
    }

    #[test]
    fn parses_legacy_database_urls_for_all_supported_drivers() {
        let mysql = DatabaseConfig::from_url(
            "mysql",
            "bs_".to_owned(),
            "mysql://blessing:p%40ss@db.example.test:3307/skin?ssl-ca=url-ca.pem",
            None,
            Some("legacy-ca.pem"),
        )
        .unwrap();
        assert_eq!(mysql.driver, "MySQL/MariaDB");
        assert_eq!(mysql.host.as_deref(), Some("db.example.test"));
        assert_eq!(mysql.port, Some(3307));
        assert_eq!(mysql.username.as_deref(), Some("blessing"));
        assert_eq!(mysql.database, "skin");
        assert_eq!(mysql.table_prefix, "bs_");
        let DatabaseConnection::MySql(mysql_options) = mysql.connection else {
            panic!("expected MySQL connection options");
        };
        assert_eq!(
            mysql_ssl_ca_path(&mysql_options).as_deref(),
            Some("legacy-ca.pem")
        );

        let postgres = DatabaseConfig::from_url(
            "pgsql",
            String::new(),
            "postgres://blessing:secret@db.example.test:5433/skin?sslmode=require",
            None,
            None,
        )
        .unwrap();
        assert_eq!(postgres.driver, "PostgreSQL");
        assert_eq!(postgres.host.as_deref(), Some("db.example.test"));
        assert_eq!(postgres.port, Some(5433));
        assert_eq!(postgres.username.as_deref(), Some("blessing"));
        assert_eq!(postgres.database, "skin");
        assert!(matches!(
            postgres.connection,
            DatabaseConnection::Postgres(_)
        ));

        let sqlite = DatabaseConfig::from_url(
            "sqlite",
            String::new(),
            "sqlite:///var/lib/blessing-skin/database.sqlite?mode=rw",
            Some("false"),
            None,
        )
        .unwrap();
        assert_eq!(sqlite.database, "/var/lib/blessing-skin/database.sqlite");
        assert!(matches!(sqlite.connection, DatabaseConnection::Sqlite(_)));

        assert!(matches!(
            DatabaseConfig::from_url("mysql", String::new(), "not-a-url", None, None),
            Err(ConfigError::InvalidDatabaseUrl)
        ));
    }

    #[test]
    fn rejects_sql_identifiers_with_special_characters() {
        assert!(!valid_table_prefix("x; DROP TABLE users"));
        assert!(!valid_table_prefix("bs-skin_"));
    }

    #[test]
    fn honors_legacy_mysql_socket_and_ignores_empty_values() {
        let options = mysql_connect_options(
            "127.0.0.1",
            3306,
            "blessing",
            "secret",
            "blessingskin",
            Some("/run/mysqld/mysqld.sock"),
        );
        assert_eq!(
            options.get_socket().map(|path| path.as_path()),
            Some(Path::new("/run/mysqld/mysqld.sock"))
        );

        let options = mysql_connect_options("localhost", 3306, "user", "", "skin", Some(" "));
        assert!(options.get_socket().is_none());

        let options = with_mysql_ssl_ca(options, Some("/etc/mysql/ca.pem"));
        assert_eq!(
            mysql_ssl_ca_path(&options).as_deref(),
            Some("/etc/mysql/ca.pem")
        );
        let options = with_mysql_ssl_ca(options, Some("  "));
        assert_eq!(
            mysql_ssl_ca_path(&options).as_deref(),
            Some("/etc/mysql/ca.pem")
        );
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
    if let Some(configured) = legacy_env(environment_variable) {
        if let Some(path) = configured.strip_prefix("file://") {
            return std::fs::read(path).ok();
        }
        return Some(configured.replace("\\n", "\n").into_bytes());
    }

    std::fs::read(storage.join(default_filename)).ok()
}
