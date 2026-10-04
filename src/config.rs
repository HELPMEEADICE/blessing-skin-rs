use std::{env, net::SocketAddr, path::PathBuf};

use sqlx::{mysql::MySqlConnectOptions, postgres::PgConnectOptions, sqlite::SqliteConnectOptions};
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct Config {
    pub bind: SocketAddr,
    pub version: &'static str,
    pub locale: String,
    pub fallback_locale: String,
    pub database: DatabaseConfig,
    pub textures_dir: PathBuf,
    pub plugins_dir: PathBuf,
    pub wasm_plugin_registry_url: Option<String>,
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
            fallback_locale: env::var("APP_FALLBACK_LOCALE").unwrap_or_else(|_| "en".to_owned()),
            database: DatabaseConfig::from_env(table_prefix)?,
            textures_dir,
            plugins_dir,
            wasm_plugin_registry_url: env::var("WASM_PLUGIN_REGISTRY_URL")
                .ok()
                .filter(|value| !value.trim().is_empty()),
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
                if sqlite_foreign_keys.is_some_and(|value| value == "false" || value == "0") {
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
        let driver = env::var("DB_CONNECTION").unwrap_or_else(|_| "mysql".to_owned());
        if let Some(url) = env::var("DATABASE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
        {
            let foreign_keys = env::var("DB_FOREIGN_KEYS").ok();
            return Self::from_url(&driver, table_prefix, &url, foreign_keys.as_deref());
        }
        let (connection, display_driver, host, port, username, database) = match driver
            .to_ascii_lowercase()
            .as_str()
        {
            "sqlite" => {
                let database = env::var("DB_DATABASE")
                    .unwrap_or_else(|_| "storage/database.sqlite".to_owned());
                let mut options = SqliteConnectOptions::new()
                    .filename(&database)
                    .create_if_missing(false);
                if env::var("DB_FOREIGN_KEYS").is_ok_and(|value| value == "false" || value == "0") {
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
                let host = env::var("DB_HOST").unwrap_or_else(|_| "127.0.0.1".to_owned());
                let port = parse_port("DB_PORT", 3306);
                let username = env::var("DB_USERNAME").unwrap_or_else(|_| "forge".to_owned());
                let database = env::var("DB_DATABASE").unwrap_or_else(|_| "forge".to_owned());
                let options = mysql_connect_options(
                    &host,
                    port,
                    &username,
                    &env::var("DB_PASSWORD").unwrap_or_default(),
                    &database,
                    env::var("DB_SOCKET").ok().as_deref(),
                );
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
                let host = env::var("DB_HOST").unwrap_or_else(|_| "127.0.0.1".to_owned());
                let port = parse_port("DB_PORT", 5432);
                let username = env::var("DB_USERNAME").unwrap_or_else(|_| "forge".to_owned());
                let database = env::var("DB_DATABASE").unwrap_or_else(|_| "forge".to_owned());
                let options = PgConnectOptions::new()
                    .host(&host)
                    .port(port)
                    .username(&username)
                    .password(&env::var("DB_PASSWORD").unwrap_or_default())
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
    use super::{
        ConfigError, DatabaseConfig, DatabaseConnection, mysql_connect_options, valid_table_prefix,
    };
    use std::path::Path;

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
            "mysql://blessing:p%40ss@db.example.test:3307/skin",
            None,
        )
        .unwrap();
        assert_eq!(mysql.driver, "MySQL/MariaDB");
        assert_eq!(mysql.host.as_deref(), Some("db.example.test"));
        assert_eq!(mysql.port, Some(3307));
        assert_eq!(mysql.username.as_deref(), Some("blessing"));
        assert_eq!(mysql.database, "skin");
        assert_eq!(mysql.table_prefix, "bs_");
        assert!(matches!(mysql.connection, DatabaseConnection::MySql(_)));

        let postgres = DatabaseConfig::from_url(
            "pgsql",
            String::new(),
            "postgres://blessing:secret@db.example.test:5433/skin?sslmode=require",
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
        )
        .unwrap();
        assert_eq!(sqlite.database, "/var/lib/blessing-skin/database.sqlite");
        assert!(matches!(sqlite.connection, DatabaseConnection::Sqlite(_)));

        assert!(matches!(
            DatabaseConfig::from_url("mysql", String::new(), "not-a-url", None),
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
