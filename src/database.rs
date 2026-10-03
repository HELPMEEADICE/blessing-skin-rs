use sqlx::{
    FromRow, MySqlPool, PgPool, SqlitePool, mysql::MySqlPoolOptions, postgres::PgPoolOptions,
    sqlite::SqlitePoolOptions,
};
use thiserror::Error;

use crate::config::{DatabaseConfig, DatabaseConnection};

#[derive(Clone)]
pub enum DatabasePool {
    Sqlite(SqlitePool),
    MySql(MySqlPool),
    Postgres(PgPool),
}

#[derive(Debug)]
enum AdminUserSearchBind {
    Text(String),
    Integer(i64),
    Boolean(bool),
}

#[derive(Debug)]
enum AdminUserSearchFilter {
    Text {
        column: &'static str,
        value: String,
        contains: bool,
        negated: bool,
    },
    Global {
        value: String,
        negated: bool,
    },
    Integer {
        column: &'static str,
        value: i64,
        negated: bool,
    },
    Boolean {
        column: &'static str,
        value: bool,
        negated: bool,
    },
}

fn admin_user_where(query: Option<&str>, postgres: bool) -> (String, Vec<AdminUserSearchBind>) {
    let mut groups: Vec<Vec<AdminUserSearchFilter>> = Vec::new();
    let mut current = Vec::new();
    let mut negate_next = false;
    for token in split_user_search(query.unwrap_or_default()) {
        if token.eq_ignore_ascii_case("and") {
            continue;
        }
        if token.eq_ignore_ascii_case("or") {
            if !current.is_empty() {
                groups.push(std::mem::take(&mut current));
            }
            negate_next = false;
            continue;
        }
        if token.eq_ignore_ascii_case("not") {
            negate_next = true;
            continue;
        }
        let negated = std::mem::take(&mut negate_next);
        let filter = if let Some((field, value)) = token.split_once(':') {
            let value = value.trim_matches('"');
            match field {
                "uid" | "avatar" | "score" | "permission" => {
                    value.parse::<i64>().ok().map(|value| {
                        let column = match field {
                            "uid" => "uid",
                            "avatar" => "avatar",
                            "score" => "score",
                            _ => "permission",
                        };
                        AdminUserSearchFilter::Integer {
                            column,
                            value,
                            negated,
                        }
                    })
                }
                "verified" | "is_dark_mode" => {
                    parse_legacy_bool(value).map(|value| AdminUserSearchFilter::Boolean {
                        column: if field == "verified" {
                            "verified"
                        } else {
                            "is_dark_mode"
                        },
                        value,
                        negated,
                    })
                }
                "email" | "nickname" | "ip" | "last_sign_at" | "register_at" => {
                    Some(AdminUserSearchFilter::Text {
                        column: match field {
                            "email" => "email",
                            "nickname" => "nickname",
                            "ip" => "ip",
                            "last_sign_at" => "last_sign_at",
                            _ => "register_at",
                        },
                        value: value.to_owned(),
                        contains: matches!(field, "last_sign_at" | "register_at"),
                        negated,
                    })
                }
                _ => None,
            }
        } else if matches!(token.as_str(), "verified" | "is_dark_mode") {
            Some(AdminUserSearchFilter::Boolean {
                column: if token == "verified" {
                    "verified"
                } else {
                    "is_dark_mode"
                },
                value: !negated,
                negated: false,
            })
        } else {
            Some(AdminUserSearchFilter::Global {
                value: token,
                negated,
            })
        };
        if let Some(filter) = filter {
            current.push(filter);
        }
    }
    if !current.is_empty() {
        groups.push(current);
    }

    let mut binds = Vec::new();
    let mut group_sql = Vec::new();
    for group in groups {
        let mut conditions = Vec::new();
        for filter in group {
            let marker = |index: usize| {
                if postgres {
                    format!("${index}")
                } else {
                    "?".to_owned()
                }
            };
            let idx = binds.len() + 1;
            match filter {
                AdminUserSearchFilter::Text {
                    column,
                    value,
                    contains,
                    negated,
                } => {
                    let operator = if negated {
                        if contains { "NOT LIKE" } else { "<>" }
                    } else if contains {
                        "LIKE"
                    } else {
                        "="
                    };
                    let value = if contains {
                        format!("%{value}%")
                    } else {
                        value
                    };
                    conditions.push(format!("LOWER({column}) {operator} LOWER({})", marker(idx)));
                    binds.push(AdminUserSearchBind::Text(value));
                }
                AdminUserSearchFilter::Global { value, negated } => {
                    let operator = if negated { "NOT LIKE" } else { "LIKE" };
                    let join = if negated { "AND" } else { "OR" };
                    conditions.push(format!(
                        "(LOWER(email) {operator} LOWER({}) {join} LOWER(nickname) {operator} LOWER({}))",
                        marker(idx), marker(idx + 1)
                    ));
                    let value = format!("%{value}%");
                    binds.push(AdminUserSearchBind::Text(value.clone()));
                    binds.push(AdminUserSearchBind::Text(value));
                }
                AdminUserSearchFilter::Integer {
                    column,
                    value,
                    negated,
                } => {
                    let operator = if negated { "<>" } else { "=" };
                    conditions.push(format!("{column} {operator} {}", marker(idx)));
                    binds.push(AdminUserSearchBind::Integer(value));
                }
                AdminUserSearchFilter::Boolean {
                    column,
                    value,
                    negated,
                } => {
                    let operator = if negated { "<>" } else { "=" };
                    conditions.push(format!("{column} {operator} {}", marker(idx)));
                    binds.push(AdminUserSearchBind::Boolean(value));
                }
            }
        }
        if !conditions.is_empty() {
            group_sql.push(format!("({})", conditions.join(" AND ")));
        }
    }
    if group_sql.is_empty() {
        (String::new(), binds)
    } else {
        (format!(" WHERE {}", group_sql.join(" OR ")), binds)
    }
}

fn split_user_search(query: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut token = String::new();
    let mut quoted = false;
    for ch in query.chars() {
        match ch {
            '"' => quoted = !quoted,
            ch if ch.is_whitespace() && !quoted => {
                if !token.is_empty() {
                    tokens.push(std::mem::take(&mut token));
                }
            }
            _ => token.push(ch),
        }
    }
    if !token.is_empty() {
        tokens.push(token);
    }
    tokens
}

fn parse_legacy_bool(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    }
}

#[derive(Debug)]
enum AdminPlayerSearchBind {
    Text(String),
    Integer(i64),
}

#[derive(Debug)]
enum AdminPlayerSearchFilter {
    Text {
        column: &'static str,
        value: String,
        contains: bool,
    },
    Global(String),
    Integer {
        column: &'static str,
        value: i64,
    },
}

fn admin_player_where(query: Option<&str>, postgres: bool) -> (String, Vec<AdminPlayerSearchBind>) {
    let mut groups: Vec<Vec<AdminPlayerSearchFilter>> = Vec::new();
    let mut current = Vec::new();
    for token in split_user_search(query.unwrap_or_default()) {
        if token.eq_ignore_ascii_case("and") {
            continue;
        }
        if token.eq_ignore_ascii_case("or") {
            if !current.is_empty() {
                groups.push(std::mem::take(&mut current));
            }
            continue;
        }
        let filter = if let Some((field, value)) = token.split_once(':') {
            let value = value.trim_matches('"');
            match field {
                "pid" | "uid" | "skin" | "tid_skin" | "cape" | "tid_cape" => value
                    .parse::<i64>()
                    .ok()
                    .map(|value| AdminPlayerSearchFilter::Integer {
                        column: match field {
                            "pid" => "pid",
                            "uid" => "uid",
                            "skin" | "tid_skin" => "tid_skin",
                            _ => "tid_cape",
                        },
                        value,
                    }),
                "name" => Some(AdminPlayerSearchFilter::Text {
                    column: "name",
                    value: value.to_owned(),
                    contains: false,
                }),
                "last_modified" => Some(AdminPlayerSearchFilter::Text {
                    column: "last_modified",
                    value: format!("%{value}%"),
                    contains: true,
                }),
                _ => None,
            }
        } else {
            Some(AdminPlayerSearchFilter::Global(token))
        };
        if let Some(filter) = filter {
            current.push(filter);
        }
    }
    if !current.is_empty() {
        groups.push(current);
    }
    let mut binds = Vec::new();
    let mut group_sql = Vec::new();
    for group in groups {
        let mut conditions = Vec::new();
        for filter in group {
            let marker = |index: usize| {
                if postgres {
                    format!("${index}")
                } else {
                    "?".to_owned()
                }
            };
            let index = binds.len() + 1;
            match filter {
                AdminPlayerSearchFilter::Text {
                    column,
                    value,
                    contains,
                } => {
                    let operator = if contains { "LIKE" } else { "=" };
                    conditions.push(format!("{column} {operator} {}", marker(index)));
                    binds.push(AdminPlayerSearchBind::Text(value));
                }
                AdminPlayerSearchFilter::Global(value) => {
                    conditions.push(format!("LOWER(name) LIKE LOWER({})", marker(index)));
                    binds.push(AdminPlayerSearchBind::Text(format!("%{value}%")));
                }
                AdminPlayerSearchFilter::Integer { column, value } => {
                    conditions.push(format!("{column} = {}", marker(index)));
                    binds.push(AdminPlayerSearchBind::Integer(value));
                }
            }
        }
        if !conditions.is_empty() {
            group_sql.push(format!("({})", conditions.join(" AND ")));
        }
    }
    if group_sql.is_empty() {
        (String::new(), binds)
    } else {
        (format!(" WHERE {}", group_sql.join(" OR ")), binds)
    }
}

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
}

#[derive(Debug, FromRow)]
pub struct PlayerProfile {
    pub name: String,
    pub permission: i32,
    pub skin_type: Option<String>,
    pub skin_hash: Option<String>,
    pub cape_hash: Option<String>,
    pub last_modified: Option<String>,
}

#[derive(Debug, FromRow, serde::Serialize)]
pub struct AdminDashboardStats {
    pub users: i64,
    pub players: i64,
    pub textures: i64,
    pub storage: i64,
}

#[derive(Debug, FromRow)]
pub struct LanguageLineRecord {
    pub id: i64,
    #[sqlx(rename = "group")]
    pub group_name: String,
    pub key: String,
    pub text: String,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}
#[derive(Debug, FromRow)]
pub struct AccessTokenRecord {
    pub user_id: Option<i64>,
    pub client_id: i64,
    pub revoked: bool,
}
#[derive(Debug, FromRow, serde::Serialize)]
pub struct AdminPlayerManagementRecord {
    pub pid: i64,
    pub uid: i64,
    pub name: String,
    pub tid_skin: i64,
    pub tid_cape: i64,
    pub last_modified: String,
    pub owner_permission: i32,
}

#[derive(Debug, FromRow, serde::Serialize)]
pub struct AdminUserRecord {
    pub uid: i64,
    pub email: String,
    pub nickname: String,
    pub locale: Option<String>,
    pub score: i64,
    pub avatar: i64,
    pub permission: i32,
    pub ip: String,
    pub is_dark_mode: bool,
    pub last_sign_at: String,
    pub register_at: String,
    pub verified: bool,
}

#[derive(Debug, Clone, FromRow, serde::Serialize)]
pub struct OAuthClientRecord {
    pub id: i64,
    pub name: String,
    pub secret: String,
    pub redirect: String,
}
#[derive(Debug, FromRow)]
pub struct OAuthGrantClientRecord {
    pub id: i64,
    pub secret: Option<String>,
    pub password_client: bool,
    pub revoked: bool,
}

#[derive(Debug, FromRow)]
pub struct OAuthAuthorizationClientRecord {
    pub id: i64,
    pub name: String,
    pub redirect: String,
    pub secret: Option<String>,
    pub personal_access_client: bool,
    pub password_client: bool,
    pub revoked: bool,
}

#[derive(Debug, FromRow)]
pub struct OAuthAuthorizedTokenRecord {
    pub id: String,
    pub user_id: Option<i64>,
    pub client_id: i64,
    pub name: Option<String>,
    pub scopes: Option<String>,
    pub revoked: bool,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub expires_at: Option<String>,
    pub client_user_id: Option<i64>,
    pub client_name: Option<String>,
    pub client_provider: Option<String>,
    pub client_redirect: Option<String>,
    pub client_personal_access_client: Option<bool>,
    pub client_password_client: Option<bool>,
    pub client_revoked: Option<bool>,
    pub client_created_at: Option<String>,
    pub client_updated_at: Option<String>,
}

#[derive(Debug, FromRow)]
pub struct OAuthRefreshRecord {
    pub user_id: Option<i64>,
    pub client_id: i64,
    pub scopes: String,
}

#[derive(Debug, FromRow)]
pub struct OAuthAuthCodeRecord {
    pub user_id: Option<i64>,
    pub client_id: i64,
    pub scopes: String,
    pub revoked: bool,
}

#[derive(Debug, FromRow)]
pub struct OAuthScopeRecord {
    pub name: String,
    pub description: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum OAuthClientDeleteOutcome {
    NotFound,
    Revoked,
}

#[derive(Debug, FromRow, serde::Serialize)]
pub struct UserProfile {
    pub uid: i64,
    pub email: String,
    pub nickname: String,
    pub locale: Option<String>,
    pub score: i64,
    pub avatar: i64,
    pub permission: i32,
    pub last_sign_at: String,
    pub register_at: String,
    pub verified: bool,
    pub is_dark_mode: bool,
}
#[derive(Debug, FromRow, serde::Serialize)]
pub struct PlayerRecord {
    pub pid: i64,
    pub uid: i64,
    pub name: String,
    pub tid_skin: i64,
    pub tid_cape: i64,
    pub last_modified: String,
}
#[derive(Debug, PartialEq, Eq)]
pub enum UserRegistrationOutcome {
    Registered(i64),
    EmailExists,
    PlayerNameExists,
    IpLimit,
}

#[derive(Debug, PartialEq, Eq)]
pub enum UserSignOutcome {
    Signed(i64),
    NotEligible,
}
#[derive(Debug, FromRow)]
pub struct PasswordCredential {
    pub uid: i64,
    pub password: String,
    pub permission: i32,
}
#[derive(Debug)]
pub enum NotificationAudience {
    All,
    Normal,
    User(i64),
    Email(String),
}
#[derive(Debug, FromRow)]
pub struct NotificationRecord {
    pub id: String,
    pub data: String,
    pub created_at: String,
}
#[derive(Debug, FromRow)]
pub struct SkinLibraryRecord {
    pub tid: i64,
    pub name: String,
    pub texture_type: String,
    pub uploader: i64,
    pub is_public: bool,
    pub likes: i64,
    pub nickname: String,
}
#[derive(Debug, Default)]
pub struct ReportSearchFilters {
    pub id: Option<i64>,
    pub tid: Option<i64>,
    pub uploader: Option<i64>,
    pub reporter: Option<i64>,
    pub status: Option<i32>,
    pub reason: Option<String>,
}
#[derive(Debug, FromRow)]
pub struct ReportManagementRecord {
    pub id: i64,
    pub tid: i64,
    pub uploader: i64,
    pub reporter: i64,
    pub reason: String,
    pub status: i32,
    pub report_at: String,
    pub texture_tid: Option<i64>,
    pub texture_name: Option<String>,
    pub texture_type: Option<String>,
    pub texture_hash: Option<String>,
    pub texture_size: Option<i64>,
    pub texture_uploader: Option<i64>,
    pub texture_public: Option<bool>,
    pub texture_upload_at: Option<String>,
    pub texture_likes: Option<i64>,
    pub texture_uploader_uid: Option<i64>,
    pub texture_uploader_email: Option<String>,
    pub texture_uploader_nickname: Option<String>,
    pub texture_uploader_locale: Option<String>,
    pub texture_uploader_score: Option<i64>,
    pub texture_uploader_avatar: Option<i64>,
    pub texture_uploader_permission: Option<i32>,
    pub texture_uploader_ip: Option<String>,
    pub texture_uploader_last_sign_at: Option<String>,
    pub texture_uploader_register_at: Option<String>,
    pub texture_uploader_verified: Option<bool>,
    pub texture_uploader_is_dark_mode: Option<bool>,
    pub informer_uid: Option<i64>,
    pub informer_email: Option<String>,
    pub informer_nickname: Option<String>,
    pub informer_locale: Option<String>,
    pub informer_score: Option<i64>,
    pub informer_avatar: Option<i64>,
    pub informer_permission: Option<i32>,
    pub informer_ip: Option<String>,
    pub informer_last_sign_at: Option<String>,
    pub informer_register_at: Option<String>,
    pub informer_verified: Option<bool>,
    pub informer_is_dark_mode: Option<bool>,
}
#[derive(Debug, FromRow, serde::Serialize)]
pub struct AdminClosetUserRecord {
    pub uid: i64,
    pub email: String,
    pub nickname: String,
    pub locale: Option<String>,
    pub score: i64,
    pub avatar: i64,
    pub ip: String,
    pub permission: i32,
    pub last_sign_at: String,
    pub register_at: String,
    pub verified: bool,
    pub is_dark_mode: bool,
}
#[derive(Debug, PartialEq, Eq)]
pub enum AdminClosetAddOutcome {
    Added,
    Repeated,
    TextureNotFound,
}
#[derive(Debug, PartialEq, Eq)]
pub enum AdminClosetRemoveOutcome {
    Removed,
    NonExistent,
}

#[derive(Debug, FromRow)]
pub struct TextureInfoRecord {
    pub tid: i64,
    pub name: String,
    pub texture_type: String,
    pub hash: String,
    pub size: i64,
    pub uploader: i64,
    pub is_public: bool,
    pub upload_at: String,
    pub likes: i64,
}
#[derive(Debug, FromRow)]
pub struct ClosetTextureRecord {
    pub tid: i64,
    pub name: String,
    pub texture_type: String,
    pub hash: String,
    pub size: i64,
    pub uploader: i64,
    pub is_public: bool,
    pub upload_at: String,
    pub likes: i64,
    pub user_uid: i64,
    pub texture_tid: i64,
    pub item_name: Option<String>,
}
#[derive(Debug, PartialEq, Eq)]
pub enum ReportSubmissionOutcome {
    AlreadyReported,
    InsufficientScore,
    Submitted,
}
#[derive(Debug, PartialEq, Eq)]
pub enum ReportReviewOutcome {
    NotFound,
    Rejected,
    Resolved,
    UploaderNotFound,
    UploaderPermissionDenied,
}
#[derive(Debug, PartialEq, Eq)]
pub enum TexturePrivacyOutcome {
    DuplicatePublicTexture(i64),
    InsufficientScore,
    Updated { is_public: bool },
}
#[derive(Debug, PartialEq, Eq)]
pub enum TextureUploadOutcome {
    AlreadyUploaded(i64),
    InsufficientScore,
    Uploaded(i64),
}
#[derive(Debug, PartialEq, Eq)]
pub enum TextureDeleteOutcome {
    Deleted(bool),
    ReportNotFound,
}
#[derive(Debug)]
pub enum PlayerRenameOutcome {
    NotFound,
    Forbidden,
    NameExists,
    Renamed {
        previous_name: String,
        player: PlayerRecord,
    },
}
#[derive(Debug)]
pub enum ClosetAddOutcome {
    Added,
    NameExists,
    InsufficientScore,
    TextureNotFound,
    PrivateTexture,
}
#[derive(Debug)]
pub enum ClosetRenameOutcome {
    Renamed,
    NotInCloset,
}
#[derive(Debug)]
pub enum ClosetRemoveOutcome {
    Removed,
    NotInCloset,
}
#[derive(Debug)]
pub enum PlayerAddOutcome {
    NameExists,
    InsufficientScore,
    Added(PlayerRecord),
}
#[derive(Debug)]
pub enum PlayerDeleteOutcome {
    NotFound,
    Forbidden,
    Deleted(String),
}
#[derive(Debug)]
pub enum PlayerTextureOutcome {
    NotFound,
    Forbidden,
    TextureNotFound,
    TextureNotInCloset,
    Updated(PlayerRecord),
}
impl DatabasePool {
    pub async fn connect(config: &DatabaseConfig) -> Result<Self, DatabaseError> {
        let pool = match &config.connection {
            DatabaseConnection::Sqlite(options) => Self::Sqlite(
                SqlitePoolOptions::new()
                    .max_connections(10)
                    .connect_with(options.clone())
                    .await?,
            ),
            DatabaseConnection::MySql(options) => Self::MySql(
                MySqlPoolOptions::new()
                    .max_connections(10)
                    .connect_with(options.clone())
                    .await?,
            ),
            DatabaseConnection::Postgres(options) => Self::Postgres(
                PgPoolOptions::new()
                    .max_connections(10)
                    .connect_with(options.clone())
                    .await?,
            ),
        };
        Ok(pool)
    }

    pub async fn connect_for_install(config: &DatabaseConfig) -> Result<Self, DatabaseError> {
        let pool = match &config.connection {
            DatabaseConnection::Sqlite(options) => Self::Sqlite(
                SqlitePoolOptions::new()
                    .max_connections(1)
                    .connect_with(options.clone().create_if_missing(true))
                    .await?,
            ),
            DatabaseConnection::MySql(options) => Self::MySql(
                MySqlPoolOptions::new()
                    .max_connections(1)
                    .connect_with(options.clone())
                    .await?,
            ),
            DatabaseConnection::Postgres(options) => Self::Postgres(
                PgPoolOptions::new()
                    .max_connections(1)
                    .connect_with(options.clone())
                    .await?,
            ),
        };
        Ok(pool)
    }
    pub async fn ping(&self) -> Result<(), sqlx::Error> {
        match self {
            Self::Sqlite(pool) => {
                sqlx::query("SELECT 1").execute(pool).await?;
            }
            Self::MySql(pool) => {
                sqlx::query("SELECT 1").execute(pool).await?;
            }
            Self::Postgres(pool) => {
                sqlx::query("SELECT 1").execute(pool).await?;
            }
        }
        Ok(())
    }

    pub async fn option(&self, prefix: &str, key: &str) -> Result<Option<String>, sqlx::Error> {
        let sql = match self {
            Self::Sqlite(_) | Self::MySql(_) => {
                format!("SELECT option_value FROM {prefix}options WHERE option_name = ? LIMIT 1")
            }
            Self::Postgres(_) => {
                format!("SELECT option_value FROM {prefix}options WHERE option_name = $1 LIMIT 1")
            }
        };
        match self {
            Self::Sqlite(pool) => Ok(sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(sql))
                .bind(key)
                .fetch_optional(pool)
                .await?),
            Self::MySql(pool) => {
                let sql = sql.replace("$1", "?");
                Ok(sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(sql))
                    .bind(key)
                    .fetch_optional(pool)
                    .await?)
            }
            Self::Postgres(pool) => Ok(sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(sql))
                .bind(key)
                .fetch_optional(pool)
                .await?),
        }
    }

    pub async fn all_options(&self, prefix: &str) -> Result<Vec<(String, String)>, sqlx::Error> {
        let sql = format!("SELECT option_name, option_value FROM {prefix}options");
        match self {
            Self::Sqlite(pool) => {
                sqlx::query_as::<_, (String, String)>(sqlx::AssertSqlSafe(sql))
                    .fetch_all(pool)
                    .await
            }
            Self::MySql(pool) => {
                sqlx::query_as::<_, (String, String)>(sqlx::AssertSqlSafe(sql))
                    .fetch_all(pool)
                    .await
            }
            Self::Postgres(pool) => {
                sqlx::query_as::<_, (String, String)>(sqlx::AssertSqlSafe(sql))
                    .fetch_all(pool)
                    .await
            }
        }
    }

    pub async fn language_lines_page(
        &self,
        prefix: &str,
        page: i64,
        per_page: i64,
    ) -> Result<(Vec<LanguageLineRecord>, i64), sqlx::Error> {
        let page = page.max(1);
        let per_page = per_page.max(1);
        let offset = (page - 1).saturating_mul(per_page);
        let count_sql = format!("SELECT COUNT(*) FROM {prefix}language_lines");
        let mysql = matches!(self, Self::MySql(_));
        let group_column = if mysql {
            format!("{}group{}", char::from(96), char::from(96))
        } else {
            "\"group\"".to_owned()
        };
        let key_column = if mysql {
            format!("{}key{}", char::from(96), char::from(96))
        } else {
            "\"key\"".to_owned()
        };
        let sql = match self {
            Self::Postgres(_) => format!(
                "SELECT CAST(id AS BIGINT) AS id, {group_column} AS \"group\", {key_column} AS \"key\", text, CAST(created_at AS TEXT) AS created_at, CAST(updated_at AS TEXT) AS updated_at FROM {prefix}language_lines ORDER BY {group_column}, {key_column}, id LIMIT $1 OFFSET $2"
            ),
            Self::MySql(_) => format!(
                "SELECT CAST(id AS SIGNED) AS id, {group_column}, {key_column}, text, CAST(created_at AS CHAR) AS created_at, CAST(updated_at AS CHAR) AS updated_at FROM {prefix}language_lines ORDER BY {group_column}, {key_column}, id LIMIT ? OFFSET ?"
            ),
            Self::Sqlite(_) => format!(
                "SELECT CAST(id AS BIGINT) AS id, {group_column} AS \"group\", {key_column} AS \"key\", text, CAST(created_at AS TEXT) AS created_at, CAST(updated_at AS TEXT) AS updated_at FROM {prefix}language_lines ORDER BY {group_column}, {key_column}, id LIMIT ? OFFSET ?"
            ),
        };
        let total = match self {
            Self::Sqlite(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(count_sql))
                    .fetch_one(pool)
                    .await?
            }
            Self::MySql(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(count_sql))
                    .fetch_one(pool)
                    .await?
            }
            Self::Postgres(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(count_sql))
                    .fetch_one(pool)
                    .await?
            }
        };
        let rows = match self {
            Self::Sqlite(pool) => {
                sqlx::query_as::<_, LanguageLineRecord>(sqlx::AssertSqlSafe(sql))
                    .bind(per_page)
                    .bind(offset)
                    .fetch_all(pool)
                    .await?
            }
            Self::MySql(pool) => {
                sqlx::query_as::<_, LanguageLineRecord>(sqlx::AssertSqlSafe(sql))
                    .bind(per_page)
                    .bind(offset)
                    .fetch_all(pool)
                    .await?
            }
            Self::Postgres(pool) => {
                sqlx::query_as::<_, LanguageLineRecord>(sqlx::AssertSqlSafe(sql))
                    .bind(per_page)
                    .bind(offset)
                    .fetch_all(pool)
                    .await?
            }
        };
        Ok((rows, total))
    }

    pub async fn language_line_exists(
        &self,
        prefix: &str,
        group: &str,
        key: &str,
    ) -> Result<bool, sqlx::Error> {
        let group_column = if matches!(self, Self::MySql(_)) {
            format!("{}group{}", char::from(96), char::from(96))
        } else {
            "\"group\"".to_owned()
        };
        let key_column = if matches!(self, Self::MySql(_)) {
            format!("{}key{}", char::from(96), char::from(96))
        } else {
            "\"key\"".to_owned()
        };
        let sql = match self {
            Self::Postgres(_) => format!(
                "SELECT COUNT(*) FROM {prefix}language_lines WHERE {group_column} = $1 AND {key_column} = $2"
            ),
            _ => format!(
                "SELECT COUNT(*) FROM {prefix}language_lines WHERE {group_column} = ? AND {key_column} = ?"
            ),
        };
        match self {
            Self::Sqlite(pool) => Ok(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                .bind(group)
                .bind(key)
                .fetch_one(pool)
                .await?
                > 0),
            Self::MySql(pool) => Ok(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                .bind(group)
                .bind(key)
                .fetch_one(pool)
                .await?
                > 0),
            Self::Postgres(pool) => Ok(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                .bind(group)
                .bind(key)
                .fetch_one(pool)
                .await?
                > 0),
        }
    }

    pub async fn create_language_line(
        &self,
        prefix: &str,
        group: &str,
        key: &str,
        locale: &str,
        text: &str,
    ) -> Result<i64, sqlx::Error> {
        let translations = serde_json::json!({ (locale): text }).to_string();
        let mysql = matches!(self, Self::MySql(_));
        let group_column = if mysql {
            format!("{}group{}", char::from(96), char::from(96))
        } else {
            "\"group\"".to_owned()
        };
        let key_column = if mysql {
            format!("{}key{}", char::from(96), char::from(96))
        } else {
            "\"key\"".to_owned()
        };
        let sql = match self {
            Self::Postgres(_) => format!(
                "INSERT INTO {prefix}language_lines ({group_column}, {key_column}, text, created_at, updated_at) VALUES ($1, $2, $3, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) RETURNING CAST(id AS BIGINT)"
            ),
            _ => format!(
                "INSERT INTO {prefix}language_lines ({group_column}, {key_column}, text, created_at, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            ),
        };
        match self {
            Self::Sqlite(pool) => {
                let result = sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(group)
                    .bind(key)
                    .bind(translations)
                    .execute(pool)
                    .await?;
                Ok(result.last_insert_rowid())
            }
            Self::MySql(pool) => {
                let result = sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(group)
                    .bind(key)
                    .bind(translations)
                    .execute(pool)
                    .await?;
                Ok(result.last_insert_id() as i64)
            }
            Self::Postgres(pool) => Ok(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                .bind(group)
                .bind(key)
                .bind(translations)
                .fetch_one(pool)
                .await?),
        }
    }

    pub async fn update_language_line(
        &self,
        prefix: &str,
        id: i64,
        locale: &str,
        text: &str,
    ) -> Result<bool, sqlx::Error> {
        let select_sql = match self {
            Self::Postgres(_) => format!("SELECT text FROM {prefix}language_lines WHERE id = $1"),
            _ => format!("SELECT text FROM {prefix}language_lines WHERE id = ?"),
        };
        let stored = match self {
            Self::Sqlite(pool) => {
                sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(select_sql))
                    .bind(id)
                    .fetch_optional(pool)
                    .await?
            }
            Self::MySql(pool) => {
                sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(select_sql))
                    .bind(id)
                    .fetch_optional(pool)
                    .await?
            }
            Self::Postgres(pool) => {
                sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(select_sql))
                    .bind(id)
                    .fetch_optional(pool)
                    .await?
            }
        };
        let Some(stored) = stored else {
            return Ok(false);
        };
        let mut translations =
            serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&stored)
                .unwrap_or_default();
        translations.insert(
            locale.to_owned(),
            serde_json::Value::String(text.to_owned()),
        );
        let updated_text = serde_json::Value::Object(translations).to_string();
        let update_sql = match self {
            Self::Postgres(_) => format!(
                "UPDATE {prefix}language_lines SET text = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2"
            ),
            _ => format!(
                "UPDATE {prefix}language_lines SET text = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
            ),
        };
        match self {
            Self::Sqlite(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(update_sql))
                    .bind(updated_text)
                    .bind(id)
                    .execute(pool)
                    .await?;
            }
            Self::MySql(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(update_sql))
                    .bind(updated_text)
                    .bind(id)
                    .execute(pool)
                    .await?;
            }
            Self::Postgres(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(update_sql))
                    .bind(updated_text)
                    .bind(id)
                    .execute(pool)
                    .await?;
            }
        }
        Ok(true)
    }

    pub async fn delete_language_line(&self, prefix: &str, id: i64) -> Result<bool, sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => format!("DELETE FROM {prefix}language_lines WHERE id = $1"),
            _ => format!("DELETE FROM {prefix}language_lines WHERE id = ?"),
        };
        match self {
            Self::Sqlite(pool) => Ok(sqlx::query(sqlx::AssertSqlSafe(sql))
                .bind(id)
                .execute(pool)
                .await?
                .rows_affected()
                > 0),
            Self::MySql(pool) => Ok(sqlx::query(sqlx::AssertSqlSafe(sql))
                .bind(id)
                .execute(pool)
                .await?
                .rows_affected()
                > 0),
            Self::Postgres(pool) => Ok(sqlx::query(sqlx::AssertSqlSafe(sql))
                .bind(id)
                .execute(pool)
                .await?
                .rows_affected()
                > 0),
        }
    }
    pub async fn set_option(
        &self,
        prefix: &str,
        key: &str,
        value: &str,
    ) -> Result<(), sqlx::Error> {
        let (update_sql, exists_sql, insert_sql) = match self {
            Self::Postgres(_) => (
                format!("UPDATE {prefix}options SET option_value = $1 WHERE option_name = $2"),
                format!("SELECT COUNT(*) FROM {prefix}options WHERE option_name = $1"),
                format!("INSERT INTO {prefix}options (option_name, option_value) VALUES ($1, $2)"),
            ),
            Self::Sqlite(_) | Self::MySql(_) => (
                format!("UPDATE {prefix}options SET option_value = ? WHERE option_name = ?"),
                format!("SELECT COUNT(*) FROM {prefix}options WHERE option_name = ?"),
                format!("INSERT INTO {prefix}options (option_name, option_value) VALUES (?, ?)"),
            ),
        };
        match self {
            Self::Sqlite(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(update_sql))
                    .bind(value)
                    .bind(key)
                    .execute(pool)
                    .await?;
                let exists = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(exists_sql))
                    .bind(key)
                    .fetch_one(pool)
                    .await?;
                if exists == 0 {
                    sqlx::query(sqlx::AssertSqlSafe(insert_sql))
                        .bind(key)
                        .bind(value)
                        .execute(pool)
                        .await?;
                }
            }
            Self::MySql(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(update_sql))
                    .bind(value)
                    .bind(key)
                    .execute(pool)
                    .await?;
                let exists = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(exists_sql))
                    .bind(key)
                    .fetch_one(pool)
                    .await?;
                if exists == 0 {
                    sqlx::query(sqlx::AssertSqlSafe(insert_sql))
                        .bind(key)
                        .bind(value)
                        .execute(pool)
                        .await?;
                }
            }
            Self::Postgres(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(update_sql))
                    .bind(value)
                    .bind(key)
                    .execute(pool)
                    .await?;
                let exists = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(exists_sql))
                    .bind(key)
                    .fetch_one(pool)
                    .await?;
                if exists == 0 {
                    sqlx::query(sqlx::AssertSqlSafe(insert_sql))
                        .bind(key)
                        .bind(value)
                        .execute(pool)
                        .await?;
                }
            }
        }
        Ok(())
    }

    pub async fn submit_report(
        &self,
        prefix: &str,
        tid: i64,
        uploader_id: i64,
        reporter_id: i64,
        reason: &str,
        score_modification: i64,
    ) -> Result<ReportSubmissionOutcome, sqlx::Error> {
        match self {
            Self::Sqlite(pool) => {
                let mut transaction = pool.begin().await?;
                let score_sql =
                    format!("SELECT CAST(score AS BIGINT) FROM {prefix}users WHERE uid = ?");
                let score = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(score_sql))
                    .bind(reporter_id)
                    .fetch_optional(&mut *transaction)
                    .await?;
                let Some(score) = score else {
                    transaction.rollback().await?;
                    return Ok(ReportSubmissionOutcome::InsufficientScore);
                };
                let duplicate_sql =
                    format!("SELECT COUNT(*) FROM {prefix}reports WHERE reporter = ? AND tid = ?");
                let duplicate = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(duplicate_sql))
                    .bind(reporter_id)
                    .bind(tid)
                    .fetch_one(&mut *transaction)
                    .await?;
                if duplicate > 0 {
                    transaction.rollback().await?;
                    return Ok(ReportSubmissionOutcome::AlreadyReported);
                }
                if score.saturating_add(score_modification) < 0 {
                    transaction.rollback().await?;
                    return Ok(ReportSubmissionOutcome::InsufficientScore);
                }
                let update_sql =
                    format!("UPDATE {prefix}users SET score = score + ? WHERE uid = ?");
                sqlx::query(sqlx::AssertSqlSafe(update_sql))
                    .bind(score_modification)
                    .bind(reporter_id)
                    .execute(&mut *transaction)
                    .await?;
                let insert_sql = format!(
                    "INSERT INTO {prefix}reports (tid, uploader, reporter, reason, status, report_at) \
                     VALUES (?, ?, ?, ?, 0, CURRENT_TIMESTAMP)"
                );
                sqlx::query(sqlx::AssertSqlSafe(insert_sql))
                    .bind(tid)
                    .bind(uploader_id)
                    .bind(reporter_id)
                    .bind(reason)
                    .execute(&mut *transaction)
                    .await?;
                transaction.commit().await?;
            }
            Self::MySql(pool) => {
                let mut transaction = pool.begin().await?;
                let score_sql = format!(
                    "SELECT CAST(score AS SIGNED) FROM {prefix}users WHERE uid = ? FOR UPDATE"
                );
                let score = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(score_sql))
                    .bind(reporter_id)
                    .fetch_optional(&mut *transaction)
                    .await?;
                let Some(score) = score else {
                    transaction.rollback().await?;
                    return Ok(ReportSubmissionOutcome::InsufficientScore);
                };
                let duplicate_sql =
                    format!("SELECT COUNT(*) FROM {prefix}reports WHERE reporter = ? AND tid = ?");
                let duplicate = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(duplicate_sql))
                    .bind(reporter_id)
                    .bind(tid)
                    .fetch_one(&mut *transaction)
                    .await?;
                if duplicate > 0 {
                    transaction.rollback().await?;
                    return Ok(ReportSubmissionOutcome::AlreadyReported);
                }
                if score.saturating_add(score_modification) < 0 {
                    transaction.rollback().await?;
                    return Ok(ReportSubmissionOutcome::InsufficientScore);
                }
                let update_sql =
                    format!("UPDATE {prefix}users SET score = score + ? WHERE uid = ?");
                sqlx::query(sqlx::AssertSqlSafe(update_sql))
                    .bind(score_modification)
                    .bind(reporter_id)
                    .execute(&mut *transaction)
                    .await?;
                let insert_sql = format!(
                    "INSERT INTO {prefix}reports (tid, uploader, reporter, reason, status, report_at) \
                     VALUES (?, ?, ?, ?, 0, CURRENT_TIMESTAMP)"
                );
                sqlx::query(sqlx::AssertSqlSafe(insert_sql))
                    .bind(tid)
                    .bind(uploader_id)
                    .bind(reporter_id)
                    .bind(reason)
                    .execute(&mut *transaction)
                    .await?;
                transaction.commit().await?;
            }
            Self::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                let score_sql = format!(
                    "SELECT CAST(score AS BIGINT) FROM {prefix}users WHERE uid = $1 FOR UPDATE"
                );
                let score = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(score_sql))
                    .bind(reporter_id)
                    .fetch_optional(&mut *transaction)
                    .await?;
                let Some(score) = score else {
                    transaction.rollback().await?;
                    return Ok(ReportSubmissionOutcome::InsufficientScore);
                };
                let duplicate_sql = format!(
                    "SELECT COUNT(*) FROM {prefix}reports WHERE reporter = $1 AND tid = $2"
                );
                let duplicate = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(duplicate_sql))
                    .bind(reporter_id)
                    .bind(tid)
                    .fetch_one(&mut *transaction)
                    .await?;
                if duplicate > 0 {
                    transaction.rollback().await?;
                    return Ok(ReportSubmissionOutcome::AlreadyReported);
                }
                if score.saturating_add(score_modification) < 0 {
                    transaction.rollback().await?;
                    return Ok(ReportSubmissionOutcome::InsufficientScore);
                }
                let update_sql =
                    format!("UPDATE {prefix}users SET score = score + $1 WHERE uid = $2");
                sqlx::query(sqlx::AssertSqlSafe(update_sql))
                    .bind(score_modification)
                    .bind(reporter_id)
                    .execute(&mut *transaction)
                    .await?;
                let insert_sql = format!(
                    "INSERT INTO {prefix}reports (tid, uploader, reporter, reason, status, report_at) \
                     VALUES ($1, $2, $3, $4, 0, CURRENT_TIMESTAMP)"
                );
                sqlx::query(sqlx::AssertSqlSafe(insert_sql))
                    .bind(tid)
                    .bind(uploader_id)
                    .bind(reporter_id)
                    .bind(reason)
                    .execute(&mut *transaction)
                    .await?;
                transaction.commit().await?;
            }
        }
        Ok(ReportSubmissionOutcome::Submitted)
    }
    pub async fn report_management_items(
        &self,
        prefix: &str,
        filters: &ReportSearchFilters,
        sort_field: &str,
        descending: bool,
        page: i64,
        per_page: i64,
    ) -> Result<(Vec<ReportManagementRecord>, i64), sqlx::Error> {
        let is_postgres = matches!(self, Self::Postgres(_));
        let marker = |index: usize| {
            if is_postgres {
                format!("${index}")
            } else {
                "?".to_owned()
            }
        };
        let status_enabled = marker(1);
        let status_value = marker(2);
        let tid_enabled = marker(3);
        let tid_value = marker(4);
        let id_enabled = marker(5);
        let id_value = marker(6);
        let uploader_enabled = marker(7);
        let uploader_value = marker(8);
        let reporter_enabled = marker(9);
        let reporter_value = marker(10);
        let reason_enabled = marker(11);
        let reason_value = marker(12);
        let integer_cast = if matches!(self, Self::MySql(_)) {
            "SIGNED"
        } else {
            "BIGINT"
        };
        let status_cast = if matches!(self, Self::MySql(_)) {
            "SIGNED"
        } else {
            "INTEGER"
        };
        let text_cast = if matches!(self, Self::MySql(_)) {
            "CHAR"
        } else {
            "TEXT"
        };
        let where_sql = format!(
            "({status_enabled} = FALSE OR r.status = {status_value}) \
             AND ({tid_enabled} = FALSE OR r.tid = {tid_value}) \
             AND ({id_enabled} = FALSE OR r.id = {id_value}) \
             AND ({uploader_enabled} = FALSE OR r.uploader = {uploader_value}) \
             AND ({reporter_enabled} = FALSE OR r.reporter = {reporter_value}) \
             AND ({reason_enabled} = FALSE OR r.reason LIKE {reason_value})"
        );
        let count_sql = format!("SELECT COUNT(*) FROM {prefix}reports r WHERE {where_sql}");
        let sort_column = match sort_field {
            "id" => "r.id",
            "tid" => "r.tid",
            "uploader" => "r.uploader",
            "reporter" => "r.reporter",
            "reason" => "r.reason",
            "status" => "r.status",
            _ => "r.report_at",
        };
        let direction = if descending { "DESC" } else { "ASC" };
        let limit = marker(13);
        let offset = marker(14);
        let rows_sql = format!(
            "SELECT CAST(r.id AS {integer_cast}) AS id, CAST(r.tid AS {integer_cast}) AS tid, \
             CAST(r.uploader AS {integer_cast}) AS uploader, CAST(r.reporter AS {integer_cast}) AS reporter, \
             r.reason, CAST(r.status AS {status_cast}) AS status, CAST(r.report_at AS {text_cast}) AS report_at, \
             CAST(t.tid AS {integer_cast}) AS texture_tid, t.name AS texture_name, \
             t.type AS texture_type, t.hash AS texture_hash, CAST(t.size AS {integer_cast}) AS texture_size, \
             CAST(t.uploader AS {integer_cast}) AS texture_uploader, t.public AS texture_public, \
             CAST(t.upload_at AS {text_cast}) AS texture_upload_at, CAST(t.likes AS {integer_cast}) AS texture_likes, \
             CAST(tu.uid AS {integer_cast}) AS texture_uploader_uid, \
             tu.email AS texture_uploader_email, tu.nickname AS texture_uploader_nickname, \
             tu.locale AS texture_uploader_locale, CAST(tu.score AS {integer_cast}) AS texture_uploader_score, \
             CAST(tu.avatar AS {integer_cast}) AS texture_uploader_avatar, \
             CAST(tu.permission AS {status_cast}) AS texture_uploader_permission, \
             tu.ip AS texture_uploader_ip, CAST(tu.last_sign_at AS {text_cast}) AS texture_uploader_last_sign_at, \
             CAST(tu.register_at AS {text_cast}) AS texture_uploader_register_at, \
             tu.verified AS texture_uploader_verified, tu.is_dark_mode AS texture_uploader_is_dark_mode, \
             CAST(ru.uid AS {integer_cast}) AS informer_uid, ru.email AS informer_email, \
             ru.nickname AS informer_nickname, ru.locale AS informer_locale, \
             CAST(ru.score AS {integer_cast}) AS informer_score, CAST(ru.avatar AS {integer_cast}) AS informer_avatar, \
             CAST(ru.permission AS {status_cast}) AS informer_permission, ru.ip AS informer_ip, \
             CAST(ru.last_sign_at AS {text_cast}) AS informer_last_sign_at, \
             CAST(ru.register_at AS {text_cast}) AS informer_register_at, \
             ru.verified AS informer_verified, ru.is_dark_mode AS informer_is_dark_mode \
             FROM {prefix}reports r \
             LEFT JOIN {prefix}textures t ON t.tid = r.tid \
             LEFT JOIN {prefix}users tu ON tu.uid = r.uploader \
             LEFT JOIN {prefix}users ru ON ru.uid = r.reporter \
             WHERE {where_sql} ORDER BY {sort_column} {direction} \
             LIMIT {limit} OFFSET {offset}"
        );
        let reason_pattern = filters.reason.as_ref().map(|value| format!("%{value}%"));
        let status = filters.status.unwrap_or_default();
        let tid = filters.tid.unwrap_or_default();
        let id = filters.id.unwrap_or_default();
        let uploader = filters.uploader.unwrap_or_default();
        let reporter = filters.reporter.unwrap_or_default();
        let reason = reason_pattern.as_deref().unwrap_or_default();
        let count = match self {
            Self::Sqlite(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(count_sql))
                    .bind(filters.status.is_some())
                    .bind(status)
                    .bind(filters.tid.is_some())
                    .bind(tid)
                    .bind(filters.id.is_some())
                    .bind(id)
                    .bind(filters.uploader.is_some())
                    .bind(uploader)
                    .bind(filters.reporter.is_some())
                    .bind(reporter)
                    .bind(filters.reason.is_some())
                    .bind(reason)
                    .fetch_one(pool)
                    .await?
            }
            Self::MySql(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(count_sql))
                    .bind(filters.status.is_some())
                    .bind(status)
                    .bind(filters.tid.is_some())
                    .bind(tid)
                    .bind(filters.id.is_some())
                    .bind(id)
                    .bind(filters.uploader.is_some())
                    .bind(uploader)
                    .bind(filters.reporter.is_some())
                    .bind(reporter)
                    .bind(filters.reason.is_some())
                    .bind(reason)
                    .fetch_one(pool)
                    .await?
            }
            Self::Postgres(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(count_sql))
                    .bind(filters.status.is_some())
                    .bind(status)
                    .bind(filters.tid.is_some())
                    .bind(tid)
                    .bind(filters.id.is_some())
                    .bind(id)
                    .bind(filters.uploader.is_some())
                    .bind(uploader)
                    .bind(filters.reporter.is_some())
                    .bind(reporter)
                    .bind(filters.reason.is_some())
                    .bind(reason)
                    .fetch_one(pool)
                    .await?
            }
        };
        let offset = page.saturating_sub(1).saturating_mul(per_page);
        let rows = match self {
            Self::Sqlite(pool) => {
                sqlx::query_as::<_, ReportManagementRecord>(sqlx::AssertSqlSafe(rows_sql))
                    .bind(filters.status.is_some())
                    .bind(status)
                    .bind(filters.tid.is_some())
                    .bind(tid)
                    .bind(filters.id.is_some())
                    .bind(id)
                    .bind(filters.uploader.is_some())
                    .bind(uploader)
                    .bind(filters.reporter.is_some())
                    .bind(reporter)
                    .bind(filters.reason.is_some())
                    .bind(reason)
                    .bind(per_page)
                    .bind(offset)
                    .fetch_all(pool)
                    .await?
            }
            Self::MySql(pool) => {
                sqlx::query_as::<_, ReportManagementRecord>(sqlx::AssertSqlSafe(rows_sql))
                    .bind(filters.status.is_some())
                    .bind(status)
                    .bind(filters.tid.is_some())
                    .bind(tid)
                    .bind(filters.id.is_some())
                    .bind(id)
                    .bind(filters.uploader.is_some())
                    .bind(uploader)
                    .bind(filters.reporter.is_some())
                    .bind(reporter)
                    .bind(filters.reason.is_some())
                    .bind(reason)
                    .bind(per_page)
                    .bind(offset)
                    .fetch_all(pool)
                    .await?
            }
            Self::Postgres(pool) => {
                sqlx::query_as::<_, ReportManagementRecord>(sqlx::AssertSqlSafe(rows_sql))
                    .bind(filters.status.is_some())
                    .bind(status)
                    .bind(filters.tid.is_some())
                    .bind(tid)
                    .bind(filters.id.is_some())
                    .bind(id)
                    .bind(filters.uploader.is_some())
                    .bind(uploader)
                    .bind(filters.reporter.is_some())
                    .bind(reporter)
                    .bind(filters.reason.is_some())
                    .bind(reason)
                    .bind(per_page)
                    .bind(offset)
                    .fetch_all(pool)
                    .await?
            }
        };
        Ok((rows, count))
    }

    pub async fn reject_report(
        &self,
        prefix: &str,
        report_id: i64,
        reporter_score_modification: i64,
    ) -> Result<ReportReviewOutcome, sqlx::Error> {
        let postgres = matches!(self, Self::Postgres(_));
        let marker = |index: usize| {
            if postgres {
                format!("${index}")
            } else {
                "?".to_owned()
            }
        };
        let lock_clause = if matches!(self, Self::Sqlite(_)) {
            ""
        } else {
            " FOR UPDATE"
        };
        let integer_cast = if matches!(self, Self::MySql(_)) {
            "SIGNED"
        } else {
            "BIGINT"
        };
        let status_cast = if matches!(self, Self::MySql(_)) {
            "SIGNED"
        } else {
            "INTEGER"
        };
        let report_sql = format!(
            "SELECT CAST(status AS {status_cast}), CAST(reporter AS {integer_cast}) \
             FROM {prefix}reports WHERE id = {} LIMIT 1{lock_clause}",
            marker(1)
        );
        let retract_score_sql = format!(
            "UPDATE {prefix}users SET score = score - {} WHERE uid = {}",
            marker(1),
            marker(2)
        );
        let update_report_sql = format!(
            "UPDATE {prefix}reports SET status = 2 WHERE id = {}",
            marker(1)
        );
        let reporter_score_modification = reporter_score_modification.max(0);
        match self {
            Self::Sqlite(pool) => {
                let mut transaction = pool.begin().await?;
                let report = sqlx::query_as::<_, (i32, i64)>(sqlx::AssertSqlSafe(report_sql))
                    .bind(report_id)
                    .fetch_optional(&mut *transaction)
                    .await?;
                let Some((status, reporter_id)) = report else {
                    transaction.rollback().await?;
                    return Ok(ReportReviewOutcome::NotFound);
                };
                if status == 0 && reporter_score_modification > 0 {
                    sqlx::query(sqlx::AssertSqlSafe(retract_score_sql))
                        .bind(reporter_score_modification)
                        .bind(reporter_id)
                        .execute(&mut *transaction)
                        .await?;
                }
                sqlx::query(sqlx::AssertSqlSafe(update_report_sql))
                    .bind(report_id)
                    .execute(&mut *transaction)
                    .await?;
                transaction.commit().await?;
            }
            Self::MySql(pool) => {
                let mut transaction = pool.begin().await?;
                let report = sqlx::query_as::<_, (i32, i64)>(sqlx::AssertSqlSafe(report_sql))
                    .bind(report_id)
                    .fetch_optional(&mut *transaction)
                    .await?;
                let Some((status, reporter_id)) = report else {
                    transaction.rollback().await?;
                    return Ok(ReportReviewOutcome::NotFound);
                };
                if status == 0 && reporter_score_modification > 0 {
                    sqlx::query(sqlx::AssertSqlSafe(retract_score_sql))
                        .bind(reporter_score_modification)
                        .bind(reporter_id)
                        .execute(&mut *transaction)
                        .await?;
                }
                sqlx::query(sqlx::AssertSqlSafe(update_report_sql))
                    .bind(report_id)
                    .execute(&mut *transaction)
                    .await?;
                transaction.commit().await?;
            }
            Self::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                let report = sqlx::query_as::<_, (i32, i64)>(sqlx::AssertSqlSafe(report_sql))
                    .bind(report_id)
                    .fetch_optional(&mut *transaction)
                    .await?;
                let Some((status, reporter_id)) = report else {
                    transaction.rollback().await?;
                    return Ok(ReportReviewOutcome::NotFound);
                };
                if status == 0 && reporter_score_modification > 0 {
                    sqlx::query(sqlx::AssertSqlSafe(retract_score_sql))
                        .bind(reporter_score_modification)
                        .bind(reporter_id)
                        .execute(&mut *transaction)
                        .await?;
                }
                sqlx::query(sqlx::AssertSqlSafe(update_report_sql))
                    .bind(report_id)
                    .execute(&mut *transaction)
                    .await?;
                transaction.commit().await?;
            }
        }
        Ok(ReportReviewOutcome::Rejected)
    }

    pub async fn ban_report_uploader(
        &self,
        prefix: &str,
        report_id: i64,
        admin_permission: i32,
        reporter_score_modification: i64,
        reporter_reward_score: i64,
    ) -> Result<ReportReviewOutcome, sqlx::Error> {
        let postgres = matches!(self, Self::Postgres(_));
        let marker = |index: usize| {
            if postgres {
                format!("${index}")
            } else {
                "?".to_owned()
            }
        };
        let lock_clause = if matches!(self, Self::Sqlite(_)) {
            ""
        } else {
            " FOR UPDATE"
        };
        let integer_cast = if matches!(self, Self::MySql(_)) {
            "SIGNED"
        } else {
            "BIGINT"
        };
        let status_cast = if matches!(self, Self::MySql(_)) {
            "SIGNED"
        } else {
            "INTEGER"
        };
        let report_sql = format!(
            "SELECT CAST(status AS {status_cast}), CAST(uploader AS {integer_cast}), \
             CAST(reporter AS {integer_cast}) FROM {prefix}reports \
             WHERE id = {} LIMIT 1{lock_clause}",
            marker(1)
        );
        let uploader_sql = format!(
            "SELECT CAST(permission AS {status_cast}) FROM {prefix}users \
             WHERE uid = {} LIMIT 1{lock_clause}",
            marker(1)
        );
        let ban_uploader_sql = format!(
            "UPDATE {prefix}users SET permission = -1 WHERE uid = {}",
            marker(1)
        );
        let update_reporter_score_sql = format!(
            "UPDATE {prefix}users SET score = score + {} WHERE uid = {}",
            marker(1),
            marker(2)
        );
        let resolve_report_sql = format!(
            "UPDATE {prefix}reports SET status = 1 WHERE id = {}",
            marker(1)
        );
        let lock_report = |report: (i32, i64, i64), uploader_permission: i32| {
            if admin_permission <= uploader_permission {
                return Err(ReportReviewOutcome::UploaderPermissionDenied);
            }
            Ok(report)
        };
        let score_adjustment = reporter_score_modification
            .min(0)
            .saturating_neg()
            .saturating_add(reporter_reward_score);
        match self {
            Self::Sqlite(pool) => {
                let mut transaction = pool.begin().await?;
                let report = sqlx::query_as::<_, (i32, i64, i64)>(sqlx::AssertSqlSafe(report_sql))
                    .bind(report_id)
                    .fetch_optional(&mut *transaction)
                    .await?;
                let Some(report) = report else {
                    transaction.rollback().await?;
                    return Ok(ReportReviewOutcome::NotFound);
                };
                let uploader_permission =
                    sqlx::query_scalar::<_, i32>(sqlx::AssertSqlSafe(uploader_sql))
                        .bind(report.1)
                        .fetch_optional(&mut *transaction)
                        .await?;
                let Some(uploader_permission) = uploader_permission else {
                    transaction.rollback().await?;
                    return Ok(ReportReviewOutcome::UploaderNotFound);
                };
                if let Err(outcome) = lock_report(report, uploader_permission) {
                    transaction.rollback().await?;
                    return Ok(outcome);
                }
                sqlx::query(sqlx::AssertSqlSafe(ban_uploader_sql))
                    .bind(report.1)
                    .execute(&mut *transaction)
                    .await?;
                if report.0 == 0 && score_adjustment != 0 {
                    sqlx::query(sqlx::AssertSqlSafe(update_reporter_score_sql))
                        .bind(score_adjustment)
                        .bind(report.2)
                        .execute(&mut *transaction)
                        .await?;
                }
                sqlx::query(sqlx::AssertSqlSafe(resolve_report_sql))
                    .bind(report_id)
                    .execute(&mut *transaction)
                    .await?;
                transaction.commit().await?;
            }
            Self::MySql(pool) => {
                let mut transaction = pool.begin().await?;
                let report = sqlx::query_as::<_, (i32, i64, i64)>(sqlx::AssertSqlSafe(report_sql))
                    .bind(report_id)
                    .fetch_optional(&mut *transaction)
                    .await?;
                let Some(report) = report else {
                    transaction.rollback().await?;
                    return Ok(ReportReviewOutcome::NotFound);
                };
                let uploader_permission =
                    sqlx::query_scalar::<_, i32>(sqlx::AssertSqlSafe(uploader_sql))
                        .bind(report.1)
                        .fetch_optional(&mut *transaction)
                        .await?;
                let Some(uploader_permission) = uploader_permission else {
                    transaction.rollback().await?;
                    return Ok(ReportReviewOutcome::UploaderNotFound);
                };
                if let Err(outcome) = lock_report(report, uploader_permission) {
                    transaction.rollback().await?;
                    return Ok(outcome);
                }
                sqlx::query(sqlx::AssertSqlSafe(ban_uploader_sql))
                    .bind(report.1)
                    .execute(&mut *transaction)
                    .await?;
                if report.0 == 0 && score_adjustment != 0 {
                    sqlx::query(sqlx::AssertSqlSafe(update_reporter_score_sql))
                        .bind(score_adjustment)
                        .bind(report.2)
                        .execute(&mut *transaction)
                        .await?;
                }
                sqlx::query(sqlx::AssertSqlSafe(resolve_report_sql))
                    .bind(report_id)
                    .execute(&mut *transaction)
                    .await?;
                transaction.commit().await?;
            }
            Self::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                let report = sqlx::query_as::<_, (i32, i64, i64)>(sqlx::AssertSqlSafe(report_sql))
                    .bind(report_id)
                    .fetch_optional(&mut *transaction)
                    .await?;
                let Some(report) = report else {
                    transaction.rollback().await?;
                    return Ok(ReportReviewOutcome::NotFound);
                };
                let uploader_permission =
                    sqlx::query_scalar::<_, i32>(sqlx::AssertSqlSafe(uploader_sql))
                        .bind(report.1)
                        .fetch_optional(&mut *transaction)
                        .await?;
                let Some(uploader_permission) = uploader_permission else {
                    transaction.rollback().await?;
                    return Ok(ReportReviewOutcome::UploaderNotFound);
                };
                if let Err(outcome) = lock_report(report, uploader_permission) {
                    transaction.rollback().await?;
                    return Ok(outcome);
                }
                sqlx::query(sqlx::AssertSqlSafe(ban_uploader_sql))
                    .bind(report.1)
                    .execute(&mut *transaction)
                    .await?;
                if report.0 == 0 && score_adjustment != 0 {
                    sqlx::query(sqlx::AssertSqlSafe(update_reporter_score_sql))
                        .bind(score_adjustment)
                        .bind(report.2)
                        .execute(&mut *transaction)
                        .await?;
                }
                sqlx::query(sqlx::AssertSqlSafe(resolve_report_sql))
                    .bind(report_id)
                    .execute(&mut *transaction)
                    .await?;
                transaction.commit().await?;
            }
        }
        Ok(ReportReviewOutcome::Resolved)
    }

    pub async fn toggle_texture_privacy(
        &self,
        prefix: &str,
        tid: i64,
        uploader_id: i64,
        hash: &str,
        was_public: bool,
        score_diff: i64,
    ) -> Result<TexturePrivacyOutcome, sqlx::Error> {
        let is_public = !was_public;
        match self {
            Self::Sqlite(pool) => {
                let mut transaction = pool.begin().await?;
                let score_sql =
                    format!("SELECT CAST(score AS BIGINT) FROM {prefix}users WHERE uid = ?");
                let score = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(score_sql))
                    .bind(uploader_id)
                    .fetch_optional(&mut *transaction)
                    .await?;
                let Some(score) = score else {
                    transaction.rollback().await?;
                    return Ok(TexturePrivacyOutcome::InsufficientScore);
                };
                if score.saturating_add(score_diff) < 0 {
                    transaction.rollback().await?;
                    return Ok(TexturePrivacyOutcome::InsufficientScore);
                }
                if is_public {
                    let duplicate_sql = format!(
                        "SELECT tid FROM {prefix}textures WHERE hash = ? AND public = TRUE LIMIT 1"
                    );
                    if let Some(duplicate_tid) =
                        sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(duplicate_sql))
                            .bind(hash)
                            .fetch_optional(&mut *transaction)
                            .await?
                    {
                        transaction.rollback().await?;
                        return Ok(TexturePrivacyOutcome::DuplicatePublicTexture(duplicate_tid));
                    }
                }
                let update_user_sql =
                    format!("UPDATE {prefix}users SET score = score + ? WHERE uid = ?");
                sqlx::query(sqlx::AssertSqlSafe(update_user_sql))
                    .bind(score_diff)
                    .bind(uploader_id)
                    .execute(&mut *transaction)
                    .await?;
                let update_texture_sql =
                    format!("UPDATE {prefix}textures SET public = ? WHERE tid = ?");
                sqlx::query(sqlx::AssertSqlSafe(update_texture_sql))
                    .bind(is_public)
                    .bind(tid)
                    .execute(&mut *transaction)
                    .await?;
                transaction.commit().await?;
            }
            Self::MySql(pool) => {
                let mut transaction = pool.begin().await?;
                let score_sql = format!(
                    "SELECT CAST(score AS SIGNED) FROM {prefix}users WHERE uid = ? FOR UPDATE"
                );
                let score = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(score_sql))
                    .bind(uploader_id)
                    .fetch_optional(&mut *transaction)
                    .await?;
                let Some(score) = score else {
                    transaction.rollback().await?;
                    return Ok(TexturePrivacyOutcome::InsufficientScore);
                };
                if score.saturating_add(score_diff) < 0 {
                    transaction.rollback().await?;
                    return Ok(TexturePrivacyOutcome::InsufficientScore);
                }
                if is_public {
                    let duplicate_sql = format!(
                        "SELECT CAST(tid AS SIGNED) FROM {prefix}textures WHERE hash = ? AND public = TRUE LIMIT 1"
                    );
                    if let Some(duplicate_tid) =
                        sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(duplicate_sql))
                            .bind(hash)
                            .fetch_optional(&mut *transaction)
                            .await?
                    {
                        transaction.rollback().await?;
                        return Ok(TexturePrivacyOutcome::DuplicatePublicTexture(duplicate_tid));
                    }
                }
                let update_user_sql =
                    format!("UPDATE {prefix}users SET score = score + ? WHERE uid = ?");
                sqlx::query(sqlx::AssertSqlSafe(update_user_sql))
                    .bind(score_diff)
                    .bind(uploader_id)
                    .execute(&mut *transaction)
                    .await?;
                let update_texture_sql =
                    format!("UPDATE {prefix}textures SET public = ? WHERE tid = ?");
                sqlx::query(sqlx::AssertSqlSafe(update_texture_sql))
                    .bind(is_public)
                    .bind(tid)
                    .execute(&mut *transaction)
                    .await?;
                transaction.commit().await?;
            }
            Self::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                let score_sql = format!(
                    "SELECT CAST(score AS BIGINT) FROM {prefix}users WHERE uid = $1 FOR UPDATE"
                );
                let score = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(score_sql))
                    .bind(uploader_id)
                    .fetch_optional(&mut *transaction)
                    .await?;
                let Some(score) = score else {
                    transaction.rollback().await?;
                    return Ok(TexturePrivacyOutcome::InsufficientScore);
                };
                if score.saturating_add(score_diff) < 0 {
                    transaction.rollback().await?;
                    return Ok(TexturePrivacyOutcome::InsufficientScore);
                }
                if is_public {
                    let duplicate_sql = format!(
                        "SELECT CAST(tid AS BIGINT) FROM {prefix}textures WHERE hash = $1 AND public = TRUE LIMIT 1"
                    );
                    if let Some(duplicate_tid) =
                        sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(duplicate_sql))
                            .bind(hash)
                            .fetch_optional(&mut *transaction)
                            .await?
                    {
                        transaction.rollback().await?;
                        return Ok(TexturePrivacyOutcome::DuplicatePublicTexture(duplicate_tid));
                    }
                }
                let update_user_sql =
                    format!("UPDATE {prefix}users SET score = score + $1 WHERE uid = $2");
                sqlx::query(sqlx::AssertSqlSafe(update_user_sql))
                    .bind(score_diff)
                    .bind(uploader_id)
                    .execute(&mut *transaction)
                    .await?;
                let update_texture_sql =
                    format!("UPDATE {prefix}textures SET public = $1 WHERE tid = $2");
                sqlx::query(sqlx::AssertSqlSafe(update_texture_sql))
                    .bind(is_public)
                    .bind(tid)
                    .execute(&mut *transaction)
                    .await?;
                transaction.commit().await?;
            }
        }
        Ok(TexturePrivacyOutcome::Updated { is_public })
    }
    pub async fn upload_texture(
        &self,
        prefix: &str,
        name: &str,
        texture_type: &str,
        hash: &str,
        size: i64,
        uploader_id: i64,
        is_public: bool,
        score_cost: i64,
    ) -> Result<TextureUploadOutcome, sqlx::Error> {
        match self {
            Self::Sqlite(pool) => {
                let mut transaction = pool.begin().await?;
                let score_sql =
                    format!("SELECT CAST(score AS BIGINT) FROM {prefix}users WHERE uid = ?");
                let score = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(score_sql))
                    .bind(uploader_id)
                    .fetch_optional(&mut *transaction)
                    .await?;
                let Some(score) = score else {
                    transaction.rollback().await?;
                    return Ok(TextureUploadOutcome::InsufficientScore);
                };
                let duplicate_sql = format!(
                    "SELECT tid FROM {prefix}textures WHERE hash = ? \
                     AND (public = TRUE OR uploader = ?) LIMIT 1"
                );
                if let Some(duplicate_tid) =
                    sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(duplicate_sql))
                        .bind(hash)
                        .bind(uploader_id)
                        .fetch_optional(&mut *transaction)
                        .await?
                {
                    transaction.rollback().await?;
                    return Ok(TextureUploadOutcome::AlreadyUploaded(duplicate_tid));
                }
                if score < score_cost {
                    transaction.rollback().await?;
                    return Ok(TextureUploadOutcome::InsufficientScore);
                }
                let insert_sql = format!(
                    "INSERT INTO {prefix}textures \
                     (name, type, hash, size, uploader, public, upload_at, likes) \
                     VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, 1)"
                );
                let inserted = sqlx::query(sqlx::AssertSqlSafe(insert_sql))
                    .bind(name)
                    .bind(texture_type)
                    .bind(hash)
                    .bind(size)
                    .bind(uploader_id)
                    .bind(is_public)
                    .execute(&mut *transaction)
                    .await?;
                let tid = inserted.last_insert_rowid();
                let update_user_sql =
                    format!("UPDATE {prefix}users SET score = score - ? WHERE uid = ?");
                sqlx::query(sqlx::AssertSqlSafe(update_user_sql))
                    .bind(score_cost)
                    .bind(uploader_id)
                    .execute(&mut *transaction)
                    .await?;
                let closet_sql = format!(
                    "INSERT INTO {prefix}user_closet (user_uid, texture_tid, item_name) VALUES (?, ?, ?)"
                );
                sqlx::query(sqlx::AssertSqlSafe(closet_sql))
                    .bind(uploader_id)
                    .bind(tid)
                    .bind(name)
                    .execute(&mut *transaction)
                    .await?;
                transaction.commit().await?;
                return Ok(TextureUploadOutcome::Uploaded(tid));
            }
            Self::MySql(pool) => {
                let mut transaction = pool.begin().await?;
                let score_sql = format!(
                    "SELECT CAST(score AS SIGNED) FROM {prefix}users WHERE uid = ? FOR UPDATE"
                );
                let score = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(score_sql))
                    .bind(uploader_id)
                    .fetch_optional(&mut *transaction)
                    .await?;
                let Some(score) = score else {
                    transaction.rollback().await?;
                    return Ok(TextureUploadOutcome::InsufficientScore);
                };
                let duplicate_sql = format!(
                    "SELECT CAST(tid AS SIGNED) FROM {prefix}textures WHERE hash = ? \
                     AND (public = TRUE OR uploader = ?) LIMIT 1"
                );
                if let Some(duplicate_tid) =
                    sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(duplicate_sql))
                        .bind(hash)
                        .bind(uploader_id)
                        .fetch_optional(&mut *transaction)
                        .await?
                {
                    transaction.rollback().await?;
                    return Ok(TextureUploadOutcome::AlreadyUploaded(duplicate_tid));
                }
                if score < score_cost {
                    transaction.rollback().await?;
                    return Ok(TextureUploadOutcome::InsufficientScore);
                }
                let insert_sql = format!(
                    "INSERT INTO {prefix}textures \
                     (name, type, hash, size, uploader, public, upload_at, likes) \
                     VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, 1)"
                );
                let inserted = sqlx::query(sqlx::AssertSqlSafe(insert_sql))
                    .bind(name)
                    .bind(texture_type)
                    .bind(hash)
                    .bind(size)
                    .bind(uploader_id)
                    .bind(is_public)
                    .execute(&mut *transaction)
                    .await?;
                let tid = inserted.last_insert_id() as i64;
                let update_user_sql =
                    format!("UPDATE {prefix}users SET score = score - ? WHERE uid = ?");
                sqlx::query(sqlx::AssertSqlSafe(update_user_sql))
                    .bind(score_cost)
                    .bind(uploader_id)
                    .execute(&mut *transaction)
                    .await?;
                let closet_sql = format!(
                    "INSERT INTO {prefix}user_closet (user_uid, texture_tid, item_name) VALUES (?, ?, ?)"
                );
                sqlx::query(sqlx::AssertSqlSafe(closet_sql))
                    .bind(uploader_id)
                    .bind(tid)
                    .bind(name)
                    .execute(&mut *transaction)
                    .await?;
                transaction.commit().await?;
                return Ok(TextureUploadOutcome::Uploaded(tid));
            }
            Self::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                let score_sql = format!(
                    "SELECT CAST(score AS BIGINT) FROM {prefix}users WHERE uid = $1 FOR UPDATE"
                );
                let score = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(score_sql))
                    .bind(uploader_id)
                    .fetch_optional(&mut *transaction)
                    .await?;
                let Some(score) = score else {
                    transaction.rollback().await?;
                    return Ok(TextureUploadOutcome::InsufficientScore);
                };
                let duplicate_sql = format!(
                    "SELECT CAST(tid AS BIGINT) FROM {prefix}textures WHERE hash = $1 \
                     AND (public = TRUE OR uploader = $2) LIMIT 1"
                );
                if let Some(duplicate_tid) =
                    sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(duplicate_sql))
                        .bind(hash)
                        .bind(uploader_id)
                        .fetch_optional(&mut *transaction)
                        .await?
                {
                    transaction.rollback().await?;
                    return Ok(TextureUploadOutcome::AlreadyUploaded(duplicate_tid));
                }
                if score < score_cost {
                    transaction.rollback().await?;
                    return Ok(TextureUploadOutcome::InsufficientScore);
                }
                let insert_sql = format!(
                    "INSERT INTO {prefix}textures \
                     (name, type, hash, size, uploader, public, upload_at, likes) \
                     VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP, 1) \
                     RETURNING CAST(tid AS BIGINT)"
                );
                let tid = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(insert_sql))
                    .bind(name)
                    .bind(texture_type)
                    .bind(hash)
                    .bind(size)
                    .bind(uploader_id)
                    .bind(is_public)
                    .fetch_one(&mut *transaction)
                    .await?;
                let update_user_sql =
                    format!("UPDATE {prefix}users SET score = score - $1 WHERE uid = $2");
                sqlx::query(sqlx::AssertSqlSafe(update_user_sql))
                    .bind(score_cost)
                    .bind(uploader_id)
                    .execute(&mut *transaction)
                    .await?;
                let closet_sql = format!(
                    "INSERT INTO {prefix}user_closet (user_uid, texture_tid, item_name) VALUES ($1, $2, $3)"
                );
                sqlx::query(sqlx::AssertSqlSafe(closet_sql))
                    .bind(uploader_id)
                    .bind(tid)
                    .bind(name)
                    .execute(&mut *transaction)
                    .await?;
                transaction.commit().await?;
                return Ok(TextureUploadOutcome::Uploaded(tid));
            }
        }
    }
    pub async fn delete_texture(
        &self,
        prefix: &str,
        texture: &TextureInfoRecord,
        uploader_score_refund: i64,
        closet_score_refund: i64,
    ) -> Result<bool, sqlx::Error> {
        match self
            .delete_texture_inner(
                prefix,
                texture,
                uploader_score_refund,
                closet_score_refund,
                None,
            )
            .await?
        {
            TextureDeleteOutcome::Deleted(remove_shared_file) => Ok(remove_shared_file),
            TextureDeleteOutcome::ReportNotFound => unreachable!("no report was supplied"),
        }
    }

    pub async fn delete_reported_texture(
        &self,
        prefix: &str,
        texture: &TextureInfoRecord,
        report_id: i64,
        reporter_score_adjustment: i64,
        uploader_score_refund: i64,
        closet_score_refund: i64,
    ) -> Result<TextureDeleteOutcome, sqlx::Error> {
        self.delete_texture_inner(
            prefix,
            texture,
            uploader_score_refund,
            closet_score_refund,
            Some((report_id, reporter_score_adjustment)),
        )
        .await
    }

    async fn delete_texture_inner(
        &self,
        prefix: &str,
        texture: &TextureInfoRecord,
        uploader_score_refund: i64,
        closet_score_refund: i64,
        report_review: Option<(i64, i64)>,
    ) -> Result<TextureDeleteOutcome, sqlx::Error> {
        let postgres = matches!(self, Self::Postgres(_));
        let marker = |index: usize| {
            if postgres {
                format!("${index}")
            } else {
                "?".to_owned()
            }
        };
        let report_lock = if matches!(self, Self::Sqlite(_)) {
            ""
        } else {
            " FOR UPDATE"
        };
        let status_cast = if matches!(self, Self::MySql(_)) {
            "SIGNED"
        } else {
            "INTEGER"
        };
        let integer_cast = if matches!(self, Self::MySql(_)) {
            "SIGNED"
        } else {
            "BIGINT"
        };
        let report_sql = format!(
            "SELECT CAST(status AS {status_cast}), CAST(reporter AS {integer_cast}) \
             FROM {prefix}reports WHERE id = {} LIMIT 1{report_lock}",
            marker(1)
        );
        let report_score_sql = format!(
            "UPDATE {prefix}users SET score = score + {} WHERE uid = {}",
            marker(1),
            marker(2)
        );
        let report_status_sql = format!(
            "UPDATE {prefix}reports SET status = 1 WHERE id = {}",
            marker(1)
        );
        let delete_shared_file = match self {
            Self::Sqlite(pool) => {
                let mut transaction = pool.begin().await?;
                let report_review_state = if let Some((report_id, score_adjustment)) = report_review
                {
                    let report = sqlx::query_as::<_, (i32, i64)>(sqlx::AssertSqlSafe(report_sql))
                        .bind(report_id)
                        .fetch_optional(&mut *transaction)
                        .await?;
                    let Some((status, reporter_id)) = report else {
                        transaction.rollback().await?;
                        return Ok(TextureDeleteOutcome::ReportNotFound);
                    };
                    Some((report_id, status, reporter_id, score_adjustment))
                } else {
                    None
                };
                let count_sql = format!("SELECT COUNT(*) FROM {prefix}textures WHERE hash = ?");
                let reference_count = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(count_sql))
                    .bind(&texture.hash)
                    .fetch_one(&mut *transaction)
                    .await?;
                let likers_sql = format!(
                    "SELECT CAST(user_uid AS BIGINT) FROM {prefix}user_closet \
                     WHERE texture_tid = ? AND user_uid <> ? ORDER BY user_uid"
                );
                let likers = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(likers_sql))
                    .bind(texture.tid)
                    .bind(texture.uploader)
                    .fetch_all(&mut *transaction)
                    .await?;
                if uploader_score_refund != 0 {
                    let score_sql =
                        format!("UPDATE {prefix}users SET score = score + ? WHERE uid = ?");
                    sqlx::query(sqlx::AssertSqlSafe(score_sql))
                        .bind(uploader_score_refund)
                        .bind(texture.uploader)
                        .execute(&mut *transaction)
                        .await?;
                }
                if closet_score_refund != 0 {
                    let score_sql =
                        format!("UPDATE {prefix}users SET score = score + ? WHERE uid = ?");
                    for user_id in likers {
                        sqlx::query(sqlx::AssertSqlSafe(score_sql.clone()))
                            .bind(closet_score_refund)
                            .bind(user_id)
                            .execute(&mut *transaction)
                            .await?;
                    }
                }
                let closet_sql = format!(
                    "DELETE FROM {prefix}user_closet WHERE texture_tid = ? AND user_uid <> ?"
                );
                sqlx::query(sqlx::AssertSqlSafe(closet_sql))
                    .bind(texture.tid)
                    .bind(texture.uploader)
                    .execute(&mut *transaction)
                    .await?;
                let players_skin_sql =
                    format!("UPDATE {prefix}players SET tid_skin = 0 WHERE tid_skin = ?");
                sqlx::query(sqlx::AssertSqlSafe(players_skin_sql))
                    .bind(texture.tid)
                    .execute(&mut *transaction)
                    .await?;
                let players_cape_sql =
                    format!("UPDATE {prefix}players SET tid_cape = 0 WHERE tid_cape = ?");
                sqlx::query(sqlx::AssertSqlSafe(players_cape_sql))
                    .bind(texture.tid)
                    .execute(&mut *transaction)
                    .await?;
                let delete_sql = format!("DELETE FROM {prefix}textures WHERE tid = ?");
                sqlx::query(sqlx::AssertSqlSafe(delete_sql))
                    .bind(texture.tid)
                    .execute(&mut *transaction)
                    .await?;
                if let Some((report_id, status, reporter_id, score_adjustment)) =
                    report_review_state
                {
                    if status == 0 && score_adjustment != 0 {
                        sqlx::query(sqlx::AssertSqlSafe(report_score_sql))
                            .bind(score_adjustment)
                            .bind(reporter_id)
                            .execute(&mut *transaction)
                            .await?;
                    }
                    sqlx::query(sqlx::AssertSqlSafe(report_status_sql))
                        .bind(report_id)
                        .execute(&mut *transaction)
                        .await?;
                }
                transaction.commit().await?;
                TextureDeleteOutcome::Deleted(reference_count == 1)
            }
            Self::MySql(pool) => {
                let mut transaction = pool.begin().await?;
                let report_review_state = if let Some((report_id, score_adjustment)) = report_review
                {
                    let report = sqlx::query_as::<_, (i32, i64)>(sqlx::AssertSqlSafe(report_sql))
                        .bind(report_id)
                        .fetch_optional(&mut *transaction)
                        .await?;
                    let Some((status, reporter_id)) = report else {
                        transaction.rollback().await?;
                        return Ok(TextureDeleteOutcome::ReportNotFound);
                    };
                    Some((report_id, status, reporter_id, score_adjustment))
                } else {
                    None
                };
                let count_sql = format!("SELECT COUNT(*) FROM {prefix}textures WHERE hash = ?");
                let reference_count = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(count_sql))
                    .bind(&texture.hash)
                    .fetch_one(&mut *transaction)
                    .await?;
                let likers_sql = format!(
                    "SELECT CAST(user_uid AS SIGNED) FROM {prefix}user_closet \
                     WHERE texture_tid = ? AND user_uid <> ? ORDER BY user_uid"
                );
                let likers = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(likers_sql))
                    .bind(texture.tid)
                    .bind(texture.uploader)
                    .fetch_all(&mut *transaction)
                    .await?;
                if uploader_score_refund != 0 {
                    let score_sql =
                        format!("UPDATE {prefix}users SET score = score + ? WHERE uid = ?");
                    sqlx::query(sqlx::AssertSqlSafe(score_sql))
                        .bind(uploader_score_refund)
                        .bind(texture.uploader)
                        .execute(&mut *transaction)
                        .await?;
                }
                if closet_score_refund != 0 {
                    let score_sql =
                        format!("UPDATE {prefix}users SET score = score + ? WHERE uid = ?");
                    for user_id in likers {
                        sqlx::query(sqlx::AssertSqlSafe(score_sql.clone()))
                            .bind(closet_score_refund)
                            .bind(user_id)
                            .execute(&mut *transaction)
                            .await?;
                    }
                }
                let closet_sql = format!(
                    "DELETE FROM {prefix}user_closet WHERE texture_tid = ? AND user_uid <> ?"
                );
                sqlx::query(sqlx::AssertSqlSafe(closet_sql))
                    .bind(texture.tid)
                    .bind(texture.uploader)
                    .execute(&mut *transaction)
                    .await?;
                let players_skin_sql =
                    format!("UPDATE {prefix}players SET tid_skin = 0 WHERE tid_skin = ?");
                sqlx::query(sqlx::AssertSqlSafe(players_skin_sql))
                    .bind(texture.tid)
                    .execute(&mut *transaction)
                    .await?;
                let players_cape_sql =
                    format!("UPDATE {prefix}players SET tid_cape = 0 WHERE tid_cape = ?");
                sqlx::query(sqlx::AssertSqlSafe(players_cape_sql))
                    .bind(texture.tid)
                    .execute(&mut *transaction)
                    .await?;
                let delete_sql = format!("DELETE FROM {prefix}textures WHERE tid = ?");
                sqlx::query(sqlx::AssertSqlSafe(delete_sql))
                    .bind(texture.tid)
                    .execute(&mut *transaction)
                    .await?;
                if let Some((report_id, status, reporter_id, score_adjustment)) =
                    report_review_state
                {
                    if status == 0 && score_adjustment != 0 {
                        sqlx::query(sqlx::AssertSqlSafe(report_score_sql))
                            .bind(score_adjustment)
                            .bind(reporter_id)
                            .execute(&mut *transaction)
                            .await?;
                    }
                    sqlx::query(sqlx::AssertSqlSafe(report_status_sql))
                        .bind(report_id)
                        .execute(&mut *transaction)
                        .await?;
                }
                transaction.commit().await?;
                TextureDeleteOutcome::Deleted(reference_count == 1)
            }
            Self::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                let report_review_state = if let Some((report_id, score_adjustment)) = report_review
                {
                    let report = sqlx::query_as::<_, (i32, i64)>(sqlx::AssertSqlSafe(report_sql))
                        .bind(report_id)
                        .fetch_optional(&mut *transaction)
                        .await?;
                    let Some((status, reporter_id)) = report else {
                        transaction.rollback().await?;
                        return Ok(TextureDeleteOutcome::ReportNotFound);
                    };
                    Some((report_id, status, reporter_id, score_adjustment))
                } else {
                    None
                };
                let count_sql = format!("SELECT COUNT(*) FROM {prefix}textures WHERE hash = $1");
                let reference_count = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(count_sql))
                    .bind(&texture.hash)
                    .fetch_one(&mut *transaction)
                    .await?;
                let likers_sql = format!(
                    "SELECT CAST(user_uid AS BIGINT) FROM {prefix}user_closet \
                     WHERE texture_tid = $1 AND user_uid <> $2 ORDER BY user_uid"
                );
                let likers = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(likers_sql))
                    .bind(texture.tid)
                    .bind(texture.uploader)
                    .fetch_all(&mut *transaction)
                    .await?;
                if uploader_score_refund != 0 {
                    let score_sql =
                        format!("UPDATE {prefix}users SET score = score + $1 WHERE uid = $2");
                    sqlx::query(sqlx::AssertSqlSafe(score_sql))
                        .bind(uploader_score_refund)
                        .bind(texture.uploader)
                        .execute(&mut *transaction)
                        .await?;
                }
                if closet_score_refund != 0 {
                    let score_sql =
                        format!("UPDATE {prefix}users SET score = score + $1 WHERE uid = $2");
                    for user_id in likers {
                        sqlx::query(sqlx::AssertSqlSafe(score_sql.clone()))
                            .bind(closet_score_refund)
                            .bind(user_id)
                            .execute(&mut *transaction)
                            .await?;
                    }
                }
                let closet_sql = format!(
                    "DELETE FROM {prefix}user_closet WHERE texture_tid = $1 AND user_uid <> $2"
                );
                sqlx::query(sqlx::AssertSqlSafe(closet_sql))
                    .bind(texture.tid)
                    .bind(texture.uploader)
                    .execute(&mut *transaction)
                    .await?;
                let players_skin_sql =
                    format!("UPDATE {prefix}players SET tid_skin = 0 WHERE tid_skin = $1");
                sqlx::query(sqlx::AssertSqlSafe(players_skin_sql))
                    .bind(texture.tid)
                    .execute(&mut *transaction)
                    .await?;
                let players_cape_sql =
                    format!("UPDATE {prefix}players SET tid_cape = 0 WHERE tid_cape = $1");
                sqlx::query(sqlx::AssertSqlSafe(players_cape_sql))
                    .bind(texture.tid)
                    .execute(&mut *transaction)
                    .await?;
                let delete_sql = format!("DELETE FROM {prefix}textures WHERE tid = $1");
                sqlx::query(sqlx::AssertSqlSafe(delete_sql))
                    .bind(texture.tid)
                    .execute(&mut *transaction)
                    .await?;
                if let Some((report_id, status, reporter_id, score_adjustment)) =
                    report_review_state
                {
                    if status == 0 && score_adjustment != 0 {
                        sqlx::query(sqlx::AssertSqlSafe(report_score_sql))
                            .bind(score_adjustment)
                            .bind(reporter_id)
                            .execute(&mut *transaction)
                            .await?;
                    }
                    sqlx::query(sqlx::AssertSqlSafe(report_status_sql))
                        .bind(report_id)
                        .execute(&mut *transaction)
                        .await?;
                }
                transaction.commit().await?;
                TextureDeleteOutcome::Deleted(reference_count == 1)
            }
        };
        Ok(delete_shared_file)
    }
    pub async fn resolve_report_without_texture(
        &self,
        prefix: &str,
        report_id: i64,
        reporter_score_modification: i64,
    ) -> Result<ReportReviewOutcome, sqlx::Error> {
        let postgres = matches!(self, Self::Postgres(_));
        let marker = |index: usize| {
            if postgres {
                format!("${index}")
            } else {
                "?".to_owned()
            }
        };
        let lock_clause = if matches!(self, Self::Sqlite(_)) {
            ""
        } else {
            " FOR UPDATE"
        };
        let integer_cast = if matches!(self, Self::MySql(_)) {
            "SIGNED"
        } else {
            "BIGINT"
        };
        let status_cast = if matches!(self, Self::MySql(_)) {
            "SIGNED"
        } else {
            "INTEGER"
        };
        let report_sql = format!(
            "SELECT CAST(status AS {status_cast}), CAST(reporter AS {integer_cast}) \
             FROM {prefix}reports WHERE id = {} LIMIT 1{lock_clause}",
            marker(1)
        );
        let refund = reporter_score_modification.min(0).saturating_neg();
        let score_sql = format!(
            "UPDATE {prefix}users SET score = score + {} WHERE uid = {}",
            marker(1),
            marker(2)
        );
        let status_sql = format!(
            "UPDATE {prefix}reports SET status = 1 WHERE id = {}",
            marker(1)
        );
        match self {
            Self::Sqlite(pool) => {
                let mut transaction = pool.begin().await?;
                let report = sqlx::query_as::<_, (i32, i64)>(sqlx::AssertSqlSafe(report_sql))
                    .bind(report_id)
                    .fetch_optional(&mut *transaction)
                    .await?;
                let Some((status, reporter_id)) = report else {
                    transaction.rollback().await?;
                    return Ok(ReportReviewOutcome::NotFound);
                };
                if status == 0 && refund > 0 {
                    sqlx::query(sqlx::AssertSqlSafe(score_sql))
                        .bind(refund)
                        .bind(reporter_id)
                        .execute(&mut *transaction)
                        .await?;
                }
                sqlx::query(sqlx::AssertSqlSafe(status_sql))
                    .bind(report_id)
                    .execute(&mut *transaction)
                    .await?;
                transaction.commit().await?;
            }
            Self::MySql(pool) => {
                let mut transaction = pool.begin().await?;
                let report = sqlx::query_as::<_, (i32, i64)>(sqlx::AssertSqlSafe(report_sql))
                    .bind(report_id)
                    .fetch_optional(&mut *transaction)
                    .await?;
                let Some((status, reporter_id)) = report else {
                    transaction.rollback().await?;
                    return Ok(ReportReviewOutcome::NotFound);
                };
                if status == 0 && refund > 0 {
                    sqlx::query(sqlx::AssertSqlSafe(score_sql))
                        .bind(refund)
                        .bind(reporter_id)
                        .execute(&mut *transaction)
                        .await?;
                }
                sqlx::query(sqlx::AssertSqlSafe(status_sql))
                    .bind(report_id)
                    .execute(&mut *transaction)
                    .await?;
                transaction.commit().await?;
            }
            Self::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                let report = sqlx::query_as::<_, (i32, i64)>(sqlx::AssertSqlSafe(report_sql))
                    .bind(report_id)
                    .fetch_optional(&mut *transaction)
                    .await?;
                let Some((status, reporter_id)) = report else {
                    transaction.rollback().await?;
                    return Ok(ReportReviewOutcome::NotFound);
                };
                if status == 0 && refund > 0 {
                    sqlx::query(sqlx::AssertSqlSafe(score_sql))
                        .bind(refund)
                        .bind(reporter_id)
                        .execute(&mut *transaction)
                        .await?;
                }
                sqlx::query(sqlx::AssertSqlSafe(status_sql))
                    .bind(report_id)
                    .execute(&mut *transaction)
                    .await?;
                transaction.commit().await?;
            }
        }
        Ok(ReportReviewOutcome::Resolved)
    }

    pub async fn player_profile(
        &self,
        prefix: &str,
        name: &str,
    ) -> Result<Option<PlayerProfile>, sqlx::Error> {
        let sql = match self {
            Self::Sqlite(_) => format!(
                "SELECT p.name, u.permission, s.type AS skin_type, s.hash AS skin_hash, \
                 c.hash AS cape_hash, CAST(p.last_modified AS TEXT) AS last_modified \
                 FROM {prefix}players p \
                 INNER JOIN {prefix}users u ON u.uid = p.uid \
                 LEFT JOIN {prefix}textures s ON s.tid = p.tid_skin \
                 LEFT JOIN {prefix}textures c ON c.tid = p.tid_cape \
                 WHERE p.name = ? LIMIT 1"
            ),
            Self::MySql(_) => format!(
                "SELECT p.name, u.permission, s.type AS skin_type, s.hash AS skin_hash, \
                 c.hash AS cape_hash, DATE_FORMAT(p.last_modified, '%Y-%m-%d %H:%i:%s') AS last_modified \
                 FROM {prefix}players p \
                 INNER JOIN {prefix}users u ON u.uid = p.uid \
                 LEFT JOIN {prefix}textures s ON s.tid = p.tid_skin \
                 LEFT JOIN {prefix}textures c ON c.tid = p.tid_cape \
                 WHERE p.name = ? LIMIT 1"
            ),
            Self::Postgres(_) => format!(
                "SELECT p.name, u.permission, s.type AS skin_type, s.hash AS skin_hash, \
                 c.hash AS cape_hash, to_char(p.last_modified, 'YYYY-MM-DD HH24:MI:SS') AS last_modified \
                 FROM {prefix}players p \
                 INNER JOIN {prefix}users u ON u.uid = p.uid \
                 LEFT JOIN {prefix}textures s ON s.tid = p.tid_skin \
                 LEFT JOIN {prefix}textures c ON c.tid = p.tid_cape \
                 WHERE p.name = $1 LIMIT 1"
            ),
        };
        match self {
            Self::Sqlite(pool) => Ok(sqlx::query_as::<_, PlayerProfile>(sqlx::AssertSqlSafe(sql))
                .bind(name)
                .fetch_optional(pool)
                .await?),
            Self::MySql(pool) => Ok(sqlx::query_as::<_, PlayerProfile>(sqlx::AssertSqlSafe(sql))
                .bind(name)
                .fetch_optional(pool)
                .await?),
            Self::Postgres(pool) => {
                Ok(sqlx::query_as::<_, PlayerProfile>(sqlx::AssertSqlSafe(sql))
                    .bind(name)
                    .fetch_optional(pool)
                    .await?)
            }
        }
    }

    pub async fn texture_id_by_hash(
        &self,
        prefix: &str,
        hash: &str,
    ) -> Result<Option<i64>, sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => {
                format!("SELECT CAST(tid AS BIGINT) FROM {prefix}textures WHERE hash = $1 LIMIT 1")
            }
            Self::MySql(_) => {
                format!("SELECT CAST(tid AS SIGNED) FROM {prefix}textures WHERE hash = ? LIMIT 1")
            }
            Self::Sqlite(_) => {
                format!("SELECT CAST(tid AS BIGINT) FROM {prefix}textures WHERE hash = ? LIMIT 1")
            }
        };
        match self {
            Self::Sqlite(pool) => Ok(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                .bind(hash)
                .fetch_optional(pool)
                .await?),
            Self::MySql(pool) => Ok(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                .bind(hash)
                .fetch_optional(pool)
                .await?),
            Self::Postgres(pool) => Ok(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                .bind(hash)
                .fetch_optional(pool)
                .await?),
        }
    }

    pub async fn texture_hash(
        &self,
        prefix: &str,
        tid: i64,
    ) -> Result<Option<String>, sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => {
                format!("SELECT hash FROM {prefix}textures WHERE tid = $1 LIMIT 1")
            }
            _ => format!("SELECT hash FROM {prefix}textures WHERE tid = ? LIMIT 1"),
        };
        match self {
            Self::Sqlite(pool) => Ok(sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(sql))
                .bind(tid)
                .fetch_optional(pool)
                .await?),
            Self::MySql(pool) => Ok(sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(sql))
                .bind(tid)
                .fetch_optional(pool)
                .await?),
            Self::Postgres(pool) => Ok(sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(sql))
                .bind(tid)
                .fetch_optional(pool)
                .await?),
        }
    }
    pub async fn set_texture_type(
        &self,
        prefix: &str,
        tid: i64,
        texture_type: &str,
    ) -> Result<(), sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => format!("UPDATE {prefix}textures SET type = $1 WHERE tid = $2"),
            _ => format!("UPDATE {prefix}textures SET type = ? WHERE tid = ?"),
        };
        match self {
            Self::Sqlite(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(texture_type)
                    .bind(tid)
                    .execute(pool)
                    .await?;
            }
            Self::MySql(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(texture_type)
                    .bind(tid)
                    .execute(pool)
                    .await?;
            }
            Self::Postgres(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(texture_type)
                    .bind(tid)
                    .execute(pool)
                    .await?;
            }
        }
        Ok(())
    }
    pub async fn rename_texture(
        &self,
        prefix: &str,
        tid: i64,
        name: &str,
    ) -> Result<(), sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => {
                format!("UPDATE {prefix}textures SET name = $1 WHERE tid = $2")
            }
            _ => format!("UPDATE {prefix}textures SET name = ? WHERE tid = ?"),
        };
        match self {
            Self::Sqlite(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(name)
                    .bind(tid)
                    .execute(pool)
                    .await?;
            }
            Self::MySql(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(name)
                    .bind(tid)
                    .execute(pool)
                    .await?;
            }
            Self::Postgres(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(name)
                    .bind(tid)
                    .execute(pool)
                    .await?;
            }
        }
        Ok(())
    }
    pub async fn texture_info(
        &self,
        prefix: &str,
        tid: i64,
    ) -> Result<Option<TextureInfoRecord>, sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => format!(
                "SELECT CAST(tid AS BIGINT) AS tid, name, type AS texture_type, hash, \
                 CAST(size AS BIGINT) AS size, CAST(uploader AS BIGINT) AS uploader, \
                 public AS is_public, TO_CHAR(upload_at, 'YYYY-MM-DD HH24:MI:SS') AS upload_at, \
                 CAST(likes AS BIGINT) AS likes FROM {prefix}textures WHERE tid = $1 LIMIT 1"
            ),
            Self::MySql(_) => format!(
                "SELECT CAST(tid AS SIGNED) AS tid, name, type AS texture_type, hash, \
                 CAST(size AS SIGNED) AS size, CAST(uploader AS SIGNED) AS uploader, \
                 public AS is_public, DATE_FORMAT(upload_at, '%Y-%m-%d %H:%i:%s') AS upload_at, \
                 CAST(likes AS SIGNED) AS likes FROM {prefix}textures WHERE tid = ? LIMIT 1"
            ),
            Self::Sqlite(_) => format!(
                "SELECT CAST(tid AS BIGINT) AS tid, name, type AS texture_type, hash, \
                 CAST(size AS BIGINT) AS size, CAST(uploader AS BIGINT) AS uploader, \
                 public AS is_public, CAST(upload_at AS TEXT) AS upload_at, \
                 CAST(likes AS BIGINT) AS likes FROM {prefix}textures WHERE tid = ? LIMIT 1"
            ),
        };
        match self {
            Self::Sqlite(pool) => Ok(sqlx::query_as::<_, TextureInfoRecord>(sqlx::AssertSqlSafe(
                sql,
            ))
            .bind(tid)
            .fetch_optional(pool)
            .await?),
            Self::MySql(pool) => Ok(sqlx::query_as::<_, TextureInfoRecord>(sqlx::AssertSqlSafe(
                sql,
            ))
            .bind(tid)
            .fetch_optional(pool)
            .await?),
            Self::Postgres(pool) => Ok(sqlx::query_as::<_, TextureInfoRecord>(
                sqlx::AssertSqlSafe(sql),
            )
            .bind(tid)
            .fetch_optional(pool)
            .await?),
        }
    }
    pub async fn texture_hash_reference_count(
        &self,
        prefix: &str,
        hash: &str,
    ) -> Result<i64, sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => format!("SELECT COUNT(*) FROM {prefix}textures WHERE hash = $1"),
            _ => format!("SELECT COUNT(*) FROM {prefix}textures WHERE hash = ?"),
        };
        match self {
            Self::Sqlite(pool) => Ok(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                .bind(hash)
                .fetch_one(pool)
                .await?),
            Self::MySql(pool) => Ok(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                .bind(hash)
                .fetch_one(pool)
                .await?),
            Self::Postgres(pool) => Ok(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                .bind(hash)
                .fetch_one(pool)
                .await?),
        }
    }

    pub async fn admin_players(
        &self,
        prefix: &str,
        search: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<PlayerRecord>, i64), sqlx::Error> {
        let postgres = matches!(self, Self::Postgres(_));
        let (where_sql, binds) = admin_player_where(search, postgres);
        let page_sql = match self {
            Self::Sqlite(_) => format!(
                "SELECT CAST(pid AS BIGINT) AS pid, CAST(uid AS BIGINT) AS uid, name, CAST(tid_skin AS BIGINT) AS tid_skin, \
                 CAST(tid_cape AS BIGINT) AS tid_cape, CAST(last_modified AS TEXT) AS last_modified \
                 FROM {prefix}players{where_sql} ORDER BY pid ASC LIMIT ? OFFSET ?"
            ),
            Self::MySql(_) => format!(
                "SELECT CAST(pid AS SIGNED) AS pid, CAST(uid AS SIGNED) AS uid, name, CAST(tid_skin AS SIGNED) AS tid_skin, \
                 CAST(tid_cape AS SIGNED) AS tid_cape, DATE_FORMAT(last_modified, '%Y-%m-%d %H:%i:%s') AS last_modified \
                 FROM {prefix}players{where_sql} ORDER BY pid ASC LIMIT ? OFFSET ?"
            ),
            Self::Postgres(_) => format!(
                "SELECT CAST(pid AS BIGINT) AS pid, CAST(uid AS BIGINT) AS uid, name, CAST(tid_skin AS BIGINT) AS tid_skin, \
                 CAST(tid_cape AS BIGINT) AS tid_cape, to_char(last_modified, 'YYYY-MM-DD HH24:MI:SS') AS last_modified \
                 FROM {prefix}players{where_sql} ORDER BY pid ASC LIMIT ${} OFFSET ${}",
                binds.len() + 1,
                binds.len() + 2
            ),
        };
        let count_sql = format!("SELECT COUNT(*) FROM {prefix}players{where_sql}");
        let (players, total) = match self {
            Self::Sqlite(pool) => {
                let mut page = sqlx::query_as::<_, PlayerRecord>(sqlx::AssertSqlSafe(page_sql));
                let mut count = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(count_sql));
                for bind in &binds {
                    match bind {
                        AdminPlayerSearchBind::Text(value) => {
                            page = page.bind(value.clone());
                            count = count.bind(value.clone());
                        }
                        AdminPlayerSearchBind::Integer(value) => {
                            page = page.bind(*value);
                            count = count.bind(*value);
                        }
                    }
                }
                let players = page.bind(limit).bind(offset).fetch_all(pool).await?;
                let total = count.fetch_one(pool).await?;
                (players, total)
            }
            Self::MySql(pool) => {
                let mut page = sqlx::query_as::<_, PlayerRecord>(sqlx::AssertSqlSafe(page_sql));
                let mut count = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(count_sql));
                for bind in &binds {
                    match bind {
                        AdminPlayerSearchBind::Text(value) => {
                            page = page.bind(value.clone());
                            count = count.bind(value.clone());
                        }
                        AdminPlayerSearchBind::Integer(value) => {
                            page = page.bind(*value);
                            count = count.bind(*value);
                        }
                    }
                }
                let players = page.bind(limit).bind(offset).fetch_all(pool).await?;
                let total = count.fetch_one(pool).await?;
                (players, total)
            }
            Self::Postgres(pool) => {
                let mut page = sqlx::query_as::<_, PlayerRecord>(sqlx::AssertSqlSafe(page_sql));
                let mut count = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(count_sql));
                for bind in &binds {
                    match bind {
                        AdminPlayerSearchBind::Text(value) => {
                            page = page.bind(value.clone());
                            count = count.bind(value.clone());
                        }
                        AdminPlayerSearchBind::Integer(value) => {
                            page = page.bind(*value);
                            count = count.bind(*value);
                        }
                    }
                }
                let players = page.bind(limit).bind(offset).fetch_all(pool).await?;
                let total = count.fetch_one(pool).await?;
                (players, total)
            }
        };
        Ok((players, total))
    }

    pub async fn admin_player_for_update(
        &self,
        prefix: &str,
        pid: i64,
    ) -> Result<Option<AdminPlayerManagementRecord>, sqlx::Error> {
        let sql = match self {
            Self::Sqlite(_) => format!(
                "SELECT CAST(p.pid AS BIGINT) AS pid, CAST(p.uid AS BIGINT) AS uid, p.name, \
                 CAST(p.tid_skin AS BIGINT) AS tid_skin, CAST(p.tid_cape AS BIGINT) AS tid_cape, \
                 CAST(p.last_modified AS TEXT) AS last_modified, u.permission AS owner_permission \
                 FROM {prefix}players p JOIN {prefix}users u ON u.uid = p.uid WHERE p.pid = ? LIMIT 1"
            ),
            Self::MySql(_) => format!(
                "SELECT CAST(p.pid AS SIGNED) AS pid, CAST(p.uid AS SIGNED) AS uid, p.name, \
                 CAST(p.tid_skin AS SIGNED) AS tid_skin, CAST(p.tid_cape AS SIGNED) AS tid_cape, \
                 DATE_FORMAT(p.last_modified, '%Y-%m-%d %H:%i:%s') AS last_modified, u.permission AS owner_permission \
                 FROM {prefix}players p JOIN {prefix}users u ON u.uid = p.uid WHERE p.pid = ? LIMIT 1"
            ),
            Self::Postgres(_) => format!(
                "SELECT CAST(p.pid AS BIGINT) AS pid, CAST(p.uid AS BIGINT) AS uid, p.name, \
                 CAST(p.tid_skin AS BIGINT) AS tid_skin, CAST(p.tid_cape AS BIGINT) AS tid_cape, \
                 to_char(p.last_modified, 'YYYY-MM-DD HH24:MI:SS') AS last_modified, u.permission AS owner_permission \
                 FROM {prefix}players p JOIN {prefix}users u ON u.uid = p.uid WHERE p.pid = $1 LIMIT 1"
            ),
        };
        match self {
            Self::Sqlite(pool) => Ok(sqlx::query_as::<_, AdminPlayerManagementRecord>(
                sqlx::AssertSqlSafe(sql),
            )
            .bind(pid)
            .fetch_optional(pool)
            .await?),
            Self::MySql(pool) => Ok(sqlx::query_as::<_, AdminPlayerManagementRecord>(
                sqlx::AssertSqlSafe(sql),
            )
            .bind(pid)
            .fetch_optional(pool)
            .await?),
            Self::Postgres(pool) => Ok(sqlx::query_as::<_, AdminPlayerManagementRecord>(
                sqlx::AssertSqlSafe(sql),
            )
            .bind(pid)
            .fetch_optional(pool)
            .await?),
        }
    }

    pub async fn admin_player_name_exists(
        &self,
        prefix: &str,
        name: &str,
    ) -> Result<bool, sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => format!("SELECT COUNT(*) FROM {prefix}players WHERE name = $1"),
            _ => format!("SELECT COUNT(*) FROM {prefix}players WHERE name = ?"),
        };
        let count = match self {
            Self::Sqlite(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                    .bind(name)
                    .fetch_one(pool)
                    .await?
            }
            Self::MySql(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                    .bind(name)
                    .fetch_one(pool)
                    .await?
            }
            Self::Postgres(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                    .bind(name)
                    .fetch_one(pool)
                    .await?
            }
        };
        Ok(count > 0)
    }

    pub async fn update_admin_player_text(
        &self,
        prefix: &str,
        pid: i64,
        column: &'static str,
        value: &str,
    ) -> Result<(), sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => format!(
                "UPDATE {prefix}players SET {column} = $1, last_modified = CURRENT_TIMESTAMP WHERE pid = $2"
            ),
            _ => format!(
                "UPDATE {prefix}players SET {column} = ?, last_modified = CURRENT_TIMESTAMP WHERE pid = ?"
            ),
        };
        match self {
            Self::Sqlite(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(value)
                    .bind(pid)
                    .execute(pool)
                    .await?;
            }
            Self::MySql(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(value)
                    .bind(pid)
                    .execute(pool)
                    .await?;
            }
            Self::Postgres(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(value)
                    .bind(pid)
                    .execute(pool)
                    .await?;
            }
        }
        Ok(())
    }

    pub async fn update_admin_player_integer(
        &self,
        prefix: &str,
        pid: i64,
        column: &'static str,
        value: i64,
    ) -> Result<(), sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => format!(
                "UPDATE {prefix}players SET {column} = $1, last_modified = CURRENT_TIMESTAMP WHERE pid = $2"
            ),
            _ => format!(
                "UPDATE {prefix}players SET {column} = ?, last_modified = CURRENT_TIMESTAMP WHERE pid = ?"
            ),
        };
        match self {
            Self::Sqlite(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(value)
                    .bind(pid)
                    .execute(pool)
                    .await?;
            }
            Self::MySql(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(value)
                    .bind(pid)
                    .execute(pool)
                    .await?;
            }
            Self::Postgres(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(value)
                    .bind(pid)
                    .execute(pool)
                    .await?;
            }
        }
        Ok(())
    }

    pub async fn delete_admin_player(&self, prefix: &str, pid: i64) -> Result<bool, sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => format!("DELETE FROM {prefix}players WHERE pid = $1"),
            _ => format!("DELETE FROM {prefix}players WHERE pid = ?"),
        };
        let affected = match self {
            Self::Sqlite(pool) => sqlx::query(sqlx::AssertSqlSafe(sql))
                .bind(pid)
                .execute(pool)
                .await?
                .rows_affected(),
            Self::MySql(pool) => sqlx::query(sqlx::AssertSqlSafe(sql))
                .bind(pid)
                .execute(pool)
                .await?
                .rows_affected(),
            Self::Postgres(pool) => sqlx::query(sqlx::AssertSqlSafe(sql))
                .bind(pid)
                .execute(pool)
                .await?
                .rows_affected(),
        };
        Ok(affected > 0)
    }

    pub async fn admin_users(
        &self,
        prefix: &str,
        search: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<AdminUserRecord>, i64), sqlx::Error> {
        let sqlite = matches!(self, Self::Sqlite(_));
        let mysql = matches!(self, Self::MySql(_));
        let postgres = matches!(self, Self::Postgres(_));
        let (where_sql, binds) = admin_user_where(search, postgres);
        let (uid_cast, int_cast) = if sqlite {
            ("BIGINT", "INTEGER")
        } else if mysql {
            ("SIGNED", "SIGNED")
        } else {
            ("BIGINT", "INTEGER")
        };
        let page_sql = if postgres {
            format!(
                "SELECT CAST(uid AS {uid_cast}) AS uid, email, nickname, locale, CAST(score AS BIGINT) AS score, \
                 CAST(avatar AS BIGINT) AS avatar, CAST(permission AS {int_cast}) AS permission, ip, is_dark_mode, \
                 last_sign_at, register_at, verified FROM {prefix}users{where_sql} ORDER BY uid ASC LIMIT ${} OFFSET ${}",
                binds.len() + 1,
                binds.len() + 2
            )
        } else {
            format!(
                "SELECT CAST(uid AS {uid_cast}) AS uid, email, nickname, locale, CAST(score AS BIGINT) AS score, \
                 CAST(avatar AS BIGINT) AS avatar, CAST(permission AS {int_cast}) AS permission, ip, is_dark_mode, \
                 last_sign_at, register_at, verified FROM {prefix}users{where_sql} ORDER BY uid ASC LIMIT ? OFFSET ?"
            )
        };
        let count_sql = format!("SELECT COUNT(*) FROM {prefix}users{where_sql}");
        let (users, total) = match self {
            Self::Sqlite(pool) => {
                let mut page = sqlx::query_as::<_, AdminUserRecord>(sqlx::AssertSqlSafe(page_sql));
                let mut count = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(count_sql));
                for bind in &binds {
                    match bind {
                        AdminUserSearchBind::Text(value) => {
                            page = page.bind(value.clone());
                            count = count.bind(value.clone());
                        }
                        AdminUserSearchBind::Integer(value) => {
                            page = page.bind(*value);
                            count = count.bind(*value);
                        }
                        AdminUserSearchBind::Boolean(value) => {
                            page = page.bind(*value);
                            count = count.bind(*value);
                        }
                    }
                }
                let users = page.bind(limit).bind(offset).fetch_all(pool).await?;
                let total = count.fetch_one(pool).await?;
                (users, total)
            }
            Self::MySql(pool) => {
                let mut page = sqlx::query_as::<_, AdminUserRecord>(sqlx::AssertSqlSafe(page_sql));
                let mut count = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(count_sql));
                for bind in &binds {
                    match bind {
                        AdminUserSearchBind::Text(value) => {
                            page = page.bind(value.clone());
                            count = count.bind(value.clone());
                        }
                        AdminUserSearchBind::Integer(value) => {
                            page = page.bind(*value);
                            count = count.bind(*value);
                        }
                        AdminUserSearchBind::Boolean(value) => {
                            page = page.bind(*value);
                            count = count.bind(*value);
                        }
                    }
                }
                let users = page.bind(limit).bind(offset).fetch_all(pool).await?;
                let total = count.fetch_one(pool).await?;
                (users, total)
            }
            Self::Postgres(pool) => {
                let mut page = sqlx::query_as::<_, AdminUserRecord>(sqlx::AssertSqlSafe(page_sql));
                let mut count = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(count_sql));
                for bind in &binds {
                    match bind {
                        AdminUserSearchBind::Text(value) => {
                            page = page.bind(value.clone());
                            count = count.bind(value.clone());
                        }
                        AdminUserSearchBind::Integer(value) => {
                            page = page.bind(*value);
                            count = count.bind(*value);
                        }
                        AdminUserSearchBind::Boolean(value) => {
                            page = page.bind(*value);
                            count = count.bind(*value);
                        }
                    }
                }
                let users = page.bind(limit).bind(offset).fetch_all(pool).await?;
                let total = count.fetch_one(pool).await?;
                (users, total)
            }
        };
        Ok((users, total))
    }

    pub async fn oauth_clients_for_user(
        &self,
        prefix: &str,
        user_id: i64,
    ) -> Result<Vec<OAuthClientRecord>, sqlx::Error> {
        let sql = match self {
            Self::Sqlite(_) => format!(
                "SELECT CAST(id AS BIGINT) AS id, name, secret, redirect FROM {prefix}oauth_clients \
                 WHERE user_id = ? AND personal_access_client = FALSE \
                 AND password_client = FALSE AND revoked = FALSE ORDER BY id"
            ),
            Self::MySql(_) => format!(
                "SELECT CAST(id AS SIGNED) AS id, name, secret, redirect FROM {prefix}oauth_clients \
                 WHERE user_id = ? AND personal_access_client = FALSE \
                 AND password_client = FALSE AND revoked = FALSE ORDER BY id"
            ),
            Self::Postgres(_) => format!(
                "SELECT CAST(id AS BIGINT) AS id, name, secret, redirect FROM {prefix}oauth_clients \
                 WHERE user_id = $1 AND personal_access_client = FALSE \
                 AND password_client = FALSE AND revoked = FALSE ORDER BY id"
            ),
        };
        match self {
            Self::Sqlite(pool) => Ok(sqlx::query_as::<_, OAuthClientRecord>(sqlx::AssertSqlSafe(
                sql,
            ))
            .bind(user_id)
            .fetch_all(pool)
            .await?),
            Self::MySql(pool) => Ok(sqlx::query_as::<_, OAuthClientRecord>(sqlx::AssertSqlSafe(
                sql,
            ))
            .bind(user_id)
            .fetch_all(pool)
            .await?),
            Self::Postgres(pool) => Ok(sqlx::query_as::<_, OAuthClientRecord>(
                sqlx::AssertSqlSafe(sql),
            )
            .bind(user_id)
            .fetch_all(pool)
            .await?),
        }
    }

    pub async fn create_oauth_client(
        &self,
        prefix: &str,
        user_id: i64,
        name: &str,
        secret: &str,
        redirect: &str,
    ) -> Result<OAuthClientRecord, sqlx::Error> {
        let record = match self {
            Self::Sqlite(pool) => {
                let sql = format!(
                    "INSERT INTO {prefix}oauth_clients \
                     (user_id, name, secret, provider, redirect, personal_access_client, \
                      password_client, revoked, created_at, updated_at) \
                     VALUES (?, ?, ?, NULL, ?, FALSE, FALSE, FALSE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
                );
                let inserted = sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(user_id)
                    .bind(name)
                    .bind(secret)
                    .bind(redirect)
                    .execute(pool)
                    .await?;
                OAuthClientRecord {
                    id: inserted.last_insert_rowid(),
                    name: name.to_owned(),
                    secret: secret.to_owned(),
                    redirect: redirect.to_owned(),
                }
            }
            Self::MySql(pool) => {
                let sql = format!(
                    "INSERT INTO {prefix}oauth_clients \
                     (user_id, name, secret, provider, redirect, personal_access_client, \
                      password_client, revoked, created_at, updated_at) \
                     VALUES (?, ?, ?, NULL, ?, FALSE, FALSE, FALSE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
                );
                let inserted = sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(user_id)
                    .bind(name)
                    .bind(secret)
                    .bind(redirect)
                    .execute(pool)
                    .await?;
                OAuthClientRecord {
                    id: inserted.last_insert_id() as i64,
                    name: name.to_owned(),
                    secret: secret.to_owned(),
                    redirect: redirect.to_owned(),
                }
            }
            Self::Postgres(pool) => {
                let sql = format!(
                    "INSERT INTO {prefix}oauth_clients \
                     (user_id, name, secret, provider, redirect, personal_access_client, \
                      password_client, revoked, created_at, updated_at) \
                     VALUES ($1, $2, $3, NULL, $4, FALSE, FALSE, FALSE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) \
                     RETURNING CAST(id AS BIGINT)"
                );
                let id = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                    .bind(user_id)
                    .bind(name)
                    .bind(secret)
                    .bind(redirect)
                    .fetch_one(pool)
                    .await?;
                OAuthClientRecord {
                    id,
                    name: name.to_owned(),
                    secret: secret.to_owned(),
                    redirect: redirect.to_owned(),
                }
            }
        };
        Ok(record)
    }

    pub async fn update_oauth_client(
        &self,
        prefix: &str,
        user_id: i64,
        client_id: i64,
        name: &str,
        redirect: &str,
    ) -> Result<bool, sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => format!(
                "UPDATE {prefix}oauth_clients SET name = $1, redirect = $2, updated_at = CURRENT_TIMESTAMP \
                 WHERE id = $3 AND user_id = $4 AND personal_access_client = FALSE AND revoked = FALSE"
            ),
            _ => format!(
                "UPDATE {prefix}oauth_clients SET name = ?, redirect = ?, updated_at = CURRENT_TIMESTAMP \
                 WHERE id = ? AND user_id = ? AND personal_access_client = FALSE AND revoked = FALSE"
            ),
        };
        let rows_affected = match self {
            Self::Sqlite(pool) => sqlx::query(sqlx::AssertSqlSafe(sql))
                .bind(name)
                .bind(redirect)
                .bind(client_id)
                .bind(user_id)
                .execute(pool)
                .await?
                .rows_affected(),
            Self::MySql(pool) => sqlx::query(sqlx::AssertSqlSafe(sql))
                .bind(name)
                .bind(redirect)
                .bind(client_id)
                .bind(user_id)
                .execute(pool)
                .await?
                .rows_affected(),
            Self::Postgres(pool) => sqlx::query(sqlx::AssertSqlSafe(sql))
                .bind(name)
                .bind(redirect)
                .bind(client_id)
                .bind(user_id)
                .execute(pool)
                .await?
                .rows_affected(),
        };
        Ok(rows_affected > 0)
    }

    pub async fn revoke_oauth_client(
        &self,
        prefix: &str,
        user_id: i64,
        client_id: i64,
    ) -> Result<OAuthClientDeleteOutcome, sqlx::Error> {
        let postgres = matches!(self, Self::Postgres(_));
        let marker = |index: usize| {
            if postgres {
                format!("${index}")
            } else {
                "?".to_owned()
            }
        };
        let lock_clause = if matches!(self, Self::Sqlite(_)) {
            ""
        } else {
            " FOR UPDATE"
        };
        let client_sql = format!(
            "SELECT id FROM {prefix}oauth_clients WHERE id = {} AND user_id = {} \
             AND personal_access_client = FALSE AND revoked = FALSE LIMIT 1{lock_clause}",
            marker(1),
            marker(2)
        );
        let access_token_sql = format!(
            "UPDATE {prefix}oauth_access_tokens SET revoked = TRUE WHERE client_id = {}",
            marker(1)
        );
        let refresh_token_sql = format!(
            "UPDATE {prefix}oauth_refresh_tokens SET revoked = TRUE WHERE access_token_id \
             IN (SELECT id FROM {prefix}oauth_access_tokens WHERE client_id = {})",
            marker(1)
        );
        let auth_code_sql = format!(
            "UPDATE {prefix}oauth_auth_codes SET revoked = TRUE WHERE client_id = {}",
            marker(1)
        );
        let revoke_client_sql = format!(
            "UPDATE {prefix}oauth_clients SET revoked = TRUE, updated_at = CURRENT_TIMESTAMP \
             WHERE id = {} AND user_id = {} AND personal_access_client = FALSE",
            marker(1),
            marker(2)
        );
        match self {
            Self::Sqlite(pool) => {
                let mut transaction = pool.begin().await?;
                let owned = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(client_sql))
                    .bind(client_id)
                    .bind(user_id)
                    .fetch_optional(&mut *transaction)
                    .await?;
                if owned.is_none() {
                    transaction.rollback().await?;
                    return Ok(OAuthClientDeleteOutcome::NotFound);
                }
                sqlx::query(sqlx::AssertSqlSafe(access_token_sql))
                    .bind(client_id)
                    .execute(&mut *transaction)
                    .await?;
                sqlx::query(sqlx::AssertSqlSafe(refresh_token_sql))
                    .bind(client_id)
                    .execute(&mut *transaction)
                    .await?;
                sqlx::query(sqlx::AssertSqlSafe(auth_code_sql))
                    .bind(client_id)
                    .execute(&mut *transaction)
                    .await?;
                sqlx::query(sqlx::AssertSqlSafe(revoke_client_sql))
                    .bind(client_id)
                    .bind(user_id)
                    .execute(&mut *transaction)
                    .await?;
                transaction.commit().await?;
            }
            Self::MySql(pool) => {
                let mut transaction = pool.begin().await?;
                let owned = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(client_sql))
                    .bind(client_id)
                    .bind(user_id)
                    .fetch_optional(&mut *transaction)
                    .await?;
                if owned.is_none() {
                    transaction.rollback().await?;
                    return Ok(OAuthClientDeleteOutcome::NotFound);
                }
                sqlx::query(sqlx::AssertSqlSafe(access_token_sql))
                    .bind(client_id)
                    .execute(&mut *transaction)
                    .await?;
                sqlx::query(sqlx::AssertSqlSafe(refresh_token_sql))
                    .bind(client_id)
                    .execute(&mut *transaction)
                    .await?;
                sqlx::query(sqlx::AssertSqlSafe(auth_code_sql))
                    .bind(client_id)
                    .execute(&mut *transaction)
                    .await?;
                sqlx::query(sqlx::AssertSqlSafe(revoke_client_sql))
                    .bind(client_id)
                    .bind(user_id)
                    .execute(&mut *transaction)
                    .await?;
                transaction.commit().await?;
            }
            Self::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                let owned = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(client_sql))
                    .bind(client_id)
                    .bind(user_id)
                    .fetch_optional(&mut *transaction)
                    .await?;
                if owned.is_none() {
                    transaction.rollback().await?;
                    return Ok(OAuthClientDeleteOutcome::NotFound);
                }
                sqlx::query(sqlx::AssertSqlSafe(access_token_sql))
                    .bind(client_id)
                    .execute(&mut *transaction)
                    .await?;
                sqlx::query(sqlx::AssertSqlSafe(refresh_token_sql))
                    .bind(client_id)
                    .execute(&mut *transaction)
                    .await?;
                sqlx::query(sqlx::AssertSqlSafe(auth_code_sql))
                    .bind(client_id)
                    .execute(&mut *transaction)
                    .await?;
                sqlx::query(sqlx::AssertSqlSafe(revoke_client_sql))
                    .bind(client_id)
                    .bind(user_id)
                    .execute(&mut *transaction)
                    .await?;
                transaction.commit().await?;
            }
        }
        Ok(OAuthClientDeleteOutcome::Revoked)
    }

    pub async fn access_token(
        &self,
        prefix: &str,
        token_id: &str,
    ) -> Result<Option<AccessTokenRecord>, sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => format!(
                "SELECT user_id, client_id, revoked FROM {prefix}oauth_access_tokens WHERE id = $1 LIMIT 1"
            ),
            _ => format!(
                "SELECT user_id, client_id, revoked FROM {prefix}oauth_access_tokens WHERE id = ? LIMIT 1"
            ),
        };
        match self {
            Self::Sqlite(pool) => Ok(sqlx::query_as::<_, AccessTokenRecord>(sqlx::AssertSqlSafe(
                sql,
            ))
            .bind(token_id)
            .fetch_optional(pool)
            .await?),
            Self::MySql(pool) => Ok(sqlx::query_as::<_, AccessTokenRecord>(sqlx::AssertSqlSafe(
                sql,
            ))
            .bind(token_id)
            .fetch_optional(pool)
            .await?),
            Self::Postgres(pool) => Ok(sqlx::query_as::<_, AccessTokenRecord>(
                sqlx::AssertSqlSafe(sql),
            )
            .bind(token_id)
            .fetch_optional(pool)
            .await?),
        }
    }

    pub async fn oauth_personal_access_client_id(
        &self,
        prefix: &str,
    ) -> Result<Option<i64>, sqlx::Error> {
        let sql = format!(
            "SELECT CAST(id AS BIGINT) FROM {prefix}oauth_clients \
             WHERE personal_access_client = TRUE AND revoked = FALSE ORDER BY id LIMIT 1"
        );
        match self {
            Self::Sqlite(pool) => Ok(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                .fetch_optional(pool)
                .await?),
            Self::MySql(pool) => Ok(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                .fetch_optional(pool)
                .await?),
            Self::Postgres(pool) => Ok(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                .fetch_optional(pool)
                .await?),
        }
    }

    pub async fn issue_oauth_personal_access_token(
        &self,
        prefix: &str,
        access_token_id: &str,
        user_id: i64,
        client_id: i64,
        name: &str,
        scopes: &str,
        created_at: &str,
        expires_at: &str,
    ) -> Result<(), sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => format!(
                "INSERT INTO {prefix}oauth_access_tokens \
                 (id,user_id,client_id,name,scopes,revoked,created_at,updated_at,expires_at) \
                 VALUES ($1,$2,$3,$4,$5,FALSE,$6::TIMESTAMP,$6::TIMESTAMP,$7::TIMESTAMP)"
            ),
            _ => format!(
                "INSERT INTO {prefix}oauth_access_tokens \
                 (id,user_id,client_id,name,scopes,revoked,created_at,updated_at,expires_at) \
                 VALUES (?,?,?,?,?,FALSE,?,?,?)"
            ),
        };
        match self {
            Self::Sqlite(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(access_token_id)
                    .bind(user_id)
                    .bind(client_id)
                    .bind(name)
                    .bind(scopes)
                    .bind(created_at)
                    .bind(created_at)
                    .bind(expires_at)
                    .execute(pool)
                    .await?;
            }
            Self::MySql(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(access_token_id)
                    .bind(user_id)
                    .bind(client_id)
                    .bind(name)
                    .bind(scopes)
                    .bind(created_at)
                    .bind(created_at)
                    .bind(expires_at)
                    .execute(pool)
                    .await?;
            }
            Self::Postgres(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(access_token_id)
                    .bind(user_id)
                    .bind(client_id)
                    .bind(name)
                    .bind(scopes)
                    .bind(created_at)
                    .bind(expires_at)
                    .execute(pool)
                    .await?;
            }
        }
        Ok(())
    }

    pub async fn oauth_scope_descriptions(
        &self,
        prefix: &str,
    ) -> Result<Vec<OAuthScopeRecord>, sqlx::Error> {
        let sql = format!("SELECT name, description FROM {prefix}scopes ORDER BY name");
        match self {
            Self::Sqlite(pool) => Ok(sqlx::query_as::<_, OAuthScopeRecord>(sqlx::AssertSqlSafe(
                sql,
            ))
            .fetch_all(pool)
            .await?),
            Self::MySql(pool) => Ok(sqlx::query_as::<_, OAuthScopeRecord>(sqlx::AssertSqlSafe(
                sql,
            ))
            .fetch_all(pool)
            .await?),
            Self::Postgres(pool) => Ok(sqlx::query_as::<_, OAuthScopeRecord>(sqlx::AssertSqlSafe(
                sql,
            ))
            .fetch_all(pool)
            .await?),
        }
    }

    pub async fn oauth_scopes(&self, prefix: &str) -> Result<Vec<String>, sqlx::Error> {
        let sql = format!("SELECT name FROM {prefix}scopes ORDER BY name");
        match self {
            Self::Sqlite(pool) => Ok(sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(sql))
                .fetch_all(pool)
                .await?),
            Self::MySql(pool) => Ok(sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(sql))
                .fetch_all(pool)
                .await?),
            Self::Postgres(pool) => Ok(sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(sql))
                .fetch_all(pool)
                .await?),
        }
    }

    pub async fn oauth_grant_client(
        &self,
        prefix: &str,
        client_id: i64,
    ) -> Result<Option<OAuthGrantClientRecord>, sqlx::Error> {
        let sql = match self {
            Self::Sqlite(_) => format!(
                "SELECT CAST(id AS BIGINT) AS id, secret, password_client, revoked \
                 FROM {prefix}oauth_clients WHERE id = ? LIMIT 1"
            ),
            Self::MySql(_) => format!(
                "SELECT CAST(id AS SIGNED) AS id, secret, password_client, revoked \
                 FROM {prefix}oauth_clients WHERE id = ? LIMIT 1"
            ),
            Self::Postgres(_) => format!(
                "SELECT CAST(id AS BIGINT) AS id, secret, password_client, revoked \
                 FROM {prefix}oauth_clients WHERE id = $1 LIMIT 1"
            ),
        };
        match self {
            Self::Sqlite(pool) => Ok(sqlx::query_as::<_, OAuthGrantClientRecord>(
                sqlx::AssertSqlSafe(sql),
            )
            .bind(client_id)
            .fetch_optional(pool)
            .await?),
            Self::MySql(pool) => Ok(sqlx::query_as::<_, OAuthGrantClientRecord>(
                sqlx::AssertSqlSafe(sql),
            )
            .bind(client_id)
            .fetch_optional(pool)
            .await?),
            Self::Postgres(pool) => Ok(sqlx::query_as::<_, OAuthGrantClientRecord>(
                sqlx::AssertSqlSafe(sql),
            )
            .bind(client_id)
            .fetch_optional(pool)
            .await?),
        }
    }

    pub async fn oauth_authorization_client(
        &self,
        prefix: &str,
        client_id: i64,
    ) -> Result<Option<OAuthAuthorizationClientRecord>, sqlx::Error> {
        let sql = match self {
            Self::Sqlite(_) => format!(
                "SELECT CAST(id AS BIGINT) AS id, name, redirect, secret, personal_access_client, password_client, revoked FROM {prefix}oauth_clients WHERE id = ? LIMIT 1"
            ),
            Self::MySql(_) => format!(
                "SELECT CAST(id AS SIGNED) AS id, name, redirect, secret, personal_access_client, password_client, revoked FROM {prefix}oauth_clients WHERE id = ? LIMIT 1"
            ),
            Self::Postgres(_) => format!(
                "SELECT CAST(id AS BIGINT) AS id, name, redirect, secret, personal_access_client, password_client, revoked FROM {prefix}oauth_clients WHERE id = $1 LIMIT 1"
            ),
        };
        match self {
            Self::Sqlite(pool) => Ok(sqlx::query_as::<_, OAuthAuthorizationClientRecord>(
                sqlx::AssertSqlSafe(sql),
            )
            .bind(client_id)
            .fetch_optional(pool)
            .await?),
            Self::MySql(pool) => Ok(sqlx::query_as::<_, OAuthAuthorizationClientRecord>(
                sqlx::AssertSqlSafe(sql),
            )
            .bind(client_id)
            .fetch_optional(pool)
            .await?),
            Self::Postgres(pool) => Ok(sqlx::query_as::<_, OAuthAuthorizationClientRecord>(
                sqlx::AssertSqlSafe(sql),
            )
            .bind(client_id)
            .fetch_optional(pool)
            .await?),
        }
    }

    pub async fn create_oauth_auth_code(
        &self,
        prefix: &str,
        auth_code_id: &str,
        user_id: i64,
        client_id: i64,
        scopes: &str,
    ) -> Result<(), sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => format!(
                "INSERT INTO {prefix}oauth_auth_codes (id,user_id,client_id,scopes,revoked) VALUES ($1,$2,$3,$4,FALSE)"
            ),
            _ => format!(
                "INSERT INTO {prefix}oauth_auth_codes (id,user_id,client_id,scopes,revoked) VALUES (?,?,?,?,FALSE)"
            ),
        };
        match self {
            Self::Sqlite(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(auth_code_id)
                    .bind(user_id)
                    .bind(client_id)
                    .bind(scopes)
                    .execute(pool)
                    .await?;
            }
            Self::MySql(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(auth_code_id)
                    .bind(user_id)
                    .bind(client_id)
                    .bind(scopes)
                    .execute(pool)
                    .await?;
            }
            Self::Postgres(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(auth_code_id)
                    .bind(user_id)
                    .bind(client_id)
                    .bind(scopes)
                    .execute(pool)
                    .await?;
            }
        }
        Ok(())
    }

    pub async fn oauth_auth_code(
        &self,
        prefix: &str,
        auth_code_id: &str,
    ) -> Result<Option<OAuthAuthCodeRecord>, sqlx::Error> {
        let sql = match self {
            Self::Sqlite(_) => format!(
                "SELECT user_id, CAST(client_id AS BIGINT) AS client_id, scopes, revoked FROM {prefix}oauth_auth_codes WHERE id = ? LIMIT 1"
            ),
            Self::MySql(_) => format!(
                "SELECT user_id, CAST(client_id AS SIGNED) AS client_id, scopes, revoked FROM {prefix}oauth_auth_codes WHERE id = ? LIMIT 1"
            ),
            Self::Postgres(_) => format!(
                "SELECT user_id, CAST(client_id AS BIGINT) AS client_id, scopes, revoked FROM {prefix}oauth_auth_codes WHERE id = $1 LIMIT 1"
            ),
        };
        match self {
            Self::Sqlite(pool) => Ok(sqlx::query_as::<_, OAuthAuthCodeRecord>(
                sqlx::AssertSqlSafe(sql),
            )
            .bind(auth_code_id)
            .fetch_optional(pool)
            .await?),
            Self::MySql(pool) => Ok(
                sqlx::query_as::<_, OAuthAuthCodeRecord>(sqlx::AssertSqlSafe(sql))
                    .bind(auth_code_id)
                    .fetch_optional(pool)
                    .await?,
            ),
            Self::Postgres(pool) => Ok(sqlx::query_as::<_, OAuthAuthCodeRecord>(
                sqlx::AssertSqlSafe(sql),
            )
            .bind(auth_code_id)
            .fetch_optional(pool)
            .await?),
        }
    }

    pub async fn oauth_refresh_token(
        &self,
        prefix: &str,
        refresh_token_id: &str,
    ) -> Result<Option<OAuthRefreshRecord>, sqlx::Error> {
        let sql = match self {
            Self::Sqlite(_) => format!(
                "SELECT a.user_id, CAST(a.client_id AS BIGINT) AS client_id, a.scopes \
                 FROM {prefix}oauth_refresh_tokens r \
                 INNER JOIN {prefix}oauth_access_tokens a ON a.id = r.access_token_id \
                 WHERE r.id = ? AND r.revoked = FALSE AND r.expires_at > CURRENT_TIMESTAMP LIMIT 1"
            ),
            Self::MySql(_) => format!(
                "SELECT a.user_id, CAST(a.client_id AS SIGNED) AS client_id, a.scopes \
                 FROM {prefix}oauth_refresh_tokens r \
                 INNER JOIN {prefix}oauth_access_tokens a ON a.id = r.access_token_id \
                 WHERE r.id = ? AND r.revoked = FALSE AND r.expires_at > CURRENT_TIMESTAMP LIMIT 1"
            ),
            Self::Postgres(_) => format!(
                "SELECT a.user_id, CAST(a.client_id AS BIGINT) AS client_id, a.scopes \
                 FROM {prefix}oauth_refresh_tokens r \
                 INNER JOIN {prefix}oauth_access_tokens a ON a.id = r.access_token_id \
                 WHERE r.id = $1 AND r.revoked = FALSE AND r.expires_at > CURRENT_TIMESTAMP LIMIT 1"
            ),
        };
        match self {
            Self::Sqlite(pool) => Ok(sqlx::query_as::<_, OAuthRefreshRecord>(sqlx::AssertSqlSafe(
                sql,
            ))
            .bind(refresh_token_id)
            .fetch_optional(pool)
            .await?),
            Self::MySql(pool) => Ok(sqlx::query_as::<_, OAuthRefreshRecord>(sqlx::AssertSqlSafe(
                sql,
            ))
            .bind(refresh_token_id)
            .fetch_optional(pool)
            .await?),
            Self::Postgres(pool) => Ok(sqlx::query_as::<_, OAuthRefreshRecord>(
                sqlx::AssertSqlSafe(sql),
            )
            .bind(refresh_token_id)
            .fetch_optional(pool)
            .await?),
        }
    }

    pub async fn oauth_tokens_for_user(
        &self,
        prefix: &str,
        user_id: i64,
        personal_access: bool,
    ) -> Result<Vec<OAuthAuthorizedTokenRecord>, sqlx::Error> {
        let client_filter = if personal_access {
            "c.personal_access_client = TRUE AND t.revoked = FALSE"
        } else {
            "c.personal_access_client = FALSE AND c.password_client = FALSE"
        };
        let sql = match self {
            Self::Sqlite(_) => format!(
                "SELECT t.id, CAST(t.user_id AS BIGINT) AS user_id, \
                 CAST(t.client_id AS BIGINT) AS client_id, t.name, CAST(t.scopes AS TEXT) AS scopes, \
                 t.revoked, CAST(t.created_at AS TEXT) AS created_at, CAST(t.updated_at AS TEXT) AS updated_at, \
                 CAST(t.expires_at AS TEXT) AS expires_at, CAST(c.user_id AS BIGINT) AS client_user_id, \
                 c.name AS client_name, c.provider AS client_provider, c.redirect AS client_redirect, \
                 c.personal_access_client AS client_personal_access_client, \
                 c.password_client AS client_password_client, c.revoked AS client_revoked, \
                 CAST(c.created_at AS TEXT) AS client_created_at, CAST(c.updated_at AS TEXT) AS client_updated_at \
                 FROM {prefix}oauth_access_tokens t JOIN {prefix}oauth_clients c ON c.id = t.client_id \
                 WHERE t.user_id = ? AND {client_filter} \
                 ORDER BY t.created_at DESC"
            ),
            Self::MySql(_) => format!(
                "SELECT t.id, CAST(t.user_id AS SIGNED) AS user_id, \
                 CAST(t.client_id AS SIGNED) AS client_id, t.name, CAST(t.scopes AS CHAR) AS scopes, \
                 t.revoked, DATE_FORMAT(t.created_at, '%Y-%m-%d %H:%i:%s') AS created_at, \
                 DATE_FORMAT(t.updated_at, '%Y-%m-%d %H:%i:%s') AS updated_at, \
                 DATE_FORMAT(t.expires_at, '%Y-%m-%d %H:%i:%s') AS expires_at, \
                 CAST(c.user_id AS SIGNED) AS client_user_id, c.name AS client_name, c.provider AS client_provider, \
                 c.redirect AS client_redirect, c.personal_access_client AS client_personal_access_client, \
                 c.password_client AS client_password_client, c.revoked AS client_revoked, \
                 DATE_FORMAT(c.created_at, '%Y-%m-%d %H:%i:%s') AS client_created_at, \
                 DATE_FORMAT(c.updated_at, '%Y-%m-%d %H:%i:%s') AS client_updated_at \
                 FROM {prefix}oauth_access_tokens t JOIN {prefix}oauth_clients c ON c.id = t.client_id \
                 WHERE t.user_id = ? AND {client_filter} \
                 ORDER BY t.created_at DESC"
            ),
            Self::Postgres(_) => format!(
                "SELECT t.id, CAST(t.user_id AS BIGINT) AS user_id, \
                 CAST(t.client_id AS BIGINT) AS client_id, t.name, CAST(t.scopes AS TEXT) AS scopes, \
                 t.revoked, to_char(t.created_at, 'YYYY-MM-DD HH24:MI:SS') AS created_at, \
                 to_char(t.updated_at, 'YYYY-MM-DD HH24:MI:SS') AS updated_at, \
                 to_char(t.expires_at, 'YYYY-MM-DD HH24:MI:SS') AS expires_at, \
                 CAST(c.user_id AS BIGINT) AS client_user_id, c.name AS client_name, c.provider AS client_provider, \
                 c.redirect AS client_redirect, c.personal_access_client AS client_personal_access_client, \
                 c.password_client AS client_password_client, c.revoked AS client_revoked, \
                 to_char(c.created_at, 'YYYY-MM-DD HH24:MI:SS') AS client_created_at, \
                 to_char(c.updated_at, 'YYYY-MM-DD HH24:MI:SS') AS client_updated_at \
                 FROM {prefix}oauth_access_tokens t JOIN {prefix}oauth_clients c ON c.id = t.client_id \
                 WHERE t.user_id = $1 AND {client_filter} \
                 ORDER BY t.created_at DESC"
            ),
        };
        match self {
            Self::Sqlite(pool) => Ok(sqlx::query_as::<_, OAuthAuthorizedTokenRecord>(
                sqlx::AssertSqlSafe(sql),
            )
            .bind(user_id)
            .fetch_all(pool)
            .await?),
            Self::MySql(pool) => Ok(sqlx::query_as::<_, OAuthAuthorizedTokenRecord>(
                sqlx::AssertSqlSafe(sql),
            )
            .bind(user_id)
            .fetch_all(pool)
            .await?),
            Self::Postgres(pool) => Ok(sqlx::query_as::<_, OAuthAuthorizedTokenRecord>(
                sqlx::AssertSqlSafe(sql),
            )
            .bind(user_id)
            .fetch_all(pool)
            .await?),
        }
    }

    pub async fn revoke_oauth_access_token(
        &self,
        prefix: &str,
        user_id: i64,
        token_id: &str,
    ) -> Result<bool, sqlx::Error> {
        let postgres = matches!(self, Self::Postgres(_));
        let access_sql = if postgres {
            format!(
                "UPDATE {prefix}oauth_access_tokens SET revoked = TRUE \
                 WHERE id = $1 AND user_id = $2 AND revoked = FALSE"
            )
        } else {
            format!(
                "UPDATE {prefix}oauth_access_tokens SET revoked = TRUE \
                 WHERE id = ? AND user_id = ? AND revoked = FALSE"
            )
        };
        let refresh_sql = if postgres {
            format!(
                "UPDATE {prefix}oauth_refresh_tokens SET revoked = TRUE \
                 WHERE access_token_id = $1 AND revoked = FALSE"
            )
        } else {
            format!(
                "UPDATE {prefix}oauth_refresh_tokens SET revoked = TRUE \
                 WHERE access_token_id = ? AND revoked = FALSE"
            )
        };
        macro_rules! revoke_in_transaction {
            ($pool:expr) => {{
                let mut transaction = $pool.begin().await?;
                let result = sqlx::query(sqlx::AssertSqlSafe(access_sql))
                    .bind(token_id)
                    .bind(user_id)
                    .execute(&mut *transaction)
                    .await?;
                if result.rows_affected() == 0 {
                    transaction.rollback().await?;
                    return Ok(false);
                }
                sqlx::query(sqlx::AssertSqlSafe(refresh_sql))
                    .bind(token_id)
                    .execute(&mut *transaction)
                    .await?;
                transaction.commit().await?;
            }};
        }
        match self {
            Self::Sqlite(pool) => revoke_in_transaction!(pool),
            Self::MySql(pool) => revoke_in_transaction!(pool),
            Self::Postgres(pool) => revoke_in_transaction!(pool),
        }
        Ok(true)
    }

    pub async fn issue_oauth_token_pair(
        &self,
        prefix: &str,
        access_token_id: &str,
        user_id: i64,
        client_id: i64,
        scopes: &str,
        access_expires_at: &str,
        refresh_token_id: &str,
        refresh_expires_at: &str,
        rotate_refresh_token_id: Option<&str>,
        consume_auth_code: Option<(&str, i64, i64)>,
    ) -> Result<bool, sqlx::Error> {
        let postgres = matches!(self, Self::Postgres(_));
        let access_sql = if postgres {
            format!(
                "INSERT INTO {prefix}oauth_access_tokens \
                 (id,user_id,client_id,scopes,revoked,created_at,updated_at,expires_at) \
                 VALUES ($1,$2,$3,$4,FALSE,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,$5::TIMESTAMP)"
            )
        } else {
            format!(
                "INSERT INTO {prefix}oauth_access_tokens \
                 (id,user_id,client_id,scopes,revoked,created_at,updated_at,expires_at) \
                 VALUES (?,?,?,?,FALSE,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,?)"
            )
        };
        let refresh_sql = if postgres {
            format!(
                "INSERT INTO {prefix}oauth_refresh_tokens (id,access_token_id,revoked,expires_at) \
                 VALUES ($1,$2,FALSE,$3::TIMESTAMP)"
            )
        } else {
            format!(
                "INSERT INTO {prefix}oauth_refresh_tokens (id,access_token_id,revoked,expires_at) \
                 VALUES (?,?,FALSE,?)"
            )
        };
        let revoke_sql = if postgres {
            format!(
                "UPDATE {prefix}oauth_refresh_tokens SET revoked = TRUE \
                 WHERE id = $1 AND revoked = FALSE AND expires_at > CURRENT_TIMESTAMP"
            )
        } else {
            format!(
                "UPDATE {prefix}oauth_refresh_tokens SET revoked = TRUE \
                 WHERE id = ? AND revoked = FALSE AND expires_at > CURRENT_TIMESTAMP"
            )
        };
        let consume_auth_code_sql = if postgres {
            format!(
                "UPDATE {prefix}oauth_auth_codes SET revoked = TRUE WHERE id = $1 AND user_id = $2 AND client_id = $3 AND revoked = FALSE"
            )
        } else {
            format!(
                "UPDATE {prefix}oauth_auth_codes SET revoked = TRUE WHERE id = ? AND user_id = ? AND client_id = ? AND revoked = FALSE"
            )
        };
        macro_rules! issue_in_transaction {
            ($pool:expr) => {{
                let mut transaction = $pool.begin().await?;
                if let Some((code_id, code_user_id, code_client_id)) = consume_auth_code {
                    let result = sqlx::query(sqlx::AssertSqlSafe(consume_auth_code_sql))
                        .bind(code_id)
                        .bind(code_user_id)
                        .bind(code_client_id)
                        .execute(&mut *transaction)
                        .await?;
                    if result.rows_affected() == 0 {
                        transaction.rollback().await?;
                        return Ok(false);
                    }
                }
                if let Some(old_id) = rotate_refresh_token_id {
                    let result = sqlx::query(sqlx::AssertSqlSafe(revoke_sql))
                        .bind(old_id)
                        .execute(&mut *transaction)
                        .await?;
                    if result.rows_affected() == 0 {
                        transaction.rollback().await?;
                        return Ok(false);
                    }
                }
                sqlx::query(sqlx::AssertSqlSafe(access_sql))
                    .bind(access_token_id)
                    .bind(user_id)
                    .bind(client_id)
                    .bind(scopes)
                    .bind(access_expires_at)
                    .execute(&mut *transaction)
                    .await?;
                sqlx::query(sqlx::AssertSqlSafe(refresh_sql))
                    .bind(refresh_token_id)
                    .bind(access_token_id)
                    .bind(refresh_expires_at)
                    .execute(&mut *transaction)
                    .await?;
                transaction.commit().await?;
            }};
        }
        match self {
            Self::Sqlite(pool) => issue_in_transaction!(pool),
            Self::MySql(pool) => issue_in_transaction!(pool),
            Self::Postgres(pool) => issue_in_transaction!(pool),
        }
        Ok(true)
    }

    pub async fn registered_user_count_by_ip(
        &self,
        prefix: &str,
        ip: &str,
    ) -> Result<i64, sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => format!("SELECT COUNT(*) FROM {prefix}users WHERE ip = $1"),
            _ => format!("SELECT COUNT(*) FROM {prefix}users WHERE ip = ?"),
        };
        match self {
            Self::Sqlite(pool) => Ok(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                .bind(ip)
                .fetch_one(pool)
                .await?),
            Self::MySql(pool) => Ok(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                .bind(ip)
                .fetch_one(pool)
                .await?),
            Self::Postgres(pool) => Ok(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                .bind(ip)
                .fetch_one(pool)
                .await?),
        }
    }

    pub async fn register_user(
        &self,
        prefix: &str,
        email: &str,
        nickname: &str,
        score: i64,
        password_hash: &str,
        ip: &str,
        now: &str,
        last_sign_at: &str,
        max_registrations_per_ip: i64,
        player_name: Option<&str>,
    ) -> Result<UserRegistrationOutcome, sqlx::Error> {
        if self.user_email_exists(prefix, email, 0).await? {
            return Ok(UserRegistrationOutcome::EmailExists);
        }
        if let Some(player_name) = player_name
            && self.admin_player_name_exists(prefix, player_name).await?
        {
            return Ok(UserRegistrationOutcome::PlayerNameExists);
        }
        if self.registered_user_count_by_ip(prefix, ip).await? >= max_registrations_per_ip {
            return Ok(UserRegistrationOutcome::IpLimit);
        }
        let uid = self
            .insert_registered_user(
                prefix,
                email,
                nickname,
                score,
                password_hash,
                ip,
                now,
                last_sign_at,
            )
            .await?;
        if let Some(player_name) = player_name {
            self.insert_registered_player(prefix, uid, player_name, now)
                .await?;
        }
        Ok(UserRegistrationOutcome::Registered(uid))
    }

    async fn insert_registered_user(
        &self,
        prefix: &str,
        email: &str,
        nickname: &str,
        score: i64,
        password_hash: &str,
        ip: &str,
        now: &str,
        last_sign_at: &str,
    ) -> Result<i64, sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => format!(
                "INSERT INTO {prefix}users (email,nickname,score,avatar,password,ip,permission,last_sign_at,register_at,verified,is_dark_mode) \
                 VALUES ($1,$2,$3,0,$4,$5,0,CAST($6 AS TIMESTAMP),CAST($7 AS TIMESTAMP),FALSE,FALSE) RETURNING CAST(uid AS BIGINT)"
            ),
            _ => format!(
                "INSERT INTO {prefix}users (email,nickname,score,avatar,password,ip,permission,last_sign_at,register_at,verified,is_dark_mode) \
                 VALUES (?,?,?,0,?,?,0,?,?,0,0)"
            ),
        };
        match self {
            Self::Sqlite(pool) => {
                let result = sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(email)
                    .bind(nickname)
                    .bind(score)
                    .bind(password_hash)
                    .bind(ip)
                    .bind(last_sign_at)
                    .bind(now)
                    .execute(pool)
                    .await?;
                Ok(result.last_insert_rowid())
            }
            Self::MySql(pool) => {
                let result = sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(email)
                    .bind(nickname)
                    .bind(score)
                    .bind(password_hash)
                    .bind(ip)
                    .bind(last_sign_at)
                    .bind(now)
                    .execute(pool)
                    .await?;
                Ok(result.last_insert_id() as i64)
            }
            Self::Postgres(pool) => Ok(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                .bind(email)
                .bind(nickname)
                .bind(score)
                .bind(password_hash)
                .bind(ip)
                .bind(last_sign_at)
                .bind(now)
                .fetch_one(pool)
                .await?),
        }
    }

    async fn insert_registered_player(
        &self,
        prefix: &str,
        uid: i64,
        player_name: &str,
        now: &str,
    ) -> Result<(), sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => format!(
                "INSERT INTO {prefix}players (uid,name,tid_skin,tid_cape,last_modified) VALUES ($1,$2,0,0,CAST($3 AS TIMESTAMP))"
            ),
            _ => format!(
                "INSERT INTO {prefix}players (uid,name,tid_skin,tid_cape,last_modified) VALUES (?,?,0,0,?)"
            ),
        };
        match self {
            Self::Sqlite(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(uid)
                    .bind(player_name)
                    .bind(now)
                    .execute(pool)
                    .await?;
            }
            Self::MySql(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(uid)
                    .bind(player_name)
                    .bind(now)
                    .execute(pool)
                    .await?;
            }
            Self::Postgres(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(uid)
                    .bind(player_name)
                    .bind(now)
                    .execute(pool)
                    .await?;
            }
        }
        Ok(())
    }

    pub async fn user_email_exists(
        &self,
        prefix: &str,
        email: &str,
        except_uid: i64,
    ) -> Result<bool, sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => {
                format!("SELECT COUNT(*) FROM {prefix}users WHERE email = $1 AND uid <> $2")
            }
            _ => format!("SELECT COUNT(*) FROM {prefix}users WHERE email = ? AND uid <> ?"),
        };
        let count = match self {
            Self::Sqlite(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                    .bind(email)
                    .bind(except_uid)
                    .fetch_one(pool)
                    .await?
            }
            Self::MySql(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                    .bind(email)
                    .bind(except_uid)
                    .fetch_one(pool)
                    .await?
            }
            Self::Postgres(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                    .bind(email)
                    .bind(except_uid)
                    .fetch_one(pool)
                    .await?
            }
        };
        Ok(count > 0)
    }

    pub async fn update_user_text(
        &self,
        prefix: &str,
        uid: i64,
        column: &'static str,
        value: &str,
    ) -> Result<(), sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => format!("UPDATE {prefix}users SET {column} = $1 WHERE uid = $2"),
            _ => format!("UPDATE {prefix}users SET {column} = ? WHERE uid = ?"),
        };
        match self {
            Self::Sqlite(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(value)
                    .bind(uid)
                    .execute(pool)
                    .await?;
            }
            Self::MySql(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(value)
                    .bind(uid)
                    .execute(pool)
                    .await?;
            }
            Self::Postgres(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(value)
                    .bind(uid)
                    .execute(pool)
                    .await?;
            }
        }
        Ok(())
    }

    pub async fn credentials_by_user_id(
        &self,
        prefix: &str,
        uid: i64,
    ) -> Result<Option<PasswordCredential>, sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => format!(
                "SELECT CAST(uid AS BIGINT) AS uid, password, permission FROM {prefix}users WHERE uid = $1 LIMIT 1"
            ),
            Self::MySql(_) => format!(
                "SELECT CAST(uid AS SIGNED) AS uid, password, permission FROM {prefix}users WHERE uid = ? LIMIT 1"
            ),
            Self::Sqlite(_) => format!(
                "SELECT CAST(uid AS BIGINT) AS uid, password, permission FROM {prefix}users WHERE uid = ? LIMIT 1"
            ),
        };
        match self {
            Self::Sqlite(pool) => Ok(sqlx::query_as::<_, PasswordCredential>(sqlx::AssertSqlSafe(
                sql,
            ))
            .bind(uid)
            .fetch_optional(pool)
            .await?),
            Self::MySql(pool) => Ok(sqlx::query_as::<_, PasswordCredential>(sqlx::AssertSqlSafe(
                sql,
            ))
            .bind(uid)
            .fetch_optional(pool)
            .await?),
            Self::Postgres(pool) => Ok(sqlx::query_as::<_, PasswordCredential>(
                sqlx::AssertSqlSafe(sql),
            )
            .bind(uid)
            .fetch_optional(pool)
            .await?),
        }
    }

    pub async fn update_user_email_and_reset_verification(
        &self,
        prefix: &str,
        uid: i64,
        email: &str,
    ) -> Result<(), sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => {
                format!("UPDATE {prefix}users SET email = $1, verified = FALSE WHERE uid = $2")
            }
            _ => format!("UPDATE {prefix}users SET email = ?, verified = FALSE WHERE uid = ?"),
        };
        match self {
            Self::Sqlite(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(email)
                    .bind(uid)
                    .execute(pool)
                    .await?;
            }
            Self::MySql(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(email)
                    .bind(uid)
                    .execute(pool)
                    .await?;
            }
            Self::Postgres(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(email)
                    .bind(uid)
                    .execute(pool)
                    .await?;
            }
        }
        Ok(())
    }

    pub async fn set_user_verified(
        &self,
        prefix: &str,
        uid: i64,
        verified: bool,
    ) -> Result<(), sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => format!("UPDATE {prefix}users SET verified = $1 WHERE uid = $2"),
            _ => format!("UPDATE {prefix}users SET verified = ? WHERE uid = ?"),
        };
        match self {
            Self::Sqlite(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(verified)
                    .bind(uid)
                    .execute(pool)
                    .await?;
            }
            Self::MySql(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(verified)
                    .bind(uid)
                    .execute(pool)
                    .await?;
            }
            Self::Postgres(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(verified)
                    .bind(uid)
                    .execute(pool)
                    .await?;
            }
        }
        Ok(())
    }

    pub async fn toggle_user_dark_mode(&self, prefix: &str, uid: i64) -> Result<(), sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => {
                format!("UPDATE {prefix}users SET is_dark_mode = NOT is_dark_mode WHERE uid = $1")
            }
            _ => format!("UPDATE {prefix}users SET is_dark_mode = NOT is_dark_mode WHERE uid = ?"),
        };
        match self {
            Self::Sqlite(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(uid)
                    .execute(pool)
                    .await?;
            }
            Self::MySql(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(uid)
                    .execute(pool)
                    .await?;
            }
            Self::Postgres(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(uid)
                    .execute(pool)
                    .await?;
            }
        }
        Ok(())
    }

    pub async fn update_user_integer(
        &self,
        prefix: &str,
        uid: i64,
        column: &'static str,
        value: i64,
    ) -> Result<(), sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => format!("UPDATE {prefix}users SET {column} = $1 WHERE uid = $2"),
            _ => format!("UPDATE {prefix}users SET {column} = ? WHERE uid = ?"),
        };
        match self {
            Self::Sqlite(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(value)
                    .bind(uid)
                    .execute(pool)
                    .await?;
            }
            Self::MySql(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(value)
                    .bind(uid)
                    .execute(pool)
                    .await?;
            }
            Self::Postgres(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(value)
                    .bind(uid)
                    .execute(pool)
                    .await?;
            }
        }
        Ok(())
    }

    pub async fn toggle_user_verification(
        &self,
        prefix: &str,
        uid: i64,
    ) -> Result<(), sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => {
                format!("UPDATE {prefix}users SET verified = NOT verified WHERE uid = $1")
            }
            _ => format!("UPDATE {prefix}users SET verified = NOT verified WHERE uid = ?"),
        };
        match self {
            Self::Sqlite(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(uid)
                    .execute(pool)
                    .await?;
            }
            Self::MySql(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(uid)
                    .execute(pool)
                    .await?;
            }
            Self::Postgres(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(uid)
                    .execute(pool)
                    .await?;
            }
        }
        Ok(())
    }

    pub async fn delete_user(&self, prefix: &str, uid: i64) -> Result<bool, sqlx::Error> {
        let postgres = matches!(self, Self::Postgres(_));
        let marker = if postgres { "$1" } else { "?" };
        let lock_clause = if matches!(self, Self::Sqlite(_)) {
            ""
        } else {
            " FOR UPDATE"
        };
        let uid_cast = if matches!(self, Self::MySql(_)) {
            "SIGNED"
        } else {
            "BIGINT"
        };
        let select_sql = format!(
            "SELECT CAST(uid AS {uid_cast}) FROM {prefix}users WHERE uid = {marker} LIMIT 1{lock_clause}"
        );
        let delete_players_sql = match self {
            Self::Postgres(_) => format!("DELETE FROM {prefix}players WHERE uid = $1"),
            _ => format!("DELETE FROM {prefix}players WHERE uid = ?"),
        };
        let delete_user_sql = match self {
            Self::Postgres(_) => format!("DELETE FROM {prefix}users WHERE uid = $1"),
            _ => format!("DELETE FROM {prefix}users WHERE uid = ?"),
        };
        match self {
            Self::Sqlite(pool) => {
                let mut transaction = pool.begin().await?;
                let exists = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(select_sql))
                    .bind(uid)
                    .fetch_optional(&mut *transaction)
                    .await?;
                if exists.is_none() {
                    transaction.rollback().await?;
                    return Ok(false);
                }
                sqlx::query(sqlx::AssertSqlSafe(delete_players_sql))
                    .bind(uid)
                    .execute(&mut *transaction)
                    .await?;
                sqlx::query(sqlx::AssertSqlSafe(delete_user_sql))
                    .bind(uid)
                    .execute(&mut *transaction)
                    .await?;
                transaction.commit().await?;
            }
            Self::MySql(pool) => {
                let mut transaction = pool.begin().await?;
                let exists = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(select_sql))
                    .bind(uid)
                    .fetch_optional(&mut *transaction)
                    .await?;
                if exists.is_none() {
                    transaction.rollback().await?;
                    return Ok(false);
                }
                sqlx::query(sqlx::AssertSqlSafe(delete_players_sql))
                    .bind(uid)
                    .execute(&mut *transaction)
                    .await?;
                sqlx::query(sqlx::AssertSqlSafe(delete_user_sql))
                    .bind(uid)
                    .execute(&mut *transaction)
                    .await?;
                transaction.commit().await?;
            }
            Self::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                let exists = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(select_sql))
                    .bind(uid)
                    .fetch_optional(&mut *transaction)
                    .await?;
                if exists.is_none() {
                    transaction.rollback().await?;
                    return Ok(false);
                }
                sqlx::query(sqlx::AssertSqlSafe(delete_players_sql))
                    .bind(uid)
                    .execute(&mut *transaction)
                    .await?;
                sqlx::query(sqlx::AssertSqlSafe(delete_user_sql))
                    .bind(uid)
                    .execute(&mut *transaction)
                    .await?;
                transaction.commit().await?;
            }
        }
        Ok(true)
    }

    pub async fn user_id_by_email(
        &self,
        prefix: &str,
        email: &str,
    ) -> Result<Option<i64>, sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => {
                format!("SELECT CAST(uid AS BIGINT) FROM {prefix}users WHERE email = $1 LIMIT 1")
            }
            Self::MySql(_) => {
                format!("SELECT CAST(uid AS SIGNED) FROM {prefix}users WHERE email = ? LIMIT 1")
            }
            Self::Sqlite(_) => {
                format!("SELECT CAST(uid AS BIGINT) FROM {prefix}users WHERE email = ? LIMIT 1")
            }
        };
        match self {
            Self::Sqlite(pool) => Ok(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                .bind(email)
                .fetch_optional(pool)
                .await?),
            Self::MySql(pool) => Ok(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                .bind(email)
                .fetch_optional(pool)
                .await?),
            Self::Postgres(pool) => Ok(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                .bind(email)
                .fetch_optional(pool)
                .await?),
        }
    }

    pub async fn user_profile(
        &self,
        prefix: &str,
        uid: i64,
    ) -> Result<Option<UserProfile>, sqlx::Error> {
        let sql = match self {
            Self::Sqlite(_) => format!(
                "SELECT CAST(uid AS BIGINT) AS uid, email, nickname, locale, CAST(score AS BIGINT) AS score, CAST(avatar AS BIGINT) AS avatar, permission, \
                 CAST(last_sign_at AS TEXT) AS last_sign_at, CAST(register_at AS TEXT) AS register_at, \
                 verified, is_dark_mode FROM {prefix}users WHERE uid = ? LIMIT 1"
            ),
            Self::MySql(_) => format!(
                "SELECT CAST(uid AS BIGINT) AS uid, email, nickname, locale, CAST(score AS BIGINT) AS score, CAST(avatar AS BIGINT) AS avatar, permission, \
                 DATE_FORMAT(last_sign_at, '%Y-%m-%d %H:%i:%s') AS last_sign_at, \
                 DATE_FORMAT(register_at, '%Y-%m-%d %H:%i:%s') AS register_at, \
                 verified, is_dark_mode FROM {prefix}users WHERE uid = ? LIMIT 1"
            ),
            Self::Postgres(_) => format!(
                "SELECT CAST(uid AS BIGINT) AS uid, email, nickname, locale, CAST(score AS BIGINT) AS score, CAST(avatar AS BIGINT) AS avatar, permission, \
                 to_char(last_sign_at, 'YYYY-MM-DD HH24:MI:SS') AS last_sign_at, \
                 to_char(register_at, 'YYYY-MM-DD HH24:MI:SS') AS register_at, \
                 verified, is_dark_mode FROM {prefix}users WHERE uid = $1 LIMIT 1"
            ),
        };
        match self {
            Self::Sqlite(pool) => Ok(sqlx::query_as::<_, UserProfile>(sqlx::AssertSqlSafe(sql))
                .bind(uid)
                .fetch_optional(pool)
                .await?),
            Self::MySql(pool) => Ok(sqlx::query_as::<_, UserProfile>(sqlx::AssertSqlSafe(sql))
                .bind(uid)
                .fetch_optional(pool)
                .await?),
            Self::Postgres(pool) => Ok(sqlx::query_as::<_, UserProfile>(sqlx::AssertSqlSafe(sql))
                .bind(uid)
                .fetch_optional(pool)
                .await?),
        }
    }
    pub async fn admin_closet_user(
        &self,
        prefix: &str,
        uid: i64,
    ) -> Result<Option<AdminClosetUserRecord>, sqlx::Error> {
        let sql = match self {
            Self::Sqlite(_) => format!(
                "SELECT CAST(uid AS BIGINT) AS uid, email, nickname, locale, CAST(score AS BIGINT) AS score, \
                 CAST(avatar AS BIGINT) AS avatar, ip, permission, CAST(last_sign_at AS TEXT) AS last_sign_at, \
                 CAST(register_at AS TEXT) AS register_at, verified, is_dark_mode FROM {prefix}users WHERE uid = ? LIMIT 1"
            ),
            Self::MySql(_) => format!(
                "SELECT CAST(uid AS SIGNED) AS uid, email, nickname, locale, CAST(score AS SIGNED) AS score, \
                 CAST(avatar AS SIGNED) AS avatar, ip, permission, DATE_FORMAT(last_sign_at, '%Y-%m-%d %H:%i:%s') AS last_sign_at, \
                 DATE_FORMAT(register_at, '%Y-%m-%d %H:%i:%s') AS register_at, verified, is_dark_mode FROM {prefix}users WHERE uid = ? LIMIT 1"
            ),
            Self::Postgres(_) => format!(
                "SELECT CAST(uid AS BIGINT) AS uid, email, nickname, locale, CAST(score AS BIGINT) AS score, \
                 CAST(avatar AS BIGINT) AS avatar, ip, permission, to_char(last_sign_at, 'YYYY-MM-DD HH24:MI:SS') AS last_sign_at, \
                 to_char(register_at, 'YYYY-MM-DD HH24:MI:SS') AS register_at, verified, is_dark_mode FROM {prefix}users WHERE uid = $1 LIMIT 1"
            ),
        };
        match self {
            Self::Sqlite(pool) => Ok(sqlx::query_as::<_, AdminClosetUserRecord>(
                sqlx::AssertSqlSafe(sql),
            )
            .bind(uid)
            .fetch_optional(pool)
            .await?),
            Self::MySql(pool) => Ok(sqlx::query_as::<_, AdminClosetUserRecord>(
                sqlx::AssertSqlSafe(sql),
            )
            .bind(uid)
            .fetch_optional(pool)
            .await?),
            Self::Postgres(pool) => Ok(sqlx::query_as::<_, AdminClosetUserRecord>(
                sqlx::AssertSqlSafe(sql),
            )
            .bind(uid)
            .fetch_optional(pool)
            .await?),
        }
    }
    pub async fn admin_dashboard_stats(
        &self,
        prefix: &str,
    ) -> Result<AdminDashboardStats, sqlx::Error> {
        let integer_cast = if matches!(self, Self::MySql(_)) {
            "SIGNED"
        } else {
            "BIGINT"
        };
        let sql = format!(
            "SELECT CAST((SELECT COUNT(*) FROM {prefix}users) AS {integer_cast}) AS users, CAST((SELECT COUNT(*) FROM {prefix}players) AS {integer_cast}) AS players, CAST((SELECT COUNT(*) FROM {prefix}textures) AS {integer_cast}) AS textures, CAST((SELECT COALESCE(SUM(size), 0) FROM {prefix}textures) AS {integer_cast}) AS storage"
        );
        match self {
            Self::Sqlite(pool) => Ok(sqlx::query_as::<_, AdminDashboardStats>(
                sqlx::AssertSqlSafe(sql),
            )
            .fetch_one(pool)
            .await?),
            Self::MySql(pool) => Ok(
                sqlx::query_as::<_, AdminDashboardStats>(sqlx::AssertSqlSafe(sql))
                    .fetch_one(pool)
                    .await?,
            ),
            Self::Postgres(pool) => Ok(sqlx::query_as::<_, AdminDashboardStats>(
                sqlx::AssertSqlSafe(sql),
            )
            .fetch_one(pool)
            .await?),
        }
    }

    pub async fn admin_activity_counts(
        &self,
        prefix: &str,
        since: &str,
    ) -> Result<(Vec<(String, i64)>, Vec<(String, i64)>), sqlx::Error> {
        let (date_sql, integer_cast, since_sql) = match self {
            Self::Sqlite(_) => ("SUBSTR(CAST(register_at AS TEXT), 1, 10)", "BIGINT", "?"),
            Self::MySql(_) => ("DATE_FORMAT(register_at, '%Y-%m-%d')", "SIGNED", "?"),
            Self::Postgres(_) => (
                "TO_CHAR(register_at, 'YYYY-MM-DD')",
                "BIGINT",
                "CAST($1 AS TIMESTAMP)",
            ),
        };
        let users_sql = format!(
            "SELECT {date_sql} AS activity_date, CAST(COUNT(*) AS {integer_cast}) AS amount FROM {prefix}users WHERE register_at >= {since_sql} GROUP BY activity_date"
        );
        let textures_sql = users_sql
            .replace(
                &format!("FROM {prefix}users"),
                &format!("FROM {prefix}textures"),
            )
            .replace("register_at", "upload_at");

        match self {
            Self::Sqlite(pool) => {
                let users = sqlx::query_as::<_, (String, i64)>(sqlx::AssertSqlSafe(users_sql))
                    .bind(since)
                    .fetch_all(pool)
                    .await?;
                let textures =
                    sqlx::query_as::<_, (String, i64)>(sqlx::AssertSqlSafe(textures_sql))
                        .bind(since)
                        .fetch_all(pool)
                        .await?;
                Ok((users, textures))
            }
            Self::MySql(pool) => {
                let users = sqlx::query_as::<_, (String, i64)>(sqlx::AssertSqlSafe(users_sql))
                    .bind(since)
                    .fetch_all(pool)
                    .await?;
                let textures =
                    sqlx::query_as::<_, (String, i64)>(sqlx::AssertSqlSafe(textures_sql))
                        .bind(since)
                        .fetch_all(pool)
                        .await?;
                Ok((users, textures))
            }
            Self::Postgres(pool) => {
                let users = sqlx::query_as::<_, (String, i64)>(sqlx::AssertSqlSafe(users_sql))
                    .bind(since)
                    .fetch_all(pool)
                    .await?;
                let textures =
                    sqlx::query_as::<_, (String, i64)>(sqlx::AssertSqlSafe(textures_sql))
                        .bind(since)
                        .fetch_all(pool)
                        .await?;
                Ok((users, textures))
            }
        }
    }

    pub async fn user_usage(&self, prefix: &str, uid: i64) -> Result<(i64, i64), sqlx::Error> {
        let integer_cast = if matches!(self, Self::MySql(_)) {
            "SIGNED"
        } else {
            "BIGINT"
        };
        let sql = format!(
            "SELECT CAST((SELECT COUNT(*) FROM {prefix}players WHERE uid = {{uid}}) AS {integer_cast}) AS player_count, \
             CAST((SELECT COALESCE(SUM(size), 0) FROM {prefix}textures WHERE uploader = {{uid}}) AS {integer_cast}) AS storage_size"
        );
        let sql = if matches!(self, Self::Postgres(_)) {
            sql.replace("{uid}", "$1")
        } else {
            sql.replace("{uid}", "?")
        };
        match self {
            Self::Sqlite(pool) => Ok(sqlx::query_as::<_, (i64, i64)>(sqlx::AssertSqlSafe(sql))
                .bind(uid)
                .bind(uid)
                .fetch_one(pool)
                .await?),
            Self::MySql(pool) => Ok(sqlx::query_as::<_, (i64, i64)>(sqlx::AssertSqlSafe(sql))
                .bind(uid)
                .bind(uid)
                .fetch_one(pool)
                .await?),
            Self::Postgres(pool) => Ok(sqlx::query_as::<_, (i64, i64)>(sqlx::AssertSqlSafe(sql))
                .bind(uid)
                .fetch_one(pool)
                .await?),
        }
    }

    pub async fn sign_user(
        &self,
        prefix: &str,
        uid: i64,
        score_reward: i64,
        now: &str,
        eligible_before: &str,
    ) -> Result<UserSignOutcome, sqlx::Error> {
        let update_sql = match self {
            Self::Postgres(_) => format!(
                "UPDATE {prefix}users SET score = score + $1, last_sign_at = CAST($2 AS TIMESTAMP) \
                 WHERE uid = $3 AND last_sign_at <= CAST($4 AS TIMESTAMP)"
            ),
            _ => format!(
                "UPDATE {prefix}users SET score = score + ?, last_sign_at = ? \
                 WHERE uid = ? AND last_sign_at <= ?"
            ),
        };
        let affected = match self {
            Self::Sqlite(pool) => sqlx::query(sqlx::AssertSqlSafe(update_sql))
                .bind(score_reward)
                .bind(now)
                .bind(uid)
                .bind(eligible_before)
                .execute(pool)
                .await?
                .rows_affected(),
            Self::MySql(pool) => sqlx::query(sqlx::AssertSqlSafe(update_sql))
                .bind(score_reward)
                .bind(now)
                .bind(uid)
                .bind(eligible_before)
                .execute(pool)
                .await?
                .rows_affected(),
            Self::Postgres(pool) => sqlx::query(sqlx::AssertSqlSafe(update_sql))
                .bind(score_reward)
                .bind(now)
                .bind(uid)
                .bind(eligible_before)
                .execute(pool)
                .await?
                .rows_affected(),
        };
        if affected == 0 {
            return Ok(UserSignOutcome::NotEligible);
        }
        let score_sql = match self {
            Self::Postgres(_) => {
                format!("SELECT CAST(score AS BIGINT) FROM {prefix}users WHERE uid = $1")
            }
            Self::MySql(_) => {
                format!("SELECT CAST(score AS SIGNED) FROM {prefix}users WHERE uid = ?")
            }
            Self::Sqlite(_) => {
                format!("SELECT CAST(score AS BIGINT) FROM {prefix}users WHERE uid = ?")
            }
        };
        let score = match self {
            Self::Sqlite(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(score_sql))
                    .bind(uid)
                    .fetch_one(pool)
                    .await?
            }
            Self::MySql(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(score_sql))
                    .bind(uid)
                    .fetch_one(pool)
                    .await?
            }
            Self::Postgres(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(score_sql))
                    .bind(uid)
                    .fetch_one(pool)
                    .await?
            }
        };
        Ok(UserSignOutcome::Signed(score))
    }

    pub async fn players_for_user(
        &self,
        prefix: &str,
        uid: i64,
    ) -> Result<Vec<PlayerRecord>, sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => format!(
                "SELECT CAST(pid AS BIGINT) AS pid, CAST(uid AS BIGINT) AS uid, name, \
                 CAST(tid_skin AS BIGINT) AS tid_skin, CAST(tid_cape AS BIGINT) AS tid_cape, \
                 to_char(last_modified, 'YYYY-MM-DD HH24:MI:SS') AS last_modified \
                 FROM {prefix}players WHERE CAST(uid AS BIGINT) = $1 ORDER BY pid"
            ),
            Self::MySql(_) => format!(
                "SELECT CAST(pid AS SIGNED) AS pid, CAST(uid AS SIGNED) AS uid, name, \
                 CAST(tid_skin AS SIGNED) AS tid_skin, CAST(tid_cape AS SIGNED) AS tid_cape, \
                 DATE_FORMAT(last_modified, '%Y-%m-%d %H:%i:%s') AS last_modified \
                 FROM {prefix}players WHERE uid = ? ORDER BY pid"
            ),
            Self::Sqlite(_) => format!(
                "SELECT CAST(pid AS BIGINT) AS pid, CAST(uid AS BIGINT) AS uid, name, \
                 CAST(tid_skin AS BIGINT) AS tid_skin, CAST(tid_cape AS BIGINT) AS tid_cape, \
                 CAST(last_modified AS TEXT) AS last_modified \
                 FROM {prefix}players WHERE uid = ? ORDER BY pid"
            ),
        };
        match self {
            Self::Sqlite(pool) => Ok(sqlx::query_as::<_, PlayerRecord>(sqlx::AssertSqlSafe(sql))
                .bind(uid)
                .fetch_all(pool)
                .await?),
            Self::MySql(pool) => Ok(sqlx::query_as::<_, PlayerRecord>(sqlx::AssertSqlSafe(sql))
                .bind(uid)
                .fetch_all(pool)
                .await?),
            Self::Postgres(pool) => Ok(sqlx::query_as::<_, PlayerRecord>(sqlx::AssertSqlSafe(sql))
                .bind(uid)
                .fetch_all(pool)
                .await?),
        }
    }
    pub async fn rename_player(
        &self,
        prefix: &str,
        user_id: i64,
        player_id: i64,
        new_name: &str,
    ) -> Result<PlayerRenameOutcome, sqlx::Error> {
        let select_sql = match self {
            Self::Postgres(_) => format!(
                "SELECT name, CAST(uid AS BIGINT) AS uid FROM {prefix}players WHERE pid = $1 LIMIT 1"
            ),
            _ => format!(
                "SELECT name, CAST(uid AS BIGINT) AS uid FROM {prefix}players WHERE pid = ? LIMIT 1"
            ),
        };
        let player_identity = match self {
            Self::Sqlite(pool) => {
                sqlx::query_as::<_, (String, i64)>(sqlx::AssertSqlSafe(select_sql))
                    .bind(player_id)
                    .fetch_optional(pool)
                    .await?
            }
            Self::MySql(pool) => {
                sqlx::query_as::<_, (String, i64)>(sqlx::AssertSqlSafe(select_sql))
                    .bind(player_id)
                    .fetch_optional(pool)
                    .await?
            }
            Self::Postgres(pool) => {
                sqlx::query_as::<_, (String, i64)>(sqlx::AssertSqlSafe(select_sql))
                    .bind(player_id)
                    .fetch_optional(pool)
                    .await?
            }
        };
        let Some((previous_name, owner_id)) = player_identity else {
            return Ok(PlayerRenameOutcome::NotFound);
        };
        if owner_id != user_id {
            return Ok(PlayerRenameOutcome::Forbidden);
        }

        let duplicate_sql = match self {
            Self::Postgres(_) => {
                format!("SELECT COUNT(*) FROM {prefix}players WHERE name = $1 AND pid <> $2")
            }
            _ => format!("SELECT COUNT(*) FROM {prefix}players WHERE name = ? AND pid <> ?"),
        };
        let duplicate_count = match self {
            Self::Sqlite(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(duplicate_sql))
                    .bind(new_name)
                    .bind(player_id)
                    .fetch_one(pool)
                    .await?
            }
            Self::MySql(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(duplicate_sql))
                    .bind(new_name)
                    .bind(player_id)
                    .fetch_one(pool)
                    .await?
            }
            Self::Postgres(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(duplicate_sql))
                    .bind(new_name)
                    .bind(player_id)
                    .fetch_one(pool)
                    .await?
            }
        };
        if duplicate_count > 0 {
            return Ok(PlayerRenameOutcome::NameExists);
        }

        let update_sql = match self {
            Self::Postgres(_) => format!(
                "UPDATE {prefix}players SET name = $1, last_modified = CURRENT_TIMESTAMP \
                 WHERE pid = $2 AND uid = $3"
            ),
            _ => format!(
                "UPDATE {prefix}players SET name = ?, last_modified = CURRENT_TIMESTAMP \
                 WHERE pid = ? AND uid = ?"
            ),
        };
        let updated_rows = match self {
            Self::Sqlite(pool) => sqlx::query(sqlx::AssertSqlSafe(update_sql))
                .bind(new_name)
                .bind(player_id)
                .bind(user_id)
                .execute(pool)
                .await?
                .rows_affected(),
            Self::MySql(pool) => sqlx::query(sqlx::AssertSqlSafe(update_sql))
                .bind(new_name)
                .bind(player_id)
                .bind(user_id)
                .execute(pool)
                .await?
                .rows_affected(),
            Self::Postgres(pool) => sqlx::query(sqlx::AssertSqlSafe(update_sql))
                .bind(new_name)
                .bind(player_id)
                .bind(user_id)
                .execute(pool)
                .await?
                .rows_affected(),
        };
        if updated_rows == 0 {
            return Ok(PlayerRenameOutcome::NotFound);
        }
        let player = self
            .players_for_user(prefix, user_id)
            .await?
            .into_iter()
            .find(|player| player.pid == player_id);
        Ok(match player {
            Some(player) => PlayerRenameOutcome::Renamed {
                previous_name,
                player,
            },
            None => PlayerRenameOutcome::NotFound,
        })
    }

    pub async fn add_closet_item(
        &self,
        prefix: &str,
        user_id: i64,
        tid: i64,
        name: &str,
        score_cost: i64,
        is_admin: bool,
        score_award_per_like: i64,
    ) -> Result<ClosetAddOutcome, sqlx::Error> {
        let score_sql = match self {
            Self::Postgres(_) => {
                format!("SELECT CAST(score AS BIGINT) FROM {prefix}users WHERE uid = $1")
            }
            Self::MySql(_) => {
                format!("SELECT CAST(score AS SIGNED) FROM {prefix}users WHERE uid = ?")
            }
            Self::Sqlite(_) => {
                format!("SELECT CAST(score AS BIGINT) FROM {prefix}users WHERE uid = ?")
            }
        };
        let score = match self {
            Self::Sqlite(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(score_sql))
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await?
            }
            Self::MySql(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(score_sql))
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await?
            }
            Self::Postgres(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(score_sql))
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await?
            }
        };
        if score.is_none_or(|score| score < score_cost) {
            return Ok(ClosetAddOutcome::InsufficientScore);
        }

        let texture_sql = match self {
            Self::Postgres(_) => format!(
                "SELECT public, CAST(uploader AS BIGINT) FROM {prefix}textures WHERE tid = $1"
            ),
            Self::MySql(_) => format!(
                "SELECT public, CAST(uploader AS SIGNED) FROM {prefix}textures WHERE tid = ?"
            ),
            Self::Sqlite(_) => format!(
                "SELECT public, CAST(uploader AS BIGINT) FROM {prefix}textures WHERE tid = ?"
            ),
        };
        let texture = match self {
            Self::Sqlite(pool) => {
                sqlx::query_as::<_, (bool, i64)>(sqlx::AssertSqlSafe(texture_sql))
                    .bind(tid)
                    .fetch_optional(pool)
                    .await?
            }
            Self::MySql(pool) => {
                sqlx::query_as::<_, (bool, i64)>(sqlx::AssertSqlSafe(texture_sql))
                    .bind(tid)
                    .fetch_optional(pool)
                    .await?
            }
            Self::Postgres(pool) => {
                sqlx::query_as::<_, (bool, i64)>(sqlx::AssertSqlSafe(texture_sql))
                    .bind(tid)
                    .fetch_optional(pool)
                    .await?
            }
        };
        let Some((is_public, uploader_id)) = texture else {
            return Ok(ClosetAddOutcome::TextureNotFound);
        };
        if !is_public && uploader_id != user_id && !is_admin {
            return Ok(ClosetAddOutcome::PrivateTexture);
        }

        let duplicate_sql = match self {
            Self::Postgres(_) => format!(
                "SELECT COUNT(*) FROM {prefix}user_closet WHERE user_uid = $1 AND texture_tid = $2"
            ),
            _ => format!(
                "SELECT COUNT(*) FROM {prefix}user_closet WHERE user_uid = ? AND texture_tid = ?"
            ),
        };
        let duplicate_count = match self {
            Self::Sqlite(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(duplicate_sql))
                    .bind(user_id)
                    .bind(tid)
                    .fetch_one(pool)
                    .await?
            }
            Self::MySql(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(duplicate_sql))
                    .bind(user_id)
                    .bind(tid)
                    .fetch_one(pool)
                    .await?
            }
            Self::Postgres(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(duplicate_sql))
                    .bind(user_id)
                    .bind(tid)
                    .fetch_one(pool)
                    .await?
            }
        };
        if duplicate_count > 0 {
            return Ok(ClosetAddOutcome::NameExists);
        }

        let insert_sql = match self {
            Self::Postgres(_) => format!(
                "INSERT INTO {prefix}user_closet (user_uid, texture_tid, item_name) VALUES ($1, $2, $3)"
            ),
            _ => format!(
                "INSERT INTO {prefix}user_closet (user_uid, texture_tid, item_name) VALUES (?, ?, ?)"
            ),
        };
        match self {
            Self::Sqlite(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(insert_sql))
                    .bind(user_id)
                    .bind(tid)
                    .bind(name)
                    .execute(pool)
                    .await?;
            }
            Self::MySql(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(insert_sql))
                    .bind(user_id)
                    .bind(tid)
                    .bind(name)
                    .execute(pool)
                    .await?;
            }
            Self::Postgres(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(insert_sql))
                    .bind(user_id)
                    .bind(tid)
                    .bind(name)
                    .execute(pool)
                    .await?;
            }
        }

        if score_cost != 0 {
            let update_sql = match self {
                Self::Postgres(_) => format!(
                    "UPDATE {prefix}users SET score = score - $1 WHERE uid = $2 AND score >= $3"
                ),
                _ => format!(
                    "UPDATE {prefix}users SET score = score - ? WHERE uid = ? AND score >= ?"
                ),
            };
            let updated = match self {
                Self::Sqlite(pool) => sqlx::query(sqlx::AssertSqlSafe(update_sql))
                    .bind(score_cost)
                    .bind(user_id)
                    .bind(score_cost)
                    .execute(pool)
                    .await?
                    .rows_affected(),
                Self::MySql(pool) => sqlx::query(sqlx::AssertSqlSafe(update_sql))
                    .bind(score_cost)
                    .bind(user_id)
                    .bind(score_cost)
                    .execute(pool)
                    .await?
                    .rows_affected(),
                Self::Postgres(pool) => sqlx::query(sqlx::AssertSqlSafe(update_sql))
                    .bind(score_cost)
                    .bind(user_id)
                    .bind(score_cost)
                    .execute(pool)
                    .await?
                    .rows_affected(),
            };
            if updated == 0 {
                let delete_sql = match self {
                    Self::Postgres(_) => format!(
                        "DELETE FROM {prefix}user_closet WHERE user_uid = $1 AND texture_tid = $2"
                    ),
                    _ => format!(
                        "DELETE FROM {prefix}user_closet WHERE user_uid = ? AND texture_tid = ?"
                    ),
                };
                match self {
                    Self::Sqlite(pool) => {
                        sqlx::query(sqlx::AssertSqlSafe(delete_sql))
                            .bind(user_id)
                            .bind(tid)
                            .execute(pool)
                            .await?;
                    }
                    Self::MySql(pool) => {
                        sqlx::query(sqlx::AssertSqlSafe(delete_sql))
                            .bind(user_id)
                            .bind(tid)
                            .execute(pool)
                            .await?;
                    }
                    Self::Postgres(pool) => {
                        sqlx::query(sqlx::AssertSqlSafe(delete_sql))
                            .bind(user_id)
                            .bind(tid)
                            .execute(pool)
                            .await?;
                    }
                }
                return Ok(ClosetAddOutcome::InsufficientScore);
            }
        }

        let likes_sql = format!(
            "UPDATE {prefix}textures SET likes = likes + 1 WHERE tid = {}",
            if matches!(self, Self::Postgres(_)) {
                "$1"
            } else {
                "?"
            }
        );
        match self {
            Self::Sqlite(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(likes_sql))
                    .bind(tid)
                    .execute(pool)
                    .await?;
            }
            Self::MySql(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(likes_sql))
                    .bind(tid)
                    .execute(pool)
                    .await?;
            }
            Self::Postgres(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(likes_sql))
                    .bind(tid)
                    .execute(pool)
                    .await?;
            }
        }
        if uploader_id != user_id && score_award_per_like != 0 {
            let award_sql = match self {
                Self::Postgres(_) => {
                    format!("UPDATE {prefix}users SET score = score + $1 WHERE uid = $2")
                }
                _ => format!("UPDATE {prefix}users SET score = score + ? WHERE uid = ?"),
            };
            match self {
                Self::Sqlite(pool) => {
                    sqlx::query(sqlx::AssertSqlSafe(award_sql))
                        .bind(score_award_per_like)
                        .bind(uploader_id)
                        .execute(pool)
                        .await?;
                }
                Self::MySql(pool) => {
                    sqlx::query(sqlx::AssertSqlSafe(award_sql))
                        .bind(score_award_per_like)
                        .bind(uploader_id)
                        .execute(pool)
                        .await?;
                }
                Self::Postgres(pool) => {
                    sqlx::query(sqlx::AssertSqlSafe(award_sql))
                        .bind(score_award_per_like)
                        .bind(uploader_id)
                        .execute(pool)
                        .await?;
                }
            }
        }
        Ok(ClosetAddOutcome::Added)
    }

    pub async fn rename_closet_item(
        &self,
        prefix: &str,
        user_id: i64,
        tid: i64,
        name: &str,
    ) -> Result<ClosetRenameOutcome, sqlx::Error> {
        let exists_sql = match self {
            Self::Postgres(_) => format!(
                "SELECT COUNT(*) FROM {prefix}user_closet WHERE user_uid = $1 AND texture_tid = $2"
            ),
            _ => format!(
                "SELECT COUNT(*) FROM {prefix}user_closet WHERE user_uid = ? AND texture_tid = ?"
            ),
        };
        let exists = match self {
            Self::Sqlite(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(exists_sql))
                    .bind(user_id)
                    .bind(tid)
                    .fetch_one(pool)
                    .await?
            }
            Self::MySql(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(exists_sql))
                    .bind(user_id)
                    .bind(tid)
                    .fetch_one(pool)
                    .await?
            }
            Self::Postgres(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(exists_sql))
                    .bind(user_id)
                    .bind(tid)
                    .fetch_one(pool)
                    .await?
            }
        };
        if exists == 0 {
            return Ok(ClosetRenameOutcome::NotInCloset);
        }
        let update_sql = match self {
            Self::Postgres(_) => format!(
                "UPDATE {prefix}user_closet SET item_name = $1 WHERE user_uid = $2 AND texture_tid = $3"
            ),
            _ => format!(
                "UPDATE {prefix}user_closet SET item_name = ? WHERE user_uid = ? AND texture_tid = ?"
            ),
        };
        match self {
            Self::Sqlite(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(update_sql))
                    .bind(name)
                    .bind(user_id)
                    .bind(tid)
                    .execute(pool)
                    .await?;
            }
            Self::MySql(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(update_sql))
                    .bind(name)
                    .bind(user_id)
                    .bind(tid)
                    .execute(pool)
                    .await?;
            }
            Self::Postgres(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(update_sql))
                    .bind(name)
                    .bind(user_id)
                    .bind(tid)
                    .execute(pool)
                    .await?;
            }
        }
        Ok(ClosetRenameOutcome::Renamed)
    }

    pub async fn remove_closet_item(
        &self,
        prefix: &str,
        user_id: i64,
        tid: i64,
        return_score: bool,
        score_refund: i64,
        score_award_per_like: i64,
    ) -> Result<ClosetRemoveOutcome, sqlx::Error> {
        let exists_sql = match self {
            Self::Postgres(_) => format!(
                "SELECT COUNT(*) FROM {prefix}user_closet WHERE user_uid = $1 AND texture_tid = $2"
            ),
            _ => format!(
                "SELECT COUNT(*) FROM {prefix}user_closet WHERE user_uid = ? AND texture_tid = ?"
            ),
        };
        let exists = match self {
            Self::Sqlite(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(exists_sql))
                    .bind(user_id)
                    .bind(tid)
                    .fetch_one(pool)
                    .await?
            }
            Self::MySql(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(exists_sql))
                    .bind(user_id)
                    .bind(tid)
                    .fetch_one(pool)
                    .await?
            }
            Self::Postgres(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(exists_sql))
                    .bind(user_id)
                    .bind(tid)
                    .fetch_one(pool)
                    .await?
            }
        };
        if exists == 0 {
            return Ok(ClosetRemoveOutcome::NotInCloset);
        }
        let texture_sql = match self {
            Self::Postgres(_) => {
                format!("SELECT CAST(uploader AS BIGINT) FROM {prefix}textures WHERE tid = $1")
            }
            Self::MySql(_) => {
                format!("SELECT CAST(uploader AS SIGNED) FROM {prefix}textures WHERE tid = ?")
            }
            Self::Sqlite(_) => {
                format!("SELECT CAST(uploader AS BIGINT) FROM {prefix}textures WHERE tid = ?")
            }
        };
        let uploader_id = match self {
            Self::Sqlite(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(texture_sql))
                    .bind(tid)
                    .fetch_optional(pool)
                    .await?
            }
            Self::MySql(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(texture_sql))
                    .bind(tid)
                    .fetch_optional(pool)
                    .await?
            }
            Self::Postgres(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(texture_sql))
                    .bind(tid)
                    .fetch_optional(pool)
                    .await?
            }
        };
        let Some(uploader_id) = uploader_id else {
            return Ok(ClosetRemoveOutcome::NotInCloset);
        };
        let delete_sql = match self {
            Self::Postgres(_) => {
                format!("DELETE FROM {prefix}user_closet WHERE user_uid = $1 AND texture_tid = $2")
            }
            _ => format!("DELETE FROM {prefix}user_closet WHERE user_uid = ? AND texture_tid = ?"),
        };
        match self {
            Self::Sqlite(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(delete_sql))
                    .bind(user_id)
                    .bind(tid)
                    .execute(pool)
                    .await?;
            }
            Self::MySql(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(delete_sql))
                    .bind(user_id)
                    .bind(tid)
                    .execute(pool)
                    .await?;
            }
            Self::Postgres(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(delete_sql))
                    .bind(user_id)
                    .bind(tid)
                    .execute(pool)
                    .await?;
            }
        }
        if return_score && score_refund != 0 {
            let refund_sql = match self {
                Self::Postgres(_) => {
                    format!("UPDATE {prefix}users SET score = score + $1 WHERE uid = $2")
                }
                _ => format!("UPDATE {prefix}users SET score = score + ? WHERE uid = ?"),
            };
            match self {
                Self::Sqlite(pool) => {
                    sqlx::query(sqlx::AssertSqlSafe(refund_sql))
                        .bind(score_refund)
                        .bind(user_id)
                        .execute(pool)
                        .await?;
                }
                Self::MySql(pool) => {
                    sqlx::query(sqlx::AssertSqlSafe(refund_sql))
                        .bind(score_refund)
                        .bind(user_id)
                        .execute(pool)
                        .await?;
                }
                Self::Postgres(pool) => {
                    sqlx::query(sqlx::AssertSqlSafe(refund_sql))
                        .bind(score_refund)
                        .bind(user_id)
                        .execute(pool)
                        .await?;
                }
            }
        }
        let likes_sql = format!(
            "UPDATE {prefix}textures SET likes = likes - 1 WHERE tid = {}",
            if matches!(self, Self::Postgres(_)) {
                "$1"
            } else {
                "?"
            }
        );
        match self {
            Self::Sqlite(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(likes_sql))
                    .bind(tid)
                    .execute(pool)
                    .await?;
            }
            Self::MySql(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(likes_sql))
                    .bind(tid)
                    .execute(pool)
                    .await?;
            }
            Self::Postgres(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(likes_sql))
                    .bind(tid)
                    .execute(pool)
                    .await?;
            }
        }
        if score_award_per_like != 0 {
            let retract_sql = match self {
                Self::Postgres(_) => {
                    format!("UPDATE {prefix}users SET score = score - $1 WHERE uid = $2")
                }
                _ => format!("UPDATE {prefix}users SET score = score - ? WHERE uid = ?"),
            };
            match self {
                Self::Sqlite(pool) => {
                    sqlx::query(sqlx::AssertSqlSafe(retract_sql))
                        .bind(score_award_per_like)
                        .bind(uploader_id)
                        .execute(pool)
                        .await?;
                }
                Self::MySql(pool) => {
                    sqlx::query(sqlx::AssertSqlSafe(retract_sql))
                        .bind(score_award_per_like)
                        .bind(uploader_id)
                        .execute(pool)
                        .await?;
                }
                Self::Postgres(pool) => {
                    sqlx::query(sqlx::AssertSqlSafe(retract_sql))
                        .bind(score_award_per_like)
                        .bind(uploader_id)
                        .execute(pool)
                        .await?;
                }
            }
        }
        Ok(ClosetRemoveOutcome::Removed)
    }
    pub async fn skinlib_items(
        &self,
        prefix: &str,
        user_id: Option<i64>,
        is_admin: bool,
        filter: &str,
        keyword: Option<&str>,
        uploader: Option<i64>,
        sort: &str,
        page: i64,
        per_page: i64,
    ) -> Result<(Vec<SkinLibraryRecord>, i64), sqlx::Error> {
        let is_postgres = matches!(self, Self::Postgres(_));
        let (keyword_enabled, keyword_pattern, uploader_enabled, uploader_value) = if is_postgres {
            ("$3", "$4", "$5", "$6")
        } else {
            ("?", "?", "?", "?")
        };
        let category = match filter {
            "skin" => "t.type IN ('steve', 'alex')",
            "steve" | "alex" | "cape" => match filter {
                "steve" => "t.type = 'steve'",
                "alex" => "t.type = 'alex'",
                _ => "t.type = 'cape'",
            },
            _ => "t.type = '__no_such_texture_type__'",
        };
        let order_by = match sort {
            "likes" => "t.likes",
            "name" => "t.name",
            _ => "t.upload_at",
        };
        let visibility = if is_postgres {
            "$1 = TRUE OR t.public = TRUE OR t.uploader = $2"
        } else {
            "? = TRUE OR t.public = TRUE OR t.uploader = ?"
        };
        let where_sql = format!(
            "({visibility}) AND {category} \
             AND ({keyword_enabled} = FALSE OR t.name LIKE {keyword_pattern}) \
             AND ({uploader_enabled} = FALSE OR t.uploader = {uploader_value})"
        );
        let count_sql = format!(
            "SELECT COUNT(*) FROM {prefix}textures t \
             INNER JOIN {prefix}users u ON u.uid = t.uploader \
             WHERE {where_sql}"
        );
        let search_pattern = format!("%{}%", keyword.unwrap_or_default());
        let count = match self {
            Self::Sqlite(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(count_sql))
                    .bind(is_admin)
                    .bind(user_id)
                    .bind(keyword.is_some())
                    .bind(&search_pattern)
                    .bind(uploader.is_some())
                    .bind(uploader.unwrap_or_default())
                    .fetch_one(pool)
                    .await?
            }
            Self::MySql(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(count_sql))
                    .bind(is_admin)
                    .bind(user_id)
                    .bind(keyword.is_some())
                    .bind(&search_pattern)
                    .bind(uploader.is_some())
                    .bind(uploader.unwrap_or_default())
                    .fetch_one(pool)
                    .await?
            }
            Self::Postgres(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(count_sql))
                    .bind(is_admin)
                    .bind(user_id)
                    .bind(keyword.is_some())
                    .bind(&search_pattern)
                    .bind(uploader.is_some())
                    .bind(uploader.unwrap_or_default())
                    .fetch_one(pool)
                    .await?
            }
        };
        let (limit_marker, offset_marker) = if is_postgres {
            ("$7".to_owned(), "$8".to_owned())
        } else {
            ("?".to_owned(), "?".to_owned())
        };
        let rows_sql = format!(
            "SELECT CAST(t.tid AS BIGINT) AS tid, t.name, t.type AS texture_type, \
             CAST(t.uploader AS BIGINT) AS uploader, t.public AS is_public, \
             CAST(t.likes AS BIGINT) AS likes, u.nickname \
             FROM {prefix}textures t INNER JOIN {prefix}users u ON u.uid = t.uploader \
             WHERE {where_sql} ORDER BY {order_by} DESC \
             LIMIT {limit_marker} OFFSET {offset_marker}"
        );
        let offset = page.saturating_sub(1).saturating_mul(per_page);
        let rows = match self {
            Self::Sqlite(pool) => {
                sqlx::query_as::<_, SkinLibraryRecord>(sqlx::AssertSqlSafe(rows_sql))
                    .bind(is_admin)
                    .bind(user_id)
                    .bind(keyword.is_some())
                    .bind(&search_pattern)
                    .bind(uploader.is_some())
                    .bind(uploader.unwrap_or_default())
                    .bind(per_page)
                    .bind(offset)
                    .fetch_all(pool)
                    .await?
            }
            Self::MySql(pool) => {
                sqlx::query_as::<_, SkinLibraryRecord>(sqlx::AssertSqlSafe(rows_sql))
                    .bind(is_admin)
                    .bind(user_id)
                    .bind(keyword.is_some())
                    .bind(&search_pattern)
                    .bind(uploader.is_some())
                    .bind(uploader.unwrap_or_default())
                    .bind(per_page)
                    .bind(offset)
                    .fetch_all(pool)
                    .await?
            }
            Self::Postgres(pool) => {
                sqlx::query_as::<_, SkinLibraryRecord>(sqlx::AssertSqlSafe(rows_sql))
                    .bind(is_admin)
                    .bind(user_id)
                    .bind(keyword.is_some())
                    .bind(&search_pattern)
                    .bind(uploader.is_some())
                    .bind(uploader.unwrap_or_default())
                    .bind(per_page)
                    .bind(offset)
                    .fetch_all(pool)
                    .await?
            }
        };
        Ok((rows, count))
    }
    pub async fn admin_closet_items(
        &self,
        prefix: &str,
        user_id: i64,
    ) -> Result<Vec<ClosetTextureRecord>, sqlx::Error> {
        let sql = match self {
            Self::Sqlite(_) => format!(
                "SELECT CAST(t.tid AS BIGINT) AS tid, t.name, t.type AS texture_type, t.hash, \
                 CAST(t.size AS BIGINT) AS size, CAST(t.uploader AS BIGINT) AS uploader, t.public AS is_public, \
                 CAST(t.upload_at AS TEXT) AS upload_at, CAST(t.likes AS BIGINT) AS likes, \
                 CAST(c.user_uid AS BIGINT) AS user_uid, CAST(c.texture_tid AS BIGINT) AS texture_tid, c.item_name \
                 FROM {prefix}textures t INNER JOIN {prefix}user_closet c ON c.texture_tid = t.tid \
                 WHERE c.user_uid = ? ORDER BY c.texture_tid"
            ),
            Self::MySql(_) => format!(
                "SELECT CAST(t.tid AS SIGNED) AS tid, t.name, t.type AS texture_type, t.hash, \
                 CAST(t.size AS SIGNED) AS size, CAST(t.uploader AS SIGNED) AS uploader, t.public AS is_public, \
                 DATE_FORMAT(t.upload_at, '%Y-%m-%d %H:%i:%s') AS upload_at, CAST(t.likes AS SIGNED) AS likes, \
                 CAST(c.user_uid AS SIGNED) AS user_uid, CAST(c.texture_tid AS SIGNED) AS texture_tid, c.item_name \
                 FROM {prefix}textures t INNER JOIN {prefix}user_closet c ON c.texture_tid = t.tid \
                 WHERE c.user_uid = ? ORDER BY c.texture_tid"
            ),
            Self::Postgres(_) => format!(
                "SELECT CAST(t.tid AS BIGINT) AS tid, t.name, t.type AS texture_type, t.hash, \
                 CAST(t.size AS BIGINT) AS size, CAST(t.uploader AS BIGINT) AS uploader, t.public AS is_public, \
                 to_char(t.upload_at, 'YYYY-MM-DD HH24:MI:SS') AS upload_at, CAST(t.likes AS BIGINT) AS likes, \
                 CAST(c.user_uid AS BIGINT) AS user_uid, CAST(c.texture_tid AS BIGINT) AS texture_tid, c.item_name \
                 FROM {prefix}textures t INNER JOIN {prefix}user_closet c ON c.texture_tid = t.tid \
                 WHERE c.user_uid = $1 ORDER BY c.texture_tid"
            ),
        };
        match self {
            Self::Sqlite(pool) => Ok(sqlx::query_as::<_, ClosetTextureRecord>(
                sqlx::AssertSqlSafe(sql),
            )
            .bind(user_id)
            .fetch_all(pool)
            .await?),
            Self::MySql(pool) => Ok(
                sqlx::query_as::<_, ClosetTextureRecord>(sqlx::AssertSqlSafe(sql))
                    .bind(user_id)
                    .fetch_all(pool)
                    .await?,
            ),
            Self::Postgres(pool) => Ok(sqlx::query_as::<_, ClosetTextureRecord>(
                sqlx::AssertSqlSafe(sql),
            )
            .bind(user_id)
            .fetch_all(pool)
            .await?),
        }
    }

    pub async fn add_admin_closet_item(
        &self,
        prefix: &str,
        user_id: i64,
        tid: i64,
    ) -> Result<AdminClosetAddOutcome, sqlx::Error> {
        let Some(texture) = self.texture_info(prefix, tid).await? else {
            return Ok(AdminClosetAddOutcome::TextureNotFound);
        };
        let exists_sql = match self {
            Self::Postgres(_) => format!(
                "SELECT COUNT(*) FROM {prefix}user_closet WHERE user_uid = $1 AND texture_tid = $2"
            ),
            _ => format!(
                "SELECT COUNT(*) FROM {prefix}user_closet WHERE user_uid = ? AND texture_tid = ?"
            ),
        };
        let count = match self {
            Self::Sqlite(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(exists_sql))
                    .bind(user_id)
                    .bind(tid)
                    .fetch_one(pool)
                    .await?
            }
            Self::MySql(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(exists_sql))
                    .bind(user_id)
                    .bind(tid)
                    .fetch_one(pool)
                    .await?
            }
            Self::Postgres(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(exists_sql))
                    .bind(user_id)
                    .bind(tid)
                    .fetch_one(pool)
                    .await?
            }
        };
        if count > 0 {
            return Ok(AdminClosetAddOutcome::Repeated);
        }
        let insert_sql = match self {
            Self::Postgres(_) => format!(
                "INSERT INTO {prefix}user_closet (user_uid, texture_tid, item_name) VALUES ($1, $2, $3)"
            ),
            _ => format!(
                "INSERT INTO {prefix}user_closet (user_uid, texture_tid, item_name) VALUES (?, ?, ?)"
            ),
        };
        match self {
            Self::Sqlite(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(insert_sql))
                    .bind(user_id)
                    .bind(tid)
                    .bind(&texture.name)
                    .execute(pool)
                    .await?;
            }
            Self::MySql(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(insert_sql))
                    .bind(user_id)
                    .bind(tid)
                    .bind(&texture.name)
                    .execute(pool)
                    .await?;
            }
            Self::Postgres(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(insert_sql))
                    .bind(user_id)
                    .bind(tid)
                    .bind(&texture.name)
                    .execute(pool)
                    .await?;
            }
        };
        Ok(AdminClosetAddOutcome::Added)
    }

    pub async fn remove_admin_closet_item(
        &self,
        prefix: &str,
        user_id: i64,
        tid: i64,
    ) -> Result<AdminClosetRemoveOutcome, sqlx::Error> {
        let delete_sql = match self {
            Self::Postgres(_) => {
                format!("DELETE FROM {prefix}user_closet WHERE user_uid = $1 AND texture_tid = $2")
            }
            _ => format!("DELETE FROM {prefix}user_closet WHERE user_uid = ? AND texture_tid = ?"),
        };
        let affected = match self {
            Self::Sqlite(pool) => sqlx::query(sqlx::AssertSqlSafe(delete_sql))
                .bind(user_id)
                .bind(tid)
                .execute(pool)
                .await?
                .rows_affected(),
            Self::MySql(pool) => sqlx::query(sqlx::AssertSqlSafe(delete_sql))
                .bind(user_id)
                .bind(tid)
                .execute(pool)
                .await?
                .rows_affected(),
            Self::Postgres(pool) => sqlx::query(sqlx::AssertSqlSafe(delete_sql))
                .bind(user_id)
                .bind(tid)
                .execute(pool)
                .await?
                .rows_affected(),
        };
        Ok(if affected == 0 {
            AdminClosetRemoveOutcome::NonExistent
        } else {
            AdminClosetRemoveOutcome::Removed
        })
    }

    pub async fn closet_item_ids(
        &self,
        prefix: &str,
        user_id: i64,
    ) -> Result<Vec<i64>, sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => format!(
                "SELECT CAST(texture_tid AS BIGINT) FROM {prefix}user_closet WHERE user_uid = $1 ORDER BY texture_tid"
            ),
            Self::MySql(_) => format!(
                "SELECT CAST(texture_tid AS SIGNED) FROM {prefix}user_closet WHERE user_uid = ? ORDER BY texture_tid"
            ),
            Self::Sqlite(_) => format!(
                "SELECT CAST(texture_tid AS BIGINT) FROM {prefix}user_closet WHERE user_uid = ? ORDER BY texture_tid"
            ),
        };
        match self {
            Self::Sqlite(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                    .bind(user_id)
                    .fetch_all(pool)
                    .await
            }
            Self::MySql(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                    .bind(user_id)
                    .fetch_all(pool)
                    .await
            }
            Self::Postgres(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                    .bind(user_id)
                    .fetch_all(pool)
                    .await
            }
        }
    }

    pub async fn closet_items(
        &self,
        prefix: &str,
        user_id: i64,
        category: &str,
        search: Option<&str>,
        page: i64,
        per_page: i64,
    ) -> Result<(Vec<ClosetTextureRecord>, i64), sqlx::Error> {
        let is_postgres = matches!(self, Self::Postgres(_));
        let search_marker = if is_postgres { "$3" } else { "?" };
        let enabled_marker = if is_postgres { "$2" } else { "?" };
        let user_marker = if is_postgres { "$1" } else { "?" };
        let where_sql = if category == "cape" {
            format!(
                "c.user_uid = {user_marker} AND t.type = 'cape' \
                 AND ({enabled_marker} = {} OR c.item_name LIKE {search_marker})",
                if is_postgres { "FALSE" } else { "0" }
            )
        } else {
            format!(
                "c.user_uid = {user_marker} AND t.type IN ('steve', 'alex') \
                 AND ({enabled_marker} = {} OR c.item_name LIKE {search_marker})",
                if is_postgres { "FALSE" } else { "0" }
            )
        };
        let count_sql = format!(
            "SELECT COUNT(*) FROM {prefix}textures t \
             INNER JOIN {prefix}user_closet c ON c.texture_tid = t.tid \
             WHERE {where_sql}"
        );
        let total = match self {
            Self::Sqlite(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(count_sql))
                    .bind(user_id)
                    .bind(search.is_some())
                    .bind(format!("%{}%", search.unwrap_or_default()))
                    .fetch_one(pool)
                    .await?
            }
            Self::MySql(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(count_sql))
                    .bind(user_id)
                    .bind(search.is_some())
                    .bind(format!("%{}%", search.unwrap_or_default()))
                    .fetch_one(pool)
                    .await?
            }
            Self::Postgres(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(count_sql))
                    .bind(user_id)
                    .bind(search.is_some())
                    .bind(format!("%{}%", search.unwrap_or_default()))
                    .fetch_one(pool)
                    .await?
            }
        };

        let mut next_marker = if is_postgres { 4 } else { 0 };
        let limit_marker = if is_postgres {
            let marker = format!("{}{}", "$", next_marker);
            next_marker += 1;
            marker
        } else {
            "?".to_owned()
        };
        let offset_marker = if is_postgres {
            format!("{}{}", "$", next_marker)
        } else {
            "?".to_owned()
        };
        let upload_at = match self {
            Self::MySql(_) => "DATE_FORMAT(t.upload_at, '%Y-%m-%d %H:%i:%s')",
            Self::Postgres(_) => "CAST(t.upload_at AS TEXT)",
            Self::Sqlite(_) => "CAST(t.upload_at AS TEXT)",
        };
        let rows_sql = format!(
            "SELECT CAST(t.tid AS BIGINT) AS tid, t.name, t.type AS texture_type, t.hash, \
             CAST(t.size AS BIGINT) AS size, CAST(t.uploader AS BIGINT) AS uploader, \
             t.public AS is_public, {upload_at} AS upload_at, CAST(t.likes AS BIGINT) AS likes, \
             CAST(c.user_uid AS BIGINT) AS user_uid, CAST(c.texture_tid AS BIGINT) AS texture_tid, \
             c.item_name \
             FROM {prefix}textures t \
             INNER JOIN {prefix}user_closet c ON c.texture_tid = t.tid \
             WHERE {where_sql} ORDER BY c.texture_tid DESC \
             LIMIT {limit_marker} OFFSET {offset_marker}"
        );
        let offset = page.saturating_sub(1).saturating_mul(per_page);
        let rows = match self {
            Self::Sqlite(pool) => {
                sqlx::query_as::<_, ClosetTextureRecord>(sqlx::AssertSqlSafe(rows_sql))
                    .bind(user_id)
                    .bind(search.is_some())
                    .bind(format!("%{}%", search.unwrap_or_default()))
                    .bind(per_page)
                    .bind(offset)
                    .fetch_all(pool)
                    .await?
            }
            Self::MySql(pool) => {
                sqlx::query_as::<_, ClosetTextureRecord>(sqlx::AssertSqlSafe(rows_sql))
                    .bind(user_id)
                    .bind(search.is_some())
                    .bind(format!("%{}%", search.unwrap_or_default()))
                    .bind(per_page)
                    .bind(offset)
                    .fetch_all(pool)
                    .await?
            }
            Self::Postgres(pool) => {
                sqlx::query_as::<_, ClosetTextureRecord>(sqlx::AssertSqlSafe(rows_sql))
                    .bind(user_id)
                    .bind(search.is_some())
                    .bind(format!("%{}%", search.unwrap_or_default()))
                    .bind(per_page)
                    .bind(offset)
                    .fetch_all(pool)
                    .await?
            }
        };
        Ok((rows, total))
    }
    pub async fn add_player(
        &self,
        prefix: &str,
        user_id: i64,
        name: &str,
        score_cost: i64,
    ) -> Result<PlayerAddOutcome, sqlx::Error> {
        let duplicate_sql = match self {
            Self::Postgres(_) => format!("SELECT COUNT(*) FROM {prefix}players WHERE name = $1"),
            _ => format!("SELECT COUNT(*) FROM {prefix}players WHERE name = ?"),
        };
        let duplicate_count = match self {
            Self::Sqlite(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(duplicate_sql))
                    .bind(name)
                    .fetch_one(pool)
                    .await?
            }
            Self::MySql(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(duplicate_sql))
                    .bind(name)
                    .fetch_one(pool)
                    .await?
            }
            Self::Postgres(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(duplicate_sql))
                    .bind(name)
                    .fetch_one(pool)
                    .await?
            }
        };
        if duplicate_count > 0 {
            return Ok(PlayerAddOutcome::NameExists);
        }

        let score_sql = match self {
            Self::Postgres(_) => {
                format!("SELECT CAST(score AS BIGINT) FROM {prefix}users WHERE uid = $1")
            }
            Self::MySql(_) => {
                format!("SELECT CAST(score AS SIGNED) FROM {prefix}users WHERE uid = ?")
            }
            Self::Sqlite(_) => {
                format!("SELECT CAST(score AS BIGINT) FROM {prefix}users WHERE uid = ?")
            }
        };
        let score = match self {
            Self::Sqlite(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(score_sql))
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await?
            }
            Self::MySql(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(score_sql))
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await?
            }
            Self::Postgres(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(score_sql))
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await?
            }
        };
        let Some(score) = score else {
            return Err(sqlx::Error::RowNotFound);
        };
        if score < score_cost {
            return Ok(PlayerAddOutcome::InsufficientScore);
        }

        let player_id = match self {
            Self::Sqlite(pool) => sqlx::query(sqlx::AssertSqlSafe(format!(
                "INSERT INTO {prefix}players (uid, name, tid_skin, tid_cape, last_modified) \
                     VALUES (?, ?, 0, 0, CURRENT_TIMESTAMP)"
            )))
            .bind(user_id)
            .bind(name)
            .execute(pool)
            .await?
            .last_insert_rowid(),
            Self::MySql(pool) => sqlx::query(sqlx::AssertSqlSafe(format!(
                "INSERT INTO {prefix}players (uid, name, tid_skin, tid_cape, last_modified) \
                     VALUES (?, ?, 0, 0, CURRENT_TIMESTAMP)"
            )))
            .bind(user_id)
            .bind(name)
            .execute(pool)
            .await?
            .last_insert_id() as i64,
            Self::Postgres(pool) => {
                let insert_sql = format!(
                    "INSERT INTO {prefix}players (uid, name, tid_skin, tid_cape, last_modified) \
                     VALUES ($1, $2, 0, 0, CURRENT_TIMESTAMP) RETURNING CAST(pid AS BIGINT)"
                );
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(insert_sql))
                    .bind(user_id)
                    .bind(name)
                    .fetch_one(pool)
                    .await?
            }
        };

        if score_cost != 0 {
            let update_sql = match self {
                Self::Postgres(_) => format!(
                    "UPDATE {prefix}users SET score = score - $1 WHERE uid = $2 AND score >= $3"
                ),
                _ => format!(
                    "UPDATE {prefix}users SET score = score - ? WHERE uid = ? AND score >= ?"
                ),
            };
            let updated = match self {
                Self::Sqlite(pool) => sqlx::query(sqlx::AssertSqlSafe(update_sql))
                    .bind(score_cost)
                    .bind(user_id)
                    .bind(score_cost)
                    .execute(pool)
                    .await?
                    .rows_affected(),
                Self::MySql(pool) => sqlx::query(sqlx::AssertSqlSafe(update_sql))
                    .bind(score_cost)
                    .bind(user_id)
                    .bind(score_cost)
                    .execute(pool)
                    .await?
                    .rows_affected(),
                Self::Postgres(pool) => sqlx::query(sqlx::AssertSqlSafe(update_sql))
                    .bind(score_cost)
                    .bind(user_id)
                    .bind(score_cost)
                    .execute(pool)
                    .await?
                    .rows_affected(),
            };
            if updated == 0 {
                let delete_sql = match self {
                    Self::Postgres(_) => {
                        format!("DELETE FROM {prefix}players WHERE pid = $1 AND uid = $2")
                    }
                    _ => format!("DELETE FROM {prefix}players WHERE pid = ? AND uid = ?"),
                };
                match self {
                    Self::Sqlite(pool) => {
                        sqlx::query(sqlx::AssertSqlSafe(delete_sql))
                            .bind(player_id)
                            .bind(user_id)
                            .execute(pool)
                            .await?;
                    }
                    Self::MySql(pool) => {
                        sqlx::query(sqlx::AssertSqlSafe(delete_sql))
                            .bind(player_id)
                            .bind(user_id)
                            .execute(pool)
                            .await?;
                    }
                    Self::Postgres(pool) => {
                        sqlx::query(sqlx::AssertSqlSafe(delete_sql))
                            .bind(player_id)
                            .bind(user_id)
                            .execute(pool)
                            .await?;
                    }
                }
                return Ok(PlayerAddOutcome::InsufficientScore);
            }
        }
        let player = self
            .players_for_user(prefix, user_id)
            .await?
            .into_iter()
            .find(|player| player.pid == player_id)
            .ok_or(sqlx::Error::RowNotFound)?;
        Ok(PlayerAddOutcome::Added(player))
    }

    pub async fn delete_player(
        &self,
        prefix: &str,
        user_id: i64,
        player_id: i64,
        return_score: bool,
        score_reward: i64,
    ) -> Result<PlayerDeleteOutcome, sqlx::Error> {
        let Some(player) = self
            .players_for_user(prefix, user_id)
            .await?
            .into_iter()
            .find(|player| player.pid == player_id)
        else {
            return Ok(if self.player_exists(prefix, player_id).await? {
                PlayerDeleteOutcome::Forbidden
            } else {
                PlayerDeleteOutcome::NotFound
            });
        };
        let delete_sql = match self {
            Self::Postgres(_) => format!("DELETE FROM {prefix}players WHERE pid = $1 AND uid = $2"),
            _ => format!("DELETE FROM {prefix}players WHERE pid = ? AND uid = ?"),
        };
        let deleted = match self {
            Self::Sqlite(pool) => sqlx::query(sqlx::AssertSqlSafe(delete_sql))
                .bind(player_id)
                .bind(user_id)
                .execute(pool)
                .await?
                .rows_affected(),
            Self::MySql(pool) => sqlx::query(sqlx::AssertSqlSafe(delete_sql))
                .bind(player_id)
                .bind(user_id)
                .execute(pool)
                .await?
                .rows_affected(),
            Self::Postgres(pool) => sqlx::query(sqlx::AssertSqlSafe(delete_sql))
                .bind(player_id)
                .bind(user_id)
                .execute(pool)
                .await?
                .rows_affected(),
        };
        if deleted == 0 {
            return Ok(if self.player_exists(prefix, player_id).await? {
                PlayerDeleteOutcome::Forbidden
            } else {
                PlayerDeleteOutcome::NotFound
            });
        }
        if return_score && score_reward != 0 {
            let update_sql = match self {
                Self::Postgres(_) => {
                    format!("UPDATE {prefix}users SET score = score + $1 WHERE uid = $2")
                }
                _ => format!("UPDATE {prefix}users SET score = score + ? WHERE uid = ?"),
            };
            match self {
                Self::Sqlite(pool) => {
                    sqlx::query(sqlx::AssertSqlSafe(update_sql))
                        .bind(score_reward)
                        .bind(user_id)
                        .execute(pool)
                        .await?;
                }
                Self::MySql(pool) => {
                    sqlx::query(sqlx::AssertSqlSafe(update_sql))
                        .bind(score_reward)
                        .bind(user_id)
                        .execute(pool)
                        .await?;
                }
                Self::Postgres(pool) => {
                    sqlx::query(sqlx::AssertSqlSafe(update_sql))
                        .bind(score_reward)
                        .bind(user_id)
                        .execute(pool)
                        .await?;
                }
            }
        }
        Ok(PlayerDeleteOutcome::Deleted(player.name))
    }
    pub async fn set_player_textures(
        &self,
        prefix: &str,
        user_id: i64,
        player_id: i64,
        skin: Option<i64>,
        cape: Option<i64>,
    ) -> Result<PlayerTextureOutcome, sqlx::Error> {
        let Some(player) = self
            .players_for_user(prefix, user_id)
            .await?
            .into_iter()
            .find(|player| player.pid == player_id)
        else {
            return Ok(if self.player_exists(prefix, player_id).await? {
                PlayerTextureOutcome::Forbidden
            } else {
                PlayerTextureOutcome::NotFound
            });
        };

        for tid in [skin, cape].into_iter().flatten().filter(|tid| *tid != 0) {
            if !self.texture_exists(prefix, tid).await? {
                return Ok(PlayerTextureOutcome::TextureNotFound);
            }
            if !self.user_has_texture(prefix, user_id, tid).await? {
                return Ok(PlayerTextureOutcome::TextureNotInCloset);
            }
        }
        if let Some(tid) = skin.filter(|tid| *tid != 0) {
            self.update_player_texture(prefix, player_id, user_id, "tid_skin", tid)
                .await?;
        }
        if let Some(tid) = cape.filter(|tid| *tid != 0) {
            self.update_player_texture(prefix, player_id, user_id, "tid_cape", tid)
                .await?;
        }
        let updated = self
            .players_for_user(prefix, user_id)
            .await?
            .into_iter()
            .find(|item| item.pid == player_id)
            .unwrap_or(player);
        Ok(PlayerTextureOutcome::Updated(updated))
    }

    pub async fn clear_player_textures(
        &self,
        prefix: &str,
        user_id: i64,
        player_id: i64,
        skin: bool,
        cape: bool,
    ) -> Result<PlayerTextureOutcome, sqlx::Error> {
        let Some(player) = self
            .players_for_user(prefix, user_id)
            .await?
            .into_iter()
            .find(|player| player.pid == player_id)
        else {
            return Ok(if self.player_exists(prefix, player_id).await? {
                PlayerTextureOutcome::Forbidden
            } else {
                PlayerTextureOutcome::NotFound
            });
        };
        if skin {
            self.update_player_texture(prefix, player_id, user_id, "tid_skin", 0)
                .await?;
        }
        if cape {
            self.update_player_texture(prefix, player_id, user_id, "tid_cape", 0)
                .await?;
        }
        let updated = self
            .players_for_user(prefix, user_id)
            .await?
            .into_iter()
            .find(|item| item.pid == player_id)
            .unwrap_or(player);
        Ok(PlayerTextureOutcome::Updated(updated))
    }

    async fn player_exists(&self, prefix: &str, player_id: i64) -> Result<bool, sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => format!("SELECT COUNT(*) FROM {prefix}players WHERE pid = $1"),
            _ => format!("SELECT COUNT(*) FROM {prefix}players WHERE pid = ?"),
        };
        match self {
            Self::Sqlite(pool) => Ok(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                .bind(player_id)
                .fetch_one(pool)
                .await?
                > 0),
            Self::MySql(pool) => Ok(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                .bind(player_id)
                .fetch_one(pool)
                .await?
                > 0),
            Self::Postgres(pool) => Ok(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                .bind(player_id)
                .fetch_one(pool)
                .await?
                > 0),
        }
    }

    async fn texture_exists(&self, prefix: &str, tid: i64) -> Result<bool, sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => format!("SELECT COUNT(*) FROM {prefix}textures WHERE tid = $1"),
            _ => format!("SELECT COUNT(*) FROM {prefix}textures WHERE tid = ?"),
        };
        match self {
            Self::Sqlite(pool) => Ok(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                .bind(tid)
                .fetch_one(pool)
                .await?
                > 0),
            Self::MySql(pool) => Ok(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                .bind(tid)
                .fetch_one(pool)
                .await?
                > 0),
            Self::Postgres(pool) => Ok(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                .bind(tid)
                .fetch_one(pool)
                .await?
                > 0),
        }
    }

    async fn user_has_texture(
        &self,
        prefix: &str,
        user_id: i64,
        tid: i64,
    ) -> Result<bool, sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => format!(
                "SELECT COUNT(*) FROM {prefix}user_closet WHERE user_uid = $1 AND texture_tid = $2"
            ),
            _ => format!(
                "SELECT COUNT(*) FROM {prefix}user_closet WHERE user_uid = ? AND texture_tid = ?"
            ),
        };
        match self {
            Self::Sqlite(pool) => Ok(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                .bind(user_id)
                .bind(tid)
                .fetch_one(pool)
                .await?
                > 0),
            Self::MySql(pool) => Ok(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                .bind(user_id)
                .bind(tid)
                .fetch_one(pool)
                .await?
                > 0),
            Self::Postgres(pool) => Ok(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                .bind(user_id)
                .bind(tid)
                .fetch_one(pool)
                .await?
                > 0),
        }
    }

    async fn update_player_texture(
        &self,
        prefix: &str,
        player_id: i64,
        user_id: i64,
        column: &str,
        tid: i64,
    ) -> Result<(), sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => format!(
                "UPDATE {prefix}players SET {column} = $1, last_modified = CURRENT_TIMESTAMP \
                 WHERE pid = $2 AND uid = $3"
            ),
            _ => format!(
                "UPDATE {prefix}players SET {column} = ?, last_modified = CURRENT_TIMESTAMP \
                 WHERE pid = ? AND uid = ?"
            ),
        };
        match self {
            Self::Sqlite(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(tid)
                    .bind(player_id)
                    .bind(user_id)
                    .execute(pool)
                    .await?;
            }
            Self::MySql(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(tid)
                    .bind(player_id)
                    .bind(user_id)
                    .execute(pool)
                    .await?;
            }
            Self::Postgres(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(tid)
                    .bind(player_id)
                    .bind(user_id)
                    .execute(pool)
                    .await?;
            }
        }
        Ok(())
    }

    pub async fn notification_recipients(
        &self,
        prefix: &str,
        audience: &NotificationAudience,
    ) -> Result<Option<Vec<i64>>, sqlx::Error> {
        let (sql, targeted) = match (self, audience) {
            (Self::Postgres(_), NotificationAudience::All) => (
                format!("SELECT CAST(uid AS BIGINT) FROM {prefix}users ORDER BY uid"),
                false,
            ),
            (Self::Postgres(_), NotificationAudience::Normal) => (
                format!(
                    "SELECT CAST(uid AS BIGINT) FROM {prefix}users WHERE permission = 0 ORDER BY uid"
                ),
                false,
            ),
            (Self::Postgres(_), NotificationAudience::User(_)) => (
                format!("SELECT CAST(uid AS BIGINT) FROM {prefix}users WHERE uid = $1"),
                true,
            ),
            (Self::Postgres(_), NotificationAudience::Email(_)) => (
                format!("SELECT CAST(uid AS BIGINT) FROM {prefix}users WHERE email = $1"),
                true,
            ),
            (_, NotificationAudience::All) => (
                format!("SELECT CAST(uid AS SIGNED) FROM {prefix}users ORDER BY uid"),
                false,
            ),
            (_, NotificationAudience::Normal) => (
                format!(
                    "SELECT CAST(uid AS SIGNED) FROM {prefix}users WHERE permission = 0 ORDER BY uid"
                ),
                false,
            ),
            (_, NotificationAudience::User(_)) => (
                format!("SELECT CAST(uid AS SIGNED) FROM {prefix}users WHERE uid = ?"),
                true,
            ),
            (_, NotificationAudience::Email(_)) => (
                format!("SELECT CAST(uid AS SIGNED) FROM {prefix}users WHERE email = ?"),
                true,
            ),
        };
        let recipients = match (self, audience) {
            (Self::Sqlite(pool), NotificationAudience::User(user_id)) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                    .bind(user_id)
                    .fetch_all(pool)
                    .await?
            }
            (Self::MySql(pool), NotificationAudience::User(user_id)) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                    .bind(user_id)
                    .fetch_all(pool)
                    .await?
            }
            (Self::Postgres(pool), NotificationAudience::User(user_id)) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                    .bind(user_id)
                    .fetch_all(pool)
                    .await?
            }
            (Self::Sqlite(pool), NotificationAudience::Email(email)) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                    .bind(email)
                    .fetch_all(pool)
                    .await?
            }
            (Self::MySql(pool), NotificationAudience::Email(email)) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                    .bind(email)
                    .fetch_all(pool)
                    .await?
            }
            (Self::Postgres(pool), NotificationAudience::Email(email)) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                    .bind(email)
                    .fetch_all(pool)
                    .await?
            }
            (Self::Sqlite(pool), _) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                    .fetch_all(pool)
                    .await?
            }
            (Self::MySql(pool), _) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                    .fetch_all(pool)
                    .await?
            }
            (Self::Postgres(pool), _) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                    .fetch_all(pool)
                    .await?
            }
        };
        if targeted && recipients.is_empty() {
            Ok(None)
        } else {
            Ok(Some(recipients))
        }
    }

    pub async fn create_site_notification(
        &self,
        prefix: &str,
        id: &str,
        user_id: i64,
        data: &str,
    ) -> Result<(), sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => format!(
                "INSERT INTO {prefix}notifications (id, type, notifiable_type, notifiable_id, data, created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            ),
            _ => format!(
                "INSERT INTO {prefix}notifications (id, type, notifiable_type, notifiable_id, data, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            ),
        };
        match self {
            Self::Sqlite(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(id)
                    .bind("App\\Notifications\\SiteMessage")
                    .bind("App\\Models\\User")
                    .bind(user_id)
                    .bind(data)
                    .execute(pool)
                    .await?;
            }
            Self::MySql(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(id)
                    .bind("App\\Notifications\\SiteMessage")
                    .bind("App\\Models\\User")
                    .bind(user_id)
                    .bind(data)
                    .execute(pool)
                    .await?;
            }
            Self::Postgres(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(id)
                    .bind("App\\Notifications\\SiteMessage")
                    .bind("App\\Models\\User")
                    .bind(user_id)
                    .bind(data)
                    .execute(pool)
                    .await?;
            }
        }
        Ok(())
    }
    pub async fn unread_notifications(
        &self,
        prefix: &str,
        user_id: i64,
    ) -> Result<Vec<NotificationRecord>, sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => format!(
                "SELECT id, data, to_char(created_at, 'YYYY-MM-DD HH24:MI:SS') AS created_at \
                 FROM {prefix}notifications WHERE notifiable_type = $1 AND notifiable_id = $2 \
                 AND read_at IS NULL ORDER BY created_at DESC"
            ),
            Self::MySql(_) => format!(
                "SELECT id, data, DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') AS created_at \
                 FROM {prefix}notifications WHERE notifiable_type = ? AND notifiable_id = ? \
                 AND read_at IS NULL ORDER BY created_at DESC"
            ),
            Self::Sqlite(_) => format!(
                "SELECT id, data, CAST(created_at AS TEXT) AS created_at \
                 FROM {prefix}notifications WHERE notifiable_type = ? AND notifiable_id = ? \
                 AND read_at IS NULL ORDER BY created_at DESC"
            ),
        };
        match self {
            Self::Sqlite(pool) => {
                sqlx::query_as::<_, NotificationRecord>(sqlx::AssertSqlSafe(sql))
                    .bind("App\\Models\\User")
                    .bind(user_id)
                    .fetch_all(pool)
                    .await
            }
            Self::MySql(pool) => {
                sqlx::query_as::<_, NotificationRecord>(sqlx::AssertSqlSafe(sql))
                    .bind("App\\Models\\User")
                    .bind(user_id)
                    .fetch_all(pool)
                    .await
            }
            Self::Postgres(pool) => {
                sqlx::query_as::<_, NotificationRecord>(sqlx::AssertSqlSafe(sql))
                    .bind("App\\Models\\User")
                    .bind(user_id)
                    .fetch_all(pool)
                    .await
            }
        }
    }

    pub async fn read_notification(
        &self,
        prefix: &str,
        user_id: i64,
        id: &str,
    ) -> Result<Option<NotificationRecord>, sqlx::Error> {
        let select_sql = match self {
            Self::Postgres(_) => format!(
                "SELECT id, data, to_char(created_at, 'YYYY-MM-DD HH24:MI:SS') AS created_at \
                 FROM {prefix}notifications WHERE id = $1 AND notifiable_type = $2 \
                 AND notifiable_id = $3 AND read_at IS NULL LIMIT 1"
            ),
            Self::MySql(_) => format!(
                "SELECT id, data, DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') AS created_at \
                 FROM {prefix}notifications WHERE id = ? AND notifiable_type = ? \
                 AND notifiable_id = ? AND read_at IS NULL LIMIT 1"
            ),
            Self::Sqlite(_) => format!(
                "SELECT id, data, CAST(created_at AS TEXT) AS created_at \
                 FROM {prefix}notifications WHERE id = ? AND notifiable_type = ? \
                 AND notifiable_id = ? AND read_at IS NULL LIMIT 1"
            ),
        };
        let notification = match self {
            Self::Sqlite(pool) => {
                sqlx::query_as::<_, NotificationRecord>(sqlx::AssertSqlSafe(select_sql))
                    .bind(id)
                    .bind("App\\Models\\User")
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await?
            }
            Self::MySql(pool) => {
                sqlx::query_as::<_, NotificationRecord>(sqlx::AssertSqlSafe(select_sql))
                    .bind(id)
                    .bind("App\\Models\\User")
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await?
            }
            Self::Postgres(pool) => {
                sqlx::query_as::<_, NotificationRecord>(sqlx::AssertSqlSafe(select_sql))
                    .bind(id)
                    .bind("App\\Models\\User")
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await?
            }
        };
        let Some(notification) = notification else {
            return Ok(None);
        };

        let update_sql = match self {
            Self::Postgres(_) => format!(
                "UPDATE {prefix}notifications SET read_at = CURRENT_TIMESTAMP \
                 WHERE id = $1 AND notifiable_type = $2 AND notifiable_id = $3 AND read_at IS NULL"
            ),
            _ => format!(
                "UPDATE {prefix}notifications SET read_at = CURRENT_TIMESTAMP \
                 WHERE id = ? AND notifiable_type = ? AND notifiable_id = ? AND read_at IS NULL"
            ),
        };
        let updated_rows = match self {
            Self::Sqlite(pool) => sqlx::query(sqlx::AssertSqlSafe(update_sql))
                .bind(id)
                .bind("App\\Models\\User")
                .bind(user_id)
                .execute(pool)
                .await?
                .rows_affected(),
            Self::MySql(pool) => sqlx::query(sqlx::AssertSqlSafe(update_sql))
                .bind(id)
                .bind("App\\Models\\User")
                .bind(user_id)
                .execute(pool)
                .await?
                .rows_affected(),
            Self::Postgres(pool) => sqlx::query(sqlx::AssertSqlSafe(update_sql))
                .bind(id)
                .bind("App\\Models\\User")
                .bind(user_id)
                .execute(pool)
                .await?
                .rows_affected(),
        };
        Ok((updated_rows > 0).then_some(notification))
    }

    pub async fn credentials_by_email(
        &self,
        prefix: &str,
        email: &str,
    ) -> Result<Option<PasswordCredential>, sqlx::Error> {
        self.password_credential(prefix, email, true).await
    }

    pub async fn credentials_by_player_name(
        &self,
        prefix: &str,
        player_name: &str,
    ) -> Result<Option<PasswordCredential>, sqlx::Error> {
        self.password_credential(prefix, player_name, false).await
    }

    async fn password_credential(
        &self,
        prefix: &str,
        identifier: &str,
        is_email: bool,
    ) -> Result<Option<PasswordCredential>, sqlx::Error> {
        let sql = match (self, is_email) {
            (Self::Postgres(_), true) => format!(
                "SELECT CAST(uid AS BIGINT) AS uid, password, permission FROM {prefix}users WHERE email = $1 LIMIT 1"
            ),
            (Self::Postgres(_), false) => format!(
                "SELECT CAST(u.uid AS BIGINT) AS uid, u.password, u.permission FROM {prefix}players p INNER JOIN {prefix}users u ON u.uid = p.uid WHERE p.name = $1 LIMIT 1"
            ),
            (_, true) => format!(
                "SELECT CAST(uid AS BIGINT) AS uid, password, permission FROM {prefix}users WHERE email = ? LIMIT 1"
            ),
            (_, false) => format!(
                "SELECT CAST(u.uid AS BIGINT) AS uid, u.password, u.permission FROM {prefix}players p INNER JOIN {prefix}users u ON u.uid = p.uid WHERE p.name = ? LIMIT 1"
            ),
        };
        match self {
            Self::Sqlite(pool) => Ok(sqlx::query_as::<_, PasswordCredential>(sqlx::AssertSqlSafe(
                sql,
            ))
            .bind(identifier)
            .fetch_optional(pool)
            .await?),
            Self::MySql(pool) => Ok(sqlx::query_as::<_, PasswordCredential>(sqlx::AssertSqlSafe(
                sql,
            ))
            .bind(identifier)
            .fetch_optional(pool)
            .await?),
            Self::Postgres(pool) => Ok(sqlx::query_as::<_, PasswordCredential>(
                sqlx::AssertSqlSafe(sql),
            )
            .bind(identifier)
            .fetch_optional(pool)
            .await?),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::DatabasePool;
    use sqlx::sqlite::SqlitePoolOptions;

    #[tokio::test]
    async fn reads_profiles_and_options_from_legacy_tables() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query("CREATE TABLE bs_users (uid INTEGER PRIMARY KEY, email TEXT NOT NULL DEFAULT '', nickname TEXT NOT NULL DEFAULT '', locale TEXT, score INTEGER NOT NULL DEFAULT 0, avatar INTEGER NOT NULL DEFAULT 0, password TEXT NOT NULL DEFAULT '', ip TEXT NOT NULL DEFAULT '', permission INTEGER NOT NULL, last_sign_at TEXT NOT NULL DEFAULT '', register_at TEXT NOT NULL DEFAULT '', verified BOOLEAN NOT NULL DEFAULT 0, is_dark_mode BOOLEAN NOT NULL DEFAULT 0)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE bs_players (pid INTEGER PRIMARY KEY, uid INTEGER NOT NULL, name TEXT NOT NULL, tid_skin INTEGER, tid_cape INTEGER, last_modified TEXT)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE bs_textures (tid INTEGER PRIMARY KEY, name TEXT NOT NULL, type TEXT NOT NULL, hash TEXT NOT NULL, size INTEGER NOT NULL, uploader INTEGER NOT NULL, public BOOLEAN NOT NULL, upload_at TEXT NOT NULL, likes INTEGER NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE bs_reports (id INTEGER PRIMARY KEY AUTOINCREMENT, tid INTEGER NOT NULL, uploader INTEGER NOT NULL, reporter INTEGER NOT NULL, reason TEXT NOT NULL, status INTEGER NOT NULL, report_at TEXT NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE bs_user_closet (user_uid INTEGER NOT NULL, texture_tid INTEGER NOT NULL, item_name TEXT NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE bs_options (id INTEGER PRIMARY KEY, option_name TEXT NOT NULL, option_value TEXT NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE bs_notifications (id TEXT PRIMARY KEY, type TEXT NOT NULL, notifiable_type TEXT NOT NULL, notifiable_id INTEGER NOT NULL, data TEXT NOT NULL, read_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE bs_oauth_access_tokens (id TEXT PRIMARY KEY, user_id INTEGER, client_id INTEGER NOT NULL, scopes TEXT NOT NULL, revoked BOOLEAN NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO bs_oauth_access_tokens (id, user_id, client_id, scopes, revoked) VALUES ('legacy-token-id', 7, 3, 'User.Read', 0)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO bs_users (uid, email, nickname, locale, score, avatar, permission, last_sign_at, register_at, verified, is_dark_mode) VALUES (7, 'alex@example.test', 'Alex User', 'zh_CN', 42, 11, 0, '2026-10-01 10:00:00', '2025-01-02 03:04:05', 1, 0), (8, 'admin@example.test', 'Admin', 'en', 50, 0, 1, '', '', 1, 0)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO bs_players (pid, uid, name, tid_skin, tid_cape, last_modified) VALUES (3, 7, 'Alex', 11, 12, '2026-10-02 12:00:00'), (4, 8, 'Other', 0, 0, '2026-10-02 13:00:00')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO bs_textures (tid, name, type, hash, size, uploader, public, upload_at, likes) VALUES (11, 'Skin', 'alex', 'skin-hash', 8, 7, 1, '2026-10-01 10:00:00', 1), (12, 'Cape', 'cape', 'cape-hash', 9, 7, 1, '2026-10-01 10:01:00', 1), (13, 'Other skin', 'alex', 'not-in-closet', 10, 8, 1, '2026-10-01 10:02:00', 0), (14, 'Private skin', 'steve', 'private-hash', 11, 8, 0, '2026-10-01 10:03:00', 4), (15, 'Private Alex', 'alex', 'owner-private-hash', 12, 7, 0, '2026-10-01 10:04:00', 2)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO bs_reports (tid, uploader, reporter, reason, status, report_at) VALUES (11, 7, 8, 'duplicate texture', 0, '2026-10-02 14:00:00'), (999, 8, 7, 'missing texture', 1, '2026-10-02 13:00:00')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO bs_user_closet (user_uid, texture_tid, item_name) VALUES (7, 11, 'Alex skin'), (7, 12, 'Alex cape')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO bs_options (id, option_name, option_value) VALUES (1, 'site_name', 'Legacy Instance')")
            .execute(&pool)
            .await
            .unwrap();

        let notice_type = "App\\Models\\Notifications\\SiteMessage";
        let notifiable_type = "App\\Models\\User";
        for (id, uid, read_at) in [
            ("notice-unread", 7_i64, None),
            ("notice-other-user", 8_i64, None),
            ("notice-read", 7_i64, Some("2026-10-01 11:00:00")),
        ] {
            sqlx::query("INSERT INTO bs_notifications (id,type,notifiable_type,notifiable_id,data,read_at,created_at,updated_at) VALUES (?,?,?, ?, ?, ?, '2026-10-01 10:00:00', '2026-10-01 10:00:00')")
                .bind(id)
                .bind(notice_type)
                .bind(notifiable_type)
                .bind(uid)
                .bind(r#"{"title":"Site notice","content":"Hello **skin**"}"#)
                .bind(read_at)
                .execute(&pool)
                .await
                .unwrap();
        }
        let database = DatabasePool::Sqlite(pool.clone());
        assert_eq!(database.all_options("bs_").await.unwrap().len(), 1);
        database
            .set_option("bs_", "site_name", "Updated legacy site")
            .await
            .unwrap();
        database
            .set_option("bs_", "require_verification", "true")
            .await
            .unwrap();
        assert_eq!(
            database
                .option("bs_", "site_name")
                .await
                .unwrap()
                .as_deref(),
            Some("Updated legacy site")
        );
        assert_eq!(
            database
                .option("bs_", "require_verification")
                .await
                .unwrap()
                .as_deref(),
            Some("true")
        );
        assert_eq!(database.all_options("bs_").await.unwrap().len(), 2);
        let (pending_reports, report_count) = database
            .report_management_items(
                "bs_",
                &super::ReportSearchFilters {
                    status: Some(0),
                    ..Default::default()
                },
                "report_at",
                true,
                1,
                9,
            )
            .await
            .unwrap();
        assert_eq!(report_count, 1);
        assert_eq!(pending_reports.len(), 1);
        assert_eq!(pending_reports[0].tid, 11);
        assert_eq!(pending_reports[0].texture_name.as_deref(), Some("Skin"));
        assert_eq!(
            pending_reports[0].texture_uploader_nickname.as_deref(),
            Some("Alex User")
        );
        assert_eq!(
            pending_reports[0].informer_nickname.as_deref(),
            Some("Admin")
        );
        let (resolved_reports, resolved_count) = database
            .report_management_items(
                "bs_",
                &super::ReportSearchFilters {
                    status: Some(1),
                    ..Default::default()
                },
                "report_at",
                true,
                1,
                9,
            )
            .await
            .unwrap();
        assert_eq!(resolved_count, 1);
        assert!(resolved_reports[0].texture_tid.is_none());
        let profile = database
            .player_profile("bs_", "Alex")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(profile.name, "Alex");
        let players = database.players_for_user("bs_", 7).await.unwrap();
        assert_eq!(players.len(), 1);
        assert_eq!(players[0].pid, 3);
        assert_eq!(players[0].uid, 7);
        assert_eq!(players[0].name, "Alex");
        assert_eq!(players[0].tid_skin, 11);
        assert_eq!(players[0].tid_cape, 12);
        assert_eq!(players[0].last_modified, "2026-10-02 12:00:00");
        let unread = database.unread_notifications("bs_", 7).await.unwrap();
        assert_eq!(unread.len(), 1);
        assert_eq!(unread[0].id, "notice-unread");
        let marked_read = database
            .read_notification("bs_", 7, "notice-unread")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            marked_read.data,
            r#"{"title":"Site notice","content":"Hello **skin**"}"#
        );
        assert!(
            database
                .unread_notifications("bs_", 7)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            database
                .read_notification("bs_", 8, "notice-unread")
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            database
                .notification_recipients("bs_", &super::NotificationAudience::All)
                .await
                .unwrap()
                .unwrap(),
            vec![7, 8]
        );
        assert_eq!(
            database
                .notification_recipients("bs_", &super::NotificationAudience::Normal)
                .await
                .unwrap()
                .unwrap(),
            vec![7]
        );
        assert_eq!(
            database
                .notification_recipients("bs_", &super::NotificationAudience::User(7))
                .await
                .unwrap()
                .unwrap(),
            vec![7]
        );
        assert_eq!(
            database
                .notification_recipients(
                    "bs_",
                    &super::NotificationAudience::Email("alex@example.test".to_owned())
                )
                .await
                .unwrap()
                .unwrap(),
            vec![7]
        );
        assert!(
            database
                .notification_recipients(
                    "bs_",
                    &super::NotificationAudience::Email("missing@example.test".to_owned())
                )
                .await
                .unwrap()
                .is_none()
        );
        database
            .create_site_notification(
                "bs_",
                "00000000-0000-4000-8000-000000000001",
                7,
                r#"{"title":"New notice","content":"Updated **skin**"}"#,
            )
            .await
            .unwrap();
        let sent_notification = database
            .read_notification("bs_", 7, "00000000-0000-4000-8000-000000000001")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&sent_notification.data).unwrap()["title"],
            "New notice"
        );
        let email_credential = database
            .credentials_by_email("bs_", "alex@example.test")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(email_credential.uid, 7);
        assert_eq!(email_credential.permission, 0);
        let player_credential = database
            .credentials_by_player_name("bs_", "Alex")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(player_credential.uid, 7);
        let renamed = database
            .rename_player("bs_", 7, 3, "Alex_New")
            .await
            .unwrap();
        match renamed {
            super::PlayerRenameOutcome::Renamed {
                previous_name,
                player,
            } => {
                assert_eq!(previous_name, "Alex");
                assert_eq!(player.name, "Alex_New");
                assert_eq!(player.uid, 7);
            }
            result => panic!("expected a rename, got {result:?}"),
        }
        assert!(matches!(
            database.rename_player("bs_", 7, 3, "Other").await.unwrap(),
            super::PlayerRenameOutcome::NameExists
        ));
        assert!(matches!(
            database
                .rename_player("bs_", 8, 3, "NoAccess")
                .await
                .unwrap(),
            super::PlayerRenameOutcome::Forbidden
        ));
        let textures_set = database
            .set_player_textures("bs_", 7, 3, Some(11), Some(12))
            .await
            .unwrap();
        match textures_set {
            super::PlayerTextureOutcome::Updated(player) => {
                assert_eq!(player.tid_skin, 11);
                assert_eq!(player.tid_cape, 12);
            }
            result => panic!("expected texture update, got {result:?}"),
        }
        assert!(matches!(
            database
                .set_player_textures("bs_", 7, 3, Some(99), None)
                .await
                .unwrap(),
            super::PlayerTextureOutcome::TextureNotFound
        ));
        assert!(matches!(
            database
                .set_player_textures("bs_", 7, 3, Some(13), None)
                .await
                .unwrap(),
            super::PlayerTextureOutcome::TextureNotInCloset
        ));
        assert!(matches!(
            database
                .set_player_textures("bs_", 8, 3, Some(11), None)
                .await
                .unwrap(),
            super::PlayerTextureOutcome::Forbidden
        ));
        assert!(matches!(
            database
                .set_player_textures("bs_", 7, 99, Some(11), None)
                .await
                .unwrap(),
            super::PlayerTextureOutcome::NotFound
        ));
        let textures_cleared = database
            .clear_player_textures("bs_", 7, 3, true, false)
            .await
            .unwrap();
        match textures_cleared {
            super::PlayerTextureOutcome::Updated(player) => {
                assert_eq!(player.tid_skin, 0);
                assert_eq!(player.tid_cape, 12);
            }
            result => panic!("expected texture clear, got {result:?}"),
        }
        let added = database
            .add_player("bs_", 7, "NewPlayer", 10)
            .await
            .unwrap();
        let new_player_id = match added {
            super::PlayerAddOutcome::Added(player) => {
                assert_eq!(player.name, "NewPlayer");
                assert_eq!(player.uid, 7);
                assert_eq!(player.tid_skin, 0);
                assert_eq!(player.tid_cape, 0);
                player.pid
            }
            result => panic!("expected a player to be added, got {result:?}"),
        };
        assert!(matches!(
            database.add_player("bs_", 7, "Alex_New", 1).await.unwrap(),
            super::PlayerAddOutcome::NameExists
        ));
        assert!(matches!(
            database
                .add_player("bs_", 7, "TooExpensive", 100)
                .await
                .unwrap(),
            super::PlayerAddOutcome::InsufficientScore
        ));
        let refunded = database
            .delete_player("bs_", 7, new_player_id, true, 10)
            .await
            .unwrap();
        assert!(matches!(
            refunded,
            super::PlayerDeleteOutcome::Deleted(name) if name == "NewPlayer"
        ));
        let added_without_refund = database.add_player("bs_", 7, "NoRefund", 5).await.unwrap();
        let no_refund_id = match added_without_refund {
            super::PlayerAddOutcome::Added(player) => player.pid,
            result => panic!("expected a player to be added, got {result:?}"),
        };
        assert!(matches!(
            database
                .delete_player("bs_", 7, no_refund_id, false, 5)
                .await
                .unwrap(),
            super::PlayerDeleteOutcome::Deleted(name) if name == "NoRefund"
        ));
        assert!(matches!(
            database.delete_player("bs_", 8, 3, false, 0).await.unwrap(),
            super::PlayerDeleteOutcome::Forbidden
        ));
        assert!(matches!(
            database
                .delete_player("bs_", 7, 99, false, 0)
                .await
                .unwrap(),
            super::PlayerDeleteOutcome::NotFound
        ));
        assert!(matches!(
            database
                .add_closet_item("bs_", 7, 99, "Missing", 0, false, 0)
                .await
                .unwrap(),
            super::ClosetAddOutcome::TextureNotFound
        ));
        assert!(matches!(
            database
                .add_closet_item("bs_", 7, 13, "Too costly", 100, false, 0)
                .await
                .unwrap(),
            super::ClosetAddOutcome::InsufficientScore
        ));
        assert!(matches!(
            database
                .add_closet_item("bs_", 7, 11, "Already saved", 0, false, 0)
                .await
                .unwrap(),
            super::ClosetAddOutcome::NameExists
        ));
        assert!(matches!(
            database
                .add_closet_item("bs_", 7, 14, "Private", 0, false, 0)
                .await
                .unwrap(),
            super::ClosetAddOutcome::PrivateTexture
        ));
        assert!(matches!(
            database
                .add_closet_item("bs_", 7, 14, "Admin saved", 0, true, 0)
                .await
                .unwrap(),
            super::ClosetAddOutcome::Added
        ));
        assert!(matches!(
            database
                .remove_closet_item("bs_", 7, 14, false, 0, 0)
                .await
                .unwrap(),
            super::ClosetRemoveOutcome::Removed
        ));
        assert!(matches!(
            database
                .add_closet_item("bs_", 7, 13, "Second skin", 2, false, 0)
                .await
                .unwrap(),
            super::ClosetAddOutcome::Added
        ));
        assert!(matches!(
            database
                .rename_closet_item("bs_", 7, 13, "Second skin renamed")
                .await
                .unwrap(),
            super::ClosetRenameOutcome::Renamed
        ));
        let (skin_page, skin_total) = database
            .closet_items("bs_", 7, "skin", None, 1, 1)
            .await
            .unwrap();
        assert_eq!(skin_total, 2);
        assert_eq!(skin_page.len(), 1);
        assert_eq!(skin_page[0].tid, 13);
        assert_eq!(skin_page[0].user_uid, 7);
        assert_eq!(skin_page[0].texture_tid, 13);
        assert_eq!(
            skin_page[0].item_name.as_deref(),
            Some("Second skin renamed")
        );
        assert!(skin_page[0].is_public);
        let (next_skin_page, next_skin_total) = database
            .closet_items("bs_", 7, "skin", None, 2, 1)
            .await
            .unwrap();
        assert_eq!(next_skin_total, 2);
        assert_eq!(next_skin_page[0].tid, 11);
        let (searched_items, searched_total) = database
            .closet_items("bs_", 7, "skin", Some("Second"), 1, 6)
            .await
            .unwrap();
        assert_eq!(searched_total, 1);
        assert_eq!(searched_items[0].tid, 13);
        assert_eq!(
            searched_items[0].item_name.as_deref(),
            Some("Second skin renamed")
        );
        assert!(matches!(
            database
                .remove_closet_item("bs_", 7, 13, true, 2, 0)
                .await
                .unwrap(),
            super::ClosetRemoveOutcome::Removed
        ));
        assert!(matches!(
            database
                .remove_closet_item("bs_", 7, 99, false, 0, 0)
                .await
                .unwrap(),
            super::ClosetRemoveOutcome::NotInCloset
        ));
        assert!(matches!(
            database
                .rename_closet_item("bs_", 7, 99, "Missing")
                .await
                .unwrap(),
            super::ClosetRenameOutcome::NotInCloset
        ));
        let texture = database.texture_info("bs_", 13).await.unwrap().unwrap();
        assert_eq!(texture.tid, 13);
        assert_eq!(texture.name, "Other skin");
        assert_eq!(texture.texture_type, "alex");
        assert_eq!(texture.hash, "not-in-closet");
        assert_eq!(texture.size, 10);
        assert_eq!(texture.uploader, 8);
        assert!(texture.is_public);
        assert_eq!(texture.upload_at, "2026-10-01 10:02:00");
        assert_eq!(texture.likes, 0);
        assert!(database.texture_info("bs_", 99).await.unwrap().is_none());
        let skin_likes: i64 = sqlx::query_scalar("SELECT likes FROM bs_textures WHERE tid = 13")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(skin_likes, 0);
        let (cape_items, cape_total) = database
            .closet_items("bs_", 7, "cape", None, 1, 6)
            .await
            .unwrap();
        assert_eq!(cape_total, 1);
        assert_eq!(cape_items[0].texture_type, "cape");
        let (public_skins, public_skin_total) = database
            .skinlib_items("bs_", None, false, "skin", None, None, "time", 1, 20)
            .await
            .unwrap();
        assert_eq!(public_skin_total, 2);
        assert_eq!(public_skins.len(), 2);
        assert_eq!(public_skins[0].tid, 13);
        assert_eq!(public_skins[0].nickname, "Admin");
        let (own_skins, own_skin_total) = database
            .skinlib_items("bs_", Some(7), false, "skin", None, None, "time", 1, 20)
            .await
            .unwrap();
        assert_eq!(own_skin_total, 3);
        assert!(
            own_skins
                .iter()
                .any(|item| item.tid == 15 && !item.is_public)
        );
        let (admin_capes, admin_cape_total) = database
            .skinlib_items("bs_", Some(8), true, "cape", None, None, "time", 1, 20)
            .await
            .unwrap();
        assert_eq!(admin_cape_total, 1);
        assert_eq!(admin_capes[0].tid, 12);
        let (admin_skins, admin_skin_total) = database
            .skinlib_items("bs_", Some(8), true, "skin", None, None, "time", 1, 20)
            .await
            .unwrap();
        assert_eq!(admin_skin_total, 4);
        assert!(
            admin_skins
                .iter()
                .any(|item| item.tid == 14 && !item.is_public)
        );
        let (searched_skins, searched_skin_total) = database
            .skinlib_items(
                "bs_",
                None,
                false,
                "skin",
                Some("Other"),
                None,
                "likes",
                1,
                20,
            )
            .await
            .unwrap();
        assert_eq!(searched_skin_total, 1);
        assert_eq!(searched_skins[0].tid, 13);
        let (uploader_skins, uploader_skin_total) = database
            .skinlib_items("bs_", None, false, "skin", None, Some(8), "likes", 1, 20)
            .await
            .unwrap();
        assert_eq!(uploader_skin_total, 1);
        assert_eq!(uploader_skins[0].tid, 13);
        let (first_skin_page, first_skin_page_total) = database
            .skinlib_items("bs_", None, false, "skin", None, None, "time", 1, 1)
            .await
            .unwrap();
        let (second_skin_page, second_skin_page_total) = database
            .skinlib_items("bs_", None, false, "skin", None, None, "time", 2, 1)
            .await
            .unwrap();
        assert_eq!(first_skin_page_total, 2);
        assert_eq!(second_skin_page_total, 2);
        assert_eq!(first_skin_page[0].tid, 13);
        assert_eq!(second_skin_page[0].tid, 11);
        database
            .rename_texture("bs_", 13, "Renamed texture")
            .await
            .unwrap();
        let renamed_texture = database.texture_info("bs_", 13).await.unwrap().unwrap();
        assert_eq!(renamed_texture.name, "Renamed texture");
        database.set_texture_type("bs_", 13, "steve").await.unwrap();
        let retyped_texture = database.texture_info("bs_", 13).await.unwrap().unwrap();
        assert_eq!(retyped_texture.texture_type, "steve");
        let user = database.user_profile("bs_", 7).await.unwrap().unwrap();
        assert_eq!(user.email, "alex@example.test");
        assert_eq!(user.nickname, "Alex User");
        assert_eq!(user.locale.as_deref(), Some("zh_CN"));
        assert_eq!(user.score, 37);
        assert_eq!(user.avatar, 11);
        assert!(user.verified);
        assert!(!user.is_dark_mode);
        let token = database
            .access_token("bs_", "legacy-token-id")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(token.user_id, Some(7));
        assert_eq!(token.client_id, 3);
        assert!(!token.revoked);
        assert_eq!(profile.permission, 0);
        assert_eq!(profile.skin_type.as_deref(), Some("alex"));
        assert_eq!(profile.skin_hash.as_deref(), Some("skin-hash"));
        assert_eq!(profile.cape_hash.as_deref(), Some("cape-hash"));
        assert_eq!(
            profile.last_modified.as_deref(),
            Some("2026-10-02 12:00:00")
        );
        assert_eq!(
            database
                .option("bs_", "site_name")
                .await
                .unwrap()
                .as_deref(),
            Some("Updated legacy site")
        );
        assert_eq!(
            database.texture_hash("bs_", 12).await.unwrap().as_deref(),
            Some("cape-hash")
        );
        assert_eq!(
            database
                .submit_report("bs_", 13, 8, 7, "Not appropriate", -50)
                .await
                .unwrap(),
            super::ReportSubmissionOutcome::InsufficientScore
        );
        let reports_after_rejection: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM bs_reports WHERE reporter = 7 AND tid = 13")
                .fetch_one(&pool)
                .await
                .unwrap();
        let score_after_rejection: i64 =
            sqlx::query_scalar("SELECT score FROM bs_users WHERE uid = 7")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(reports_after_rejection, 0);
        assert_eq!(score_after_rejection, 37);
        assert_eq!(
            database
                .submit_report("bs_", 13, 8, 7, "Not appropriate", 3)
                .await
                .unwrap(),
            super::ReportSubmissionOutcome::Submitted
        );
        assert_eq!(
            database
                .submit_report("bs_", 13, 8, 7, "Repeated report", -100)
                .await
                .unwrap(),
            super::ReportSubmissionOutcome::AlreadyReported
        );
        let report_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM bs_reports WHERE reporter = 7 AND tid = 13")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(report_count, 1);
        let report = sqlx::query_as::<_, (i64, i64, i64, String, i64)>(
            "SELECT tid, uploader, reporter, reason, status FROM bs_reports WHERE tid = 13 AND reporter = 7",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(report, (13, 8, 7, "Not appropriate".to_owned(), 0));
        let reporter_score: i64 = sqlx::query_scalar("SELECT score FROM bs_users WHERE uid = 7")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(reporter_score, 40);
        sqlx::query("INSERT INTO bs_textures (tid, name, type, hash, size, uploader, public, upload_at, likes) VALUES (16, 'Duplicate private', 'alex', 'owner-private-hash', 12, 8, 1, '2026-10-02 10:00:00', 0)")
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            database
                .toggle_texture_privacy("bs_", 13, 8, "not-in-closet", true, -4)
                .await
                .unwrap(),
            super::TexturePrivacyOutcome::Updated { is_public: false }
        );
        assert_eq!(
            database
                .toggle_texture_privacy("bs_", 13, 8, "not-in-closet", false, -100)
                .await
                .unwrap(),
            super::TexturePrivacyOutcome::InsufficientScore
        );
        assert_eq!(
            database
                .toggle_texture_privacy("bs_", 15, 7, "owner-private-hash", false, -1)
                .await
                .unwrap(),
            super::TexturePrivacyOutcome::DuplicatePublicTexture(16)
        );
        assert_eq!(
            database
                .toggle_texture_privacy("bs_", 14, 8, "private-hash", false, -1)
                .await
                .unwrap(),
            super::TexturePrivacyOutcome::Updated { is_public: true }
        );
        let private_score: i64 = sqlx::query_scalar("SELECT score FROM bs_users WHERE uid = 8")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(private_score, 45);
        sqlx::query("UPDATE bs_players SET tid_skin = 14, tid_cape = 14 WHERE pid = 4")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO bs_user_closet (user_uid, texture_tid, item_name) VALUES (7, 14, 'Other liker'), (8, 14, 'Uploader item')")
            .execute(&pool)
            .await
            .unwrap();
        let public_private_texture = database.texture_info("bs_", 14).await.unwrap().unwrap();
        assert!(
            database
                .delete_texture("bs_", &public_private_texture, -3, 2)
                .await
                .unwrap()
        );
        assert!(database.texture_info("bs_", 14).await.unwrap().is_none());
        let cleared_player: (i64, i64) =
            sqlx::query_as("SELECT tid_skin, tid_cape FROM bs_players WHERE pid = 4")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(cleared_player, (0, 0));
        let uploader_closet_rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM bs_user_closet WHERE texture_tid = 14 AND user_uid = 8",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let other_closet_rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM bs_user_closet WHERE texture_tid = 14 AND user_uid = 7",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(uploader_closet_rows, 1);
        assert_eq!(other_closet_rows, 0);
        let rewarded_user_score: i64 =
            sqlx::query_scalar("SELECT score FROM bs_users WHERE uid = 7")
                .fetch_one(&pool)
                .await
                .unwrap();
        let refunded_uploader_score: i64 =
            sqlx::query_scalar("SELECT score FROM bs_users WHERE uid = 8")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(rewarded_user_score, 42);
        assert_eq!(refunded_uploader_score, 42);
        assert_eq!(
            database
                .upload_texture("bs_", "duplicate", "alex", "not-in-closet", 10, 8, true, 1)
                .await
                .unwrap(),
            super::TextureUploadOutcome::AlreadyUploaded(13)
        );
        assert_eq!(
            database
                .upload_texture("bs_", "too costly", "steve", "new-hash", 2, 7, true, 100)
                .await
                .unwrap(),
            super::TextureUploadOutcome::InsufficientScore
        );
        let uploaded_tid = match database
            .upload_texture("bs_", "New upload", "alex", "new-hash", 2, 7, true, 5)
            .await
            .unwrap()
        {
            super::TextureUploadOutcome::Uploaded(tid) => tid,
            other => panic!("unexpected texture upload outcome: {other:?}"),
        };
        let uploaded_texture = database
            .texture_info("bs_", uploaded_tid)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(uploaded_texture.name, "New upload");
        assert_eq!(uploaded_texture.texture_type, "alex");
        assert_eq!(uploaded_texture.hash, "new-hash");
        assert_eq!(uploaded_texture.size, 2);
        assert!(uploaded_texture.is_public);
        assert_eq!(
            database
                .upload_texture(
                    "bs_",
                    "different uploader",
                    "steve",
                    "new-hash",
                    2,
                    8,
                    true,
                    0
                )
                .await
                .unwrap(),
            super::TextureUploadOutcome::AlreadyUploaded(uploaded_tid)
        );
        let upload_closet_item: Option<String> = sqlx::query_scalar(
            "SELECT item_name FROM bs_user_closet WHERE user_uid = 7 AND texture_tid = ?",
        )
        .bind(uploaded_tid)
        .fetch_optional(&pool)
        .await
        .unwrap();
        assert_eq!(upload_closet_item.as_deref(), Some("New upload"));
        let upload_score: i64 = sqlx::query_scalar("SELECT score FROM bs_users WHERE uid = 7")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(upload_score, 37);
        let shared_texture = database.texture_info("bs_", 15).await.unwrap().unwrap();
        assert!(
            !database
                .delete_texture("bs_", &shared_texture, 0, 0)
                .await
                .unwrap()
        );
        let score_before_rejection: i64 =
            sqlx::query_scalar("SELECT score FROM bs_users WHERE uid = 8")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            database.reject_report("bs_", 1, 5).await.unwrap(),
            super::ReportReviewOutcome::Rejected
        );
        assert_eq!(
            database.reject_report("bs_", 1, 5).await.unwrap(),
            super::ReportReviewOutcome::Rejected
        );
        let reporter_score: i64 = sqlx::query_scalar("SELECT score FROM bs_users WHERE uid = 8")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(reporter_score, score_before_rejection - 5);
        let rejected_status: i64 = sqlx::query_scalar("SELECT status FROM bs_reports WHERE id = 1")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(rejected_status, 2);
        sqlx::query("INSERT INTO bs_reports (id, tid, uploader, reporter, reason, status, report_at) VALUES (100, 13, 8, 7, 'abusive skin', 0, '2026-10-02 15:00:00'), (101, 11, 7, 8, 'admin target', 0, '2026-10-02 16:00:00')")
            .execute(&pool)
            .await
            .unwrap();
        let reporter_score_before_ban: i64 =
            sqlx::query_scalar("SELECT score FROM bs_users WHERE uid = 7")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            database
                .ban_report_uploader("bs_", 100, 2, -3, 5)
                .await
                .unwrap(),
            super::ReportReviewOutcome::Resolved
        );
        let reporter_score_after_ban: i64 =
            sqlx::query_scalar("SELECT score FROM bs_users WHERE uid = 7")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(reporter_score_after_ban, reporter_score_before_ban + 8);
        let banned_permission: i64 =
            sqlx::query_scalar("SELECT permission FROM bs_users WHERE uid = 8")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(banned_permission, -1);
        let resolved_status: i64 =
            sqlx::query_scalar("SELECT status FROM bs_reports WHERE id = 100")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(resolved_status, 1);
        assert_eq!(
            database
                .ban_report_uploader("bs_", 101, 0, -3, 5)
                .await
                .unwrap(),
            super::ReportReviewOutcome::UploaderPermissionDenied
        );
    }

    #[tokio::test]
    async fn oauth_client_management_is_owner_scoped_and_revokes_credentials() {
        use sqlx::sqlite::SqlitePoolOptions;

        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
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
        sqlx::query("CREATE TABLE oauth_auth_codes (id TEXT PRIMARY KEY, user_id INTEGER, client_id INTEGER NOT NULL, scopes TEXT NOT NULL, revoked BOOLEAN NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO oauth_clients (id,user_id,name,secret,provider,redirect,personal_access_client,password_client,revoked,created_at,updated_at) VALUES (1,7,'Legacy app','legacy-secret',NULL,'https://legacy.test/callback',0,0,0,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP),(2,8,'Another user app','other-secret',NULL,'https://other.test/callback',0,0,0,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP),(3,7,'Personal client','personal-secret',NULL,'http://localhost',1,0,0,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO oauth_access_tokens (id,user_id,client_id,scopes,revoked) VALUES ('legacy-access',7,1,'User.Read',0)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO oauth_refresh_tokens (id,access_token_id,revoked) VALUES ('legacy-refresh','legacy-access',0)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO oauth_auth_codes (id,user_id,client_id,scopes,revoked) VALUES ('legacy-code',7,1,'User.Read',0)")
            .execute(&pool)
            .await
            .unwrap();

        let database = super::DatabasePool::Sqlite(pool.clone());
        let clients = database.oauth_clients_for_user("", 7).await.unwrap();
        assert_eq!(clients.len(), 1);
        assert_eq!(clients[0].id, 1);
        assert_eq!(clients[0].secret, "legacy-secret");
        assert!(database.oauth_clients_for_user("", 8).await.unwrap().len() == 1);

        let created = database
            .create_oauth_client("", 7, "New app", "new-secret", "https://new.test/callback")
            .await
            .unwrap();
        assert_eq!(created.name, "New app");
        assert!(
            database
                .update_oauth_client("", 7, created.id, "Renamed app", "https://new.test/return")
                .await
                .unwrap()
        );
        assert!(
            !database
                .update_oauth_client("", 8, created.id, "Stolen", "https://evil.test/")
                .await
                .unwrap()
        );
        let updated = database.oauth_clients_for_user("", 7).await.unwrap();
        assert_eq!(
            updated
                .iter()
                .find(|client| client.id == created.id)
                .unwrap()
                .name,
            "Renamed app"
        );
        assert_eq!(
            updated
                .iter()
                .find(|client| client.id == created.id)
                .unwrap()
                .redirect,
            "https://new.test/return"
        );

        assert_eq!(
            database.revoke_oauth_client("", 8, 1).await.unwrap(),
            super::OAuthClientDeleteOutcome::NotFound
        );
        assert_eq!(
            database.revoke_oauth_client("", 7, 1).await.unwrap(),
            super::OAuthClientDeleteOutcome::Revoked
        );
        assert_eq!(
            database.revoke_oauth_client("", 7, 1).await.unwrap(),
            super::OAuthClientDeleteOutcome::NotFound
        );
        let revoked_access: bool = sqlx::query_scalar(
            "SELECT revoked FROM oauth_access_tokens WHERE id = 'legacy-access'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let revoked_refresh: bool = sqlx::query_scalar(
            "SELECT revoked FROM oauth_refresh_tokens WHERE id = 'legacy-refresh'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let revoked_code: bool =
            sqlx::query_scalar("SELECT revoked FROM oauth_auth_codes WHERE id = 'legacy-code'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(revoked_access && revoked_refresh && revoked_code);
    }
}

#[cfg(test)]
mod language_line_tests {
    use super::DatabasePool;
    use sqlx::sqlite::SqlitePoolOptions;

    #[tokio::test]
    async fn language_line_crud_preserves_other_locales_and_paginates() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE bs_language_lines (id INTEGER PRIMARY KEY AUTOINCREMENT, \"group\" TEXT NOT NULL, \"key\" TEXT NOT NULL, text TEXT NOT NULL, created_at TEXT, updated_at TEXT, UNIQUE(\"group\", \"key\"))",
        )
        .execute(&pool)
        .await
        .unwrap();
        let database = DatabasePool::Sqlite(pool);

        assert!(
            !database
                .language_line_exists("bs_", "front-end", "nav.home")
                .await
                .unwrap()
        );
        let id = database
            .create_language_line("bs_", "front-end", "nav.home", "en", "Home")
            .await
            .unwrap();
        assert!(
            database
                .language_line_exists("bs_", "front-end", "nav.home")
                .await
                .unwrap()
        );
        assert!(
            database
                .update_language_line("bs_", id, "zh_CN", "首页")
                .await
                .unwrap()
        );

        let (rows, total) = database.language_lines_page("bs_", 1, 10).await.unwrap();
        assert_eq!(total, 1);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].group_name, "front-end");
        assert_eq!(rows[0].key, "nav.home");
        let translations: serde_json::Value = serde_json::from_str(&rows[0].text).unwrap();
        assert_eq!(translations["en"], "Home");
        assert_eq!(translations["zh_CN"], "首页");

        assert!(database.delete_language_line("bs_", id).await.unwrap());
        assert!(!database.delete_language_line("bs_", id).await.unwrap());
        let (rows, total) = database.language_lines_page("bs_", 1, 10).await.unwrap();
        assert!(rows.is_empty());
        assert_eq!(total, 0);
    }
}
