mod admin_settings;
mod auth;
mod config;
mod database;
mod defuse;
mod http;
mod image_cache;
mod install_command;
mod installer;
mod mailer;
mod oauth;
mod plugin_command;
mod plugin_runtime;
mod salt_command;
mod skin_renderer;
mod update;
mod update_command;

use std::{
    collections::HashMap,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex, RwLock},
    time::Instant,
};

use config::Config;
use database::DatabasePool;
use jsonwebtoken::{DecodingKey, EncodingKey};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub database: Option<DatabasePool>,
    pub storage_dir: PathBuf,
    pub env_file: PathBuf,
    pub public_dir: PathBuf,
    pub passport_key: Option<DecodingKey>,
    pub passport_signing_key: Option<EncodingKey>,
    pub session_key: Option<EncodingKey>,
    pub revoked_web_sessions: Arc<RwLock<HashMap<String, u64>>>,
    pub login_failures: Arc<Mutex<HashMap<String, (u32, Instant)>>>,
    pub captcha_challenges: Arc<Mutex<HashMap<String, (String, Instant)>>>,
    pub mail_limits: Arc<Mutex<HashMap<String, Instant>>>,
    pub image_cache: Arc<image_cache::ImageCache>,
    pub wasm_plugins: Vec<String>,
    pub wasm_plugin_load_failures: Vec<String>,
    pub wasm_plugin_readmes: Vec<String>,
    pub wasm_plugin_configurations: Vec<String>,
    pub wasm_runtime: Arc<tokio::sync::Mutex<plugin_runtime::PluginRuntime>>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (env_file, env_file_error) = if let Some(env_file) = std::env::var_os("BS_ENV_FILE") {
        let path = PathBuf::from(env_file);
        let error = dotenvy::from_path(&path)
            .err()
            .map(|error| error.to_string());
        (path, error)
    } else {
        match dotenvy::dotenv() {
            Ok(path) => (path, None),
            Err(_) => (PathBuf::from(".env"), None),
        }
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    if let Some(error) = env_file_error {
        tracing::warn!(%error, "could not load the configured environment file");
    }

    let storage_dir = PathBuf::from(
        crate::config::legacy_env("STORAGE_PATH").unwrap_or_else(|| "storage".to_owned()),
    );
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if let Some(result) = salt_command::run(&arguments, &env_file, &storage_dir)? {
        if result.persisted {
            println!("Application salt [{}] set successfully.", result.salt);
        } else {
            println!("{}", result.salt);
        }
        return Ok(());
    }

    let plugins_dir = crate::config::legacy_env("PLUGINS_DIR")
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| storage_dir.join("plugins"));
    if let Some(outcome) = plugin_command::run(&arguments, &plugins_dir)? {
        let message = match outcome {
            plugin_command::PluginCommandOutcome::Enabled => {
                "Plugin enabled. Restart the service for the change to take effect."
            }
            plugin_command::PluginCommandOutcome::Disabled => {
                "Plugin disabled. Restart the service for the change to take effect."
            }
            plugin_command::PluginCommandOutcome::AlreadyEnabled => "Plugin is already enabled.",
            plugin_command::PluginCommandOutcome::AlreadyDisabled => "Plugin is already disabled.",
            plugin_command::PluginCommandOutcome::NotFound => "WASM plugin not found.",
        };
        println!("{message}");
        return Ok(());
    }

    if let Some(arguments) = install_command::parse(&arguments)? {
        if storage_dir.join("install.lock").exists() {
            println!("You have installed Blessing Skin Server. Nothing to do.");
            return Ok(());
        }
        let config = Config::from_env()?;
        let site_name = crate::config::legacy_env("BS_INSTALL_SITE_NAME")
            .unwrap_or_else(|| "Blessing Skin".to_owned());
        installer::install_with_details(
            &config,
            &storage_dir,
            &arguments.email,
            &arguments.nickname,
            &arguments.password,
            &site_name,
        )
        .await?;
        println!("Installation completed!");
        println!("We recommend to modify your Site URL option if incorrect.");
        return Ok(());
    }

    if update_command::parse(&arguments)? {
        let config = Config::from_env()?;
        let database = DatabasePool::connect(&config.database).await?;
        let result = update_command::run(
            &database,
            &config.database.table_prefix,
            &storage_dir,
            &config.legacy_app_version,
        )
        .await?;
        println!("Legacy database updated to {}.", config.legacy_app_version);
        if result.background_migrated {
            println!("Updated the legacy default background to WebP.");
        }
        println!("Restart the Rust service to complete the upgrade.");
        return Ok(());
    }

    let config = Arc::new(Config::from_env()?);
    let public_dir = PathBuf::from(
        crate::config::legacy_env("PUBLIC_PATH").unwrap_or_else(|| "public".to_owned()),
    );
    if std::env::args().nth(1).as_deref() == Some("install") {
        installer::run(&config).await?;
        return Ok(());
    }
    let database = match DatabasePool::connect(&config.database).await {
        Ok(pool) => Some(pool),
        Err(error) => {
            tracing::warn!(%error, "database is not ready; health endpoints remain available");
            None
        }
    };
    let revoked_web_sessions = Arc::new(RwLock::new(HashMap::new()));
    if let Some(database) = &database {
        database
            .ensure_web_session_revocations_schema(&config.database.table_prefix)
            .await?;
        let now = jsonwebtoken::get_current_timestamp();
        let now_i64 = i64::try_from(now).unwrap_or(i64::MAX);
        let revoked = database
            .active_web_session_revocations(&config.database.table_prefix, now_i64)
            .await?;
        *revoked_web_sessions
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = revoked.into_iter().collect();

        let database = database.clone();
        let table_prefix = config.database.table_prefix.clone();
        let revoked_web_sessions = revoked_web_sessions.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(15 * 60)).await;
                let now = jsonwebtoken::get_current_timestamp();
                let now_i64 = i64::try_from(now).unwrap_or(i64::MAX);
                if let Err(error) = database
                    .delete_expired_web_session_revocations(&table_prefix, now_i64)
                    .await
                {
                    tracing::warn!(%error, "could not clean expired web session revocations");
                    continue;
                }
                revoked_web_sessions
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .retain(|_, expires_at| *expires_at > now);
            }
        });
    }

    let plugins = plugin_runtime::PluginRuntime::load(
        &config.plugins_dir,
        database.clone(),
        &config.database.table_prefix,
    )
    .await?;
    let wasm_plugins = plugins.loaded_plugin_names();
    let wasm_plugin_readmes = plugins.plugin_readme_names();
    let wasm_plugin_configurations = plugins.plugin_configuration_names();
    let wasm_plugin_load_failures = plugins.failed_plugin_names();
    let wasm_runtime = Arc::new(tokio::sync::Mutex::new(plugins));

    let session_key = config
        .app_key
        .as_deref()
        .map(|key| EncodingKey::from_secret(key.as_bytes()));
    let address: SocketAddr = config.bind;
    let passport_key = config.passport_public_key.as_deref().and_then(|key| {
        match DecodingKey::from_rsa_pem(key) {
            Ok(key) => Some(key),
            Err(error) => {
                tracing::error!(%error, "configured Passport public key is invalid");
                None
            }
        }
    });
    let passport_signing_key = config.passport_private_key.as_deref().and_then(|key| {
        match EncodingKey::from_rsa_pem(key) {
            Ok(key) => Some(key),
            Err(error) => {
                tracing::error!(%error, "configured Passport private key is invalid");
                None
            }
        }
    });
    let app = http::router(AppState {
        config,
        database,
        storage_dir,
        env_file,
        public_dir,
        passport_key,
        passport_signing_key,
        session_key,
        revoked_web_sessions,
        login_failures: Arc::new(Mutex::new(HashMap::new())),
        captcha_challenges: Arc::new(Mutex::new(HashMap::new())),
        mail_limits: Arc::new(Mutex::new(HashMap::new())),
        image_cache: image_cache::ImageCache::shared(),
        wasm_plugins,
        wasm_plugin_readmes,
        wasm_plugin_configurations,
        wasm_plugin_load_failures,
        wasm_runtime: wasm_runtime.clone(),
    });
    let listener = TcpListener::bind(address).await?;
    tracing::info!(%address, "Blessing Skin Rust service listening");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    wasm_runtime.lock().await.shutdown().await;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        let _ = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
