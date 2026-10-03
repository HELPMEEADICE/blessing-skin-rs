mod admin_settings;
mod auth;
mod config;
mod database;
mod defuse;
mod http;
mod image_cache;
mod installer;
mod mailer;
mod oauth;
mod plugin_runtime;
mod skin_renderer;

use std::{
    collections::HashMap,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
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
    pub login_failures: Arc<Mutex<HashMap<String, (u32, Instant)>>>,
    pub captcha_challenges: Arc<Mutex<HashMap<String, (String, Instant)>>>,
    pub mail_limits: Arc<Mutex<HashMap<String, Instant>>>,
    pub image_cache: Arc<image_cache::ImageCache>,
    pub wasm_plugins: Vec<String>,
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

    let config = Arc::new(Config::from_env()?);
    let storage_dir =
        PathBuf::from(std::env::var("STORAGE_PATH").unwrap_or_else(|_| "storage".to_owned()));
    let public_dir =
        PathBuf::from(std::env::var("PUBLIC_PATH").unwrap_or_else(|_| "public".to_owned()));
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
    let plugins = plugin_runtime::PluginRuntime::load(
        &config.plugins_dir,
        database.clone(),
        &config.database.table_prefix,
    )
    .await?;
    let wasm_plugins = plugins.loaded_plugin_names();
    let wasm_plugin_readmes = plugins.plugin_readme_names();
    let wasm_plugin_configurations = plugins.plugin_configuration_names();
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
        login_failures: Arc::new(Mutex::new(HashMap::new())),
        captcha_challenges: Arc::new(Mutex::new(HashMap::new())),
        mail_limits: Arc::new(Mutex::new(HashMap::new())),
        image_cache: image_cache::ImageCache::shared(),
        wasm_plugins,
        wasm_plugin_readmes,
        wasm_plugin_configurations,
        wasm_runtime: wasm_runtime.clone(),
    });
    let listener = TcpListener::bind(address).await?;
    tracing::info!(%address, "Blessing Skin Rust service listening");

    axum::serve(listener, app)
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
