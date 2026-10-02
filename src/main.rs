mod admin_settings;
mod auth;
mod config;
mod database;
mod defuse;
mod http;
mod mailer;
mod oauth;
mod plugin_runtime;

use std::{
    collections::HashMap,
    net::SocketAddr,
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
    pub passport_key: Option<DecodingKey>,
    pub passport_signing_key: Option<EncodingKey>,
    pub session_key: Option<EncodingKey>,
    pub login_failures: Arc<Mutex<HashMap<String, (u32, Instant)>>>,
    pub captcha_challenges: Arc<Mutex<HashMap<String, (String, Instant)>>>,
    pub mail_limits: Arc<Mutex<HashMap<String, Instant>>>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = dotenvy::dotenv();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = Arc::new(Config::from_env()?);
    let mut plugins = plugin_runtime::PluginRuntime::load(&config.plugins_dir)?;
    let database = match DatabasePool::connect(&config.database).await {
        Ok(pool) => Some(pool),
        Err(error) => {
            tracing::warn!(%error, "database is not ready; health endpoints remain available");
            None
        }
    };

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
        passport_key,
        passport_signing_key,
        session_key,
        login_failures: Arc::new(Mutex::new(HashMap::new())),
        captcha_challenges: Arc::new(Mutex::new(HashMap::new())),
        mail_limits: Arc::new(Mutex::new(HashMap::new())),
    });
    let listener = TcpListener::bind(address).await?;
    tracing::info!(%address, "Blessing Skin Rust service listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    plugins.shutdown();
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
