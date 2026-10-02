use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::any,
};
use serde::Serialize;

use crate::{AppState, database::DatabasePool};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health/live", any(live))
        .route("/health/ready", any(ready))
        .route("/api", any(api_root))
        .route("/api/", any(api_root))
        .with_state(state)
}

#[derive(Serialize)]
struct Health {
    status: &'static str,
}

async fn live() -> Json<Health> {
    Json(Health { status: "ok" })
}

async fn ready(State(state): State<AppState>) -> Response {
    match &state.database {
        Some(database) if database.ping().await.is_ok() => {
            (StatusCode::OK, Json(Health { status: "ready" })).into_response()
        }
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(Health {
                status: "not_ready",
            }),
        )
            .into_response(),
    }
}

#[derive(Serialize)]
struct ApiRoot {
    blessing_skin: &'static str,
    spec: u8,
    copyright: &'static str,
    site_name: String,
}

async fn api_root(State(state): State<AppState>) -> Response {
    let Some(database) = &state.database else {
        return unavailable();
    };
    match build_api_root(database, &state).await {
        Ok(root) => Json(root).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to load public API metadata");
            unavailable()
        }
    }
}

async fn build_api_root(database: &DatabasePool, state: &AppState) -> Result<ApiRoot, sqlx::Error> {
    let locale_key = format!("copyright_prefer_{}", state.config.locale);
    let preference = database
        .option(&state.config.database.table_prefix, &locale_key)
        .await?
        .or(database
            .option(&state.config.database.table_prefix, "copyright_prefer")
            .await?);
    let copyright_index = preference
        .as_deref()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or_default();
    let copyright = COPYRIGHTS
        .get(copyright_index)
        .copied()
        .unwrap_or(COPYRIGHTS[0]);
    let site_name = database
        .option(&state.config.database.table_prefix, "site_name")
        .await?
        .unwrap_or_else(|| "Blessing Skin".to_owned());

    Ok(ApiRoot {
        blessing_skin: state.config.version,
        spec: 0,
        copyright,
        site_name,
    })
}

fn unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(Health {
            status: "not_ready",
        }),
    )
        .into_response()
}

const COPYRIGHTS: [&str; 7] = [
    "Powered with ❤ by Blessing Skin Server.",
    "Powered by Blessing Skin Server.",
    "Proudly powered by Blessing Skin Server.",
    "由 Blessing Skin Server 强力驱动。",
    "采用 Blessing Skin Server 搭建。",
    "使用 Blessing Skin Server 稳定运行。",
    "自豪地采用 Blessing Skin Server。",
];

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, sync::Arc};

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use sqlx::sqlite::SqliteConnectOptions;
    use tower::ServiceExt;

    use crate::{
        AppState,
        config::{Config, DatabaseConfig, DatabaseConnection},
    };

    use super::router;

    fn state() -> AppState {
        AppState {
            config: Arc::new(Config {
                bind: "127.0.0.1:3000".parse().unwrap(),
                version: "test",
                locale: "zh_CN".to_owned(),
                database: DatabaseConfig {
                    connection: DatabaseConnection::Sqlite(
                        SqliteConnectOptions::new().filename(":memory:"),
                    ),
                    table_prefix: String::new(),
                },
                textures_dir: PathBuf::from("storage/textures"),
                plugins_dir: PathBuf::from("storage/plugins"),
                app_url: "http://localhost".to_owned(),
            }),
            database: None,
        }
    }

    #[tokio::test]
    async fn liveness_is_ok_while_readiness_waits_for_database() {
        let app = router(state());
        let live = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/health/live")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let ready = app
            .oneshot(
                Request::builder()
                    .uri("/health/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(live.status(), StatusCode::OK);
        assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
