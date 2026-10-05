use semver::Version;
use std::{error::Error, io, path::Path};

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct UpdateSummary {
    pub(crate) previous_version: String,
    pub(crate) background_migrated: bool,
}

pub(crate) fn parse(arguments: &[String]) -> Result<bool, io::Error> {
    match arguments.first().map(String::as_str) {
        Some("update") if arguments.len() == 1 => Ok(true),
        Some("update") => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: blessing-skin-rs update",
        )),
        _ => Ok(false),
    }
}

/// Apply the Rust release's legacy option updates after the binary has been replaced.
/// Core PHP migrations and PHP cache backends are deliberately not invoked here.
pub(crate) async fn run(
    database: &crate::database::DatabasePool,
    table_prefix: &str,
    storage_dir: &Path,
    target_version: &str,
) -> Result<UpdateSummary, Box<dyn Error>> {
    let previous_version = database
        .option(table_prefix, "version")
        .await?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "legacy options have no version; refusing to mark this database installed",
            )
        })?;
    let parsed_version = Version::parse(
        previous_version
            .trim()
            .strip_prefix('v')
            .unwrap_or(previous_version.trim()),
    )
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let normalized_target = target_version.trim();
    Version::parse(
        normalized_target
            .strip_prefix('v')
            .unwrap_or(normalized_target),
    )
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    invalidate_legacy_option_cache(storage_dir)?;
    let background_migrated = if parsed_version < Version::new(5, 0, 0)
        && database
            .option(table_prefix, "home_pic_url")
            .await?
            .as_deref()
            == Some("./app/bg.jpg")
    {
        database
            .set_option(table_prefix, "home_pic_url", "./app/bg.webp")
            .await?;
        true
    } else {
        false
    };
    database
        .set_option(table_prefix, "version", target_version)
        .await?;

    std::fs::create_dir_all(storage_dir)?;
    std::fs::write(storage_dir.join("install.lock"), b"")?;

    Ok(UpdateSummary {
        previous_version,
        background_migrated,
    })
}

fn invalidate_legacy_option_cache(storage_dir: &Path) -> io::Result<()> {
    match std::fs::remove_file(storage_dir.join("options.php")) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::DatabasePool;
    use sqlx::sqlite::SqlitePoolOptions;
    use std::path::PathBuf;

    async fn test_database(options: &[(&str, &str)]) -> DatabasePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE options (option_name TEXT PRIMARY KEY, option_value TEXT NOT NULL)",
        )
        .execute(&pool)
        .await
        .unwrap();
        for (name, value) in options {
            sqlx::query("INSERT INTO options (option_name, option_value) VALUES (?, ?)")
                .bind(name)
                .bind(value)
                .execute(&pool)
                .await
                .unwrap();
        }
        DatabasePool::Sqlite(pool)
    }

    fn test_storage(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "blessing-update-{label}-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn recognizes_only_the_legacy_update_command() {
        assert!(!parse(&[]).unwrap());
        assert!(!parse(&["install".into()]).unwrap());
        assert!(parse(&["update".into()]).unwrap());
        assert_eq!(
            parse(&["update".into(), "unexpected".into()])
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[tokio::test]
    async fn upgrades_legacy_version_background_and_install_marker() {
        let database = test_database(&[
            ("version", "4.9.9"),
            ("home_pic_url", "./app/bg.jpg"),
            ("site_name", "Keep this option"),
        ])
        .await;
        let storage = test_storage("legacy");
        std::fs::write(
            storage.join("options.php"),
            "<?php return ['version' => '4.9.9'];",
        )
        .unwrap();
        std::fs::write(storage.join("preserve.txt"), "keep").unwrap();
        let result = run(&database, "", &storage, "6.0.2").await.unwrap();

        assert_eq!(result.previous_version, "4.9.9");
        assert!(!storage.join("options.php").exists());
        assert_eq!(
            std::fs::read_to_string(storage.join("preserve.txt")).unwrap(),
            "keep"
        );
        assert!(result.background_migrated);
        assert_eq!(
            database.option("", "version").await.unwrap().as_deref(),
            Some("6.0.2")
        );
        assert_eq!(
            database
                .option("", "home_pic_url")
                .await
                .unwrap()
                .as_deref(),
            Some("./app/bg.webp")
        );
        assert_eq!(
            database.option("", "site_name").await.unwrap().as_deref(),
            Some("Keep this option")
        );
        assert!(storage.join("install.lock").is_file());
        std::fs::remove_dir_all(storage).unwrap();
    }

    #[tokio::test]
    async fn preserves_custom_backgrounds_and_current_legacy_versions() {
        let database = test_database(&[
            ("version", "6.0.2"),
            ("home_pic_url", "https://cdn.example.test/site.jpg"),
        ])
        .await;
        let storage = test_storage("current");
        let result = run(&database, "", &storage, "6.0.2").await.unwrap();

        assert_eq!(result.previous_version, "6.0.2");
        assert!(!result.background_migrated);
        assert_eq!(
            database
                .option("", "home_pic_url")
                .await
                .unwrap()
                .as_deref(),
            Some("https://cdn.example.test/site.jpg")
        );
        assert!(storage.join("install.lock").is_file());
        std::fs::remove_dir_all(storage).unwrap();
    }

    #[tokio::test]
    async fn refuses_invalid_or_missing_versions_without_creating_install_marker() {
        for options in [&[("version", "not-a-version")][..], &[][..]] {
            let database = test_database(options).await;
            let storage = test_storage("invalid");
            assert!(run(&database, "", &storage, "6.0.2").await.is_err());
            assert!(!storage.join("install.lock").exists());
            assert_eq!(
                database.option("", "version").await.unwrap().as_deref(),
                options.first().map(|(_, value)| *value)
            );
            std::fs::remove_dir_all(storage).unwrap();
        }
    }

    #[tokio::test]
    async fn refuses_to_update_when_the_legacy_cache_cannot_be_removed() {
        let database =
            test_database(&[("version", "4.9.9"), ("home_pic_url", "./app/bg.jpg")]).await;
        let storage = test_storage("blocked-cache");
        std::fs::create_dir(storage.join("options.php")).unwrap();

        assert!(run(&database, "", &storage, "6.0.2").await.is_err());
        assert_eq!(
            database.option("", "version").await.unwrap().as_deref(),
            Some("4.9.9")
        );
        assert_eq!(
            database
                .option("", "home_pic_url")
                .await
                .unwrap()
                .as_deref(),
            Some("./app/bg.jpg")
        );
        assert!(!storage.join("install.lock").exists());
        std::fs::remove_dir_all(storage).unwrap();
    }

    #[tokio::test]
    async fn refuses_an_invalid_target_version_before_writing_anything() {
        let database = test_database(&[("version", "6.0.2")]).await;
        let storage = test_storage("invalid-target");
        std::fs::write(storage.join("options.php"), "keep until a valid update").unwrap();
        assert!(run(&database, "", &storage, "next").await.is_err());
        assert!(storage.join("options.php").is_file());
        assert_eq!(
            database.option("", "version").await.unwrap().as_deref(),
            Some("6.0.2")
        );
        assert!(!storage.join("install.lock").exists());
        std::fs::remove_dir_all(storage).unwrap();
    }
}
