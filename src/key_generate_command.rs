use std::{io, path::Path};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use rand::{RngCore, rngs::OsRng};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum KeyGenerateOutcome {
    Displayed(String),
    Written(String),
}

#[derive(Debug, Default)]
struct Options {
    show: bool,
    force: bool,
}

/// Handle Laravel's built-in `key:generate` command for the legacy `.env` file.
pub(crate) fn run(
    arguments: &[String],
    env_file: &Path,
    app_env: &str,
    current_app_key: Option<&str>,
) -> Result<Option<KeyGenerateOutcome>, io::Error> {
    let Some(options) = parse(arguments)? else {
        return Ok(None);
    };

    let key = generate_key();
    if options.show {
        return Ok(Some(KeyGenerateOutcome::Displayed(key)));
    }

    let content = std::fs::read_to_string(env_file)?;
    if !has_assignment(&content, "APP_KEY") {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Unable to set application key. No APP_KEY variable was found in the environment file.",
        ));
    }
    if app_env.eq_ignore_ascii_case("production")
        && current_app_key.is_some_and(|value| !value.is_empty())
        && !options.force
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "APP_KEY is already set in production; pass --force to rotate it.",
        ));
    }

    crate::http::write_env_file(env_file, &[("APP_KEY", key.clone())])?;
    Ok(Some(KeyGenerateOutcome::Written(key)))
}

fn parse(arguments: &[String]) -> Result<Option<Options>, io::Error> {
    if arguments.first().map(String::as_str) != Some("key:generate") {
        return Ok(None);
    }

    let mut options = Options::default();
    for argument in &arguments[1..] {
        match argument.as_str() {
            "--show" => options.show = true,
            "--force" => options.force = true,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "usage: blessing-skin-rs key:generate [--show] [--force]",
                ));
            }
        }
    }
    Ok(Some(options))
}

fn generate_key() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    format!("base64:{}", STANDARD.encode(bytes))
}

fn has_assignment(content: &str, name: &str) -> bool {
    content.lines().any(|line| {
        let line = line.trim_start();
        if line.starts_with('#') {
            return false;
        }
        let assignment = line.strip_prefix("export ").unwrap_or(line);
        assignment
            .split_once('=')
            .is_some_and(|(key, _)| key.trim() == name)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf};

    fn test_dir(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "blessing-key-generate-{label}-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn command(args: &[&str]) -> Vec<String> {
        args.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn generates_a_php_compatible_base64_key() {
        let key = generate_key();
        let encoded = key.strip_prefix("base64:").unwrap();
        let bytes = STANDARD.decode(encoded).unwrap();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn show_only_prints_a_key_without_reading_or_writing_the_env_file() {
        let directory = test_dir("show");
        let env_file = directory.join("missing.env");
        let result = run(
            &command(&["key:generate", "--show"]),
            &env_file,
            "production",
            None,
        )
        .unwrap()
        .unwrap();
        assert!(matches!(result, KeyGenerateOutcome::Displayed(key) if key.starts_with("base64:")));
        assert!(!env_file.exists());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn updates_the_env_key_and_preserves_other_settings() {
        let directory = test_dir("write");
        let env_file = directory.join(".env");
        fs::write(&env_file, "APP_KEY=old-key\nDB_DATABASE=site\n").unwrap();

        let result = run(
            &command(&["key:generate"]),
            &env_file,
            "local",
            Some("old-key"),
        )
        .unwrap()
        .unwrap();
        let KeyGenerateOutcome::Written(key) = result else {
            panic!("expected the key to be written");
        };
        let content = fs::read_to_string(&env_file).unwrap();
        assert!(content.contains(&format!("APP_KEY=\"{key}\"")));
        assert!(content.contains("DB_DATABASE=site"));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn production_key_rotation_requires_force() {
        let directory = test_dir("production");
        let env_file = directory.join(".env");
        fs::write(&env_file, "APP_KEY=keep-this-key\n").unwrap();

        let error = run(
            &command(&["key:generate"]),
            &env_file,
            "production",
            Some("keep-this-key"),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            fs::read_to_string(&env_file).unwrap(),
            "APP_KEY=keep-this-key\n"
        );

        assert!(matches!(
            run(
                &command(&["key:generate", "--force"]),
                &env_file,
                "production",
                Some("keep-this-key"),
            )
            .unwrap(),
            Some(KeyGenerateOutcome::Written(_))
        ));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn requires_an_existing_app_key_assignment_and_rejects_unknown_flags() {
        let directory = test_dir("invalid");
        let env_file = directory.join(".env");
        fs::write(&env_file, "DB_DATABASE=site\n").unwrap();
        let error = run(&command(&["key:generate"]), &env_file, "local", None).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);

        let error = run(
            &command(&["key:generate", "--unknown"]),
            &env_file,
            "local",
            None,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn ignores_other_commands() {
        assert!(
            run(&command(&["install"]), Path::new(".env"), "local", None)
                .unwrap()
                .is_none()
        );
    }
}
