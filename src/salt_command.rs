use rand::{RngCore, rngs::OsRng};
use std::{io, path::Path};

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SaltCommandResult {
    pub(crate) salt: String,
    pub(crate) persisted: bool,
}

/// Handle the Laravel-compatible `salt:random [--show]` utility.
///
/// Returns `None` when the arguments do not select this command.
pub(crate) fn run(
    arguments: &[String],
    env_file: &Path,
    storage_dir: &Path,
) -> Result<Option<SaltCommandResult>, io::Error> {
    if arguments.first().map(String::as_str) != Some("salt:random") {
        return Ok(None);
    }

    let show_only = match &arguments[1..] {
        [] => false,
        [flag] if flag == "--show" => true,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "usage: blessing-skin-rs salt:random [--show]",
            ));
        }
    };

    if !show_only && storage_dir.join("install.lock").exists() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "refusing to change SALT after installation because it would invalidate legacy password hashes",
        ));
    }

    let salt = generate_salt();
    if !show_only {
        crate::http::write_env_file(env_file, &[("SALT", salt.clone())])?;
    }

    Ok(Some(SaltCommandResult {
        salt,
        persisted: !show_only,
    }))
}

fn generate_salt() -> String {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf};

    fn test_dir(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "blessing-salt-{label}-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn generated_salt_matches_the_legacy_format() {
        let salt = generate_salt();
        assert_eq!(salt.len(), 32);
        assert!(
            salt.bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
    }

    #[test]
    fn command_updates_salt_and_preserves_other_environment_values() {
        let directory = test_dir("write");
        let env_file = directory.join(".env");
        fs::write(&env_file, "APP_KEY=keep-me\nSALT=old\nDB_DATABASE=site\n").unwrap();

        let result = run(&["salt:random".into()], &env_file, &directory)
            .unwrap()
            .unwrap();
        let content = fs::read_to_string(&env_file).unwrap();
        assert!(result.persisted);
        assert_eq!(content.matches("SALT=").count(), 1);
        assert!(content.contains(&format!("SALT=\"{}\"", result.salt)));
        assert!(content.contains("APP_KEY=keep-me"));
        assert!(content.contains("DB_DATABASE=site"));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn show_only_prints_a_salt_without_writing_the_environment_file() {
        let directory = test_dir("show");
        let env_file = directory.join(".env");
        fs::write(&env_file, "SALT=unchanged\n").unwrap();
        fs::write(directory.join("install.lock"), b"").unwrap();

        let result = run(
            &["salt:random".into(), "--show".into()],
            &env_file,
            &directory,
        )
        .unwrap()
        .unwrap();
        assert!(!result.persisted);
        assert_eq!(fs::read_to_string(&env_file).unwrap(), "SALT=unchanged\n");
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn installed_site_refuses_to_rotate_salt() {
        let directory = test_dir("installed");
        let env_file = directory.join(".env");
        fs::write(&env_file, "SALT=keep\n").unwrap();
        fs::write(directory.join("install.lock"), b"").unwrap();

        let error = run(&["salt:random".into()], &env_file, &directory).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(fs::read_to_string(&env_file).unwrap(), "SALT=keep\n");
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn command_rejects_unknown_options() {
        let directory = test_dir("invalid");
        let error = run(
            &["salt:random".into(), "--unknown".into()],
            &directory.join(".env"),
            &directory,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        fs::remove_dir_all(directory).unwrap();
    }
}
