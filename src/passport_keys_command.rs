use rand::rngs::OsRng;
use rsa::{
    RsaPrivateKey,
    pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding},
};
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PassportKeysCommand {
    pub(crate) force: bool,
    pub(crate) length: usize,
}

pub(crate) fn parse(arguments: &[String]) -> Result<Option<PassportKeysCommand>, io::Error> {
    if arguments.first().map(String::as_str) != Some("passport:keys") {
        return Ok(None);
    }
    let (mut force, mut length, mut index) = (false, 4096, 1);
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--force" if !force => force = true,
            "--length" => {
                index += 1;
                length = parse_length(arguments.get(index).ok_or_else(usage_error)?)?;
            }
            value if value.starts_with("--length=") => {
                length = parse_length(&value["--length=".len()..])?;
            }
            _ => return Err(usage_error()),
        }
        index += 1;
    }
    Ok(Some(PassportKeysCommand { force, length }))
}

pub(crate) fn run(
    command: &PassportKeysCommand,
    storage_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let private_path = storage_dir.join("oauth-private.key");
    let public_path = storage_dir.join("oauth-public.key");
    let had_private = private_path.exists();
    let had_public = public_path.exists();
    if !command.force && (had_private || had_public) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "Passport encryption keys already exist. Use --force to overwrite them.",
        )
        .into());
    }

    fs::create_dir_all(storage_dir)?;
    let private_key = RsaPrivateKey::new(&mut OsRng, command.length)?;
    let public_key = private_key.to_public_key();
    let private_pem = private_key.to_pkcs8_pem(LineEnding::LF)?;
    let public_pem = public_key.to_public_key_pem(LineEnding::LF)?;
    let nonce = format!("{}-{}", std::process::id(), rand::random::<u64>());
    let private_stage = storage_dir.join(format!(".oauth-private.key.{nonce}.tmp"));
    let public_stage = storage_dir.join(format!(".oauth-public.key.{nonce}.tmp"));
    write_staged_key(&private_stage, private_pem.as_bytes())?;
    if let Err(error) = write_staged_key(&public_stage, public_pem.as_bytes()) {
        let _ = fs::remove_file(&private_stage);
        return Err(error.into());
    }

    let private_backup = storage_dir.join(format!(".oauth-private.key.{nonce}.bak"));
    let public_backup = storage_dir.join(format!(".oauth-public.key.{nonce}.bak"));
    let backup_result = (|| -> io::Result<()> {
        if had_private {
            fs::rename(&private_path, &private_backup)?;
        }
        if had_public {
            if let Err(error) = fs::rename(&public_path, &public_backup) {
                if had_private {
                    let _ = fs::rename(&private_backup, &private_path);
                }
                return Err(error);
            }
        }
        Ok(())
    })();
    if let Err(error) = backup_result {
        let _ = fs::remove_file(&private_stage);
        let _ = fs::remove_file(&public_stage);
        return Err(error.into());
    }

    let install_result = (|| -> io::Result<()> {
        fs::rename(&private_stage, &private_path)?;
        fs::rename(&public_stage, &public_path)?;
        Ok(())
    })();
    if let Err(error) = install_result {
        let _ = fs::remove_file(&private_path);
        let _ = fs::remove_file(&public_path);
        if had_private {
            let _ = fs::rename(&private_backup, &private_path);
        }
        if had_public {
            let _ = fs::rename(&public_backup, &public_path);
        }
        let _ = fs::remove_file(&private_stage);
        let _ = fs::remove_file(&public_stage);
        return Err(error.into());
    }
    if had_private {
        fs::remove_file(private_backup)?;
    }
    if had_public {
        fs::remove_file(public_backup)?;
    }
    Ok(())
}

fn write_staged_key(path: &PathBuf, contents: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(contents)
}

fn parse_length(value: &str) -> Result<usize, io::Error> {
    let length = value.parse::<usize>().map_err(|_| usage_error())?;
    if !(1024..=8192).contains(&length) || length % 256 != 0 {
        return Err(usage_error());
    }
    Ok(length)
}

fn usage_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "usage: blessing-skin-rs passport:keys [--force] [--length=1024..8192]",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{DecodingKey, EncodingKey};

    fn test_dir(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "blessing-passport-keys-{label}-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn parses_default_force_and_length_options() {
        assert_eq!(
            parse(&["passport:keys".into()]).unwrap(),
            Some(PassportKeysCommand {
                force: false,
                length: 4096
            })
        );
        assert_eq!(
            parse(&[
                "passport:keys".into(),
                "--force".into(),
                "--length".into(),
                "2048".into()
            ])
            .unwrap(),
            Some(PassportKeysCommand {
                force: true,
                length: 2048
            })
        );
        assert_eq!(
            parse(&["passport:keys".into(), "--length=2048".into()]).unwrap(),
            Some(PassportKeysCommand {
                force: false,
                length: 2048
            })
        );
        assert!(parse(&["update".into()]).unwrap().is_none());
    }

    #[test]
    fn rejects_unknown_options_and_unsafe_key_lengths() {
        for arguments in [
            vec!["passport:keys".into(), "--other".into()],
            vec!["passport:keys".into(), "--length".into()],
            vec!["passport:keys".into(), "--length=768".into()],
            vec!["passport:keys".into(), "--force".into(), "--force".into()],
        ] {
            assert_eq!(
                parse(&arguments).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }

    #[test]
    fn generates_compatible_keys_and_refuses_overwrite_without_force() {
        let directory = test_dir("generate");
        run(
            &PassportKeysCommand {
                force: false,
                length: 2048,
            },
            &directory,
        )
        .unwrap();
        let private = fs::read(directory.join("oauth-private.key")).unwrap();
        let public = fs::read(directory.join("oauth-public.key")).unwrap();
        EncodingKey::from_rsa_pem(&private).unwrap();
        DecodingKey::from_rsa_pem(&public).unwrap();

        let error = run(
            &PassportKeysCommand {
                force: false,
                length: 2048,
            },
            &directory,
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "Passport encryption keys already exist. Use --force to overwrite them."
        );
        assert_eq!(
            fs::read(directory.join("oauth-private.key")).unwrap(),
            private
        );
        assert_eq!(
            fs::read(directory.join("oauth-public.key")).unwrap(),
            public
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn force_replaces_both_key_files() {
        let directory = test_dir("force");
        fs::write(directory.join("oauth-private.key"), b"old private").unwrap();
        fs::write(directory.join("oauth-public.key"), b"old public").unwrap();
        run(
            &PassportKeysCommand {
                force: true,
                length: 2048,
            },
            &directory,
        )
        .unwrap();
        EncodingKey::from_rsa_pem(&fs::read(directory.join("oauth-private.key")).unwrap()).unwrap();
        DecodingKey::from_rsa_pem(&fs::read(directory.join("oauth-public.key")).unwrap()).unwrap();
        fs::remove_dir_all(directory).unwrap();
    }
}
