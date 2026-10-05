use std::io;

pub(crate) struct LegacyInstallArguments {
    pub(crate) email: String,
    pub(crate) password: String,
    pub(crate) nickname: String,
}

/// Parse the positional arguments accepted by the legacy `bs:install` Artisan command.
pub(crate) fn parse(arguments: &[String]) -> Result<Option<LegacyInstallArguments>, io::Error> {
    if arguments.first().map(String::as_str) != Some("bs:install") {
        return Ok(None);
    }
    if arguments.len() != 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: blessing-skin-rs bs:install <email> <password> <nickname>",
        ));
    }
    Ok(Some(LegacyInstallArguments {
        email: arguments[1].clone(),
        password: arguments[2].clone(),
        nickname: arguments[3].clone(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_legacy_email_password_nickname_order() {
        let parsed = parse(&[
            "bs:install".into(),
            "admin@example.com".into(),
            "correct-horse".into(),
            "admin".into(),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(parsed.email, "admin@example.com");
        assert_eq!(parsed.password, "correct-horse");
        assert_eq!(parsed.nickname, "admin");
    }

    #[test]
    fn ignores_other_commands() {
        assert!(parse(&["install".into()]).unwrap().is_none());
    }

    #[test]
    fn rejects_missing_or_extra_arguments() {
        for arguments in [
            vec!["bs:install".into(), "admin@example.com".into()],
            vec![
                "bs:install".into(),
                "admin@example.com".into(),
                "correct-horse".into(),
                "admin".into(),
                "unexpected".into(),
            ],
        ] {
            assert_eq!(
                parse(&arguments).err().unwrap().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }
}
