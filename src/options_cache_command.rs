use std::{
    error::Error,
    fmt::Write as _,
    fs, io,
    path::{Path, PathBuf},
};

use crate::{config::Config, database::DatabasePool};

pub(crate) fn parse(arguments: &[String]) -> Result<bool, io::Error> {
    match arguments.first().map(String::as_str) {
        Some("options:cache") if arguments.len() == 1 => Ok(true),
        Some("options:cache") => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: blessing-skin-rs options:cache",
        )),
        _ => Ok(false),
    }
}

pub(crate) async fn run(config: &Config, storage_dir: &Path) -> Result<(), Box<dyn Error>> {
    let options = if storage_dir.join("install.lock").exists() {
        let database = DatabasePool::connect(&config.database).await?;
        database.all_options(&config.database.table_prefix).await?
    } else {
        Vec::new()
    };
    write_cache(storage_dir, &options)?;
    Ok(())
}

fn write_cache(storage_dir: &Path, options: &[(String, Option<String>)]) -> io::Result<PathBuf> {
    fs::create_dir_all(storage_dir)?;
    let path = storage_dir.join("options.php");
    fs::write(&path, render_php_options(options))?;
    Ok(path)
}

fn render_php_options(options: &[(String, Option<String>)]) -> String {
    let mut options = options.iter().collect::<Vec<_>>();
    options.sort_by(|left, right| left.0.cmp(&right.0));

    let mut output =
        String::from("<?php\n// This is auto-generated. DO NOT edit manually.\nreturn array (\n");
    for (name, value) in options {
        let value = value
            .as_deref()
            .map(|value| format!("'{}'", php_single_quoted(value)))
            .unwrap_or_else(|| "NULL".to_owned());
        let _ = writeln!(output, "  '{}' => {value},", php_single_quoted(name));
    }
    output.push_str(");\n");
    output
}

fn php_single_quoted(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => output.push_str("\\\\"),
            '\'' => output.push_str("\\'"),
            _ => output.push(character),
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{parse, php_single_quoted, render_php_options, write_cache};
    use std::{fs, path::PathBuf};

    fn test_dir(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "blessing-options-cache-{label}-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn recognizes_only_the_legacy_options_cache_command() {
        assert!(!parse(&[]).unwrap());
        assert!(!parse(&["update".into()]).unwrap());
        assert!(parse(&["options:cache".into()]).unwrap());
        assert_eq!(
            parse(&["options:cache".into(), "extra".into()])
                .unwrap_err()
                .to_string(),
            "usage: blessing-skin-rs options:cache"
        );
    }

    #[test]
    fn escapes_php_single_quoted_strings() {
        assert_eq!(php_single_quoted("skin\\path's"), "skin\\\\path\\'s");
        assert_eq!(php_single_quoted("玩家皮肤"), "玩家皮肤");
    }

    #[test]
    fn renders_deterministic_php_options_array() {
        let output = render_php_options(&[
            ("z_last".to_owned(), Some("line 1\nline 2".to_owned())),
            ("site_name".to_owned(), Some("Skin's \\ Server".to_owned())),
            ("optional".to_owned(), None),
        ]);
        assert_eq!(
            output,
            "<?php\n// This is auto-generated. DO NOT edit manually.\nreturn array (\n  'optional' => NULL,\n  'site_name' => 'Skin\\'s \\\\ Server',\n  'z_last' => 'line 1\nline 2',\n);\n"
        );
    }

    #[test]
    fn writes_the_legacy_cache_path_without_touching_database_files() {
        let directory = test_dir("write");
        let options = vec![("site_name".to_owned(), Some("Blessing Skin".to_owned()))];
        let path = write_cache(&directory, &options).unwrap();
        assert_eq!(path, directory.join("options.php"));
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            render_php_options(&options)
        );
        assert!(!directory.join("install.lock").exists());
        fs::remove_dir_all(directory).unwrap();
    }
}
