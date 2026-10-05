use std::{io, path::Path};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PluginCommandOutcome {
    Enabled,
    Disabled,
    AlreadyEnabled,
    AlreadyDisabled,
    NotFound,
}

/// Handle the legacy `plugin:enable` and `plugin:disable` commands for WASM plugins.
pub(crate) fn run(
    arguments: &[String],
    plugins_dir: &Path,
) -> Result<Option<PluginCommandOutcome>, io::Error> {
    let Some(command) = arguments.first().map(String::as_str) else {
        return Ok(None);
    };
    let enabling = match command {
        "plugin:enable" => true,
        "plugin:disable" => false,
        _ => return Ok(None),
    };
    if arguments.len() != 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("usage: blessing-skin-rs {command} <name>"),
        ));
    }
    let name = &arguments[1];
    if !crate::plugin_runtime::valid_plugin_name(name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid plugin name",
        ));
    }

    let enabled = plugins_dir.join(format!("{name}.wasm"));
    let disabled = plugins_dir.join(format!("{name}.wasm.disabled"));
    let (source, destination, already, changed) = if enabling {
        (
            disabled,
            enabled.clone(),
            enabled.exists(),
            PluginCommandOutcome::Enabled,
        )
    } else {
        (
            enabled,
            disabled.clone(),
            disabled.exists(),
            PluginCommandOutcome::Disabled,
        )
    };
    if already {
        return Ok(Some(if enabling {
            PluginCommandOutcome::AlreadyEnabled
        } else {
            PluginCommandOutcome::AlreadyDisabled
        }));
    }
    if !source.is_file() {
        return Ok(Some(PluginCommandOutcome::NotFound));
    }
    std::fs::rename(source, destination)?;
    Ok(Some(changed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf};

    fn test_dir(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "blessing-plugin-command-{label}-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn enables_a_disabled_wasm_plugin() {
        let directory = test_dir("enable");
        fs::write(directory.join("skin-tools.wasm.disabled"), b"component").unwrap();
        let result = run(&["plugin:enable".into(), "skin-tools".into()], &directory).unwrap();
        assert_eq!(result, Some(PluginCommandOutcome::Enabled));
        assert_eq!(
            fs::read(directory.join("skin-tools.wasm")).unwrap(),
            b"component"
        );
        assert!(!directory.join("skin-tools.wasm.disabled").exists());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn disables_an_enabled_wasm_plugin() {
        let directory = test_dir("disable");
        fs::write(directory.join("skin-tools.wasm"), b"component").unwrap();
        let result = run(&["plugin:disable".into(), "skin-tools".into()], &directory).unwrap();
        assert_eq!(result, Some(PluginCommandOutcome::Disabled));
        assert_eq!(
            fs::read(directory.join("skin-tools.wasm.disabled")).unwrap(),
            b"component"
        );
        assert!(!directory.join("skin-tools.wasm").exists());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn reports_existing_plugin_state_and_missing_plugins() {
        let directory = test_dir("states");
        fs::write(directory.join("enabled.wasm"), b"component").unwrap();
        fs::write(directory.join("disabled.wasm.disabled"), b"component").unwrap();
        assert_eq!(
            run(&["plugin:enable".into(), "enabled".into()], &directory).unwrap(),
            Some(PluginCommandOutcome::AlreadyEnabled)
        );
        assert_eq!(
            run(&["plugin:disable".into(), "disabled".into()], &directory).unwrap(),
            Some(PluginCommandOutcome::AlreadyDisabled)
        );
        assert_eq!(
            run(&["plugin:enable".into(), "missing".into()], &directory).unwrap(),
            Some(PluginCommandOutcome::NotFound)
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn rejects_invalid_names_and_argument_counts() {
        let directory = test_dir("invalid");
        let invalid_name =
            run(&["plugin:enable".into(), "../outside".into()], &directory).unwrap_err();
        assert_eq!(invalid_name.kind(), io::ErrorKind::InvalidInput);
        let extra_argument = run(
            &["plugin:disable".into(), "skin-tools".into(), "extra".into()],
            &directory,
        )
        .unwrap_err();
        assert_eq!(extra_argument.kind(), io::ErrorKind::InvalidInput);
        fs::remove_dir_all(directory).unwrap();
    }
}
