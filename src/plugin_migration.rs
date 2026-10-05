use serde::Serialize;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    error::Error,
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Serialize)]
pub struct PluginReport {
    pub format_version: u8,
    pub source_directory: String,
    pub plugin: PluginSummary,
    pub php_version_constraint: Option<String>,
    pub blessing_skin_server_constraint: Option<String>,
    pub legacy_plugin_dependencies: BTreeMap<String, String>,
    pub composer_dependencies: BTreeMap<String, String>,
    pub php_hooks: Vec<String>,
    pub php_source_files: Vec<String>,
    pub php_template_files: Vec<String>,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Serialize)]
pub struct PluginSummary {
    pub name: String,
    pub version: String,
    pub namespace: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Finding {
    pub code: &'static str,
    pub severity: &'static str,
    pub detail: String,
}
const PHP_SOURCE_INDICATORS: &[(&str, &str, &str)] = &[
    ("php-database-access", "database", "db::"),
    ("php-database-access", "database schema", "schema::"),
    (
        "php-database-access",
        "database package",
        "illuminate\\database",
    ),
    ("php-route-registration", "route registration", "route::"),
    ("php-event-hooks", "event hook", "event::listen"),
    ("php-event-hooks", "event hook", "hook::"),
    ("php-filesystem-access", "filesystem", "storage::"),
    ("php-filesystem-access", "filesystem", "file::"),
    ("php-filesystem-access", "filesystem", "file_get_contents("),
    ("php-filesystem-access", "filesystem", "file_put_contents("),
    ("php-filesystem-access", "filesystem", "fopen("),
    ("php-filesystem-access", "filesystem", "unlink("),
    ("php-network-access", "network", "http::"),
    ("php-network-access", "network", "curl_init("),
    ("php-network-access", "network", "guzzlehttp\\"),
    ("php-host-services", "host service", "auth::"),
    ("php-host-services", "host service", "cache::"),
    ("php-host-services", "host service", "app("),
    ("php-host-services", "host service", "resolve("),
    ("php-host-services", "host service", "view("),
];

pub fn run(args: impl IntoIterator<Item = String>) -> Result<(), Box<dyn Error>> {
    let mut args = args.into_iter();
    let mut source = None;
    let mut output = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                println!("Usage: plugin-migrate <legacy-plugin-dir> [--output <scaffold-dir>]");
                println!(
                    "Scans a Blessing Skin package.json and optional composer.json. With --output, writes a Rust component scaffold and migration-report.json."
                );
                return Ok(());
            }
            "--output" | "-o" => {
                output = Some(PathBuf::from(
                    args.next().ok_or("--output requires a directory")?,
                ));
            }
            _ if arg.starts_with('-') => return Err(format!("unknown option: {arg}").into()),
            _ if source.is_none() => source = Some(PathBuf::from(arg)),
            _ => return Err("only one legacy plugin directory may be scanned".into()),
        }
    }
    let source = source.ok_or("missing legacy plugin directory (try --help)")?;
    let report = analyze(&source)?;
    let json = serde_json::to_string_pretty(&report)?;
    if let Some(output) = output {
        write_scaffold(&output, &report, &json)?;
        println!("Generated Rust component scaffold at {}", output.display());
        println!(
            "Migration report: {}",
            output.join("migration-report.json").display()
        );
    } else {
        println!("{json}");
    }
    Ok(())
}

pub fn analyze(source: &Path) -> Result<PluginReport, Box<dyn Error>> {
    let root = source.canonicalize()?;
    if !root.is_dir() {
        return Err(format!("plugin path is not a directory: {}", root.display()).into());
    }
    let manifest_path = root.join("package.json");
    let manifest: Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    let name = required_string(&manifest, "name", &manifest_path)?;
    let version = required_string(&manifest, "version", &manifest_path)?;
    let namespace = manifest
        .get("namespace")
        .and_then(Value::as_str)
        .map(str::to_owned);

    let require = manifest.get("require").and_then(Value::as_object);
    let php_version_constraint = require
        .and_then(|requirements| requirements.get("php"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let blessing_skin_server_constraint = require
        .and_then(|requirements| requirements.get("blessing-skin-server"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let legacy_plugin_dependencies = require
        .into_iter()
        .flat_map(|requirements| requirements.iter())
        .filter(|(dependency, _)| {
            dependency.as_str() != "php" && dependency.as_str() != "blessing-skin-server"
        })
        .filter_map(|(dependency, constraint)| {
            constraint
                .as_str()
                .map(|constraint| (dependency.clone(), constraint.to_owned()))
        })
        .collect::<BTreeMap<_, _>>();

    let mut php_hooks = Vec::new();
    if let Some(providers) = manifest.pointer("/enchants/providers") {
        collect_strings(providers, "enchants.providers", &mut php_hooks);
    }
    if let Some(config) = manifest.pointer("/enchants/config") {
        collect_strings(config, "enchants.config", &mut php_hooks);
    }
    php_hooks.sort();
    php_hooks.dedup();

    let mut php_source_files = Vec::new();
    let mut php_template_files = Vec::new();
    collect_files(&root, &root, &mut php_source_files, &mut php_template_files)?;
    php_source_files.sort();
    php_template_files.sort();
    let php_source_findings = scan_php_capabilities(&root, &php_source_files)?;

    let composer_path = root.join("composer.json");
    let composer_dependencies = if composer_path.is_file() {
        let composer: Value = serde_json::from_slice(&fs::read(&composer_path)?)?;
        let mut dependencies = BTreeMap::new();
        for field in ["require", "require-dev"] {
            if let Some(values) = composer.get(field).and_then(Value::as_object) {
                for (package, constraint) in values {
                    if let Some(constraint) = constraint.as_str() {
                        dependencies.insert(format!("{field}:{package}"), constraint.to_owned());
                    }
                }
            }
        }
        dependencies
    } else {
        BTreeMap::new()
    };

    let mut findings = Vec::new();
    if let Some(constraint) = &php_version_constraint {
        findings.push(Finding {
            code: "php-runtime-requirement",
            severity: "blocking",
            detail: format!("The legacy manifest requires PHP {constraint}; Rust components cannot load PHP runtime code."),
        });
    }
    if let Some(constraint) = &blessing_skin_server_constraint {
        findings.push(Finding {
            code: "legacy-host-version-requirement",
            severity: "review",
            detail: format!("Recheck Blessing Skin Server compatibility constraint {constraint} against the Rust host API."),
        });
    }
    if !legacy_plugin_dependencies.is_empty() {
        findings.push(Finding {
            code: "legacy-plugin-dependencies",
            severity: "review",
            detail: format!("{} dependencies name other PHP plugins and need Rust/WASM replacements or removal.", legacy_plugin_dependencies.len()),
        });
    }
    if !composer_dependencies.is_empty() {
        findings.push(Finding {
            code: "composer-dependencies",
            severity: "blocking",
            detail: format!("{} Composer dependencies are PHP packages and cannot be linked into a WASM component.", composer_dependencies.len()),
        });
    }
    if !php_hooks.is_empty() {
        findings.push(Finding {
            code: "php-extension-hooks",
            severity: "blocking",
            detail: format!("{} PHP service-provider/config hook(s) need to be rewritten against the versioned component API.", php_hooks.len()),
        });
    }
    if !php_source_files.is_empty() {
        findings.push(Finding {
            code: "php-source-files",
            severity: "blocking",
            detail: format!(
                "{} PHP source file(s) were found and are not executed by the Rust server.",
                php_source_files.len()
            ),
        });
    }
    if !php_template_files.is_empty() {
        findings.push(Finding {
            code: "php-template-files",
            severity: "review",
            detail: format!(
                "{} PHP template file(s) need a UI or host-rendered replacement.",
                php_template_files.len()
            ),
        });
    }
    findings.extend(php_source_findings);
    if findings.is_empty() {
        findings.push(Finding {
            code: "no-known-php-hooks",
            severity: "info",
            detail: "No PHP-specific requirements, hooks, source files, or templates were detected by this scanner.".to_owned(),
        });
    }

    Ok(PluginReport {
        format_version: 1,
        source_directory: root.display().to_string(),
        plugin: PluginSummary {
            name,
            version,
            namespace,
        },
        php_version_constraint,
        blessing_skin_server_constraint,
        legacy_plugin_dependencies,
        composer_dependencies,
        php_hooks,
        php_source_files,
        php_template_files,
        findings,
    })
}

fn required_string(value: &Value, field: &str, path: &Path) -> Result<String, Box<dyn Error>> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .ok_or_else(|| format!("{} is missing a non-empty string `{field}`", path.display()).into())
}

fn collect_strings(value: &Value, path: &str, output: &mut Vec<String>) {
    match value {
        Value::String(value) => output.push(format!("{path}: {value}")),
        Value::Array(values) => {
            for value in values {
                collect_strings(value, path, output);
            }
        }
        Value::Object(values) => {
            for (name, value) in values {
                collect_strings(value, &format!("{path}.{name}"), output);
            }
        }
        _ => {}
    }
}

fn contains_php_indicator(line: &str, indicator: &str) -> bool {
    line.match_indices(indicator).any(|(index, _)| {
        line[..index].chars().next_back().map_or(true, |previous| {
            !previous.is_ascii_alphanumeric() && previous != '_'
        })
    })
}
fn scan_php_capabilities(
    root: &Path,
    source_files: &[String],
) -> Result<Vec<Finding>, Box<dyn Error>> {
    let mut findings = Vec::new();
    for relative in source_files {
        let bytes = fs::read(root.join(relative))?;
        let source = String::from_utf8_lossy(&bytes);
        for (line_index, line) in source.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//")
                || trimmed.starts_with("/*")
                || trimmed.starts_with('*')
                || trimmed.starts_with('#')
            {
                continue;
            }
            let normalized = line.to_ascii_lowercase();
            for (code, category, indicator) in PHP_SOURCE_INDICATORS {
                if contains_php_indicator(&normalized, indicator) {
                    findings.push(Finding {
                        code,
                        severity: "review",
                        detail: format!(
                            "Possible {category} dependency via `{indicator}` at {relative}:{}; review its Rust/WASM replacement.",
                            line_index + 1
                        ),
                    });
                }
            }
        }
    }
    Ok(findings)
}
fn collect_files(
    root: &Path,
    directory: &Path,
    php_sources: &mut Vec<String>,
    php_templates: &mut Vec<String>,
) -> Result<(), Box<dyn Error>> {
    let mut entries = fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            if matches!(
                entry.file_name().to_str(),
                Some(".git" | "node_modules" | "vendor")
            ) {
                continue;
            }
            collect_files(root, &path, php_sources, php_templates)?;
        } else if file_type.is_file() {
            let relative = path
                .strip_prefix(root)?
                .to_string_lossy()
                .replace('\\', "/");
            let lower = relative.to_ascii_lowercase();
            if lower.ends_with(".php") {
                php_sources.push(relative.clone());
            }
            if lower.ends_with(".blade.php")
                || lower.ends_with(".twig")
                || lower.ends_with(".twig.php")
            {
                php_templates.push(relative);
            }
        }
    }
    Ok(())
}

fn write_scaffold(
    output: &Path,
    report: &PluginReport,
    report_json: &str,
) -> Result<(), Box<dyn Error>> {
    if output.exists() {
        if !output.is_dir() || fs::read_dir(output)?.next().is_some() {
            return Err(format!(
                "scaffold destination must be a new or empty directory: {}",
                output.display()
            )
            .into());
        }
    } else {
        fs::create_dir_all(output)?;
    }
    let crate_name = format!("{}-plugin", crate_slug(&report.plugin.name));
    let package_toml = format!(
        "[package]\nname = \"{crate_name}\"\nversion = \"0.1.0\"\nedition = \"2024\"\ndescription = \"Rust/WASM port scaffold for a legacy Blessing Skin plugin\"\n\n[lib]\ncrate-type = [\"cdylib\"]\n\n[dependencies]\nwit-bindgen = \"0.62\"\n\n[profile.release]\nlto = true\nopt-level = \"s\"\ncodegen-units = 1\npanic = \"abort\"\n"
    );
    let readme = format!(
        "# Rust component scaffold: `{crate_name}`\n\nThis scaffold does not execute or translate PHP code. Use `migration-report.json` to review the legacy hooks and dependencies, then port each behavior explicitly.\n\nThe exported WIT contract is `blessing-skin:plugin@1.0.0`. Implement the generated guest interface in `src/lib.rs`. Build with the Rust component toolchain using `cargo component build --release`.\n\nThe generated guest imports versioned logging and plugin-scoped key/value state, and exports optional event and filter handlers. State is binary data stored in the Rust-only `wasm_plugin_state` table; one plugin may keep at most 256 keys, 64 KiB per value, and 1 MiB total. Host API version 1.9 adds the optional filters export. Its JSON-string `apply` callback receives a filter name, current value, and context; it may return no change or a replacement JSON value. `can_sign` accepts booleans or a rejection object with a string reason, and `sign_score` accepts signed integers. Host API version 1.10 adds `new_player_name` string replacements and `can_add_player` permission results. Host API version 1.11 adds `can_rename_player` and the `player.renaming` event. Host API version 1.12 adds `can_delete_player` and the `player.delete.attempt` and `player.deleting` events. Host API version 1.13 adds the `player.texture.updating` and `player.texture.updated` events. Host API version 1.14 adds the `player.owner.updating` event. Filter failures, invalid results, and failed state checkpoints leave the prior value in place. Host API version 1.8 adds user.sign.before and user.sign.after events with the selected score reward; the first runs before the database update and the second after success. Host API version 1.7 adds user.logged-out events with the user ID. Host API version 1.6 adds closet lifecycle event callbacks. Host API version 1.5 checkpoints state after initialization, successful event callbacks, successful configuration updates, and successful shutdown. Optional documentation and configuration exports power the admin readme and settings pages. Configuration is a JSON object capped at 64 KiB and stored in plugin-scoped state. The host does not grant filesystem, network, raw database, or WASI access.\n"
    );
    let source = r##"mod bindings {
    wit_bindgen::generate!({
        path: "wit",
        world: "plugin",
    });
}

struct Component;

impl bindings::exports::blessing_skin::plugin::lifecycle::Guest for Component {
    fn initialize(host_api_version: String) -> Result<(), String> {
        if !host_api_version.starts_with("1.") {
            return Err(format!("unsupported host API: {host_api_version}"));
        }
        bindings::blessing_skin::plugin::host::log("info", "plugin initialized")?;
        let first_run = bindings::blessing_skin::plugin::state::get("initialized")?.is_none();
        if first_run {
            bindings::blessing_skin::plugin::state::set("initialized", b"true")?;
        }
        Ok(())
    }

    fn shutdown() {}
}

impl bindings::exports::blessing_skin::plugin::events::Guest for Component {
    fn handle(name: String, payload: Vec<u8>) -> Result<(), String> {
        bindings::blessing_skin::plugin::host::log(
            "debug",
            &format!("received event {name} with {} JSON bytes", payload.len()),
        )?;
        Ok(())
    }
}

impl bindings::exports::blessing_skin::plugin::filters::Guest for Component {
    fn apply(
        _name: String,
        _value: String,
        _context: String,
    ) -> Result<Option<String>, String> {
        Ok(None)
    }
}

impl bindings::exports::blessing_skin::plugin::documentation::Guest for Component {
    fn readme() -> Result<Option<String>, String> {
        Ok(Some("# Migrated plugin\n\nDocument the Rust port and its settings here.".to_owned()))
    }
}

impl bindings::exports::blessing_skin::plugin::configuration::Guest for Component {
    fn get() -> Result<Option<String>, String> {
        let Some(value) = bindings::blessing_skin::plugin::state::get("configuration")? else {
            return Ok(Some("{}".to_owned()));
        };
        let value = String::from_utf8(value)
            .map_err(|_| "stored plugin configuration is not UTF-8".to_owned())?;
        Ok(Some(value))
    }

    fn set(configuration: String) -> Result<(), String> {
        bindings::blessing_skin::plugin::state::set("configuration", configuration.as_bytes())
    }
}

bindings::export!(Component with_types_in bindings);
"##;
    let wit = include_str!("../plugins/sdk/wit/world.wit");
    let files = [
        (output.join("Cargo.toml"), package_toml),
        (output.join("README.md"), readme),
        (output.join("src/lib.rs"), source.to_owned()),
        (output.join("wit/world.wit"), wit.to_owned()),
        (output.join("migration-report.json"), report_json.to_owned()),
    ];
    for (path, contents) in files {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, contents)?;
    }
    Ok(())
}

fn crate_slug(value: &str) -> String {
    let mut slug = String::new();
    let mut separator = false;
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            if separator && !slug.is_empty() {
                slug.push('-');
            }
            slug.push(ch.to_ascii_lowercase());
            separator = false;
        } else {
            separator = true;
        }
    }
    if slug.is_empty() {
        "legacy".to_owned()
    } else if slug.chars().next().is_some_and(|ch| ch.is_ascii_digit()) {
        format!("legacy-{slug}")
    } else {
        slug
    }
}

#[cfg(test)]
mod tests {
    use super::{analyze, write_scaffold};
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn temp_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "blessing-skin-plugin-migration-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn reports_php_requirements_hooks_sources_and_templates() {
        let root = temp_dir("scan");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("views")).unwrap();
        fs::write(
            root.join("package.json"),
            r#"{"name":"old-admin-addon","version":"2.1.0","namespace":"Legacy\\Admin","require":{"php":"^8.1","blessing-skin-server":"^5.0","other-plugin":"^1.2"},"enchants":{"providers":["Admin\\Provider"],"config":"Admin\\Settings"}}"#,
        )
        .unwrap();
        fs::write(
            root.join("composer.json"),
            r#"{"require":{"illuminate/support":"^10.0"},"require-dev":{"phpunit/phpunit":"^10.0"}}"#,
        )
        .unwrap();
        fs::write(
            root.join("src/Provider.php"),
            b"<?php\n// Legacy \xff marker Route::get('/comment', $handler);\nDB::table('users')->get();\nRoute::get('/admin', $handler);\nStorage::put('file', $bytes);\nHttp::get('https://example.test');",
        )
        .unwrap();
        fs::write(root.join("views/config.blade.php"), "<div />").unwrap();

        let report = analyze(&root).unwrap();
        assert_eq!(report.plugin.name, "old-admin-addon");
        assert_eq!(report.php_version_constraint.as_deref(), Some("^8.1"));
        assert_eq!(
            report.blessing_skin_server_constraint.as_deref(),
            Some("^5.0")
        );
        assert_eq!(
            report
                .legacy_plugin_dependencies
                .get("other-plugin")
                .unwrap(),
            "^1.2"
        );
        assert_eq!(report.composer_dependencies.len(), 2);
        assert!(
            report
                .php_hooks
                .iter()
                .any(|hook| hook.contains("Admin\\Provider"))
        );
        assert_eq!(
            report.php_source_files,
            vec!["src/Provider.php", "views/config.blade.php"]
        );
        assert_eq!(report.php_template_files, vec!["views/config.blade.php"]);
        assert!(
            !report
                .findings
                .iter()
                .any(|finding| { finding.detail.contains("src/Provider.php:2") })
        );
        assert!(report.findings.iter().any(|finding| {
            finding.code == "php-database-access" && finding.detail.contains("src/Provider.php:3")
        }));
        assert!(report.findings.iter().any(|finding| {
            finding.code == "php-route-registration"
                && finding.detail.contains("src/Provider.php:4")
        }));
        assert!(report.findings.iter().any(|finding| {
            finding.code == "php-filesystem-access" && finding.detail.contains("src/Provider.php:5")
        }));
        assert!(report.findings.iter().any(|finding| {
            finding.code == "php-network-access" && finding.detail.contains("src/Provider.php:6")
        }));
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "php-runtime-requirement")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn generates_versioned_component_scaffold_and_refuses_to_overwrite() {
        let root = temp_dir("scaffold-source");
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("package.json"),
            r#"{"name":"Fancy Addon","version":"1.0.0"}"#,
        )
        .unwrap();
        let report = analyze(&root).unwrap();
        let json = serde_json::to_string_pretty(&report).unwrap();
        let output = temp_dir("scaffold-output");
        write_scaffold(&output, &report, &json).unwrap();
        let manifest = fs::read_to_string(output.join("Cargo.toml")).unwrap();
        let wit = fs::read_to_string(output.join("wit/world.wit")).unwrap();
        let source = fs::read_to_string(output.join("src/lib.rs")).unwrap();
        let readme = fs::read_to_string(output.join("README.md")).unwrap();
        let sdk_wit = include_str!("../plugins/sdk/wit/world.wit");
        let example_wit = include_str!("../plugins/examples/player-counter/wit/world.wit");
        assert!(manifest.contains("name = \"fancy-addon-plugin\""));
        assert!(readme.contains("Host API version 1.6"));
        assert!(readme.contains("Host API version 1.7"));
        assert!(readme.contains("Host API version 1.8"));
        assert!(readme.contains("Host API version 1.9"));
        assert!(readme.contains("Host API version 1.10"));
        assert!(readme.contains("Host API version 1.11"));
        assert!(readme.contains("Host API version 1.12"));
        assert!(readme.contains("Host API version 1.13"));
        assert!(readme.contains("Host API version 1.14"));
        assert!(wit.contains("blessing-skin:plugin@1.0.0"));
        assert!(wit.contains("interface host"));
        assert!(wit.contains("interface state"));
        assert!(wit.contains("interface events"));
        assert!(wit.contains("interface filters"));
        assert!(wit.contains("apply: func(name: string, value: string, context: string)"));
        assert!(wit.contains("export filters;"));
        assert!(wit.contains("interface documentation"));
        assert!(wit.contains("interface configuration"));
        assert!(wit.contains("handle: func(name: string, payload: list<u8>)"));
        assert!(wit.contains("export events;"));
        assert!(wit.contains("export documentation;"));
        assert!(wit.contains("export configuration;"));
        assert!(wit.contains("get: func(key: string) -> result<option<list<u8>>, string>"));
        assert!(wit.contains("import host;"));
        assert!(wit.contains("import state;"));
        assert_eq!(wit, sdk_wit);
        assert_eq!(example_wit, sdk_wit);
        assert!(source.contains("blessing_skin::plugin::lifecycle::Guest"));
        assert!(source.contains("blessing_skin::plugin::host::log"));
        assert!(source.contains("blessing_skin::plugin::state::get"));
        assert!(source.contains("blessing_skin::plugin::filters::Guest"));
        assert!(source.contains("blessing_skin::plugin::state::set"));
        assert!(source.contains("blessing_skin::plugin::events::Guest"));
        assert!(source.contains("blessing_skin::plugin::documentation::Guest"));
        assert!(source.contains("blessing_skin::plugin::configuration::Guest"));
        assert!(source.contains("state::get(\"configuration\")"));
        assert!(source.contains("configuration.as_bytes()"));
        assert!(output.join("migration-report.json").is_file());
        assert!(write_scaffold(&output, &report, &json).is_err());
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(output).unwrap();
    }
    #[test]
    fn php_source_indicators_require_identifier_boundaries() {
        assert!(!super::contains_php_indicator(
            "Profile::current()",
            "file::"
        ));
        assert!(super::contains_php_indicator("\\file::delete()", "file::"));
    }
}
