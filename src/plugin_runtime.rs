use std::{
    collections::HashMap,
    error::Error,
    fs, io,
    path::{Path, PathBuf},
};

use crate::database::DatabasePool;

use wasmtime::{
    Config, Engine, Store, StoreContextMut, StoreLimits, StoreLimitsBuilder,
    component::{Component, ComponentExportIndex, Instance, Linker},
};

const HOST_API_VERSION: &str = "1.2.0";
const LIFECYCLE_INTERFACE: &str = "blessing-skin:plugin/lifecycle@1.0.0";
const HOST_LOG_INTERFACE: &str = "blessing-skin:plugin/host@1.0.0";
const HOST_STATE_INTERFACE: &str = "blessing-skin:plugin/state@1.0.0";
const PLUGIN_EVENTS_INTERFACE: &str = "blessing-skin:plugin/events@1.0.0";
const COMPONENT_FUEL: u64 = 5_000_000;
const COMPONENT_MEMORY_LIMIT: usize = 64 * 1024 * 1024;
const PLUGIN_LOG_MESSAGE_LIMIT: usize = 4 * 1024;
const PLUGIN_STATE_KEY_LIMIT: usize = 128;
const PLUGIN_STATE_VALUE_LIMIT: usize = 64 * 1024;
const PLUGIN_STATE_ENTRY_LIMIT: usize = 256;
const PLUGIN_STATE_TOTAL_LIMIT: usize = 1024 * 1024;
const PLUGIN_EVENT_PAYLOAD_LIMIT: usize = 64 * 1024;
const PLUGIN_EVENT_NAMES: &[&str] = &[
    "user.logged-in",
    "user.registered",
    "user.profile.updated",
    "user.avatar.updated",
    "user.deleted",
    "player.added",
    "player.renamed",
    "player.deleted",
];
pub const COMPONENT_FILE_LIMIT: u64 = 32 * 1024 * 1024;

struct PluginStore {
    name: String,
    limits: StoreLimits,
    state: HashMap<String, Vec<u8>>,
}

struct LoadedPlugin {
    path: PathBuf,
    store: Store<PluginStore>,
    instance: Instance,
    lifecycle: ComponentExportIndex,
    events: Option<ComponentExportIndex>,
}

pub struct PluginRuntime {
    plugins: Vec<LoadedPlugin>,
    database: Option<DatabasePool>,
    table_prefix: String,
}

impl PluginRuntime {
    pub fn shared_empty() -> std::sync::Arc<tokio::sync::Mutex<Self>> {
        std::sync::Arc::new(tokio::sync::Mutex::new(Self {
            plugins: Vec::new(),
            database: None,
            table_prefix: String::new(),
        }))
    }

    pub async fn load(
        directory: &Path,
        database: Option<DatabasePool>,
        table_prefix: &str,
    ) -> Result<Self, Box<dyn Error>> {
        let engine = plugin_engine()?;
        let mut paths = Vec::new();
        match find_components(directory, &mut paths) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                tracing::warn!(%error, path = %directory.display(), "could not scan WASM plugin directory")
            }
        }
        paths.sort();
        let mut runtime = Self {
            plugins: Vec::new(),
            database: database.clone(),
            table_prefix: table_prefix.to_owned(),
        };
        if paths.is_empty() {
            return Ok(runtime);
        }
        let Some(database) = database else {
            tracing::warn!(directory = %directory.display(), "WASM plugins were not loaded because the database is unavailable for persistent plugin state");
            return Ok(runtime);
        };
        if let Err(error) = database.ensure_wasm_plugin_state_schema(table_prefix).await {
            tracing::warn!(%error, "WASM plugins were not loaded because their state table could not be prepared");
            return Ok(runtime);
        }
        for path in paths {
            if let Err(error) = runtime.load_component(&engine, &path, &database).await {
                tracing::warn!(%error, plugin = %path.display(), "WASM plugin failed to load; continuing without it");
            }
        }
        tracing::info!(count = runtime.plugins.len(), directory = %directory.display(), "WASM plugins loaded");
        Ok(runtime)
    }

    pub fn validate_component_bytes(bytes: &[u8]) -> Result<(), Box<dyn Error>> {
        let engine = plugin_engine()?;
        let mut runtime = Self {
            plugins: Vec::new(),
            database: None,
            table_prefix: String::new(),
        };
        runtime.load_component_bytes(&engine, Path::new("uploaded.wasm"), bytes, HashMap::new())?;
        if let Some(plugin) = runtime.plugins.last_mut() {
            stop_plugin(plugin)?;
        }
        runtime.plugins.clear();
        Ok(())
    }

    pub fn loaded_plugin_names(&self) -> Vec<String> {
        self.plugins
            .iter()
            .map(|plugin| {
                plugin
                    .path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect()
    }

    async fn load_component(
        &mut self,
        engine: &Engine,
        path: &Path,
        database: &DatabasePool,
    ) -> Result<(), Box<dyn Error>> {
        let metadata = fs::metadata(path)?;
        if metadata.len() > COMPONENT_FILE_LIMIT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "component file exceeds the 32 MiB size limit",
            )
            .into());
        }
        let plugin_name = path
            .file_stem()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "plugin name is not UTF-8")
            })?;
        if !valid_plugin_name(plugin_name) {
            return Err(
                io::Error::new(io::ErrorKind::InvalidData, "plugin name is invalid").into(),
            );
        }
        let state = validated_plugin_state(
            database
                .wasm_plugin_state_entries(&self.table_prefix, plugin_name)
                .await?,
        )?;
        let bytes = fs::read(path)?;
        self.load_component_bytes(engine, path, &bytes, state)?;
        if let Err(error) =
            persist_plugin_state(database, &self.table_prefix, self.plugins.last().unwrap()).await
        {
            if let Some(mut plugin) = self.plugins.pop() {
                if let Err(shutdown_error) = stop_plugin(&mut plugin) {
                    tracing::warn!(%shutdown_error, plugin = %path.display(), "plugin cleanup failed after state persistence error");
                }
            }
            return Err(error);
        }
        Ok(())
    }

    fn load_component_bytes(
        &mut self,
        engine: &Engine,
        path: &Path,
        bytes: &[u8],
        state: HashMap<String, Vec<u8>>,
    ) -> Result<(), Box<dyn Error>> {
        if bytes.len() as u64 > COMPONENT_FILE_LIMIT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "component file exceeds the 32 MiB size limit",
            )
            .into());
        }
        let component = Component::new(engine, bytes)?;
        let state = PluginStore {
            name: path
                .file_stem()
                .and_then(|name| name.to_str())
                .unwrap_or("plugin")
                .to_owned(),
            limits: StoreLimitsBuilder::new()
                .memory_size(COMPONENT_MEMORY_LIMIT)
                .table_elements(10_000)
                .instances(4)
                .tables(4)
                .memories(4)
                .build(),
            state,
        };
        let mut store = Store::new(engine, state);
        store.limiter(|state| &mut state.limits);
        store.set_fuel(COMPONENT_FUEL)?;

        // Only versioned logging and plugin-scoped key/value state are linked. WASI,
        // filesystem, network, raw database access, and undocumented imports remain unavailable.
        let mut linker = Linker::new(engine);
        linker.instance(HOST_LOG_INTERFACE)?.func_wrap(
            "log",
            |store: StoreContextMut<'_, PluginStore>,
             (level, message): (String, String)|
             -> wasmtime::Result<(Result<(), String>,)> {
                let result = log_plugin_message(&store.data().name, &level, &message);
                Ok((result,))
            },
        )?;
        linker.instance(HOST_STATE_INTERFACE)?.func_wrap(
            "get",
            |store: StoreContextMut<'_, PluginStore>,
             (key,): (String,)|
             -> wasmtime::Result<(Result<Option<Vec<u8>>, String>,)> {
                Ok((plugin_state_get(store.data(), &key),))
            },
        )?;
        linker.instance(HOST_STATE_INTERFACE)?.func_wrap(
            "set",
            |mut store: StoreContextMut<'_, PluginStore>,
             (key, value): (String, Vec<u8>)|
             -> wasmtime::Result<(Result<(), String>,)> {
                let result = plugin_state_set(store.data_mut(), key, value);
                Ok((result,))
            },
        )?;
        linker.instance(HOST_STATE_INTERFACE)?.func_wrap(
            "delete",
            |mut store: StoreContextMut<'_, PluginStore>,
             (key,): (String,)|
             -> wasmtime::Result<(Result<bool, String>,)> {
                let result = plugin_state_delete(store.data_mut(), &key);
                Ok((result,))
            },
        )?;
        let instance = linker.instantiate(&mut store, &component)?;
        let lifecycle = instance
            .get_export_index(&mut store, None, LIFECYCLE_INTERFACE)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "component does not export blessing-skin:plugin/lifecycle@1.0.0",
                )
            })?;
        let initialize_export = instance
            .get_export_index(&mut store, Some(&lifecycle), "initialize")
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "component lifecycle is missing initialize",
                )
            })?;
        let initialize = instance
            .get_typed_func::<(String,), (Result<(), String>,)>(&mut store, &initialize_export)?;
        let (initialize_result,) = initialize.call(&mut store, (HOST_API_VERSION.to_owned(),))?;
        match initialize_result {
            Ok(()) => {}
            Err(message) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("plugin initialization rejected host API: {message}"),
                )
                .into());
            }
        }
        let shutdown_export = instance
            .get_export_index(&mut store, Some(&lifecycle), "shutdown")
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "component lifecycle is missing shutdown",
                )
            })?;
        instance.get_typed_func::<(), ()>(&mut store, &shutdown_export)?;
        let events = instance.get_export_index(&mut store, None, PLUGIN_EVENTS_INTERFACE);
        if let Some(events_export) = &events {
            let handle_export = instance
                .get_export_index(&mut store, Some(events_export), "handle")
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "plugin events interface is missing handle",
                    )
                })?;
            instance.get_typed_func::<(String, Vec<u8>), (Result<(), String>,)>(
                &mut store,
                &handle_export,
            )?;
        }
        self.plugins.push(LoadedPlugin {
            path: path.to_owned(),
            store,
            instance,
            lifecycle,
            events,
        });
        tracing::info!(plugin = %path.display(), host_api = HOST_API_VERSION, "WASM plugin initialized");
        Ok(())
    }

    pub async fn shutdown(&mut self) {
        let database = self.database.clone();
        let table_prefix = self.table_prefix.clone();
        for plugin in self.plugins.iter_mut().rev() {
            if let Err(error) = stop_plugin(plugin) {
                tracing::warn!(%error, plugin = %plugin.path.display(), "WASM plugin shutdown failed");
                continue;
            }
            if let Some(database) = &database {
                if let Err(error) = persist_plugin_state(database, &table_prefix, plugin).await {
                    tracing::warn!(%error, plugin = %plugin.path.display(), "WASM plugin state could not be saved during shutdown");
                }
            }
            tracing::info!(plugin = %plugin.path.display(), "WASM plugin shut down");
        }
        self.plugins.clear();
    }

    pub async fn dispatch_event(&mut self, name: &str, payload: &[u8]) {
        if let Err(error) = validate_plugin_event(name, payload) {
            tracing::warn!(%error, event = name, size = payload.len(), "ignored invalid WASM plugin event");
            return;
        }

        let (database, table_prefix) = (self.database.clone(), self.table_prefix.clone());
        for plugin in &mut self.plugins {
            let previous_state = plugin.store.data().state.clone();
            let result = invoke_plugin_event(plugin, name, payload);
            match result {
                Ok(false) => {}
                Ok(true) => {
                    if let Some(database) = &database {
                        if let Err(error) =
                            persist_plugin_state(database, &table_prefix, plugin).await
                        {
                            plugin.store.data_mut().state = previous_state;
                            tracing::warn!(%error, plugin = %plugin.path.display(), event = name, "WASM plugin event state checkpoint failed; guest state was rolled back");
                        }
                    }
                }
                Err(error) => {
                    plugin.store.data_mut().state = previous_state;
                    tracing::warn!(%error, plugin = %plugin.path.display(), event = name, "WASM plugin event failed; continuing without its changes");
                }
            }
        }
    }

    #[cfg(test)]
    fn loaded_count(&self) -> usize {
        self.plugins.len()
    }
}

fn validate_plugin_event(name: &str, payload: &[u8]) -> Result<(), String> {
    if !PLUGIN_EVENT_NAMES.contains(&name) {
        return Err("unsupported plugin event name".into());
    }
    if payload.len() > PLUGIN_EVENT_PAYLOAD_LIMIT {
        return Err(format!(
            "plugin event payload exceeds {PLUGIN_EVENT_PAYLOAD_LIMIT} bytes"
        ));
    }
    let value: serde_json::Value = serde_json::from_slice(payload)
        .map_err(|_| "plugin event payload must be UTF-8 JSON".to_owned())?;
    if !value.is_object() {
        return Err("plugin event payload must be a JSON object".into());
    }
    Ok(())
}

fn invoke_plugin_event(
    plugin: &mut LoadedPlugin,
    name: &str,
    payload: &[u8],
) -> Result<bool, String> {
    let Some(events) = plugin.events.as_ref() else {
        return Ok(false);
    };
    let handle_export = plugin
        .instance
        .get_export_index(&mut plugin.store, Some(events), "handle")
        .ok_or_else(|| "missing plugin event handler".to_owned())?;
    let handle = plugin
        .instance
        .get_typed_func::<(String, Vec<u8>), (Result<(), String>,)>(
            &mut plugin.store,
            &handle_export,
        )
        .map_err(|error| error.to_string())?;
    plugin
        .store
        .set_fuel(COMPONENT_FUEL)
        .map_err(|error| error.to_string())?;
    let previous_state = plugin.store.data().state.clone();
    let (result,) = handle
        .call(&mut plugin.store, (name.to_owned(), payload.to_vec()))
        .map_err(|error| error.to_string())?;
    if let Err(message) = result {
        plugin.store.data_mut().state = previous_state;
        return Err(format!("plugin rejected event: {message}"));
    }
    Ok(plugin.store.data().state != previous_state)
}

fn validate_plugin_state_key(key: &str) -> Result<(), String> {
    if key.is_empty() || key.len() > PLUGIN_STATE_KEY_LIMIT || key.chars().any(char::is_control) {
        return Err(format!(
            "plugin state keys must contain 1 to {PLUGIN_STATE_KEY_LIMIT} non-control bytes"
        ));
    }
    Ok(())
}

fn validated_plugin_state(
    entries: Vec<(String, Vec<u8>)>,
) -> Result<HashMap<String, Vec<u8>>, Box<dyn Error>> {
    if entries.len() > PLUGIN_STATE_ENTRY_LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "stored plugin state exceeds the entry limit",
        )
        .into());
    }
    let mut state = HashMap::with_capacity(entries.len());
    let mut total_bytes = 0usize;
    for (key, value) in entries {
        validate_plugin_state_key(&key)
            .map_err(|message| io::Error::new(io::ErrorKind::InvalidData, message))?;
        if value.len() > PLUGIN_STATE_VALUE_LIMIT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "stored plugin state value exceeds the per-value limit",
            )
            .into());
        }
        total_bytes = total_bytes.saturating_add(value.len());
        if total_bytes > PLUGIN_STATE_TOTAL_LIMIT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "stored plugin state exceeds the total size limit",
            )
            .into());
        }
        state.insert(key, value);
    }
    Ok(state)
}

fn plugin_state_get(store: &PluginStore, key: &str) -> Result<Option<Vec<u8>>, String> {
    validate_plugin_state_key(key)?;
    Ok(store.state.get(key).cloned())
}

fn plugin_state_set(store: &mut PluginStore, key: String, value: Vec<u8>) -> Result<(), String> {
    validate_plugin_state_key(&key)?;
    if value.len() > PLUGIN_STATE_VALUE_LIMIT {
        return Err(format!(
            "plugin state values cannot exceed {PLUGIN_STATE_VALUE_LIMIT} bytes"
        ));
    }
    let previous_len = store.state.get(&key).map_or(0, Vec::len);
    let current_len: usize = store.state.values().map(Vec::len).sum();
    let new_len = current_len
        .saturating_sub(previous_len)
        .saturating_add(value.len());
    if !store.state.contains_key(&key) && store.state.len() >= PLUGIN_STATE_ENTRY_LIMIT {
        return Err(format!(
            "a plugin can store at most {PLUGIN_STATE_ENTRY_LIMIT} state entries"
        ));
    }
    if new_len > PLUGIN_STATE_TOTAL_LIMIT {
        return Err(format!(
            "a plugin state store cannot exceed {PLUGIN_STATE_TOTAL_LIMIT} bytes"
        ));
    }
    store.state.insert(key, value);
    Ok(())
}

fn plugin_state_delete(store: &mut PluginStore, key: &str) -> Result<bool, String> {
    validate_plugin_state_key(key)?;
    Ok(store.state.remove(key).is_some())
}

async fn persist_plugin_state(
    database: &DatabasePool,
    table_prefix: &str,
    plugin: &LoadedPlugin,
) -> Result<(), Box<dyn Error>> {
    checkpoint_plugin_state(
        database,
        table_prefix,
        &plugin.store.data().name,
        &plugin.store.data().state,
    )
    .await
}

async fn checkpoint_plugin_state(
    database: &DatabasePool,
    table_prefix: &str,
    plugin_name: &str,
    state: &HashMap<String, Vec<u8>>,
) -> Result<(), Box<dyn Error>> {
    let mut entries: Vec<_> = state
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    database
        .replace_wasm_plugin_state(table_prefix, plugin_name, &entries)
        .await?;
    Ok(())
}

fn log_plugin_message(plugin: &str, level: &str, message: &str) -> Result<(), String> {
    if message.len() > PLUGIN_LOG_MESSAGE_LIMIT {
        return Err(format!(
            "plugin log message exceeds the {PLUGIN_LOG_MESSAGE_LIMIT}-byte limit"
        ));
    }
    match level {
        "trace" => tracing::trace!(plugin = %plugin, message = %message, "WASM plugin log"),
        "debug" => tracing::debug!(plugin = %plugin, message = %message, "WASM plugin log"),
        "info" => tracing::info!(plugin = %plugin, message = %message, "WASM plugin log"),
        "warn" => tracing::warn!(plugin = %plugin, message = %message, "WASM plugin log"),
        "error" => tracing::error!(plugin = %plugin, message = %message, "WASM plugin log"),
        _ => return Err("plugin log level must be trace, debug, info, warn, or error".into()),
    }
    Ok(())
}

fn stop_plugin(plugin: &mut LoadedPlugin) -> Result<(), Box<dyn Error>> {
    plugin.store.set_fuel(COMPONENT_FUEL)?;
    let shutdown_export = plugin
        .instance
        .get_export_index(&mut plugin.store, Some(&plugin.lifecycle), "shutdown")
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "component lifecycle is missing shutdown",
            )
        })?;
    let shutdown = plugin
        .instance
        .get_typed_func::<(), ()>(&mut plugin.store, &shutdown_export)?;
    shutdown.call(&mut plugin.store, ())?;
    Ok(())
}

fn plugin_engine() -> Result<Engine, Box<dyn Error>> {
    let mut config = Config::new();
    config.wasm_component_model(true).consume_fuel(true);
    Ok(Engine::new(&config)?)
}

pub fn valid_plugin_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.is_ascii()
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && !name.contains("..")
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn find_components(directory: &Path, output: &mut Vec<PathBuf>) -> io::Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let path = entry.path();
        if file_type.is_dir() {
            find_components(&path, output)?;
        } else if file_type.is_file()
            && path
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("wasm"))
        {
            output.push(path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        PLUGIN_EVENT_PAYLOAD_LIMIT, PLUGIN_LOG_MESSAGE_LIMIT, PLUGIN_STATE_VALUE_LIMIT,
        PluginRuntime, PluginStore, StoreLimitsBuilder, checkpoint_plugin_state,
        log_plugin_message, plugin_state_delete, plugin_state_get, plugin_state_set,
        validate_plugin_event, validated_plugin_state,
    };
    use std::{
        collections::HashMap,
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT: AtomicU64 = AtomicU64::new(1);

    fn temp_dir() -> PathBuf {
        std::env::temp_dir().join(format!(
            "blessing-skin-wasm-runtime-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn component_validation_rejects_non_component_bytes() {
        assert!(PluginRuntime::validate_component_bytes(b"not a wasm component").is_err());
    }

    #[test]
    fn plugin_events_are_allowlisted_bounded_json_objects() {
        assert!(validate_plugin_event("user.logged-in", br#"{"user_id":7}"#).is_ok());
        assert!(
            validate_plugin_event(
                "user.profile.updated",
                br#"{"user_id":7,"action":"nickname"}"#
            )
            .is_ok()
        );
        assert!(
            validate_plugin_event(
                "player.renamed",
                br#"{"user_id":7,"player_id":3,"previous_name":"Alex","name":"Steve"}"#
            )
            .is_ok()
        );
        assert!(validate_plugin_event("unsupported", b"{}").is_err());
        assert!(validate_plugin_event("player.added", b"[]").is_err());
        assert!(validate_plugin_event("player.deleted", b"not json").is_err());
        assert!(
            validate_plugin_event("player.added", &vec![b' '; PLUGIN_EVENT_PAYLOAD_LIMIT + 1])
                .is_err()
        );
    }

    #[test]
    fn plugin_names_are_single_safe_filename_stems() {
        assert!(super::valid_plugin_name("skin-tools.v2"));
        assert!(!super::valid_plugin_name("../outside"));
        assert!(!super::valid_plugin_name("folder/plugin"));
        assert!(!super::valid_plugin_name(""));
    }

    #[test]
    fn plugin_logger_accepts_known_levels_and_bounds_messages() {
        assert!(log_plugin_message("fixture", "info", "ready").is_ok());
        assert!(log_plugin_message("fixture", "notice", "ready").is_err());
        assert!(
            log_plugin_message("fixture", "info", &"x".repeat(PLUGIN_LOG_MESSAGE_LIMIT + 1))
                .is_err()
        );
    }

    #[tokio::test]
    async fn plugin_state_checkpoint_restores_the_bounded_guest_store() {
        use sqlx::sqlite::SqlitePoolOptions;

        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        let database = crate::database::DatabasePool::Sqlite(pool);
        database
            .ensure_wasm_plugin_state_schema("bs_")
            .await
            .unwrap();

        let mut guest_store = PluginStore {
            name: "checkpoint-fixture".to_owned(),
            limits: StoreLimitsBuilder::new().build(),
            state: HashMap::new(),
        };
        plugin_state_set(
            &mut guest_store,
            "binary-value".to_owned(),
            vec![0, 127, 128, 255],
        )
        .unwrap();
        checkpoint_plugin_state(&database, "bs_", &guest_store.name, &guest_store.state)
            .await
            .unwrap();

        let restored = validated_plugin_state(
            database
                .wasm_plugin_state_entries("bs_", "checkpoint-fixture")
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            plugin_state_get(
                &PluginStore {
                    name: "checkpoint-fixture".to_owned(),
                    limits: StoreLimitsBuilder::new().build(),
                    state: restored,
                },
                "binary-value",
            )
            .unwrap(),
            Some(vec![0, 127, 128, 255])
        );
    }

    #[tokio::test]
    async fn missing_plugin_directory_is_an_empty_runtime() {
        let path = temp_dir();
        let runtime = PluginRuntime::load(&path, None, "").await.unwrap();
        assert_eq!(runtime.loaded_count(), 0);
    }

    #[tokio::test]
    async fn php_files_are_ignored_and_invalid_components_are_isolated() {
        use sqlx::sqlite::SqlitePoolOptions;

        let path = temp_dir();
        fs::create_dir_all(path.join("nested")).unwrap();
        fs::write(path.join("old-plugin.php"), "<?php exit;").unwrap();
        fs::write(path.join("nested/invalid.wasm"), "not a component").unwrap();
        fs::write(path.join("nested/empty.wasm"), "(component)").unwrap();
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        let database = crate::database::DatabasePool::Sqlite(pool);
        let mut runtime = PluginRuntime::load(&path, Some(database), "bs_")
            .await
            .unwrap();
        assert_eq!(runtime.loaded_count(), 0);
        runtime.shutdown().await;
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn plugin_state_is_scoped_bounded_and_binary_safe() {
        let mut state = PluginStore {
            name: "test".to_owned(),
            limits: StoreLimitsBuilder::new().build(),
            state: HashMap::new(),
        };
        assert_eq!(plugin_state_get(&state, "token").unwrap(), None);
        plugin_state_set(&mut state, "token".to_owned(), vec![0, 128, 255]).unwrap();
        assert_eq!(
            plugin_state_get(&state, "token").unwrap(),
            Some(vec![0, 128, 255])
        );
        assert!(plugin_state_set(&mut state, "".to_owned(), vec![]).is_err());
        assert!(
            plugin_state_set(
                &mut state,
                "too-large".to_owned(),
                vec![0; PLUGIN_STATE_VALUE_LIMIT + 1]
            )
            .is_err()
        );
        assert!(plugin_state_delete(&mut state, "token").unwrap());
        assert!(!plugin_state_delete(&mut state, "token").unwrap());
        assert!(validated_plugin_state(vec![("".to_owned(), vec![])]).is_err());
        assert!(
            validated_plugin_state(vec![(
                "large".to_owned(),
                vec![0; PLUGIN_STATE_VALUE_LIMIT + 1]
            )])
            .is_err()
        );
    }
}
