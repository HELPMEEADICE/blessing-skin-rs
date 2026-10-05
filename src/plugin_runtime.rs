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

const HOST_API_VERSION: &str = "1.22.0";
const LIFECYCLE_INTERFACE: &str = "blessing-skin:plugin/lifecycle@1.0.0";
const HOST_LOG_INTERFACE: &str = "blessing-skin:plugin/host@1.0.0";
const HOST_STATE_INTERFACE: &str = "blessing-skin:plugin/state@1.0.0";
const PLUGIN_EVENTS_INTERFACE: &str = "blessing-skin:plugin/events@1.0.0";
const PLUGIN_FILTERS_INTERFACE: &str = "blessing-skin:plugin/filters@1.0.0";
const PLUGIN_DOCUMENTATION_INTERFACE: &str = "blessing-skin:plugin/documentation@1.0.0";
const PLUGIN_CONFIGURATION_INTERFACE: &str = "blessing-skin:plugin/configuration@1.0.0";
const COMPONENT_FUEL: u64 = 5_000_000;
const COMPONENT_MEMORY_LIMIT: usize = 64 * 1024 * 1024;
const PLUGIN_LOG_MESSAGE_LIMIT: usize = 4 * 1024;
const PLUGIN_STATE_KEY_LIMIT: usize = 128;
const PLUGIN_STATE_VALUE_LIMIT: usize = 64 * 1024;
const PLUGIN_STATE_ENTRY_LIMIT: usize = 256;
const PLUGIN_STATE_TOTAL_LIMIT: usize = 1024 * 1024;
const PLUGIN_EVENT_PAYLOAD_LIMIT: usize = 64 * 1024;
const PLUGIN_FILTER_VALUE_LIMIT: usize = 64 * 1024;
const PLUGIN_CONFIGURATION_LIMIT: usize = 64 * 1024;
const PLUGIN_README_LIMIT: usize = 1024 * 1024;
const PLUGIN_EVENT_NAMES: &[&str] = &[
    "user.logged-in",
    "user.logged-out",
    "auth.login.attempt",
    "auth.login.ready",
    "auth.login.succeeded",
    "auth.login.failed",
    "auth.logout.before",
    "auth.logout.after",
    "auth.registration.attempt",
    "auth.registration.ready",
    "auth.registration.completed",
    "auth.forgot.attempt",
    "auth.forgot.ready",
    "auth.forgot.sent",
    "auth.forgot.failed",
    "auth.reset.before",
    "auth.reset.after",
    "user.registered",
    "user.profile.updated",
    "user.profile.updating",
    "user.email.updating",
    "user.email.updated",
    "user.nickname.updating",
    "user.nickname.updated",
    "user.password.updating",
    "user.password.updated",
    "user.verification.updating",
    "user.score.updating",
    "user.permission.updating",
    "user.banned",
    "user.avatar.updated",
    "user.avatar.updating",
    "user.deleted",
    "user.deleting",
    "user.verification.updated",
    "user.permission.updated",
    "user.score.updated",
    "user.sign.before",
    "user.sign.after",
    "closet.added",
    "closet.renamed",
    "closet.removed",
    "player.add.attempt",
    "player.adding",
    "player.added",
    "player.delete.attempt",
    "player.deleting",
    "player.renaming",
    "player.renamed",
    "player.deleted",
    "player.owner.updated",
    "player.owner.updating",
    "player.textures.updated",
    "player.texture.updating",
    "player.texture.updated",
    "player.texture.resetting",
    "player.texture.reset",
    "texture.uploaded",
    "texture.renamed",
    "texture.deleted",
    "texture.visibility.updated",
    "texture.type.updated",
    "notification.sent",
    "notification.read",
    "report.submitted",
    "report.reviewed",
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
    filters: Option<ComponentExportIndex>,
    documentation: Option<ComponentExportIndex>,
    configuration: Option<ComponentExportIndex>,
}

pub struct PluginRuntime {
    plugins: Vec<LoadedPlugin>,
    load_failures: Vec<String>,
    database: Option<DatabasePool>,
    table_prefix: String,
}

impl PluginRuntime {
    pub fn shared_empty() -> std::sync::Arc<tokio::sync::Mutex<Self>> {
        std::sync::Arc::new(tokio::sync::Mutex::new(Self {
            plugins: Vec::new(),
            load_failures: Vec::new(),
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
            load_failures: Vec::new(),
            database: database.clone(),
            table_prefix: table_prefix.to_owned(),
        };
        if paths.is_empty() {
            return Ok(runtime);
        }
        let Some(database) = database else {
            runtime.record_failed_paths(&paths);
            tracing::warn!(directory = %directory.display(), "WASM plugins were not loaded because the database is unavailable for persistent plugin state");
            return Ok(runtime);
        };
        if let Err(error) = database.ensure_wasm_plugin_state_schema(table_prefix).await {
            runtime.record_failed_paths(&paths);
            tracing::warn!(%error, "WASM plugins were not loaded because their state table could not be prepared");
            return Ok(runtime);
        }
        for path in paths {
            if let Err(error) = runtime.load_component(&engine, &path, &database).await {
                runtime.record_failed_path(&path);
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
            load_failures: Vec::new(),
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

    pub fn failed_plugin_names(&self) -> Vec<String> {
        self.load_failures.clone()
    }

    fn record_failed_paths(&mut self, paths: &[PathBuf]) {
        for path in paths {
            self.record_failed_path(path);
        }
    }

    fn record_failed_path(&mut self, path: &Path) {
        let Some(filename) = path.file_name().and_then(|filename| filename.to_str()) else {
            return;
        };
        let Some(name) = filename.strip_suffix(".wasm") else {
            return;
        };
        if !valid_plugin_name(name) {
            return;
        }
        let filename = format!("{name}.wasm");
        if !self.load_failures.contains(&filename) {
            self.load_failures.push(filename);
        }
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

    pub fn plugin_readme_names(&self) -> Vec<String> {
        self.plugins
            .iter()
            .filter(|plugin| plugin.documentation.is_some())
            .filter_map(|plugin| plugin.path.file_stem()?.to_str().map(str::to_owned))
            .collect()
    }

    pub fn plugin_configuration_names(&self) -> Vec<String> {
        self.plugins
            .iter()
            .filter(|plugin| plugin.configuration.is_some())
            .filter_map(|plugin| plugin.path.file_stem()?.to_str().map(str::to_owned))
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
        let filters = instance.get_export_index(&mut store, None, PLUGIN_FILTERS_INTERFACE);
        if let Some(filters_export) = &filters {
            let apply_export = instance
                .get_export_index(&mut store, Some(filters_export), "apply")
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "plugin filters interface is missing apply",
                    )
                })?;
            instance
                .get_typed_func::<(String, String, String), (Result<Option<String>, String>,)>(
                    &mut store,
                    &apply_export,
                )?;
        }
        let documentation =
            instance.get_export_index(&mut store, None, PLUGIN_DOCUMENTATION_INTERFACE);
        if let Some(export) = &documentation {
            let readme = instance
                .get_export_index(&mut store, Some(export), "readme")
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "plugin documentation interface is missing readme",
                    )
                })?;
            instance
                .get_typed_func::<(), (Result<Option<String>, String>,)>(&mut store, &readme)?;
        }
        let configuration =
            instance.get_export_index(&mut store, None, PLUGIN_CONFIGURATION_INTERFACE);
        if let Some(export) = &configuration {
            let get = instance
                .get_export_index(&mut store, Some(export), "get")
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "plugin configuration interface is missing get",
                    )
                })?;
            instance.get_typed_func::<(), (Result<Option<String>, String>,)>(&mut store, &get)?;
            let set = instance
                .get_export_index(&mut store, Some(export), "set")
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "plugin configuration interface is missing set",
                    )
                })?;
            instance.get_typed_func::<(String,), (Result<(), String>,)>(&mut store, &set)?;
        }
        self.plugins.push(LoadedPlugin {
            path: path.to_owned(),
            store,
            instance,
            lifecycle,
            events,
            filters,
            documentation,
            configuration,
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

    pub async fn apply_filter(
        &mut self,
        name: &str,
        value: &serde_json::Value,
        context: &serde_json::Value,
    ) -> serde_json::Value {
        if let Err(error) = validate_plugin_filter(name, value, context) {
            tracing::warn!(%error, filter = name, "ignored invalid WASM plugin filter input");
            return value.clone();
        }
        let database = self.database.clone();
        let table_prefix = self.table_prefix.clone();
        let mut current = value.clone();
        for plugin in &mut self.plugins {
            if plugin.filters.is_none() {
                continue;
            }
            let previous_state = plugin.store.data().state.clone();
            match invoke_plugin_filter(plugin, name, &current, context) {
                Ok(filtered) => {
                    if plugin.store.data().state != previous_state {
                        let Some(database) = &database else {
                            plugin.store.data_mut().state = previous_state;
                            tracing::warn!(plugin = %plugin.path.display(), filter = name, "WASM plugin filter state was rolled back because storage is unavailable");
                            continue;
                        };
                        if let Err(error) =
                            persist_plugin_state(database, &table_prefix, plugin).await
                        {
                            plugin.store.data_mut().state = previous_state;
                            tracing::warn!(%error, plugin = %plugin.path.display(), filter = name, "WASM plugin filter checkpoint failed; guest state and result were rolled back");
                            continue;
                        }
                    }
                    if let Some(filtered) = filtered {
                        current = filtered;
                    }
                }
                Err(error) => {
                    plugin.store.data_mut().state = previous_state;
                    tracing::warn!(%error, plugin = %plugin.path.display(), filter = name, "WASM plugin filter failed; continuing with the previous value");
                }
            }
        }
        current
    }

    pub async fn read_plugin_readme(&mut self, name: &str) -> Result<Option<String>, String> {
        let Some(plugin) = self.find_plugin_mut(name) else {
            return Ok(None);
        };
        let Some(interface) = plugin.documentation.as_ref() else {
            return Ok(None);
        };
        let export = plugin
            .instance
            .get_export_index(&mut plugin.store, Some(interface), "readme")
            .ok_or_else(|| "missing plugin readme export".to_owned())?;
        let readme = plugin
            .instance
            .get_typed_func::<(), (Result<Option<String>, String>,)>(&mut plugin.store, &export)
            .map_err(|error| error.to_string())?;
        plugin
            .store
            .set_fuel(COMPONENT_FUEL)
            .map_err(|error| error.to_string())?;
        let previous_state = plugin.store.data().state.clone();
        let result = readme
            .call(&mut plugin.store, ())
            .map_err(|error| error.to_string());
        plugin.store.data_mut().state = previous_state;
        let (result,) = result?;
        let result = result?;
        if result
            .as_ref()
            .is_some_and(|value| value.len() > PLUGIN_README_LIMIT)
        {
            return Err(format!("plugin README exceeds {PLUGIN_README_LIMIT} bytes"));
        }
        Ok(result)
    }

    pub async fn read_plugin_configuration(
        &mut self,
        name: &str,
    ) -> Result<Option<String>, String> {
        let Some(plugin) = self.find_plugin_mut(name) else {
            return Ok(None);
        };
        let Some(interface) = plugin.configuration.as_ref() else {
            return Ok(None);
        };
        let export = plugin
            .instance
            .get_export_index(&mut plugin.store, Some(interface), "get")
            .ok_or_else(|| "missing plugin configuration get export".to_owned())?;
        let get = plugin
            .instance
            .get_typed_func::<(), (Result<Option<String>, String>,)>(&mut plugin.store, &export)
            .map_err(|error| error.to_string())?;
        plugin
            .store
            .set_fuel(COMPONENT_FUEL)
            .map_err(|error| error.to_string())?;
        let previous_state = plugin.store.data().state.clone();
        let result = get
            .call(&mut plugin.store, ())
            .map_err(|error| error.to_string());
        plugin.store.data_mut().state = previous_state;
        let (result,) = result?;
        let result = result?;
        if let Some(configuration) = result.as_deref() {
            validate_plugin_configuration(configuration)?;
        }
        Ok(result)
    }

    pub async fn save_plugin_configuration(
        &mut self,
        name: &str,
        configuration: &str,
    ) -> Result<bool, String> {
        validate_plugin_configuration(configuration)?;
        let database = self.database.clone();
        let table_prefix = self.table_prefix.clone();
        let Some(plugin) = self.find_plugin_mut(name) else {
            return Ok(false);
        };
        let Some(interface) = plugin.configuration.as_ref() else {
            return Ok(false);
        };
        let export = plugin
            .instance
            .get_export_index(&mut plugin.store, Some(interface), "set")
            .ok_or_else(|| "missing plugin configuration set export".to_owned())?;
        let set = plugin
            .instance
            .get_typed_func::<(String,), (Result<(), String>,)>(&mut plugin.store, &export)
            .map_err(|error| error.to_string())?;
        plugin
            .store
            .set_fuel(COMPONENT_FUEL)
            .map_err(|error| error.to_string())?;
        let previous_state = plugin.store.data().state.clone();
        let result = set
            .call(&mut plugin.store, (configuration.to_owned(),))
            .map_err(|error| error.to_string());
        let (result,) = match result {
            Ok(result) => result,
            Err(error) => {
                plugin.store.data_mut().state = previous_state;
                return Err(error);
            }
        };
        if let Err(error) = result {
            plugin.store.data_mut().state = previous_state;
            return Err(error);
        }
        if plugin.store.data().state != previous_state {
            let Some(database) = database else {
                plugin.store.data_mut().state = previous_state;
                return Err("plugin state storage is unavailable".to_owned());
            };
            if let Err(error) = persist_plugin_state(&database, &table_prefix, plugin).await {
                plugin.store.data_mut().state = previous_state;
                return Err(error.to_string());
            }
        }
        Ok(true)
    }

    fn find_plugin_mut(&mut self, name: &str) -> Option<&mut LoadedPlugin> {
        if !valid_plugin_name(name) {
            return None;
        }
        self.plugins
            .iter_mut()
            .find(|plugin| plugin.path.file_stem().and_then(|stem| stem.to_str()) == Some(name))
    }

    #[cfg(test)]
    fn loaded_count(&self) -> usize {
        self.plugins.len()
    }
}

fn validate_plugin_configuration(configuration: &str) -> Result<(), String> {
    if configuration.len() > PLUGIN_CONFIGURATION_LIMIT {
        return Err(format!(
            "plugin configuration exceeds {PLUGIN_CONFIGURATION_LIMIT} bytes"
        ));
    }
    let value: serde_json::Value = serde_json::from_str(configuration)
        .map_err(|_| "plugin configuration must be UTF-8 JSON".to_owned())?;
    if !value.is_object() {
        return Err("plugin configuration must be a JSON object".to_owned());
    }
    Ok(())
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

fn validate_plugin_filter(
    name: &str,
    value: &serde_json::Value,
    context: &serde_json::Value,
) -> Result<(), String> {
    if !matches!(
        name,
        "can_sign"
            | "sign_score"
            | "new_player_name"
            | "can_add_player"
            | "can_rename_player"
            | "can_delete_player"
            | "can_set_texture"
            | "can_clear_texture"
            | "user_can_update_avatar"
            | "user_can_edit_profile"
    ) {
        return Err("unsupported plugin filter name".to_owned());
    }
    if !context.is_object() {
        return Err("plugin filter context must be a JSON object".to_owned());
    }
    validate_plugin_filter_value(name, value)?;
    for (label, value) in [("value", value), ("context", context)] {
        let encoded = serde_json::to_vec(value).map_err(|_| "plugin filter input is not JSON")?;
        if encoded.len() > PLUGIN_FILTER_VALUE_LIMIT {
            return Err(format!(
                "plugin filter {label} exceeds {PLUGIN_FILTER_VALUE_LIMIT} bytes"
            ));
        }
    }
    Ok(())
}

fn validate_plugin_filter_value(name: &str, value: &serde_json::Value) -> Result<(), String> {
    match name {
        "can_sign"
        | "can_add_player"
        | "can_rename_player"
        | "can_delete_player"
        | "can_set_texture"
        | "can_clear_texture"
        | "user_can_update_avatar"
        | "user_can_edit_profile"
            if value.is_boolean()
                || value
                    .get("rejection")
                    .is_some_and(serde_json::Value::is_string) =>
        {
            Ok(())
        }
        "new_player_name" if value.is_string() => Ok(()),
        "sign_score" if value.as_i64().is_some() => Ok(()),
        "can_sign"
        | "can_add_player"
        | "can_rename_player"
        | "can_delete_player"
        | "can_set_texture"
        | "can_clear_texture"
        | "user_can_update_avatar"
        | "user_can_edit_profile" => Err(
            "permission filters must return a boolean or an object with a string rejection"
                .to_owned(),
        ),
        "new_player_name" => Err("new_player_name filters must return a string".to_owned()),
        "sign_score" => Err("sign_score filters must return a signed integer".to_owned()),
        _ => Err("unsupported plugin filter name".to_owned()),
    }
}

fn invoke_plugin_filter(
    plugin: &mut LoadedPlugin,
    name: &str,
    value: &serde_json::Value,
    context: &serde_json::Value,
) -> Result<Option<serde_json::Value>, String> {
    let Some(filters) = plugin.filters.as_ref() else {
        return Ok(None);
    };
    let apply_export = plugin
        .instance
        .get_export_index(&mut plugin.store, Some(filters), "apply")
        .ok_or_else(|| "missing plugin filter apply export".to_owned())?;
    let apply = plugin
        .instance
        .get_typed_func::<(String, String, String), (Result<Option<String>, String>,)>(
            &mut plugin.store,
            &apply_export,
        )
        .map_err(|error| error.to_string())?;
    plugin
        .store
        .set_fuel(COMPONENT_FUEL)
        .map_err(|error| error.to_string())?;
    let value = serde_json::to_string(value).map_err(|error| error.to_string())?;
    let context = serde_json::to_string(context).map_err(|error| error.to_string())?;
    let (result,) = apply
        .call(&mut plugin.store, (name.to_owned(), value, context))
        .map_err(|error| error.to_string())?;
    let Some(filtered) = result.map_err(|message| format!("plugin rejected filter: {message}"))?
    else {
        return Ok(None);
    };
    if filtered.len() > PLUGIN_FILTER_VALUE_LIMIT {
        return Err(format!(
            "plugin filter result exceeds {PLUGIN_FILTER_VALUE_LIMIT} bytes"
        ));
    }
    let filtered: serde_json::Value = serde_json::from_str(&filtered)
        .map_err(|_| "plugin filter result must be UTF-8 JSON".to_owned())?;
    validate_plugin_filter_value(name, &filtered)?;
    Ok(Some(filtered))
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
        PLUGIN_CONFIGURATION_LIMIT, PLUGIN_EVENT_PAYLOAD_LIMIT, PLUGIN_FILTER_VALUE_LIMIT,
        PLUGIN_LOG_MESSAGE_LIMIT, PLUGIN_STATE_VALUE_LIMIT, PluginRuntime, PluginStore,
        StoreLimitsBuilder, checkpoint_plugin_state, log_plugin_message, plugin_state_delete,
        plugin_state_get, plugin_state_set, validate_plugin_configuration, validate_plugin_event,
        validate_plugin_filter, validate_plugin_filter_value, validated_plugin_state,
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
    fn plugin_configuration_is_a_bounded_json_object() {
        assert!(validate_plugin_configuration("{}").is_ok());
        assert!(validate_plugin_configuration(r#"{"enabled":true}"#).is_ok());
        assert!(validate_plugin_configuration("[]").is_err());
        assert!(validate_plugin_configuration("null").is_err());
        assert!(validate_plugin_configuration("not json").is_err());
        assert!(
            validate_plugin_configuration(&format!(
                "{{\"value\":\"{}\"}}",
                "x".repeat(PLUGIN_CONFIGURATION_LIMIT)
            ))
            .is_err()
        );
    }

    #[test]
    fn plugin_events_are_allowlisted_bounded_json_objects() {
        assert!(validate_plugin_event("user.logged-in", br#"{"user_id":7}"#).is_ok());
        assert!(validate_plugin_event("user.logged-out", br#"{"user_id":7}"#).is_ok());
        assert!(
            validate_plugin_event(
                "user.verification.updated",
                br#"{"user_id":7,"previous_verified":false,"verified":true}"#
            )
            .is_ok()
        );
        assert!(
            validate_plugin_event(
                "user.permission.updated",
                br#"{"user_id":7,"previous_permission":0,"permission":1}"#
            )
            .is_ok()
        );
        assert!(
            validate_plugin_event(
                "user.score.updated",
                br#"{"user_id":7,"previous_score":10,"score":12}"#
            )
            .is_ok()
        );
        assert!(validate_plugin_event("user.sign.before", br#"{"user_id":7,"score":10}"#).is_ok());
        assert!(validate_plugin_event("user.sign.after", br#"{"user_id":7,"score":10}"#).is_ok());
        assert!(
            validate_plugin_event(
                "player.owner.updated",
                br#"{"player_id":11,"previous_user_id":7,"user_id":8}"#
            )
            .is_ok()
        );
        assert!(
            validate_plugin_event(
                "player.textures.updated",
                br#"{"user_id":8,"player_id":11,"skin_texture_id":12,"cape_texture_id":0}"#
            )
            .is_ok()
        );
        assert!(
            validate_plugin_event(
                "user.profile.updated",
                br#"{"user_id":7,"action":"nickname"}"#
            )
            .is_ok()
        );
        assert!(
            validate_plugin_event("user.avatar.updating", br#"{"user_id":7,"texture_id":11}"#)
                .is_ok()
        );
        assert!(
            validate_plugin_event("user.avatar.updated", br#"{"user_id":7,"texture_id":11}"#)
                .is_ok()
        );
        assert!(
            validate_plugin_event(
                "user.profile.updating",
                br#"{"user_id":7,"action":"nickname"}"#
            )
            .is_ok()
        );
        assert!(validate_plugin_event("user.deleting", br#"{"user_id":7}"#).is_ok());
        for name in [
            "auth.login.attempt",
            "auth.login.ready",
            "auth.login.succeeded",
            "auth.login.failed",
            "auth.logout.before",
            "auth.logout.after",
            "auth.registration.attempt",
            "auth.registration.ready",
            "auth.registration.completed",
            "auth.forgot.attempt",
            "auth.forgot.ready",
            "auth.forgot.sent",
            "auth.forgot.failed",
            "auth.reset.before",
            "auth.reset.after",
            "user.email.updating",
            "user.email.updated",
            "user.nickname.updating",
            "user.nickname.updated",
            "user.password.updating",
            "user.password.updated",
            "user.verification.updating",
            "user.score.updating",
            "user.permission.updating",
            "user.banned",
        ] {
            assert!(
                validate_plugin_event(name, br#"{"user_id":7}"#).is_ok(),
                "{name}"
            );
        }
        assert!(
            validate_plugin_event(
                "player.renamed",
                br#"{"user_id":7,"player_id":3,"previous_name":"Alex","name":"Steve"}"#
            )
            .is_ok()
        );
        assert!(
            validate_plugin_event(
                "notification.sent",
                br#"{"sender_id":1,"recipient_id":7,"notification_id":"legacy-id"}"#
            )
            .is_ok()
        );
        assert!(
            validate_plugin_event(
                "notification.read",
                br#"{"user_id":7,"notification_id":"legacy-id"}"#
            )
            .is_ok()
        );
        assert!(
            validate_plugin_event(
                "report.submitted",
                br#"{"reporter_id":7,"texture_id":11,"uploader_id":3}"#
            )
            .is_ok()
        );
        assert!(
            validate_plugin_event(
                "report.reviewed",
                br#"{"report_id":9,"admin_user_id":1,"action":"reject","status":2}"#
            )
            .is_ok()
        );
        assert!(
            validate_plugin_event(
                "closet.added",
                br#"{"user_id":7,"texture_id":11,"item_name":"Favorite"}"#
            )
            .is_ok()
        );
        assert!(
            validate_plugin_event(
                "closet.renamed",
                br#"{"user_id":7,"texture_id":11,"item_name":"New name"}"#
            )
            .is_ok()
        );
        assert!(
            validate_plugin_event("closet.removed", br#"{"user_id":7,"texture_id":11}"#).is_ok()
        );
        assert!(validate_plugin_event("unsupported", b"{}").is_err());
        assert!(
            validate_plugin_event("player.add.attempt", br#"{"user_id":7,"name":"Alex"}"#).is_ok()
        );
        assert!(validate_plugin_event("player.adding", br#"{"user_id":7,"name":"Alex"}"#).is_ok());
        assert!(
            validate_plugin_event(
                "player.delete.attempt",
                br#"{"user_id":7,"player_id":3,"name":"Alex"}"#
            )
            .is_ok()
        );
        assert!(
            validate_plugin_event(
                "player.deleting",
                br#"{"user_id":7,"player_id":3,"name":"Alex"}"#
            )
            .is_ok()
        );
        assert!(
            validate_plugin_event(
                "player.texture.updating",
                br#"{"user_id":7,"player_id":3,"name":"Alex","type":"skin","texture_id":11}"#
            )
            .is_ok()
        );
        assert!(
            validate_plugin_event(
                "player.texture.updated",
                br#"{"user_id":7,"player_id":3,"name":"Alex","type":"skin","previous_texture_id":0,"texture_id":11}"#
            )
            .is_ok()
        );
        assert!(
            validate_plugin_event(
                "player.texture.resetting",
                br#"{"user_id":7,"player_id":3,"name":"Alex","type":"skin","texture_id":11}"#
            )
            .is_ok()
        );
        assert!(
            validate_plugin_event(
                "player.texture.reset",
                br#"{"user_id":7,"player_id":3,"name":"Alex","type":"skin","previous_texture_id":11,"texture_id":0}"#
            )
            .is_ok()
        );
        assert!(
            validate_plugin_event(
                "player.owner.updating",
                br#"{"player_id":3,"previous_user_id":7,"user_id":9}"#
            )
            .is_ok()
        );
        assert!(
            validate_plugin_event(
                "player.renaming",
                br#"{"user_id":7,"player_id":3,"previous_name":"Alex","name":"Steve"}"#
            )
            .is_ok()
        );
        assert!(validate_plugin_event("player.added", b"[]").is_err());
        assert!(validate_plugin_event("player.deleted", b"not json").is_err());
        assert!(
            validate_plugin_event("player.added", &vec![b' '; PLUGIN_EVENT_PAYLOAD_LIMIT + 1])
                .is_err()
        );
    }

    #[test]
    fn plugin_filters_validate_supported_values_and_bound_context() {
        let context = serde_json::json!({ "user_id": 7 });
        assert!(validate_plugin_filter("can_sign", &serde_json::json!(true), &context).is_ok());
        assert!(
            validate_plugin_filter("can_add_player", &serde_json::json!(true), &context).is_ok()
        );
        assert!(validate_plugin_filter_value("can_sign", &serde_json::json!(false)).is_ok());
        assert!(
            validate_plugin_filter("can_rename_player", &serde_json::json!(true), &context).is_ok()
        );
        assert!(
            validate_plugin_filter("can_delete_player", &serde_json::json!(true), &context).is_ok()
        );
        assert!(
            validate_plugin_filter("can_set_texture", &serde_json::json!(true), &context).is_ok()
        );
        assert!(
            validate_plugin_filter("can_clear_texture", &serde_json::json!(true), &context).is_ok()
        );
        assert!(
            validate_plugin_filter("user_can_update_avatar", &serde_json::json!(true), &context)
                .is_ok()
        );
        assert!(
            validate_plugin_filter("user_can_edit_profile", &serde_json::json!(true), &context)
                .is_ok()
        );
        assert!(
            validate_plugin_filter_value(
                "can_rename_player",
                &serde_json::json!({ "rejection": "disabled" })
            )
            .is_ok()
        );
        assert!(
            validate_plugin_filter_value(
                "can_delete_player",
                &serde_json::json!({ "rejection": "deletion disabled" })
            )
            .is_ok()
        );
        assert!(
            validate_plugin_filter_value(
                "can_set_texture",
                &serde_json::json!({ "rejection": "texture setting disabled" })
            )
            .is_ok()
        );
        assert!(
            validate_plugin_filter_value(
                "can_clear_texture",
                &serde_json::json!({ "rejection": "texture clearing disabled" })
            )
            .is_ok()
        );
        assert!(
            validate_plugin_filter_value(
                "user_can_update_avatar",
                &serde_json::json!({ "rejection": "avatar update disabled" })
            )
            .is_ok()
        );
        assert!(
            validate_plugin_filter_value(
                "user_can_edit_profile",
                &serde_json::json!({ "rejection": "profile editing disabled" })
            )
            .is_ok()
        );
        assert!(
            validate_plugin_filter_value(
                "can_add_player",
                &serde_json::json!({ "rejection": "disabled" })
            )
            .is_ok()
        );
        assert!(
            validate_plugin_filter_value("new_player_name", &serde_json::json!("Steve")).is_ok()
        );
        assert!(validate_plugin_filter_value("new_player_name", &serde_json::json!(7)).is_err());
        assert!(
            validate_plugin_filter_value(
                "can_sign",
                &serde_json::json!({ "rejection": "sign-in disabled" })
            )
            .is_ok()
        );
        assert!(validate_plugin_filter("sign_score", &serde_json::json!(-4), &context).is_ok());
        assert!(validate_plugin_filter_value("sign_score", &serde_json::json!(1.5)).is_err());
        assert!(validate_plugin_filter_value("can_sign", &serde_json::json!("false")).is_err());
        assert!(
            validate_plugin_filter_value("can_sign", &serde_json::json!({ "rejection": false }))
                .is_err()
        );
        assert!(validate_plugin_filter("unknown", &serde_json::json!(true), &context).is_err());
        assert!(
            validate_plugin_filter(
                "can_sign",
                &serde_json::json!(true),
                &serde_json::json!({ "data": "x".repeat(PLUGIN_FILTER_VALUE_LIMIT) })
            )
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
        let mut failed_plugins = runtime.failed_plugin_names();
        failed_plugins.sort();
        assert_eq!(
            failed_plugins,
            vec!["empty.wasm".to_owned(), "invalid.wasm".to_owned()]
        );
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
