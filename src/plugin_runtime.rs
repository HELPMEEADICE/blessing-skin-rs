use std::{
    error::Error,
    fs, io,
    path::{Path, PathBuf},
};

use wasmtime::{
    Config, Engine, Store, StoreLimits, StoreLimitsBuilder,
    component::{Component, ComponentExportIndex, Instance, Linker},
};

const HOST_API_VERSION: &str = "1.0.0";
const LIFECYCLE_INTERFACE: &str = "blessing-skin:plugin/lifecycle@1.0.0";
const COMPONENT_FUEL: u64 = 5_000_000;
const COMPONENT_MEMORY_LIMIT: usize = 64 * 1024 * 1024;
const COMPONENT_FILE_LIMIT: u64 = 32 * 1024 * 1024;

struct PluginStore {
    limits: StoreLimits,
}

struct LoadedPlugin {
    path: PathBuf,
    store: Store<PluginStore>,
    instance: Instance,
    lifecycle: ComponentExportIndex,
}

pub struct PluginRuntime {
    plugins: Vec<LoadedPlugin>,
}

impl PluginRuntime {
    pub fn load(directory: &Path) -> Result<Self, Box<dyn Error>> {
        let mut config = Config::new();
        config.wasm_component_model(true).consume_fuel(true);
        let engine = Engine::new(&config)?;
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
        };
        for path in paths {
            if let Err(error) = runtime.load_component(&engine, &path) {
                tracing::warn!(%error, plugin = %path.display(), "WASM plugin failed to load; continuing without it");
            }
        }
        tracing::info!(count = runtime.plugins.len(), directory = %directory.display(), "WASM plugins loaded");
        Ok(runtime)
    }

    fn load_component(&mut self, engine: &Engine, path: &Path) -> Result<(), Box<dyn Error>> {
        let metadata = fs::metadata(path)?;
        if metadata.len() > COMPONENT_FILE_LIMIT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "component file exceeds the 32 MiB size limit",
            )
            .into());
        }
        let bytes = fs::read(path)?;
        let component = Component::new(engine, bytes)?;
        let state = PluginStore {
            limits: StoreLimitsBuilder::new()
                .memory_size(COMPONENT_MEMORY_LIMIT)
                .table_elements(10_000)
                .instances(4)
                .tables(4)
                .memories(4)
                .build(),
        };
        let mut store = Store::new(engine, state);
        store.limiter(|state| &mut state.limits);
        store.set_fuel(COMPONENT_FUEL)?;

        // The empty linker is the capability boundary: WASI, filesystem, network,
        // database, and undocumented host imports are unavailable to components.
        let instance = Linker::new(engine).instantiate(&mut store, &component)?;
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
        self.plugins.push(LoadedPlugin {
            path: path.to_owned(),
            store,
            instance,
            lifecycle,
        });
        tracing::info!(plugin = %path.display(), host_api = HOST_API_VERSION, "WASM plugin initialized");
        Ok(())
    }

    pub fn shutdown(&mut self) {
        for plugin in self.plugins.iter_mut().rev() {
            let result = (|| -> Result<(), Box<dyn Error>> {
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
            })();
            if let Err(error) = result {
                tracing::warn!(%error, plugin = %plugin.path.display(), "WASM plugin shutdown failed");
            } else {
                tracing::info!(plugin = %plugin.path.display(), "WASM plugin shut down");
            }
        }
        self.plugins.clear();
    }

    #[cfg(test)]
    fn loaded_count(&self) -> usize {
        self.plugins.len()
    }
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
    use super::PluginRuntime;
    use std::{
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
    fn missing_plugin_directory_is_an_empty_runtime() {
        let path = temp_dir();
        let runtime = PluginRuntime::load(&path).unwrap();
        assert_eq!(runtime.loaded_count(), 0);
    }

    #[test]
    fn php_files_are_ignored_and_invalid_components_are_isolated() {
        let path = temp_dir();
        fs::create_dir_all(path.join("nested")).unwrap();
        fs::write(path.join("old-plugin.php"), "<?php exit;").unwrap();
        fs::write(path.join("nested/invalid.wasm"), "not a component").unwrap();
        fs::write(path.join("nested/empty.wasm"), "(component)").unwrap();
        let mut runtime = PluginRuntime::load(&path).unwrap();
        assert_eq!(runtime.loaded_count(), 0);
        runtime.shutdown();
        fs::remove_dir_all(path).unwrap();
    }
}
