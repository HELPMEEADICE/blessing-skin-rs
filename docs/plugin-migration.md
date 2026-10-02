# Legacy plugin migration tool

The Rust service does not load PHP plugins. `plugin-migrate` scans one legacy plugin directory and reports the PHP-specific work before producing an independent Rust component scaffold.

```powershell
cargo run --bin plugin-migrate -- path\to\plugin
cargo run --bin plugin-migrate -- path\to\plugin --output migration\my-plugin
```

The JSON report identifies PHP and Blessing Skin version requirements, dependencies on other PHP plugins, Composer packages, `enchants.providers` and `enchants.config` hooks, PHP source files, and PHP-backed templates. The scanner reads `package.json`, optional `composer.json`, and filenames; it does not execute plugin code or claim to translate PHP behavior.

When `--output` is supplied, the destination must be new or empty. The generated crate includes `migration-report.json`, a `wit-bindgen` guest, and the versioned `blessing-skin:plugin@1.0.0` lifecycle contract. Build the component with `cargo component build --release`, then place the resulting `.wasm` component under `PLUGINS_DIR`. The server loads the `blessing-skin:plugin/lifecycle@1.0.0` export, calls `initialize` and `shutdown`, and skips components that fail to load or initialize.

The current host exposes no filesystem, network, database, WASI, or other host imports. Components run with fuel and memory limits. This lifecycle runtime is an initial sandbox boundary; plugins cannot yet register HTTP routes or use a stable business-capability API.

See the [Bytecode Alliance Rust component guide](https://component-model.bytecodealliance.org/language-support/building-a-simple-component/rust.html) for the WIT and `wit-bindgen` component workflow.
