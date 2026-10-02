# Legacy plugin migration tool

The Rust service does not load PHP plugins. `plugin-migrate` scans one legacy plugin directory and reports the PHP-specific work before producing an independent Rust component scaffold.

```powershell
cargo run --bin plugin-migrate -- path\to\plugin
cargo run --bin plugin-migrate -- path\to\plugin --output migration\my-plugin
```

The JSON report identifies PHP and Blessing Skin version requirements, dependencies on other PHP plugins, Composer packages, `enchants.providers` and `enchants.config` hooks, PHP source files, and PHP-backed templates. The scanner reads `package.json`, optional `composer.json`, and filenames; it does not execute plugin code or claim to translate PHP behavior.

When the output directory is supplied, it must be new or empty. The generated crate includes `migration-report.json`, a `wit-bindgen` guest, and the versioned `blessing-skin:plugin@1.0.0` contract. It imports `blessing-skin:plugin/host@1.0.0` and exports `blessing-skin:plugin/lifecycle@1.0.0`. The only host capability in this version is `host.log(level, message)`: levels are `trace`, `debug`, `info`, `warn`, and `error`; each message is limited to 4 KiB. Build the component with `cargo component build --release`, then place the resulting `.wasm` component under `PLUGINS_DIR`. The server calls `initialize` and `shutdown`, and skips components that fail to load or initialize.

The host does not expose filesystem, network, database, WASI, or other host imports. Components run with fuel, memory, table, and file-size limits. The versioned logging capability is intended for diagnostics only; plugins cannot register HTTP routes or access Blessing Skin business data yet. New host capabilities require an explicit versioned WIT interface and must preserve the sandbox boundary.

See the [Bytecode Alliance Rust component guide](https://component-model.bytecodealliance.org/language-support/building-a-simple-component/rust.html) for the WIT and `wit-bindgen` component workflow.
