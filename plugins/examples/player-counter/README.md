# Player counter WASM example

This small plugin demonstrates the blessing-skin:plugin@1.0.0 guest API. It persists a counter in the plugin-scoped state store, increments it after each player.added event, and exposes the count through the plugin readme page. Other event types are ignored.

Install the Rust WebAssembly component toolchain using the Bytecode Alliance component guide, then build from this directory:

    cargo component build --release

Copy target/wasm32-wasip1/release/blessing_skin_player_counter.wasm into the configured PLUGINS_DIR, then restart the Rust service. The host provides only the documented logging and plugin state imports; this guest does not use filesystem, network, WASI, or raw database access.

The WIT source here is kept byte-for-byte aligned with plugins/sdk/wit/world.wit. A repository test checks this and the legacy-plugin migration scaffold against the same contract.
