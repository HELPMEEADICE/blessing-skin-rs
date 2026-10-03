# Blessing Skin WASM plugin registry, version 1

Rust's admin plugin market consumes one operator-configured HTTPS JSON manifest. It does not read the legacy PHP plugin registry or install ZIP archives. Configure `WASM_PLUGIN_REGISTRY_URL` to enable the market; leaving it unset disables market installs while the admin can still upload reviewed `.wasm` components directly.

A registry is an executable-code source. Only configure a source whose maintainers you trust. TLS protects transport and `sha256` detects component/manifest mismatches; it does not authenticate a publisher independently of the configured registry. Review component provenance before adding a registry URL. Components run inside the documented WASM host boundary, but remain trusted server extensions.

## Version 1 schema

The manifest is UTF-8 JSON, limited to 1 MiB and 500 plugins. The Rust host currently accepts exactly `schema_version: 1` and these fields:

```json
{
  "schema_version": 1,
  "plugins": [
    {
      "name": "example-plugin",
      "version": "1.0.0",
      "title": "Example plugin",
      "description": "An example Blessing Skin component.",
      "author": "Example Maintainers",
      "download_url": "https://plugins.example.com/releases/example-plugin.wasm",
      "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }
  ]
}
```

Each field is required. Plugin names must satisfy the host's safe plugin-name rules and be unique. Version and title must be non-empty; title and author are limited to 200 bytes, version to 128 bytes, and description to 4 KiB. The component URL must use public HTTPS on port 443 and its final path segment must be exactly `<name>.wasm`. The registry may redirect only to other allowed public HTTPS targets. Downloads are limited to 32 MiB, and the received bytes must match the 64-character hexadecimal SHA-256 digest before Wasmtime validates and stores the component. Fresh installs never overwrite an existing file. If a matching component is already installed, the market offers an explicit version update; it writes a temporary file, keeps the enabled/disabled filename, and restores the previous file if replacement fails. Components loaded by the current process keep running in memory until restart. A service restart loads newly installed or updated components.

Version 1 intentionally contains no PHP-style dependencies or installation scripts. Components can use only the versioned host interfaces documented in [plugin-migration.md](plugin-migration.md); the host does not provide filesystem, network, WASI, or raw database access. Additive contract changes require a new schema version so older hosts can reject unsupported manifests explicitly.

## Hosting

Serve the manifest from a stable HTTPS URL, and publish each immutable `.wasm` release at the exact URL and SHA-256 recorded in the manifest. The host retrieves the manifest on market page load and again for each install, so a package shown in the UI is always re-resolved from the currently configured registry before download.
