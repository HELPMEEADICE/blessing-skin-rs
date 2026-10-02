#[path = "../plugin_migration.rs"]
mod plugin_migration;

fn main() {
    if let Err(error) = plugin_migration::run(std::env::args().skip(1)) {
        eprintln!("plugin-migrate: {error}");
        std::process::exit(2);
    }
}
