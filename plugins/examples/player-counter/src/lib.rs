mod bindings {
    wit_bindgen::generate!({
        path: "wit",
        world: "plugin",
    });
}

struct PlayerCounter;

impl bindings::exports::blessing_skin::plugin::lifecycle::Guest for PlayerCounter {
    fn initialize(host_api_version: String) -> Result<(), String> {
        if !host_api_version.starts_with("1.") {
            return Err(format!("unsupported host API: {host_api_version}"));
        }
        bindings::blessing_skin::plugin::state::get("players-added")?.map_or_else(
            || bindings::blessing_skin::plugin::state::set("players-added", b"0"),
            |_| Ok(()),
        )?;
        bindings::blessing_skin::plugin::host::log("info", "player counter initialized")
    }

    fn shutdown() {}
}

impl bindings::exports::blessing_skin::plugin::events::Guest for PlayerCounter {
    fn handle(name: String, payload: Vec<u8>) -> Result<(), String> {
        if name != "player.added" {
            return Ok(());
        }

        let previous = bindings::blessing_skin::plugin::state::get("players-added")?
            .map(|value| {
                String::from_utf8(value)
                    .map_err(|_| "stored player count is not UTF-8".to_owned())?
                    .parse::<u64>()
                    .map_err(|_| "stored player count is not a number".to_owned())
            })
            .transpose()?
            .unwrap_or(0);
        let count = previous.saturating_add(1);
        bindings::blessing_skin::plugin::state::set("players-added", count.to_string().as_bytes())?;
        bindings::blessing_skin::plugin::host::log(
            "info",
            &format!("player.added #{count} ({} payload bytes)", payload.len()),
        )
    }
}

impl bindings::exports::blessing_skin::plugin::documentation::Guest for PlayerCounter {
    fn readme() -> Result<Option<String>, String> {
        let count = bindings::blessing_skin::plugin::state::get("players-added")?
            .map(|value| String::from_utf8(value))
            .transpose()
            .map_err(|_| "stored player count is not UTF-8".to_owned())?
            .unwrap_or_else(|| "0".to_owned());
        Ok(Some(format!(
            "# Player counter\n\nObserved {count} player.added events since this plugin was installed."
        )))
    }
}

impl bindings::exports::blessing_skin::plugin::configuration::Guest for PlayerCounter {
    fn get() -> Result<Option<String>, String> {
        let Some(value) = bindings::blessing_skin::plugin::state::get("configuration")? else {
            return Ok(Some("{}".to_owned()));
        };
        String::from_utf8(value)
            .map(Some)
            .map_err(|_| "stored plugin configuration is not UTF-8".to_owned())
    }

    fn set(configuration: String) -> Result<(), String> {
        bindings::blessing_skin::plugin::state::set("configuration", configuration.as_bytes())
    }
}

bindings::export!(PlayerCounter with_types_in bindings);
