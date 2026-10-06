use std::collections::HashMap;

use askama::Template;
use axum::{
    Json,
    body::Bytes,
    extract::{RawQuery, State},
    http::{HeaderMap, Method, StatusCode},
    response::{Html, IntoResponse, Response},
};
use serde_json::Value;

use crate::{AppState, database::UserProfile, http};

const NONE: &[(&str, &str)] = &[];
pub(crate) const LEGACY_DEFAULT_SITE_DESCRIPTION: &str =
    "Open-source PHP Minecraft Skin Hosting Service";
pub(crate) const LEGACY_DEFAULT_COPYRIGHT_TEXT: &str =
    "<b>Copyright &copy; {year} <a href=\"{site_url}\">{site_name}</a>.</b> All rights reserved.";
const PLAYER_NAME_RULES: &[(&str, &str)] = &[
    ("official", "Official"),
    ("cjk", "CJK"),
    ("utf8", "UTF-8"),
    ("custom", "Custom"),
];
const PRIVATE_STATUSES: &[(&str, &str)] = &[("403", "403 Forbidden"), ("404", "404 Not Found")];
const COPYRIGHT_STYLES: &[(&str, &str)] = &[
    ("0", "Powered with love"),
    ("1", "Powered by Blessing Skin Server"),
    ("2", "Proudly powered by Blessing Skin Server"),
    ("3", "由 Blessing Skin Server 强力驱动"),
    ("4", "采用 Blessing Skin Server 搭建"),
    ("5", "使用 Blessing Skin Server 稳定运行"),
    ("6", "自豪地采用 Blessing Skin Server"),
];
const NAVBAR_COLORS: &[(&str, &str)] = &[
    ("primary", "Primary"),
    ("secondary", "Secondary"),
    ("success", "Success"),
    ("danger", "Danger"),
    ("indigo", "Indigo"),
    ("purple", "Purple"),
    ("pink", "Pink"),
    ("teal", "Teal"),
    ("cyan", "Cyan"),
    ("dark", "Dark"),
    ("gray", "Gray"),
    ("fuchsia", "Fuchsia"),
    ("maroon", "Maroon"),
    ("olive", "Olive"),
    ("navy", "Navy"),
    ("lime", "Lime"),
    ("light", "Light"),
    ("warning", "Warning"),
    ("white", "White"),
    ("orange", "Orange"),
];
const SIDEBAR_COLORS: &[(&str, &str)] = &[
    ("dark-primary", "Dark primary"),
    ("dark-warning", "Dark warning"),
    ("dark-info", "Dark info"),
    ("dark-danger", "Dark danger"),
    ("dark-success", "Dark success"),
    ("dark-indigo", "Dark indigo"),
    ("dark-navy", "Dark navy"),
    ("dark-purple", "Dark purple"),
    ("dark-fuchsia", "Dark fuchsia"),
    ("dark-pink", "Dark pink"),
    ("dark-maroon", "Dark maroon"),
    ("dark-orange", "Dark orange"),
    ("dark-lime", "Dark lime"),
    ("dark-teal", "Dark teal"),
    ("dark-olive", "Dark olive"),
    ("light-primary", "Light primary"),
    ("light-warning", "Light warning"),
    ("light-info", "Light info"),
    ("light-danger", "Light danger"),
    ("light-success", "Light success"),
    ("light-indigo", "Light indigo"),
    ("light-navy", "Light navy"),
    ("light-purple", "Light purple"),
    ("light-fuchsia", "Light fuchsia"),
    ("light-pink", "Light pink"),
    ("light-maroon", "Light maroon"),
    ("light-orange", "Light orange"),
    ("light-lime", "Light lime"),
    ("light-teal", "Light teal"),
    ("light-olive", "Light olive"),
];

#[derive(Clone, Copy)]
struct Definition {
    key: &'static str,
    kind: &'static str,
    default: &'static str,
    localized: bool,
    max_length: usize,
    min: Option<i64>,
    max: Option<i64>,
    choices: &'static [(&'static str, &'static str)],
}

macro_rules! setting {
    ($key:literal, $kind:literal, $default:expr) => {
        Definition {
            key: $key,
            kind: $kind,
            default: $default,
            localized: false,
            max_length: 65536,
            min: None,
            max: None,
            choices: NONE,
        }
    };
    ($key:literal, $kind:literal, $default:expr, localized) => {
        Definition {
            key: $key,
            kind: $kind,
            default: $default,
            localized: true,
            max_length: 65536,
            min: None,
            max: None,
            choices: NONE,
        }
    };
    ($key:literal, $kind:literal, $default:expr, $min:expr, $max:expr) => {
        Definition {
            key: $key,
            kind: $kind,
            default: $default,
            localized: false,
            max_length: 65536,
            min: Some($min),
            max: Some($max),
            choices: NONE,
        }
    };
    ($key:literal, $kind:literal, $default:expr, $choices:expr) => {
        Definition {
            key: $key,
            kind: $kind,
            default: $default,
            localized: false,
            max_length: 65536,
            min: None,
            max: None,
            choices: $choices,
        }
    };
}

const GENERAL: &[Definition] = &[
    setting!("site_name", "text", "Blessing Skin", localized),
    setting!(
        "site_description",
        "text",
        LEGACY_DEFAULT_SITE_DESCRIPTION,
        localized
    ),
    setting!("site_url", "url", ""),
    setting!("register_with_player_name", "checkbox", "true"),
    setting!("require_verification", "checkbox", "false"),
    setting!("regs_per_ip", "number", "3", 0, 10000),
    setting!("max_upload_file_size", "number", "1024", 1, 1048576),
    setting!("max_texture_width", "number", "8192", 1, 65536),
    setting!("player_name_rule", "select", "official", PLAYER_NAME_RULES),
    setting!("custom_player_name_regexp", "text", ""),
    setting!("player_name_length_min", "number", "3", 1, 32),
    setting!("player_name_length_max", "number", "16", 1, 32),
    setting!("auto_del_invalid_texture", "checkbox", "false"),
    setting!("allow_downloading_texture", "checkbox", "true"),
    setting!("status_code_for_private", "select", "403", PRIVATE_STATUSES),
    setting!("texture_name_regexp", "text", ""),
    setting!("content_policy", "textarea", "", localized),
    setting!(
        "announcement",
        "textarea",
        "Welcome to Blessing Skin {version}!",
        localized
    ),
    setting!("meta_keywords", "text", ""),
    setting!("meta_description", "text", ""),
    setting!("meta_extras", "textarea", ""),
    setting!("recaptcha_sitekey", "text", ""),
    setting!("recaptcha_secretkey", "text", ""),
    setting!("recaptcha_invisible", "checkbox", "false"),
];
const SCORE: &[Definition] = &[
    setting!("score_per_storage", "text", "true"),
    setting!("private_score_per_storage", "number", "10", 0, 1000000000),
    setting!("score_per_closet_item", "number", "0", 0, 1000000000),
    setting!("return_score", "checkbox", "true"),
    setting!("score_per_player", "number", "100", 0, 1000000000),
    setting!("user_initial_score", "number", "1000", 0, 1000000000),
    setting!(
        "reporter_score_modification",
        "number",
        "0",
        -1000000000,
        1000000000
    ),
    setting!(
        "reporter_reward_score",
        "number",
        "0",
        -1000000000,
        1000000000
    ),
    setting!("sign_score_from", "number", "10", -1000000000, 1000000000),
    setting!("sign_score_to", "number", "100", -1000000000, 1000000000),
    setting!("sign_gap_time", "number", "24", 0, 8760),
    setting!("sign_after_zero", "checkbox", "false"),
    setting!(
        "score_award_per_texture",
        "number",
        "0",
        -1000000000,
        1000000000
    ),
    setting!("take_back_scores_after_deletion", "checkbox", "true"),
    setting!(
        "score_award_per_like",
        "number",
        "0",
        -1000000000,
        1000000000
    ),
];
const CUSTOMIZE: &[Definition] = &[
    setting!("home_pic_url", "text", "./app/bg.webp"),
    setting!("favicon_url", "text", "app/favicon.ico"),
    setting!("transparent_navbar", "checkbox", "false"),
    setting!("hide_intro", "checkbox", "false"),
    setting!("fixed_bg", "checkbox", "false"),
    setting!("copyright_prefer", "select", "0", COPYRIGHT_STYLES),
    setting!(
        "copyright_text",
        "textarea",
        LEGACY_DEFAULT_COPYRIGHT_TEXT,
        localized
    ),
    setting!("custom_css", "textarea", ""),
    setting!("custom_js", "textarea", ""),
    setting!("navbar_color", "select", "cyan", NAVBAR_COLORS),
    setting!("sidebar_color", "select", "dark-maroon", SIDEBAR_COLORS),
];
const RESOURCE: &[Definition] = &[
    setting!("force_ssl", "checkbox", "false"),
    setting!("auto_detect_asset_url", "checkbox", "true"),
    setting!("cache_expire_time", "number", "31536000", 0, 31536000),
    setting!("cdn_address", "text", ""),
    setting!("enable_avatar_cache", "checkbox", "false"),
    setting!("enable_preview_cache", "checkbox", "false"),
];

#[derive(Template)]
#[template(path = "admin_settings.html")]
struct AdminSettingsPage {
    site_name: String,
    title: String,
    locale: String,
    section: String,
    fields: Vec<AdminSettingField>,
    frontend_style_available: bool,
    frontend_stylesheet: String,
    frontend_script_available: bool,
    frontend_script: String,
    frontend_globals_b64: String,
}

#[derive(serde::Serialize)]
struct AdminSettingField {
    key: String,
    label: String,
    kind: String,
    value: String,
    checked: bool,
    choices: Vec<AdminSettingChoice>,
}

#[derive(serde::Serialize)]
struct AdminSettingChoice {
    value: String,
    label: String,
    selected: bool,
}

pub async fn options_dispatch(
    State(state): State<AppState>,
    headers: HeaderMap,
    method: Method,
    body: Bytes,
) -> Response {
    dispatch_page(&state, &headers, "general", method, body, false).await
}
pub async fn score_dispatch(
    State(state): State<AppState>,
    headers: HeaderMap,
    method: Method,
    body: Bytes,
) -> Response {
    dispatch_page(&state, &headers, "score", method, body, false).await
}
pub async fn customize_dispatch(
    State(state): State<AppState>,
    headers: HeaderMap,
    method: Method,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> Response {
    if method == Method::POST && legacy_color_action(query.as_deref()) {
        return save_legacy_color_page(&state, &headers, body).await;
    }
    dispatch_page(&state, &headers, "customize", method, body, false).await
}
pub async fn resource_dispatch(
    State(state): State<AppState>,
    headers: HeaderMap,
    method: Method,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> Response {
    let clear_cache = query.as_deref().is_some_and(|query| {
        query
            .split('&')
            .any(|part| part.split('=').next() == Some("clear-cache"))
    });
    dispatch_page(&state, &headers, "resource", method, body, clear_cache).await
}

fn legacy_color_action(query: Option<&str>) -> bool {
    query.is_some_and(|query| {
        form_urlencoded::parse(query.as_bytes())
            .any(|(key, value)| key == "action" && value == "color")
    })
}

async fn save_legacy_color_page(state: &AppState, headers: &HeaderMap, body: Bytes) -> Response {
    if let Err(response) = admin_user(state, headers).await {
        return response;
    }
    let Some(database) = &state.database else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Database is not ready.").into_response();
    };
    let form = form_urlencoded::parse(&body)
        .into_owned()
        .collect::<HashMap<_, _>>();
    for (field, key) in [("navbar", "navbar_color"), ("sidebar", "sidebar_color")] {
        let Some(value) = form.get(field).filter(|value| !value.is_empty()) else {
            continue;
        };
        let Some(definition) = CUSTOMIZE.iter().find(|definition| definition.key == key) else {
            continue;
        };
        let Some(value) = normalize_value(definition, &Value::String(value.clone())) else {
            return invalid("Invalid color value.");
        };
        if let Err(error) = database
            .set_option(&state.config.database.table_prefix, key, &value)
            .await
        {
            tracing::error!(%error, option = key, "failed to save legacy customize color");
            return (StatusCode::SERVICE_UNAVAILABLE, "Could not save settings.").into_response();
        }
    }
    render_page(state, headers, "customize", false).await
}
async fn dispatch_page(
    state: &AppState,
    headers: &HeaderMap,
    section: &str,
    method: Method,
    body: Bytes,
    clear_cache: bool,
) -> Response {
    if clear_cache || method != Method::POST {
        render_page(state, headers, section, clear_cache).await
    } else {
        save_page(state, headers, section, body).await
    }
}

async fn render_page(
    state: &AppState,
    headers: &HeaderMap,
    section: &str,
    clear_cache: bool,
) -> Response {
    let Some(definitions) = definitions(section) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if let Err(response) = admin_user(state, headers).await {
        return response;
    }
    if clear_cache {
        state.image_cache.clear();
    }
    let Some(database) = &state.database else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Database is not ready.").into_response();
    };
    let rows = match database
        .all_options(&state.config.database.table_prefix)
        .await
    {
        Ok(rows) => rows,
        Err(error) => {
            tracing::error!(%error, "failed to read administrator settings");
            return (StatusCode::SERVICE_UNAVAILABLE, "Database is not ready.").into_response();
        }
    };
    let options = rows.into_iter().collect::<HashMap<_, _>>();
    let locale = http::request_locale(&state);
    let fields = definitions
        .iter()
        .map(|definition| {
            let localized_key = format!("{}_{}", definition.key, locale);
            let value = options
                .get(&localized_key)
                .or_else(|| options.get(definition.key))
                .cloned()
                .unwrap_or_else(|| {
                    if definition.key == "site_url" {
                        state.config.app_url.clone()
                    } else if definition.key == "sign_score_from" {
                        options
                            .get("sign_score")
                            .and_then(|value| value.split(',').next())
                            .unwrap_or(definition.default)
                            .to_owned()
                    } else if definition.key == "sign_score_to" {
                        options
                            .get("sign_score")
                            .and_then(|value| value.split(',').nth(1))
                            .unwrap_or(definition.default)
                            .to_owned()
                    } else {
                        definition.default.to_owned()
                    }
                });
            AdminSettingField {
                key: definition.key.to_owned(),
                label: label(&locale, definition.key).to_owned(),
                kind: definition.kind.to_owned(),
                checked: legacy_bool(&value),
                value: value.clone(),
                choices: definition
                    .choices
                    .iter()
                    .map(|(choice, text)| AdminSettingChoice {
                        value: (*choice).to_owned(),
                        label: if locale.starts_with("zh") {
                            chinese_choice(choice, text)
                        } else {
                            (*text).to_owned()
                        },
                        selected: *choice == value,
                    })
                    .collect(),
            }
        })
        .collect();
    let title = section_title(&locale, section);
    let site_name = http::site_name(state).await;
    let app_dir = state.public_dir.join("app");
    let stylesheet =
        http::frontend_entrypoint(&app_dir, "style", "css", &state.config.app_url).await;
    let frontend_script =
        http::frontend_entrypoint(&app_dir, "app", "js", &state.config.app_url).await;
    let i18n = http::load_frontend_translations(&state, &app_dir, &locale).await;
    let route = match section {
        "general" => "admin/options",
        "score" => "admin/score",
        "customize" => "admin/customize",
        "resource" => "admin/resource",
        _ => "admin/options",
    };
    let extra = serde_json::json!({
        "settings": {
            "section": section,
            "title": &title,
            "fields": &fields,
        }
    });
    let frontend_globals_b64 = http::encode_frontend_globals(state, &site_name, route, extra, i18n);
    let page = AdminSettingsPage {
        site_name,
        title,
        locale,
        section: section.to_owned(),
        fields,
        frontend_style_available: stylesheet.is_some(),
        frontend_stylesheet: stylesheet.unwrap_or_default(),
        frontend_script_available: frontend_script.is_some(),
        frontend_script: frontend_script.unwrap_or_default(),
        frontend_globals_b64,
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to render administrator settings page");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn save_page(state: &AppState, headers: &HeaderMap, section: &str, body: Bytes) -> Response {
    let Some(definitions) = definitions(section) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if let Err(response) = admin_user(state, headers).await {
        return response;
    }
    let Some(database) = &state.database else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"code":2,"message":"Database is not ready."})),
        )
            .into_response();
    };
    let legacy_form = is_urlencoded_form(headers);
    let values = if legacy_form {
        match legacy_form_values(section, &body) {
            Some(values) => values,
            None => return render_page(state, headers, section, false).await,
        }
    } else {
        let payload = match serde_json::from_slice::<Value>(&body) {
            Ok(Value::Object(payload)) => payload,
            _ => return invalid("Invalid settings payload."),
        };
        payload
            .get("values")
            .and_then(Value::as_object)
            .unwrap_or(&payload)
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect()
    };
    let mut normalized = Vec::with_capacity(values.len());
    for (key, value) in &values {
        let Some(definition) = definitions.iter().find(|definition| definition.key == key) else {
            return invalid(&format!("Unknown setting: {key}"));
        };
        let normalized_value = if legacy_form {
            normalize_legacy_form_value(definition, value)
        } else {
            normalize_value(definition, value)
        };
        let Some(value) = normalized_value else {
            return invalid(&format!("Invalid value for {key}"));
        };
        normalized.push((key.clone(), value));
    }
    if normalized.is_empty() {
        return invalid("No settings were provided.");
    }
    let mut updates = HashMap::new();
    for (key, value) in normalized {
        if key == "sign_score_from" || key == "sign_score_to" {
            updates.insert(key, value);
            continue;
        }
        let Some(definition) = definitions.iter().find(|definition| definition.key == key) else {
            continue;
        };
        updates.insert(key.clone(), value.clone());
        if definition.localized || (section == "customize" && key == "copyright_prefer") {
            updates.insert(format!("{key}_{}", http::request_locale(&state)), value);
        }
    }
    if section == "score"
        && (updates.contains_key("sign_score_from") || updates.contains_key("sign_score_to"))
    {
        let current = database
            .option(&state.config.database.table_prefix, "sign_score")
            .await;
        let current = match current {
            Ok(value) => value.unwrap_or_else(|| "10,100".to_owned()),
            Err(error) => {
                tracing::error!(%error, "failed to read current sign score settings");
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(serde_json::json!({"code":2,"message":"Database is not ready."})),
                )
                    .into_response();
            }
        };
        let mut parts = current.split(',');
        let from = updates
            .get("sign_score_from")
            .map(String::as_str)
            .or_else(|| parts.next())
            .unwrap_or("10");
        let to = updates
            .get("sign_score_to")
            .map(String::as_str)
            .or_else(|| parts.next())
            .unwrap_or("100");
        updates.insert("sign_score".to_owned(), format!("{from},{to}"));
        updates.remove("sign_score_from");
        updates.remove("sign_score_to");
    }
    for (key, value) in updates {
        if let Err(error) = database
            .set_option(&state.config.database.table_prefix, &key, &value)
            .await
        {
            tracing::error!(%error, option = %key, "failed to save administrator setting");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"code":2,"message":"Could not save settings."})),
            )
                .into_response();
        }
    }
    if legacy_form {
        render_page(state, headers, section, false).await
    } else {
        Json(serde_json::json!({"code":0,"message":if http::request_locale(&state).starts_with("zh") {"设置已保存。"} else {"Settings saved."}})).into_response()
    }
}

fn is_urlencoded_form(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| {
            value
                .trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
}

fn legacy_form_values(section: &str, body: &[u8]) -> Option<HashMap<String, Value>> {
    let form = form_urlencoded::parse(body)
        .into_owned()
        .collect::<HashMap<_, _>>();
    let option = form.get("option")?;
    let (fields, checkboxes): (&[&str], &[&str]) = match (section, option.as_str()) {
        ("general", "general") => (
            &[
                "site_name",
                "site_description",
                "site_url",
                "register_with_player_name",
                "require_verification",
                "regs_per_ip",
                "max_upload_file_size",
                "max_texture_width",
                "player_name_rule",
                "custom_player_name_regexp",
                "player_name_length_min",
                "player_name_length_max",
                "auto_del_invalid_texture",
                "allow_downloading_texture",
                "status_code_for_private",
                "texture_name_regexp",
                "content_policy",
            ],
            &[
                "register_with_player_name",
                "require_verification",
                "auto_del_invalid_texture",
                "allow_downloading_texture",
            ],
        ),
        ("general", "announ") => (&["announcement"], &[]),
        ("general", "meta") => (&["meta_keywords", "meta_description", "meta_extras"], &[]),
        ("general", "recaptcha") => (
            &[
                "recaptcha_sitekey",
                "recaptcha_secretkey",
                "recaptcha_invisible",
            ],
            &["recaptcha_invisible"],
        ),
        ("score", "rate") => (
            &[
                "score_per_storage",
                "private_score_per_storage",
                "score_per_closet_item",
                "return_score",
                "score_per_player",
                "user_initial_score",
            ],
            &["return_score"],
        ),
        ("score", "report") => (
            &["reporter_score_modification", "reporter_reward_score"],
            &[],
        ),
        ("score", "sign") => (
            &[
                "sign_score_from",
                "sign_score_to",
                "sign_gap_time",
                "sign_after_zero",
            ],
            &["sign_after_zero"],
        ),
        ("score", "sharing") => (
            &[
                "score_award_per_texture",
                "take_back_scores_after_deletion",
                "score_award_per_like",
            ],
            &["take_back_scores_after_deletion"],
        ),
        ("customize", "homepage") => (
            &[
                "home_pic_url",
                "favicon_url",
                "transparent_navbar",
                "hide_intro",
                "fixed_bg",
                "copyright_prefer",
                "copyright_text",
            ],
            &["transparent_navbar", "hide_intro", "fixed_bg"],
        ),
        ("customize", "customJsCss") => (&["custom_css", "custom_js"], &[]),
        ("resource", "resources") => (
            &[
                "force_ssl",
                "auto_detect_asset_url",
                "cache_expire_time",
                "cdn_address",
            ],
            &["force_ssl", "auto_detect_asset_url"],
        ),
        ("resource", "cache") => (
            &["enable_avatar_cache", "enable_preview_cache"],
            &["enable_avatar_cache", "enable_preview_cache"],
        ),
        _ => return None,
    };

    let mut values = HashMap::new();
    for key in fields {
        if let Some(value) = form.get(*key) {
            values.insert((*key).to_owned(), Value::String(value.clone()));
        } else if checkboxes.contains(key) {
            values.insert((*key).to_owned(), Value::Bool(false));
        }
    }
    (!values.is_empty()).then_some(values)
}

async fn admin_user(state: &AppState, headers: &HeaderMap) -> Result<UserProfile, Response> {
    let user = http::authenticated_web_user(state, headers).await?;
    if user.permission < 1 {
        let message = if http::request_locale(&state).starts_with("zh") {
            "只有管理员可以修改站点设置。"
        } else {
            "Only administrators can change site settings."
        };
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"code":-1,"message":message})),
        )
            .into_response());
    }
    Ok(user)
}

fn definitions(section: &str) -> Option<&'static [Definition]> {
    match section {
        "general" => Some(GENERAL),
        "score" => Some(SCORE),
        "customize" => Some(CUSTOMIZE),
        "resource" => Some(RESOURCE),
        _ => None,
    }
}

fn normalize_value(definition: &Definition, value: &Value) -> Option<String> {
    match definition.kind {
        "checkbox" => match value {
            Value::Bool(value) => Some(if *value { "true" } else { "false" }.to_owned()),
            Value::String(value) => match value.trim().to_ascii_lowercase().as_str() {
                "1" | "true" | "on" | "yes" | "(true)" => Some("true".to_owned()),
                "0" | "false" | "off" | "no" | "(false)" => Some("false".to_owned()),
                _ => None,
            },
            _ => None,
        },
        "number" => {
            let value = match value {
                Value::Number(value) => value.to_string(),
                Value::String(value) => value.clone(),
                _ => return None,
            };
            let number = value.parse::<i64>().ok()?;
            if definition.min.is_some_and(|min| number < min)
                || definition.max.is_some_and(|max| number > max)
            {
                return None;
            }
            Some(number.to_string())
        }
        "select" => {
            let value = value.as_str()?;
            definition
                .choices
                .iter()
                .any(|(choice, _)| *choice == value)
                .then(|| value.to_owned())
        }
        "text" | "textarea" | "url" => {
            let mut value = match value {
                Value::String(value) => value.clone(),
                Value::Number(value) => value.to_string(),
                _ => return None,
            };
            if value.chars().count() > definition.max_length || value.contains('\0') {
                return None;
            }
            if definition.key == "cdn_address" {
                if value.ends_with('/') {
                    value.pop();
                }
            } else if definition.kind == "url" {
                if value.ends_with('/') {
                    value.pop();
                }
                if value.ends_with("/index.php") {
                    value.truncate(value.len() - "/index.php".len());
                }
            }
            Some(value)
        }
        _ => None,
    }
}

fn normalize_legacy_form_value(definition: &Definition, value: &Value) -> Option<String> {
    let mut value = match value {
        Value::String(value) => value.clone(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        _ => return None,
    };
    if value.contains('\0') {
        return None;
    }
    if definition.key == "cdn_address" {
        if value.ends_with('/') {
            value.pop();
        }
    } else if definition.kind == "url" {
        if value.ends_with('/') {
            value.pop();
        }
        if value.ends_with("/index.php") {
            value.truncate(value.len() - "/index.php".len());
        }
    }
    Some(value)
}

fn invalid(message: &str) -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(serde_json::json!({"code":1,"message":message})),
    )
        .into_response()
}

fn legacy_bool(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "on" | "yes" | "(true)"
    )
}

fn section_title(locale: &str, section: &str) -> String {
    let chinese = locale.starts_with("zh");
    match (chinese, section) {
        (true, "general") => "站点选项",
        (true, "score") => "积分设置",
        (true, "customize") => "外观自定义",
        (true, "resource") => "资源与缓存",
        (false, "general") => "Site options",
        (false, "score") => "Score settings",
        (false, "customize") => "Customize appearance",
        (false, "resource") => "Resources and cache",
        _ => "Settings",
    }
    .to_owned()
}

fn label(locale: &str, key: &str) -> &'static str {
    if locale.starts_with("zh") {
        match key {
            "site_name" => "站点名称",
            "site_description" => "站点描述",
            "site_url" => "站点网址",
            "register_with_player_name" => "注册时使用角色名",
            "require_verification" => "要求验证邮箱",
            "regs_per_ip" => "每个 IP 的注册数量",
            "max_upload_file_size" => "最大上传大小（KB）",
            "max_texture_width" => "最大材质宽度（像素）",
            "player_name_rule" => "角色名规则",
            "custom_player_name_regexp" => "自定义角色名正则表达式",
            "player_name_length_min" => "角色名最小长度",
            "player_name_length_max" => "角色名最大长度",
            "auto_del_invalid_texture" => "自动删除无效材质",
            "allow_downloading_texture" => "允许下载材质",
            "status_code_for_private" => "私有材质响应状态码",
            "texture_name_regexp" => "材质名称正则表达式",
            "content_policy" => "内容政策",
            "announcement" => "站点公告",
            "meta_keywords" => "Meta 关键词",
            "meta_description" => "Meta 描述",
            "meta_extras" => "额外 Meta 标签",
            "recaptcha_sitekey" => "reCAPTCHA Site key",
            "recaptcha_secretkey" => "reCAPTCHA Secret key",
            "recaptcha_invisible" => "使用隐形 reCAPTCHA",
            "score_per_storage" => "每个公开材质的积分成本",
            "private_score_per_storage" => "每个私有材质的积分成本",
            "score_per_closet_item" => "每个衣柜项目的积分成本",
            "return_score" => "删除时返还积分",
            "score_per_player" => "每个角色的积分成本",
            "user_initial_score" => "新用户初始积分",
            "reporter_score_modification" => "举报者积分扣减",
            "reporter_reward_score" => "举报奖励积分",
            "sign_score_from" => "签到积分最小值",
            "sign_score_to" => "签到积分最大值",
            "sign_gap_time" => "签到间隔（小时）",
            "sign_after_zero" => "积分为零时允许签到",
            "score_award_per_texture" => "分享材质奖励积分",
            "take_back_scores_after_deletion" => "删除公开材质时收回积分",
            "score_award_per_like" => "每个点赞奖励积分",
            "home_pic_url" => "首页背景图片",
            "favicon_url" => "网站图标",
            "transparent_navbar" => "透明导航栏",
            "hide_intro" => "隐藏首页介绍",
            "fixed_bg" => "固定背景图片",
            "copyright_prefer" => "版权文案样式",
            "copyright_text" => "版权文本",
            "custom_css" => "自定义 CSS",
            "custom_js" => "自定义 JavaScript",
            "navbar_color" => "导航栏颜色",
            "sidebar_color" => "侧栏颜色",
            "force_ssl" => "强制 HTTPS",
            "auto_detect_asset_url" => "自动检测资源地址",
            "cache_expire_time" => "缓存有效期（秒）",
            "cdn_address" => "CDN 地址",
            "enable_avatar_cache" => "启用头像缓存",
            "enable_preview_cache" => "启用预览缓存",
            _ => "设置",
        }
    } else {
        match key {
            "site_name" => "Site name",
            "site_description" => "Site description",
            "site_url" => "Site URL",
            "register_with_player_name" => "Use player name on registration",
            "require_verification" => "Require email verification",
            "regs_per_ip" => "Registrations per IP",
            "max_upload_file_size" => "Maximum upload size (KB)",
            "max_texture_width" => "Maximum texture width (px)",
            "player_name_rule" => "Player name rule",
            "custom_player_name_regexp" => "Custom player name regular expression",
            "player_name_length_min" => "Minimum player name length",
            "player_name_length_max" => "Maximum player name length",
            "auto_del_invalid_texture" => "Delete invalid textures automatically",
            "allow_downloading_texture" => "Allow texture downloads",
            "status_code_for_private" => "Private texture response status",
            "texture_name_regexp" => "Texture name regular expression",
            "content_policy" => "Content policy",
            "announcement" => "Announcement",
            "meta_keywords" => "Meta keywords",
            "meta_description" => "Meta description",
            "meta_extras" => "Extra meta tags",
            "recaptcha_sitekey" => "reCAPTCHA site key",
            "recaptcha_secretkey" => "reCAPTCHA secret key",
            "recaptcha_invisible" => "Use invisible reCAPTCHA",
            "score_per_storage" => "Public texture score cost",
            "private_score_per_storage" => "Private texture score cost",
            "score_per_closet_item" => "Closet item score cost",
            "return_score" => "Refund score on deletion",
            "score_per_player" => "Score cost per player",
            "user_initial_score" => "Initial user score",
            "reporter_score_modification" => "Reporter score modification",
            "reporter_reward_score" => "Reporter reward score",
            "sign_score_from" => "Minimum sign-in score",
            "sign_score_to" => "Maximum sign-in score",
            "sign_gap_time" => "Sign-in interval (hours)",
            "sign_after_zero" => "Allow sign-in with zero score",
            "score_award_per_texture" => "Score award per shared texture",
            "take_back_scores_after_deletion" => "Revoke score when deleting public textures",
            "score_award_per_like" => "Score award per like",
            "home_pic_url" => "Homepage background image",
            "favicon_url" => "Favicon",
            "transparent_navbar" => "Transparent navbar",
            "hide_intro" => "Hide homepage introduction",
            "fixed_bg" => "Fixed background image",
            "copyright_prefer" => "Copyright text style",
            "copyright_text" => "Copyright text",
            "custom_css" => "Custom CSS",
            "custom_js" => "Custom JavaScript",
            "navbar_color" => "Navbar color",
            "sidebar_color" => "Sidebar color",
            "force_ssl" => "Force HTTPS",
            "auto_detect_asset_url" => "Detect asset URL automatically",
            "cache_expire_time" => "Cache expiration (seconds)",
            "cdn_address" => "CDN address",
            "enable_avatar_cache" => "Enable avatar cache",
            "enable_preview_cache" => "Enable preview cache",
            _ => "Setting",
        }
    }
}

fn chinese_choice(value: &str, fallback: &str) -> String {
    match value {
        "official" => "官方规则".to_owned(),
        "cjk" => "中日韩字符".to_owned(),
        "utf8" => "UTF-8 字符".to_owned(),
        "custom" => "自定义规则".to_owned(),
        "403" => "403 禁止访问".to_owned(),
        "404" => "404 未找到".to_owned(),
        "0" => "Powered with ❤ by Blessing Skin Server".to_owned(),
        "1" => "Powered by Blessing Skin Server".to_owned(),
        "2" => "Proudly powered by Blessing Skin Server".to_owned(),
        "3" => "由 Blessing Skin Server 强力驱动".to_owned(),
        "4" => "采用 Blessing Skin Server 搭建".to_owned(),
        "5" => "使用 Blessing Skin Server 稳定运行".to_owned(),
        "6" => "自豪地采用 Blessing Skin Server".to_owned(),
        _ => fallback.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CUSTOMIZE, GENERAL, LEGACY_DEFAULT_COPYRIGHT_TEXT, LEGACY_DEFAULT_SITE_DESCRIPTION,
        RESOURCE, SCORE, legacy_form_values, normalize_legacy_form_value, normalize_value,
    };
    use serde_json::json;

    #[test]
    fn legacy_forms_only_update_the_selected_option_group() {
        let values = legacy_form_values(
            "general",
            b"option=meta&meta_keywords=legacy+keywords&site_name=must+be+ignored",
        )
        .unwrap();

        assert_eq!(values.get("meta_keywords"), Some(&json!("legacy keywords")));
        assert!(!values.contains_key("site_name"));
        assert_eq!(
            legacy_form_values("score", b"option=meta&meta_keywords=ignored"),
            None
        );
    }

    #[test]
    fn legacy_forms_default_unchecked_checkboxes_to_false() {
        let values =
            legacy_form_values("resource", b"option=cache&enable_avatar_cache=on").unwrap();

        assert_eq!(values.get("enable_avatar_cache"), Some(&json!("on")));
        assert_eq!(values.get("enable_preview_cache"), Some(&json!(false)));
    }

    #[test]
    fn settings_are_allowlisted_and_legacy_urls_are_normalized() {
        let site_url = GENERAL
            .iter()
            .find(|setting| setting.key == "site_url")
            .unwrap();
        assert_eq!(
            normalize_value(site_url, &json!("https://skin.example/index.php/")),
            Some("https://skin.example".to_owned())
        );
        let rule = GENERAL
            .iter()
            .find(|setting| setting.key == "player_name_rule")
            .unwrap();
        assert_eq!(normalize_value(rule, &json!("php")), None);
    }

    #[test]
    fn legacy_forms_preserve_raw_values_accepted_by_php_option_forms() {
        let max_upload = GENERAL
            .iter()
            .find(|setting| setting.key == "max_upload_file_size")
            .unwrap();
        assert_eq!(normalize_value(max_upload, &json!("1048577")), None);
        assert_eq!(
            normalize_legacy_form_value(max_upload, &json!("1048577")),
            Some("1048577".to_owned())
        );
        let max_width = GENERAL
            .iter()
            .find(|setting| setting.key == "max_texture_width")
            .unwrap();
        assert_eq!(
            normalize_legacy_form_value(max_width, &json!("065537")),
            Some("065537".to_owned())
        );
        let player_name_rule = GENERAL
            .iter()
            .find(|setting| setting.key == "player_name_rule")
            .unwrap();
        assert_eq!(
            normalize_legacy_form_value(player_name_rule, &json!("legacy-custom")),
            Some("legacy-custom".to_owned())
        );
    }

    #[test]
    fn validates_legacy_boolean_and_score_values() {
        let enabled = GENERAL
            .iter()
            .find(|setting| setting.key == "require_verification")
            .unwrap();
        assert_eq!(
            normalize_value(enabled, &json!(true)),
            Some("true".to_owned())
        );
        assert_eq!(normalize_value(enabled, &json!("invalid")), None);
        let award = SCORE
            .iter()
            .find(|setting| setting.key == "score_award_per_like")
            .unwrap();
        assert_eq!(normalize_value(award, &json!(17)), Some("17".to_owned()));
        let color = CUSTOMIZE
            .iter()
            .find(|setting| setting.key == "navbar_color")
            .unwrap();
        assert_eq!(normalize_value(color, &json!("rgb(1,2,3)")), None);
    }
    #[test]
    fn site_setting_defaults_match_legacy_php_options() {
        let site_description = GENERAL
            .iter()
            .find(|setting| setting.key == "site_description")
            .unwrap();
        assert_eq!(site_description.default, LEGACY_DEFAULT_SITE_DESCRIPTION);

        let copyright_text = CUSTOMIZE
            .iter()
            .find(|setting| setting.key == "copyright_text")
            .unwrap();
        assert_eq!(copyright_text.default, LEGACY_DEFAULT_COPYRIGHT_TEXT);
    }
    #[test]
    fn sidebar_color_values_match_legacy_dark_and_light_palette() {
        let sidebar = CUSTOMIZE
            .iter()
            .find(|setting| setting.key == "sidebar_color")
            .unwrap();
        assert!(
            sidebar
                .choices
                .iter()
                .any(|(value, _)| *value == "dark-maroon")
        );
        assert!(
            sidebar
                .choices
                .iter()
                .any(|(value, _)| *value == "light-olive")
        );
        assert_eq!(sidebar.default, "dark-maroon");
        assert_eq!(
            normalize_value(sidebar, &json!("dark-maroon")),
            Some("dark-maroon".to_owned())
        );
    }
    #[test]
    fn cdn_address_only_trims_one_legacy_trailing_slash() {
        let cdn = RESOURCE
            .iter()
            .find(|setting| setting.key == "cdn_address")
            .unwrap();
        assert_eq!(
            normalize_value(cdn, &json!("https://cdn.example/assets/index.php/")),
            Some("https://cdn.example/assets/index.php".to_owned())
        );
        assert_eq!(
            normalize_value(cdn, &json!("https://cdn.example/assets//")),
            Some("https://cdn.example/assets/".to_owned())
        );
    }
    #[test]
    fn site_url_normalization_matches_single_pass_legacy_formatting() {
        let site_url = GENERAL
            .iter()
            .find(|setting| setting.key == "site_url")
            .unwrap();
        assert_eq!(
            normalize_value(site_url, &json!("https://skin.example///")),
            Some("https://skin.example//".to_owned())
        );
        assert_eq!(
            normalize_value(site_url, &json!(" https://skin.example/ ")),
            Some(" https://skin.example/ ".to_owned())
        );
    }
}
