use std::{
    collections::{BTreeMap, HashMap},
    io::Cursor,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use askama::Template;
use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{
        DefaultBodyLimit, Multipart, OriginalUri, Path as RoutePath, Query, RawQuery, State,
    },
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{
            CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, ETAG, IF_MODIFIED_SINCE,
            IF_NONE_MATCH, LAST_MODIFIED, LOCATION, SET_COOKIE,
        },
    },
    response::{Html, IntoResponse, Redirect, Response},
    routing::{any, delete, get, post, put},
};
use chrono::{FixedOffset, NaiveDateTime, TimeZone};
use hmac::{Hmac, Mac};
use image::{DynamicImage, ImageFormat, ImageReader, Rgb, RgbImage, Rgba, RgbaImage};
use jsonwebtoken::{Algorithm, Header, encode};
use md5::{Digest, Md5};
use pulldown_cmark::{Options, Parser, html as markdown_html};
use rand::{
    Rng,
    distributions::{Alphanumeric, DistString},
};
use regex::RegexBuilder;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::{
    AppState,
    auth::{
        audience_matches, bearer_token, decode_access_token, decode_web_session,
        hash_legacy_password, verify_legacy_password,
    },
    database::{
        AdminUserRecord, ClosetTextureRecord, DatabasePool, NotificationRecord, PlayerProfile,
        PlayerRecord, PlayerRenameOutcome, PlayerTextureOutcome, ReportManagementRecord,
        ReportSearchFilters, TextureInfoRecord, UserProfile,
    },
};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health/live", any(live))
        .route("/health/ready", any(ready))
        .route("/api", any(api_root))
        .route("/api/", any(api_root))
        .route("/", get(home))
        .route("/auth/login", get(login_page).post(handle_login))
        .route("/auth/register", get(register_page).post(handle_register))
        .route("/auth/forgot", get(forgot_page).post(handle_forgot))
        .route(
            "/auth/reset/{uid}",
            get(reset_page).post(handle_password_reset),
        )
        .route(
            "/auth/verify/{uid}",
            get(verify_email_page).post(handle_email_verification),
        )
        .route("/auth/captcha", any(captcha_image))
        .route("/auth/logout", post(logout))
        .route(
            "/oauth/clients",
            get(oauth_clients_list).post(oauth_client_create),
        )
        .route(
            "/oauth/clients/{id}",
            put(oauth_client_update).delete(oauth_client_delete),
        )
        .route("/user", get(web_dashboard))
        .route("/user/notifications/{id}", post(web_read_notification))
        .route("/user/email-verification", post(send_verification_email))
        .route("/user/player", get(web_player_page).post(web_add_player))
        .route("/user/player/list", get(web_player_list))
        .route("/user/player/{pid}/name", put(web_rename_player))
        .route(
            "/user/player/{pid}/textures",
            put(web_set_player_textures).delete(web_clear_player_textures),
        )
        .route("/user/player/{pid}", delete(web_delete_player))
        .route(
            "/user/closet",
            get(web_closet_page).post(web_add_closet_item),
        )
        .route("/user/closet/list", get(web_closet_list))
        .route("/user/closet/ids", get(web_closet_ids))
        .route(
            "/user/closet/{tid}",
            put(web_rename_closet_item).delete(web_remove_closet_item),
        )
        .route("/user/profile", post(user_profile_update))
        .route("/user/profile/avatar", post(user_set_avatar))
        .route("/user/dark-mode", put(toggle_user_dark_mode))
        .route("/user/score-info", get(user_score_info))
        .route("/user/sign", post(user_sign))
        .route("/admin/users/list", get(admin_user_list))
        .route("/admin/users/{uid}/email", put(web_admin_user_email))
        .route(
            "/admin/users/{uid}/verification",
            put(web_admin_user_verification),
        )
        .route("/admin/users/{uid}/nickname", put(web_admin_user_nickname))
        .route("/admin/users/{uid}/password", put(web_admin_user_password))
        .route("/admin/users/{uid}/score", put(web_admin_user_score))
        .route(
            "/admin/users/{uid}/permission",
            put(web_admin_user_permission),
        )
        .route("/admin/users/{uid}", delete(web_admin_user_delete))
        .route("/admin/players/list", get(admin_player_list))
        .route("/admin/players/{pid}/name", put(web_admin_player_name))
        .route("/admin/players/{pid}/owner", put(web_admin_player_owner))
        .route(
            "/admin/players/{pid}/textures",
            put(web_admin_player_texture),
        )
        .route("/admin/players/{pid}", delete(web_admin_player_delete))
        .route(
            "/admin/closet/{uid}",
            post(web_admin_closet_add).delete(web_admin_closet_remove),
        )
        .route("/admin/reports/list", get(admin_report_list))
        .route("/admin/reports/{id}", put(web_review_report))
        .route("/skinlib", get(skinlib_page))
        .route("/skinlib/upload", get(texture_upload_page))
        .route("/skinlib/show/{tid}", get(skinlib_show_page))
        .route("/skinlib/list", get(skinlib_list))
        .route("/skinlib/report", post(submit_skinlib_report))
        .route("/skinlib/info/{tid}", get(skinlib_info))
        .route(
            "/texture",
            post(upload_texture).layer(DefaultBodyLimit::max(64 * 1024 * 1024)),
        )
        .route("/texture/{tid}", get(skinlib_info).delete(delete_texture))
        .route("/texture/{tid}/name", put(rename_texture))
        .route("/texture/{tid}/type", put(update_texture_type))
        .route("/texture/{tid}/privacy", put(toggle_texture_privacy))
        .route("/api/user", get(api_user))
        .route("/api/closet", get(api_closet).post(api_add_closet_item))
        .route(
            "/api/closet/{tid}",
            put(api_rename_closet_item).delete(api_remove_closet_item),
        )
        .route("/api/user/notifications", get(api_user_notifications))
        .route("/api/admin/users", get(api_admin_user_list))
        .route("/api/admin/users/{uid}/email", put(api_admin_user_email))
        .route(
            "/api/admin/users/{uid}/verification",
            put(api_admin_user_verification),
        )
        .route(
            "/api/admin/users/{uid}/nickname",
            put(api_admin_user_nickname),
        )
        .route(
            "/api/admin/users/{uid}/password",
            put(api_admin_user_password),
        )
        .route("/api/admin/users/{uid}/score", put(api_admin_user_score))
        .route(
            "/api/admin/users/{uid}/permission",
            put(api_admin_user_permission),
        )
        .route("/api/admin/users/{uid}", delete(api_admin_user_delete))
        .route("/api/admin/players", get(api_admin_player_list))
        .route("/api/admin/players/{pid}/name", put(api_admin_player_name))
        .route(
            "/api/admin/players/{pid}/owner",
            put(api_admin_player_owner),
        )
        .route(
            "/api/admin/players/{pid}/textures",
            put(api_admin_player_texture),
        )
        .route("/api/admin/players/{pid}", delete(api_admin_player_delete))
        .route(
            "/api/admin/closet/{uid}",
            get(api_admin_closet_list)
                .post(api_admin_closet_add)
                .delete(api_admin_closet_remove),
        )
        .route("/api/admin/notifications", post(api_send_notification))
        .route("/api/admin/reports", get(api_admin_report_list))
        .route("/api/admin/reports/{id}", put(api_review_report))
        .route("/api/user/notifications/{id}", post(api_read_notification))
        .route("/api/players", get(api_players).post(api_add_player))
        .route("/api/players/{pid}", delete(api_delete_player))
        .route("/api/players/{pid}/name", put(api_rename_player))
        .route(
            "/api/players/{pid}/textures",
            put(api_set_player_textures).delete(api_clear_player_textures),
        )
        .route("/{profile}", get(player_json))
        .route("/csl/{profile}", get(player_json))
        .route("/textures/{hash}", get(texture))
        .route("/csl/textures/{hash}", get(texture))
        .route("/raw/{tid}", get(raw_texture))
        .route("/avatar/player/{name}", get(avatar_by_player))
        .route("/avatar/user/{uid}", get(avatar_by_user))
        .route("/avatar/hash/{hash}", get(avatar_by_hash))
        .route("/avatar/{tid}", get(avatar_by_texture))
        .route("/preview/{tid}", get(preview_by_texture))
        .route("/preview/hash/{hash}", get(preview_by_hash))
        .with_state(state)
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginPage {
    site_name: String,
    locale: String,
    title: String,
    prompt: String,
    identification_label: String,
    password_label: String,
    remember_label: String,
    submit_label: String,
    registration_link: String,
    forgot_link: String,
}

#[derive(Template)]
#[template(path = "forgot.html")]
struct ForgotPage {
    site_name: String,
    locale: String,
    title: String,
    prompt: String,
    email_label: String,
    captcha_label: String,
    submit_label: String,
    use_recaptcha: bool,
    recaptcha_sitekey: String,
}

#[derive(Template)]
#[template(path = "reset.html")]
struct PasswordResetPage {
    site_name: String,
    locale: String,
    title: String,
    prompt: String,
    action_url: String,
    password_label: String,
    submit_label: String,
}

#[derive(Template)]
#[template(path = "verify.html")]
struct EmailVerificationPage {
    site_name: String,
    locale: String,
    title: String,
    prompt: String,
    action_url: String,
    email_label: String,
    submit_label: String,
}

async fn login_page(State(state): State<AppState>) -> Response {
    let site_name = match &state.database {
        Some(database) => database
            .option(&state.config.database.table_prefix, "site_name")
            .await
            .ok()
            .flatten()
            .unwrap_or_else(|| "Blessing Skin".to_owned()),
        None => "Blessing Skin".to_owned(),
    };
    let chinese = state.config.locale.starts_with("zh");
    let page = LoginPage {
        site_name,
        locale: state.config.locale.clone(),
        title: if chinese { "登录" } else { "Log In" }.to_owned(),
        prompt: if chinese {
            "登录以管理您的角色与皮肤"
        } else {
            "Log in to manage your skin and players"
        }
        .to_owned(),
        identification_label: if chinese {
            "邮箱或角色名"
        } else {
            "Email or player name"
        }
        .to_owned(),
        password_label: if chinese { "密码" } else { "Password" }.to_owned(),
        remember_label: if chinese {
            "保持登录"
        } else {
            "Remember me"
        }
        .to_owned(),
        submit_label: if chinese { "登录" } else { "Log In" }.to_owned(),
        registration_link: if chinese {
            "注册新账号"
        } else {
            "Register a new account"
        }
        .to_owned(),
        forgot_link: if chinese {
            "忘记密码？"
        } else {
            "Forgot password?"
        }
        .to_owned(),
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to render login page");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Template)]
#[template(path = "register.html")]
struct RegisterPage {
    site_name: String,
    locale: String,
    title: String,
    prompt: String,
    email_label: String,
    account_label: String,
    password_label: String,
    captcha_label: String,
    submit_label: String,
    player_name_registration: bool,
    use_recaptcha: bool,
    recaptcha_sitekey: String,
}

async fn register_page(State(state): State<AppState>) -> Response {
    let Some(database) = &state.database else {
        return unavailable();
    };
    let prefix = &state.config.database.table_prefix;
    let site_name = match database.option(prefix, "site_name").await {
        Ok(value) => value.unwrap_or_else(|| "Blessing Skin".to_owned()),
        Err(error) => {
            tracing::error!(%error, "failed to read site name for registration");
            return unavailable();
        }
    };
    let player_name_registration = match database.option(prefix, "register_with_player_name").await
    {
        Ok(value) => value
            .as_deref()
            .map(|value| legacy_option_bool(Some(value)))
            .unwrap_or(true),
        Err(error) => {
            tracing::error!(%error, "failed to read registration mode");
            return unavailable();
        }
    };
    let recaptcha_secret = match database.option(prefix, "recaptcha_secretkey").await {
        Ok(value) => value.unwrap_or_default(),
        Err(error) => {
            tracing::error!(%error, "failed to read registration CAPTCHA configuration");
            return unavailable();
        }
    };
    let recaptcha_sitekey = if recaptcha_secret.is_empty() {
        String::new()
    } else {
        match database.option(prefix, "recaptcha_sitekey").await {
            Ok(value) => value.unwrap_or_default(),
            Err(error) => {
                tracing::error!(%error, "failed to read reCAPTCHA site key");
                return unavailable();
            }
        }
    };
    let chinese = state.config.locale.starts_with("zh");
    let page = RegisterPage {
        site_name,
        locale: state.config.locale.clone(),
        title: if chinese { "注册" } else { "Register" }.to_owned(),
        prompt: if chinese {
            "创建一个账号来管理你的皮肤与角色。"
        } else {
            "Create an account to manage your skins and players."
        }
        .to_owned(),
        email_label: if chinese { "邮箱" } else { "Email" }.to_owned(),
        account_label: (if chinese {
            if player_name_registration {
                "角色名"
            } else {
                "昵称"
            }
        } else if player_name_registration {
            "Player name"
        } else {
            "Nickname"
        })
        .to_owned(),
        password_label: if chinese { "密码" } else { "Password" }.to_owned(),
        captcha_label: if chinese { "验证码" } else { "CAPTCHA" }.to_owned(),
        submit_label: if chinese { "注册" } else { "Register" }.to_owned(),
        player_name_registration,
        use_recaptcha: !recaptcha_secret.is_empty(),
        recaptcha_sitekey,
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to render registration page");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn forgot_page(State(state): State<AppState>) -> Response {
    let site_name = site_name(&state).await;
    let Some(database) = &state.database else {
        return unavailable();
    };
    let prefix = &state.config.database.table_prefix;
    let (recaptcha_sitekey, recaptcha_secret) = match (
        database.option(prefix, "recaptcha_sitekey").await,
        database.option(prefix, "recaptcha_secretkey").await,
    ) {
        (Ok(sitekey), Ok(secret)) => (sitekey.unwrap_or_default(), secret.unwrap_or_default()),
        (Err(error), _) | (_, Err(error)) => {
            tracing::error!(%error, "failed to load forgot-password CAPTCHA settings");
            return unavailable();
        }
    };
    let chinese = state.config.locale.starts_with("zh");
    let page = ForgotPage {
        site_name,
        locale: state.config.locale.clone(),
        title: if chinese { "找回密码" } else { "Forgot Password" }.to_owned(),
        prompt: if chinese {
            "输入账户邮箱，我们会发送一条一小时内有效的重置链接。"
        } else {
            "Enter your account email and we will send a password reset link that expires in one hour."
        }
        .to_owned(),
        email_label: if chinese { "邮箱" } else { "Email" }.to_owned(),
        captcha_label: if chinese { "验证码" } else { "CAPTCHA" }.to_owned(),
        submit_label: if chinese { "发送重置邮件" } else { "Send reset email" }.to_owned(),
        use_recaptcha: !recaptcha_secret.is_empty(),
        recaptcha_sitekey,
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to render forgot-password page");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn handle_forgot(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let Some(database) = &state.database else {
        return unavailable();
    };
    if state.config.mail.mailer.trim().is_empty() {
        return login_result(
            1,
            &auth_message(
                &state,
                "邮件发送未配置。",
                "Email delivery is not configured.",
            ),
            None,
        );
    }
    let request = match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(request) => request,
        Err(_) => {
            return login_result(
                1,
                &auth_message(&state, "邮箱格式无效。", "Invalid email address."),
                None,
            );
        }
    };
    let email = request
        .get("email")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if !valid_email_address(email) || email.len() > 100 {
        return login_result(
            1,
            &auth_message(&state, "邮箱格式无效。", "Invalid email address."),
            None,
        );
    }
    let captcha = request
        .get("captcha")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    match verify_registration_captcha(&state, &headers, captcha).await {
        Ok(true) => {}
        Ok(false) => {
            return login_result(
                1,
                &auth_message(&state, "验证码无效。", "Invalid CAPTCHA."),
                None,
            );
        }
        Err(response) => return response,
    }
    let ip = registration_client_ip(&headers);
    let key = format!("forgot:{ip}");
    if reserve_mail_limit(&state, &key, Duration::from_secs(180)).is_err() {
        return login_result(
            2,
            &auth_message(
                &state,
                "邮件发送过于频繁，请稍后再试。",
                "You click the send button too fast. Wait for some minutes.",
            ),
            None,
        );
    }
    let uid = match database
        .user_id_by_email(&state.config.database.table_prefix, email)
        .await
    {
        Ok(Some(uid)) => uid,
        Ok(None) => {
            release_mail_limit(&state, &key);
            return login_result(
                1,
                &auth_message(
                    &state,
                    "该邮箱未注册。",
                    "The email address is not registered.",
                ),
                None,
            );
        }
        Err(error) => {
            release_mail_limit(&state, &key);
            tracing::error!(%error, "failed to find password reset recipient");
            return unavailable();
        }
    };
    let Some(path) = signed_relative_url(
        &state,
        &format!("/auth/reset/{uid}"),
        Some(unix_timestamp() + 3600),
    ) else {
        release_mail_limit(&state, &key);
        return unavailable();
    };
    let url = format!("{}{}", state.config.app_url.trim_end_matches('/'), path);
    let site_name = site_name(&state).await;
    let body = if state.config.locale.starts_with("zh") {
        format!(
            "你收到了这封邮件，因为有人请求重置 {site_name} 账户密码。\n\n请在一小时内访问以下链接重设密码：\n{url}\n\n如果你没有请求重置密码，请忽略此邮件。"
        )
    } else {
        format!(
            "You received this email because a password reset was requested for your {site_name} account.\n\nReset your password within one hour by visiting:\n{url}\n\nIf you did not request a password reset, you can ignore this email."
        )
    };
    let subject = if state.config.locale.starts_with("zh") {
        format!("{site_name} 密码重置")
    } else {
        format!("Reset your {site_name} password")
    };
    match crate::mailer::send_email(&state.config.mail, email, &subject, &body).await {
        Ok(()) => login_result(
            0,
            &auth_message(
                &state,
                "重置邮件已发送，请检查收件箱。",
                "Mail sent, please check your inbox. The link will be expired in 1 hour.",
            ),
            None,
        ),
        Err(error) => {
            release_mail_limit(&state, &key);
            tracing::warn!(%error, recipient = %email, "failed to send password reset email");
            login_result(
                2,
                &auth_message(
                    &state,
                    "重置邮件发送失败。",
                    "Failed to send password reset mail.",
                ),
                None,
            )
        }
    }
}

async fn reset_page(
    State(state): State<AppState>,
    RoutePath(uid): RoutePath<String>,
    OriginalUri(uri): OriginalUri,
    RawQuery(query): RawQuery,
) -> Response {
    let Some(uid) = uid.parse::<i64>().ok() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !valid_relative_signature(
        &state,
        uri.path(),
        query.as_deref().unwrap_or_default(),
        true,
    ) {
        return (StatusCode::FORBIDDEN, "Invalid or expired link.").into_response();
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    let user = match database
        .user_profile(&state.config.database.table_prefix, uid)
        .await
    {
        Ok(Some(user)) => user,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, uid, "failed to load password reset user");
            return unavailable();
        }
    };
    let chinese = state.config.locale.starts_with("zh");
    let page = PasswordResetPage {
        site_name: site_name(&state).await,
        locale: state.config.locale.clone(),
        title: if chinese {
            "重设密码"
        } else {
            "Reset Password"
        }
        .to_owned(),
        prompt: if chinese {
            format!("{}，请设置新密码。", user.nickname)
        } else {
            format!("{}, reset your password here.", user.nickname)
        },
        action_url: signed_action_url(&state, &uri),
        password_label: if chinese { "新密码" } else { "New password" }.to_owned(),
        submit_label: if chinese {
            "重设密码"
        } else {
            "Reset password"
        }
        .to_owned(),
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to render password reset page");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn handle_password_reset(
    State(state): State<AppState>,
    RoutePath(uid): RoutePath<String>,
    OriginalUri(uri): OriginalUri,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> Response {
    let Some(uid) = uid.parse::<i64>().ok() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !valid_relative_signature(
        &state,
        uri.path(),
        query.as_deref().unwrap_or_default(),
        true,
    ) {
        return (StatusCode::FORBIDDEN, "Invalid or expired link.").into_response();
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    let request = match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(request) => request,
        Err(_) => {
            return login_result(
                1,
                &auth_message(&state, "密码无效。", "Invalid password."),
                None,
            );
        }
    };
    let password = request
        .get("password")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let length = password.chars().count();
    if !(8..=32).contains(&length) {
        return login_result(
            1,
            &auth_message(
                &state,
                "密码长度必须为 8 到 32 个字符。",
                "Password must be between 8 and 32 characters.",
            ),
            None,
        );
    }
    match database
        .user_profile(&state.config.database.table_prefix, uid)
        .await
    {
        Ok(Some(_)) => {}
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, uid, "failed to find password reset user");
            return unavailable();
        }
    }
    let Some(password_hash) = hash_legacy_password(
        password,
        &state.config.password_method,
        &state.config.password_salt,
    ) else {
        tracing::error!(method = %state.config.password_method, "configured legacy password method cannot hash passwords");
        return unavailable();
    };
    if let Err(error) = database
        .update_user_text(
            &state.config.database.table_prefix,
            uid,
            "password",
            &password_hash,
        )
        .await
    {
        tracing::error!(%error, uid, "failed to update password through reset link");
        return unavailable();
    }
    login_result(
        0,
        &auth_message(&state, "密码已重设。", "Password resetted successfully."),
        Some(serde_json::json!({"redirectTo":"/auth/login"})),
    )
}

async fn verify_email_page(
    State(state): State<AppState>,
    RoutePath(uid): RoutePath<String>,
    OriginalUri(uri): OriginalUri,
    RawQuery(query): RawQuery,
) -> Response {
    let Some(uid) = uid.parse::<i64>().ok() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    match verification_is_required(database, &state.config.database.table_prefix).await {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::FORBIDDEN,
                "Email verification is not available.",
            )
                .into_response();
        }
        Err(error) => {
            tracing::error!(%error, "failed to load email verification option");
            return unavailable();
        }
    }
    if !valid_relative_signature(
        &state,
        uri.path(),
        query.as_deref().unwrap_or_default(),
        false,
    ) {
        return (StatusCode::FORBIDDEN, "Invalid link.").into_response();
    }
    match database
        .user_profile(&state.config.database.table_prefix, uid)
        .await
    {
        Ok(Some(_)) => {}
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, uid, "failed to find email verification user");
            return unavailable();
        }
    }
    let chinese = state.config.locale.starts_with("zh");
    let page = EmailVerificationPage {
        site_name: site_name(&state).await,
        locale: state.config.locale.clone(),
        title: if chinese {
            "邮箱验证"
        } else {
            "Email Verification"
        }
        .to_owned(),
        prompt: if chinese {
            "请输入账户邮箱以完成验证。"
        } else {
            "Enter your account email address to complete verification."
        }
        .to_owned(),
        action_url: signed_action_url(&state, &uri),
        email_label: if chinese { "邮箱" } else { "Email" }.to_owned(),
        submit_label: if chinese {
            "验证邮箱"
        } else {
            "Verify email"
        }
        .to_owned(),
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to render email verification page");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn handle_email_verification(
    State(state): State<AppState>,
    RoutePath(uid): RoutePath<String>,
    OriginalUri(uri): OriginalUri,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> Response {
    let Some(uid) = uid.parse::<i64>().ok() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    match verification_is_required(database, &state.config.database.table_prefix).await {
        Ok(true) => {}
        Ok(false) => {
            return login_result(
                1,
                &auth_message(
                    &state,
                    "邮箱验证未启用。",
                    "Email verification is not available.",
                ),
                None,
            );
        }
        Err(error) => {
            tracing::error!(%error, "failed to load email verification option");
            return unavailable();
        }
    }
    if !valid_relative_signature(
        &state,
        uri.path(),
        query.as_deref().unwrap_or_default(),
        false,
    ) {
        return (StatusCode::FORBIDDEN, "Invalid link.").into_response();
    }
    let request = match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(request) => request,
        Err(_) => {
            return login_result(
                1,
                &auth_message(&state, "邮箱格式无效。", "Invalid email address."),
                None,
            );
        }
    };
    let email = request
        .get("email")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if !valid_email_address(email) {
        return login_result(
            1,
            &auth_message(&state, "邮箱格式无效。", "Invalid email address."),
            None,
        );
    }
    let user = match database
        .user_profile(&state.config.database.table_prefix, uid)
        .await
    {
        Ok(Some(user)) => user,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, uid, "failed to load email verification user");
            return unavailable();
        }
    };
    if user.email != email {
        return login_result(
            1,
            &auth_message(&state, "邮箱不匹配。", "Email doesn't match."),
            None,
        );
    }
    if let Err(error) = database
        .set_user_verified(&state.config.database.table_prefix, uid, true)
        .await
    {
        tracing::error!(%error, uid, "failed to verify user email");
        return unavailable();
    }
    login_result(
        0,
        &auth_message(&state, "邮箱验证成功。", "Email verified successfully."),
        Some(serde_json::json!({"redirectTo":"/user"})),
    )
}

async fn send_verification_email(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(uid) = session_user_id(&state, &headers) else {
        return unauthenticated();
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    match verification_is_required(database, &state.config.database.table_prefix).await {
        Ok(true) => {}
        Ok(false) => {
            return login_result(
                1,
                &auth_message(
                    &state,
                    "邮箱验证未启用。",
                    "Email verification is not available.",
                ),
                None,
            );
        }
        Err(error) => {
            tracing::error!(%error, "failed to load email verification option");
            return unavailable();
        }
    }
    if state.config.mail.mailer.trim().is_empty() {
        return login_result(
            1,
            &auth_message(
                &state,
                "邮件发送未配置。",
                "Email delivery is not configured.",
            ),
            None,
        );
    }
    let user = match database
        .user_profile(&state.config.database.table_prefix, uid)
        .await
    {
        Ok(Some(user)) => user,
        Ok(None) => return unauthenticated(),
        Err(error) => {
            tracing::error!(%error, uid, "failed to load email-verification recipient");
            return unavailable();
        }
    };
    if user.permission == -1 {
        let message = if state.config.locale.starts_with("zh") {
            "你已被本站封禁，详情请联系站点管理员"
        } else {
            "You are banned on this site. Please contact the admin."
        };
        let mut response = login_result(-1, message, None);
        *response.status_mut() = StatusCode::FORBIDDEN;
        return response;
    }
    if user.verified {
        return login_result(
            1,
            &auth_message(
                &state,
                "账户已经验证。",
                "Your account is already verified.",
            ),
            None,
        );
    }
    let key = format!("verify:{uid}");
    if reserve_mail_limit(&state, &key, Duration::from_secs(60)).is_err() {
        return login_result(
            1,
            &auth_message(
                &state,
                "请等待一分钟后再发送验证邮件。",
                "You click the send button too fast. Wait for 60 secs.",
            ),
            None,
        );
    }
    let Some(path) = signed_relative_url(&state, &format!("/auth/verify/{uid}"), None) else {
        release_mail_limit(&state, &key);
        return unavailable();
    };
    let url = format!("{}{}", state.config.app_url.trim_end_matches('/'), path);
    let site_name = site_name(&state).await;
    let body = if state.config.locale.starts_with("zh") {
        format!(
            "有人注册了 {site_name} 账户。如果这是你的账户，请访问以下链接验证邮箱：\n{url}\n\n如果你没有注册，请忽略此邮件。"
        )
    } else {
        format!(
            "Someone registered an account with this email address on {site_name}. Verify your email by visiting:\n{url}\n\nIf you did not register, you can ignore this email."
        )
    };
    let subject = if state.config.locale.starts_with("zh") {
        format!("验证你的 {site_name} 账户")
    } else {
        format!("Verify your account on {site_name}")
    };
    match crate::mailer::send_email(&state.config.mail, &user.email, &subject, &body).await {
        Ok(()) => login_result(
            0,
            &auth_message(
                &state,
                "验证邮件已发送，请检查收件箱。",
                "Verification link was sent, please check your inbox.",
            ),
            None,
        ),
        Err(error) => {
            release_mail_limit(&state, &key);
            tracing::warn!(%error, uid, "failed to send email verification mail");
            login_result(
                2,
                &auth_message(
                    &state,
                    "验证邮件发送失败。",
                    "We failed to send you the verification link.",
                ),
                None,
            )
        }
    }
}

fn auth_message<'a>(state: &AppState, chinese: &'a str, english: &'a str) -> &'a str {
    if state.config.locale.starts_with("zh") {
        chinese
    } else {
        english
    }
}

fn reserve_mail_limit(state: &AppState, key: &str, window: Duration) -> Result<(), Duration> {
    let now = Instant::now();
    let mut limits = state
        .mail_limits
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    limits.retain(|_, sent| sent.elapsed() < Duration::from_secs(3600));
    if let Some(sent) = limits.get(key) {
        let elapsed = sent.elapsed();
        if elapsed < window {
            return Err(window - elapsed);
        }
    }
    limits.insert(key.to_owned(), now);
    Ok(())
}

fn release_mail_limit(state: &AppState, key: &str) {
    state
        .mail_limits
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(key);
}

async fn verification_is_required(
    database: &DatabasePool,
    prefix: &str,
) -> Result<bool, sqlx::Error> {
    Ok(database
        .option(prefix, "require_verification")
        .await?
        .as_deref()
        .is_some_and(|value| legacy_option_bool(Some(value))))
}

fn signed_relative_url(state: &AppState, path: &str, expires: Option<u64>) -> Option<String> {
    let key = state.config.app_key.as_deref()?;
    let mut params = BTreeMap::new();
    if let Some(expires) = expires {
        params.insert("expires", expires.to_string());
    }
    let query = form_urlencoded::Serializer::new(String::new())
        .extend_pairs(params.iter())
        .finish();
    let unsigned = if query.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{query}")
    };
    let signature = signature_hex(key, &unsigned)?;
    let signed = if query.is_empty() {
        format!("{path}?signature={signature}")
    } else {
        format!("{path}?{query}&signature={signature}")
    };
    Some(signed)
}

fn valid_relative_signature(
    state: &AppState,
    path: &str,
    raw_query: &str,
    require_expires: bool,
) -> bool {
    let Some(key) = state.config.app_key.as_deref() else {
        return false;
    };
    let mut params = BTreeMap::new();
    for (name, value) in form_urlencoded::parse(raw_query.as_bytes()) {
        params.insert(name.into_owned(), value.into_owned());
    }
    let Some(signature) = params.remove("signature") else {
        return false;
    };
    let expires = match params.get("expires") {
        Some(value) => match value.parse::<u64>() {
            Ok(expires) => Some(expires),
            Err(_) => return false,
        },
        None => None,
    };
    if require_expires && expires.is_none() {
        return false;
    }
    if expires.is_some_and(|expires| unix_timestamp() > expires) {
        return false;
    }
    let query = form_urlencoded::Serializer::new(String::new())
        .extend_pairs(params.iter())
        .finish();
    let unsigned = if query.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{query}")
    };
    let Some(expected) = signature_hex(key, &unsigned) else {
        return false;
    };
    bool::from(expected.as_bytes().ct_eq(signature.as_bytes()))
}

fn signature_hex(key: &str, value: &str) -> Option<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).ok()?;
    mac.update(value.as_bytes());
    let digest = mac.finalize().into_bytes();
    let digits = b"0123456789abcdef";
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push(digits[(byte >> 4) as usize] as char);
        hex.push(digits[(byte & 0x0f) as usize] as char);
    }
    Some(hex)
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn signed_action_url(state: &AppState, uri: &axum::http::Uri) -> String {
    format!(
        "{}{}",
        state.config.app_url.trim_end_matches('/'),
        uri.path_and_query()
            .map(|value| value.as_str())
            .unwrap_or(uri.path())
    )
}

async fn captcha_image(State(state): State<AppState>) -> Response {
    let session_id = Alphanumeric.sample_string(&mut rand::thread_rng(), 32);
    let choices = b"23456789";
    let phrase = (0..6)
        .map(|_| choices[rand::thread_rng().gen_range(0..choices.len())] as char)
        .collect::<String>();
    {
        let mut challenges = state
            .captcha_challenges
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        challenges.retain(|_, (_, created)| created.elapsed() < Duration::from_secs(300));
        challenges.insert(session_id.clone(), (phrase.clone(), Instant::now()));
    }
    let bytes = match captcha_jpeg(&phrase) {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::error!(%error, "failed to render CAPTCHA image");
            return unavailable();
        }
    };
    let secure = if state.config.app_url.starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    let cookie = format!(
        "blessing_skin_captcha={session_id}; Path=/auth; HttpOnly; SameSite=Lax; Max-Age=300{secure}"
    );
    let mut response = Response::new(Body::from(bytes));
    *response.status_mut() = StatusCode::OK;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("image/jpeg"));
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store, private"));
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().insert(SET_COOKIE, value);
    }
    response
}

fn captcha_jpeg(phrase: &str) -> Result<Vec<u8>, image::ImageError> {
    let mut rng = rand::thread_rng();
    let mut image = RgbImage::from_pixel(180, 60, Rgb([248, 250, 252]));
    for _ in 0..180 {
        let x = rng.gen_range(0..180);
        let y = rng.gen_range(0..60);
        let shade = rng.gen_range(170..225);
        image.put_pixel(x, y, Rgb([shade, shade, shade]));
    }
    for _ in 0..4 {
        let color = Rgb([
            rng.gen_range(140..190),
            rng.gen_range(140..190),
            rng.gen_range(140..190),
        ]);
        draw_captcha_line(
            &mut image,
            rng.gen_range(0..180),
            rng.gen_range(0..60),
            rng.gen_range(0..180),
            rng.gen_range(0..60),
            color,
        );
    }
    for (index, digit) in phrase.chars().enumerate() {
        let rows = captcha_digit_rows(digit);
        let origin_x = 10 + index as u32 * 27;
        let origin_y = 12;
        for (row, bits) in rows.iter().enumerate() {
            for column in 0..3 {
                if bits & (1 << (2 - column)) == 0 {
                    continue;
                }
                for dy in 0..7 {
                    for dx in 0..7 {
                        image.put_pixel(
                            origin_x + column * 7 + dx,
                            origin_y + row as u32 * 7 + dy,
                            Rgb([35, 45, 60]),
                        );
                    }
                }
            }
        }
    }
    let mut output = Cursor::new(Vec::new());
    image::DynamicImage::ImageRgb8(image).write_to(&mut output, ImageFormat::Jpeg)?;
    Ok(output.into_inner())
}

fn captcha_digit_rows(digit: char) -> [u8; 5] {
    match digit {
        '2' => [0b111, 0b001, 0b111, 0b100, 0b111],
        '3' => [0b111, 0b001, 0b111, 0b001, 0b111],
        '4' => [0b101, 0b101, 0b111, 0b001, 0b001],
        '5' => [0b111, 0b100, 0b111, 0b001, 0b111],
        '6' => [0b111, 0b100, 0b111, 0b101, 0b111],
        '7' => [0b111, 0b001, 0b010, 0b010, 0b010],
        '8' => [0b111, 0b101, 0b111, 0b101, 0b111],
        '9' => [0b111, 0b101, 0b111, 0b001, 0b111],
        _ => [0b111, 0b101, 0b101, 0b101, 0b111],
    }
}

fn draw_captcha_line(
    image: &mut RgbImage,
    mut x0: u32,
    mut y0: u32,
    x1: u32,
    y1: u32,
    color: Rgb<u8>,
) {
    let dx = x0.abs_diff(x1) as i32;
    let sx = if x0 < x1 { 1 } else { -1 };
    let dy = -(y0.abs_diff(y1) as i32);
    let sy = if y0 < y1 { 1 } else { -1 };
    let mut error = dx + dy;
    loop {
        image.put_pixel(x0, y0, color);
        if x0 == x1 && y0 == y1 {
            break;
        }
        let twice = 2 * error;
        if twice >= dy {
            error += dy;
            x0 = (i64::from(x0) + i64::from(sx)).clamp(0, i64::from(image.width() - 1)) as u32;
        }
        if twice <= dx {
            error += dx;
            y0 = (i64::from(y0) + i64::from(sy)).clamp(0, i64::from(image.height() - 1)) as u32;
        }
    }
}

#[derive(Deserialize)]
struct RecaptchaVerification {
    success: bool,
}

async fn verify_registration_captcha(
    state: &AppState,
    headers: &HeaderMap,
    value: &str,
) -> Result<bool, Response> {
    let Some(database) = &state.database else {
        return Err(unavailable());
    };
    let secret = match database
        .option(&state.config.database.table_prefix, "recaptcha_secretkey")
        .await
    {
        Ok(secret) => secret.unwrap_or_default(),
        Err(error) => {
            tracing::error!(%error, "failed to read reCAPTCHA secret");
            return Err(unavailable());
        }
    };
    if !secret.is_empty() {
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
        {
            Ok(client) => client,
            Err(error) => {
                tracing::error!(%error, "failed to construct reCAPTCHA client");
                return Err(unavailable());
            }
        };
        let verification = match client
            .post("https://www.recaptcha.net/recaptcha/api/siteverify")
            .form(&[("secret", secret.as_str()), ("response", value)])
            .send()
            .await
        {
            Ok(response) => match response.error_for_status() {
                Ok(response) => match response.json::<RecaptchaVerification>().await {
                    Ok(verification) => verification,
                    Err(error) => {
                        tracing::warn!(%error, "reCAPTCHA returned invalid JSON");
                        return Ok(false);
                    }
                },
                Err(error) => {
                    tracing::warn!(%error, "reCAPTCHA returned an HTTP error");
                    return Ok(false);
                }
            },
            Err(error) => {
                tracing::warn!(%error, "reCAPTCHA verification request failed");
                return Err(unavailable());
            }
        };
        return Ok(verification.success);
    }

    let Some(session_id) = cookie_value(headers, "blessing_skin_captcha") else {
        return Ok(false);
    };
    let challenge = state
        .captcha_challenges
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(session_id);
    Ok(challenge.is_some_and(|(answer, created)| {
        created.elapsed() <= Duration::from_secs(300) && answer.eq_ignore_ascii_case(value.trim())
    }))
}

fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|cookie| {
            let (cookie_name, value) = cookie.trim().split_once('=')?;
            (cookie_name == name && !value.is_empty()).then_some(value)
        })
}

fn registration_client_ip(headers: &HeaderMap) -> String {
    for name in ["x-real-ip", "x-forwarded-for"] {
        let Some(value) = headers.get(name).and_then(|value| value.to_str().ok()) else {
            continue;
        };
        let candidate = value.split(',').next().unwrap_or_default().trim();
        if candidate.parse::<std::net::IpAddr>().is_ok() {
            return candidate.to_owned();
        }
    }
    "unknown".to_owned()
}

async fn handle_register(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if state.session_key.is_none() {
        tracing::error!("APP_KEY is required to create a web login session");
        return unavailable();
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    let request = match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(request) => request,
        Err(_) => return registration_validation_error("email", "required", &state.config.locale),
    };
    let Some(email) = request
        .get("email")
        .and_then(serde_json::Value::as_str)
        .filter(|email| valid_email_address(email) && email.len() <= 100)
    else {
        return registration_validation_error("email", "email", &state.config.locale);
    };
    let Some(password) = request
        .get("password")
        .and_then(serde_json::Value::as_str)
        .filter(|password| (8..=32).contains(&password.chars().count()))
    else {
        return registration_validation_error("password", "length", &state.config.locale);
    };
    let Some(captcha) = request
        .get("captcha")
        .or_else(|| request.get("g-recaptcha-response"))
        .and_then(serde_json::Value::as_str)
        .filter(|captcha| !captcha.trim().is_empty())
    else {
        return registration_validation_error("captcha", "required", &state.config.locale);
    };
    match verify_registration_captcha(&state, &headers, captcha).await {
        Ok(true) => {}
        Ok(false) => {
            return registration_validation_error("captcha", "invalid", &state.config.locale);
        }
        Err(response) => return response,
    }

    let prefix = &state.config.database.table_prefix;
    let player_name_registration = match database.option(prefix, "register_with_player_name").await
    {
        Ok(value) => value
            .as_deref()
            .map(|value| legacy_option_bool(Some(value)))
            .unwrap_or(true),
        Err(error) => {
            tracing::error!(%error, "failed to read registration mode");
            return unavailable();
        }
    };
    let mut player_name = None;
    let nickname = if player_name_registration {
        let Some(name) = request
            .get("player_name")
            .and_then(serde_json::Value::as_str)
            .filter(|name| !name.is_empty())
        else {
            return registration_validation_error("player_name", "required", &state.config.locale);
        };
        let rule = match database.option(prefix, "player_name_rule").await {
            Ok(value) => value.unwrap_or_else(|| "official".to_owned()),
            Err(error) => {
                tracing::error!(%error, "failed to read player-name rule");
                return unavailable();
            }
        };
        let custom_rule = match database.option(prefix, "custom_player_name_regexp").await {
            Ok(value) => value.unwrap_or_default(),
            Err(error) => {
                tracing::error!(%error, "failed to read custom player-name rule");
                return unavailable();
            }
        };
        let min_length = match database.option(prefix, "player_name_length_min").await {
            Ok(value) => value
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(3),
            Err(error) => {
                tracing::error!(%error, "failed to read minimum player-name length");
                return unavailable();
            }
        };
        let max_length = match database.option(prefix, "player_name_length_max").await {
            Ok(value) => value
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(16),
            Err(error) => {
                tracing::error!(%error, "failed to read maximum player-name length");
                return unavailable();
            }
        };
        if !valid_player_name(name, &rule, &custom_rule, min_length, max_length) {
            return registration_validation_error("player_name", "format", &state.config.locale);
        }
        player_name = Some(name);
        name
    } else {
        let Some(nickname) = request
            .get("nickname")
            .and_then(serde_json::Value::as_str)
            .filter(|nickname| !nickname.is_empty() && nickname.chars().count() <= 255)
        else {
            return registration_validation_error("nickname", "required", &state.config.locale);
        };
        nickname
    };

    let client_ip = registration_client_ip(&headers);
    let max_registrations_per_ip = match database.option(prefix, "regs_per_ip").await {
        Ok(value) => value
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(3),
        Err(error) => {
            tracing::error!(%error, "failed to read registration IP limit");
            return unavailable();
        }
    };
    let initial_score = match database.option(prefix, "user_initial_score").await {
        Ok(value) => value
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(1000),
        Err(error) => {
            tracing::error!(%error, "failed to read initial user score");
            return unavailable();
        }
    };
    let Some(password_hash) = hash_legacy_password(
        password,
        &state.config.password_method,
        &state.config.password_salt,
    ) else {
        tracing::error!(method = %state.config.password_method, "unsupported configured legacy password method");
        return unavailable();
    };
    let now = shanghai_now();
    let last_sign_at = now - chrono::Duration::days(1);
    let now = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let last_sign_at = last_sign_at.format("%Y-%m-%d %H:%M:%S").to_string();
    match database
        .register_user(
            prefix,
            email,
            nickname,
            initial_score,
            &password_hash,
            &client_ip,
            &now,
            &last_sign_at,
            max_registrations_per_ip,
            player_name,
        )
        .await
    {
        Ok(crate::database::UserRegistrationOutcome::EmailExists) => {
            registration_validation_error("email", "unique", &state.config.locale)
        }
        Ok(crate::database::UserRegistrationOutcome::PlayerNameExists) => login_result(
            1,
            if state.config.locale.starts_with("zh") {
                "该角色名已被占用"
            } else {
                "The player name is already registered."
            },
            None,
        ),
        Ok(crate::database::UserRegistrationOutcome::IpLimit) => login_result(
            1,
            &if state.config.locale.starts_with("zh") {
                format!("你在本站注册的账号已达到上限 {max_registrations_per_ip} 个，无法继续注册")
            } else {
                format!("You can't register more than {max_registrations_per_ip} accounts.")
            },
            None,
        ),
        Ok(crate::database::UserRegistrationOutcome::Registered(uid)) => {
            let now_epoch = jsonwebtoken::get_current_timestamp();
            let claims = crate::auth::WebSessionClaims {
                sub: uid.to_string(),
                iat: now_epoch,
                exp: now_epoch + 60 * 60 * 12,
            };
            let Some(key) = &state.session_key else {
                return unavailable();
            };
            let session = match encode(&Header::new(Algorithm::HS256), &claims, key) {
                Ok(session) => session,
                Err(error) => {
                    tracing::error!(%error, user_id = uid, "failed to issue post-registration session");
                    return unavailable();
                }
            };
            let message = if state.config.locale.starts_with("zh") {
                "注册成功，正在跳转..."
            } else {
                "Your account was registered. Redirecting..."
            };
            let mut response = login_result(0, message, None);
            let secure = if state.config.app_url.starts_with("https://") {
                "; Secure"
            } else {
                ""
            };
            let cookie = format!(
                "blessing_skin_session={session}; Path=/; HttpOnly; SameSite=Lax; Max-Age=43200{secure}"
            );
            if let Ok(value) = HeaderValue::from_str(&cookie) {
                response.headers_mut().insert(SET_COOKIE, value);
            }
            response
        }
        Err(error) => {
            tracing::error!(%error, "failed to create new user registration");
            unavailable()
        }
    }
}

fn registration_validation_error(field: &str, rule: &str, locale: &str) -> Response {
    let chinese = locale.starts_with("zh");
    let message = if chinese {
        "给定数据无效。"
    } else {
        "The given data was invalid."
    };
    let error = match (field, rule, chinese) {
        ("email", "unique", true) => "该邮箱已被使用。",
        ("email", "unique", false) => "The email has already been taken.",
        ("email", "email", true) => "邮箱格式无效。",
        ("email", "email", false) => "The email must be a valid email address.",
        ("email", _, true) => "邮箱为必填项。",
        ("email", _, false) => "The email field is required.",
        ("password", _, true) => "密码为必填项且长度必须为 8 至 32 个字符。",
        ("password", _, false) => {
            "The password field is required and must be between 8 and 32 characters."
        }
        ("captcha", "invalid", true) => "验证码无效。",
        ("captcha", "invalid", false) => "The CAPTCHA is invalid.",
        ("captcha", _, true) => "验证码为必填项。",
        ("captcha", _, false) => "The CAPTCHA field is required.",
        ("player_name", "format", true) => "角色名格式或长度无效。",
        ("player_name", "format", false) => "The player name format or length is invalid.",
        ("player_name", _, true) => "角色名为必填项。",
        ("player_name", _, false) => "The player_name field is required.",
        ("nickname", _, true) => "昵称为必填项且不能超过 255 个字符。",
        ("nickname", _, false) => {
            "The nickname field is required and may not exceed 255 characters."
        }
        _ => "The given field is invalid.",
    };
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(serde_json::json!({ "message": message, "errors": { field: [error] } })),
    )
        .into_response()
}

#[derive(Deserialize)]
struct LoginRequest {
    identification: Option<String>,
    password: Option<String>,
    keep: Option<bool>,
}

async fn handle_login(State(state): State<AppState>, body: Bytes) -> Response {
    let request: LoginRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return validation_error("identification", &state.config.locale),
    };
    let Some(identification) = request
        .identification
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.trim().to_owned())
    else {
        return validation_error("identification", &state.config.locale);
    };
    let Some(password) = request.password.filter(|value| !value.is_empty()) else {
        return validation_error("password", &state.config.locale);
    };
    if !(6..=32).contains(&password.chars().count()) {
        return validation_error("password", &state.config.locale);
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    let credential = if looks_like_email(&identification) {
        database
            .credentials_by_email(&state.config.database.table_prefix, &identification)
            .await
    } else {
        database
            .credentials_by_player_name(&state.config.database.table_prefix, &identification)
            .await
    };
    let credential = match credential {
        Ok(Some(credential)) => credential,
        Ok(None) => {
            let message = if state.config.locale.starts_with("zh") {
                "用户不存在"
            } else {
                "No such user."
            };
            return login_result(2, message, None);
        }
        Err(error) => {
            tracing::error!(%error, "failed to look up login account");
            return unavailable();
        }
    };
    if !crate::auth::verify_legacy_password(
        &password,
        &credential.password,
        &state.config.password_method,
        &state.config.password_salt,
    ) {
        let failures = {
            let now = Instant::now();
            let mut attempts = state
                .login_failures
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if attempts.len() > 4096 {
                attempts.retain(|_, (_, updated)| {
                    now.duration_since(*updated) < Duration::from_secs(3600)
                });
            }
            let entry = attempts.entry(identification.clone()).or_insert((0, now));
            if now.duration_since(entry.1) >= Duration::from_secs(3600) {
                entry.0 = 0;
            }
            entry.0 = entry.0.saturating_add(1);
            entry.1 = now;
            entry.0
        };
        let message = if state.config.locale.starts_with("zh") {
            "密码错误"
        } else {
            "Wrong password."
        };
        return login_result(
            1,
            message,
            Some(serde_json::json!({ "login_fails": failures })),
        );
    }

    let Some(key) = &state.session_key else {
        tracing::error!("APP_KEY is required to create a web login session");
        return unavailable();
    };
    let now = jsonwebtoken::get_current_timestamp();
    let max_age = if request.keep.unwrap_or(false) {
        60 * 60 * 24 * 30
    } else {
        60 * 60 * 12
    };
    let claims = crate::auth::WebSessionClaims {
        sub: credential.uid.to_string(),
        iat: now,
        exp: now + max_age,
    };
    let session = match encode(&Header::new(Algorithm::HS256), &claims, key) {
        Ok(session) => session,
        Err(error) => {
            tracing::error!(%error, "failed to issue web login session");
            return unavailable();
        }
    };
    state
        .login_failures
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(&identification);

    let message = if state.config.locale.starts_with("zh") {
        "登录成功，欢迎回来"
    } else {
        "Logged in successfully."
    };
    let mut response = login_result(
        0,
        message,
        Some(serde_json::json!({ "redirectTo": "/user" })),
    );
    let secure = if state.config.app_url.starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    let cookie = format!(
        "blessing_skin_session={session}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{secure}"
    );
    match HeaderValue::from_str(&cookie) {
        Ok(value) => {
            response.headers_mut().insert(SET_COOKIE, value);
            response
        }
        Err(error) => {
            tracing::error!(%error, "failed to create web session cookie");
            unavailable()
        }
    }
}

#[derive(Template)]
#[template(path = "home.html")]
struct HomePage {
    site_name: String,
    locale: String,
    title: String,
    login: String,
}

async fn home(State(state): State<AppState>) -> Response {
    let site_name = site_name(&state).await;
    let chinese = state.config.locale.starts_with("zh");
    let page = HomePage {
        site_name,
        locale: state.config.locale.clone(),
        title: if chinese { "皮肤站" } else { "Skin Server" }.to_owned(),
        login: if chinese { "登录" } else { "Log in" }.to_owned(),
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to render home page");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardPage {
    site_name: String,
    user: UserProfile,
    players: Vec<PlayerRecord>,
    notifications: Vec<DashboardNotification>,
    show_email_verification: bool,
    locale: String,
}

struct DashboardNotification {
    id: String,
    title: String,
}

#[derive(Template)]
#[template(path = "players.html")]
struct PlayerManagementPage {
    site_name: String,
    locale: String,
    user: UserProfile,
    score_per_player: i64,
    rule_label: String,
    min_length: usize,
    max_length: usize,
}

#[derive(Template)]
#[template(path = "closet.html")]
struct ClosetManagementPage {
    site_name: String,
    locale: String,
    user: UserProfile,
}

#[derive(Template)]
#[template(path = "skinlib.html")]
struct SkinLibraryPage {
    site_name: String,
    locale: String,
    logged_in: bool,
    current_uid: i64,
}

#[derive(Template)]
#[template(path = "skinlib_show.html")]
struct SkinLibraryShowPage {
    site_name: String,
    locale: String,
    tid: i64,
    name: String,
    texture_type: String,
    hash: String,
    size: i64,
    uploader: i64,
    is_public: bool,
    upload_at: String,
    likes: i64,
    logged_in: bool,
    can_manage: bool,
}

#[derive(Template)]
#[template(path = "texture_upload.html")]
struct TextureUploadPage {
    site_name: String,
    locale: String,
    user: UserProfile,
    public_rate: i64,
    private_rate: i64,
    closet_cost: i64,
    upload_award: i64,
    max_upload_kb: i64,
    content_policy: String,
}

#[derive(Deserialize)]
struct OAuthClientRequest {
    name: Option<String>,
    redirect: Option<String>,
}

async fn oauth_clients_list(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    match database
        .oauth_clients_for_user(&state.config.database.table_prefix, user.uid)
        .await
    {
        Ok(clients) => Json(clients).into_response(),
        Err(error) => {
            tracing::error!(%error, user_id = user.uid, "failed to list Passport clients");
            unavailable()
        }
    }
}

async fn oauth_client_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let request = match serde_json::from_slice::<OAuthClientRequest>(&body) {
        Ok(request) => request,
        Err(_) => return oauth_client_validation_error("name", &state.config.locale),
    };
    let Some(name) = request
        .name
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty() && name.chars().count() <= 255)
    else {
        return oauth_client_validation_error("name", &state.config.locale);
    };
    let Some(redirect) = request
        .redirect
        .map(|redirect| redirect.trim().to_owned())
        .filter(|redirect| valid_oauth_redirect(redirect))
    else {
        return oauth_client_validation_error("redirect", &state.config.locale);
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    use rand::distributions::{Alphanumeric, DistString};
    let secret = Alphanumeric.sample_string(&mut rand::thread_rng(), 40);
    match database
        .create_oauth_client(
            &state.config.database.table_prefix,
            user.uid,
            &name,
            &secret,
            &redirect,
        )
        .await
    {
        Ok(client) => Json(client).into_response(),
        Err(error) => {
            tracing::error!(%error, user_id = user.uid, "failed to create Passport client");
            unavailable()
        }
    }
}

async fn oauth_client_update(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(id): RoutePath<i64>,
    body: Bytes,
) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let request = match serde_json::from_slice::<OAuthClientRequest>(&body) {
        Ok(request) => request,
        Err(_) => return oauth_client_validation_error("name", &state.config.locale),
    };
    let Some(name) = request
        .name
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty() && name.chars().count() <= 255)
    else {
        return oauth_client_validation_error("name", &state.config.locale);
    };
    let Some(redirect) = request
        .redirect
        .map(|redirect| redirect.trim().to_owned())
        .filter(|redirect| valid_oauth_redirect(redirect))
    else {
        return oauth_client_validation_error("redirect", &state.config.locale);
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    match database
        .update_oauth_client(
            &state.config.database.table_prefix,
            user.uid,
            id,
            &name,
            &redirect,
        )
        .await
    {
        Ok(true) => match database
            .oauth_clients_for_user(&state.config.database.table_prefix, user.uid)
            .await
        {
            Ok(clients) => clients
                .into_iter()
                .find(|client| client.id == id)
                .map(|client| Json(client).into_response())
                .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response()),
            Err(error) => {
                tracing::error!(%error, client_id = id, "failed to reload updated Passport client");
                unavailable()
            }
        },
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, client_id = id, "failed to update Passport client");
            unavailable()
        }
    }
}

async fn oauth_client_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(id): RoutePath<i64>,
) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    match database
        .revoke_oauth_client(&state.config.database.table_prefix, user.uid, id)
        .await
    {
        Ok(crate::database::OAuthClientDeleteOutcome::Revoked) => {
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(crate::database::OAuthClientDeleteOutcome::NotFound) => {
            StatusCode::NOT_FOUND.into_response()
        }
        Err(error) => {
            tracing::error!(%error, client_id = id, "failed to revoke Passport client");
            unavailable()
        }
    }
}

fn valid_oauth_redirect(redirect: &str) -> bool {
    let Ok(uri) = redirect.parse::<axum::http::Uri>() else {
        return false;
    };
    matches!(uri.scheme_str(), Some("http" | "https")) && uri.host().is_some()
}

fn oauth_client_validation_error(field: &str, locale: &str) -> Response {
    let chinese = locale.starts_with("zh");
    let message = if chinese {
        "给定数据无效。"
    } else {
        "The given data was invalid."
    };
    let field_error = match (field, chinese) {
        ("name", true) => "应用名称为必填项且不能超过 255 个字符。",
        ("name", false) => "The name field is required and may not exceed 255 characters.",
        ("redirect", true) => "重定向地址必须是有效的 HTTP 或 HTTPS URL。",
        ("redirect", false) => "The redirect field must be a valid HTTP or HTTPS URL.",
        _ => "The given field is invalid.",
    };
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(serde_json::json!({
            "message": message,
            "errors": { field: [field_error] }
        })),
    )
        .into_response()
}

async fn web_dashboard(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(user_id) = session_user_id(&state, &headers) else {
        return Redirect::to("/auth/login").into_response();
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let user = match database
        .user_profile(&state.config.database.table_prefix, user_id)
        .await
    {
        Ok(Some(user)) if user.permission != -1 => user,
        Ok(Some(_)) => return StatusCode::FORBIDDEN.into_response(),
        Ok(None) => return Redirect::to("/auth/login").into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to load web session user");
            return unavailable();
        }
    };
    let players = match database
        .players_for_user(&state.config.database.table_prefix, user_id)
        .await
    {
        Ok(players) => players,
        Err(error) => {
            tracing::error!(%error, "failed to load web session players");
            return unavailable();
        }
    };
    let notifications = match database
        .unread_notifications(&state.config.database.table_prefix, user_id)
        .await
    {
        Ok(notifications) => notifications
            .into_iter()
            .map(|notification| {
                let data = serde_json::from_str::<serde_json::Value>(&notification.data)
                    .unwrap_or(serde_json::Value::Null);
                DashboardNotification {
                    id: notification.id,
                    title: data
                        .get("title")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                }
            })
            .collect(),
        Err(error) => {
            tracing::error!(%error, user_id, "failed to load dashboard notifications");
            return unavailable();
        }
    };
    let show_email_verification = match database
        .option(&state.config.database.table_prefix, "require_verification")
        .await
    {
        Ok(value) => {
            !user.verified
                && value
                    .as_deref()
                    .is_some_and(|value| legacy_option_bool(Some(value)))
        }
        Err(error) => {
            tracing::error!(%error, "failed to load dashboard verification option");
            return unavailable();
        }
    };
    let page = DashboardPage {
        site_name: site_name(&state).await,
        user,
        players,
        notifications,
        show_email_verification,
        locale: state.config.locale.clone(),
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to render user dashboard");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn site_name(state: &AppState) -> String {
    match &state.database {
        Some(database) => database
            .option(&state.config.database.table_prefix, "site_name")
            .await
            .ok()
            .flatten()
            .unwrap_or_else(|| "Blessing Skin".to_owned()),
        None => "Blessing Skin".to_owned(),
    }
}

async fn web_read_notification(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(id): RoutePath<String>,
) -> Response {
    let Some(user_id) = session_user_id(&state, &headers) else {
        return unauthenticated();
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    match database
        .read_notification(&state.config.database.table_prefix, user_id, &id)
        .await
    {
        Ok(Some(notification)) => notification_detail(notification),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "message": "Notification not found." })),
        )
            .into_response(),
        Err(error) => {
            tracing::error!(%error, user_id, notification_id = %id, "failed to mark web notification as read");
            unavailable()
        }
    }
}

async fn user_score_info(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let prefix = &state.config.database.table_prefix;
    let (players, storage) = match database.user_usage(prefix, user.uid).await {
        Ok(usage) => usage,
        Err(error) => {
            tracing::error!(%error, user_id = user.uid, "failed to read user score usage");
            return unavailable();
        }
    };
    let option_number = |value: Option<String>, default: i64| {
        value
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(default)
    };
    let storage_rate = match database.option(prefix, "score_per_storage").await {
        Ok(value) => option_number(value, 1),
        Err(error) => {
            tracing::error!(%error, "failed to read storage score rate");
            return unavailable();
        }
    };
    let player_rate = match database.option(prefix, "score_per_player").await {
        Ok(value) => option_number(value, 100),
        Err(error) => {
            tracing::error!(%error, "failed to read player score rate");
            return unavailable();
        }
    };
    let sign_after_zero = match database.option(prefix, "sign_after_zero").await {
        Ok(value) => legacy_option_bool(value.as_deref()),
        Err(error) => {
            tracing::error!(%error, "failed to read sign reset option");
            return unavailable();
        }
    };
    let sign_gap_time = match database.option(prefix, "sign_gap_time").await {
        Ok(value) => option_number(value, 24),
        Err(error) => {
            tracing::error!(%error, "failed to read sign gap option");
            return unavailable();
        }
    };
    Json(serde_json::json!({
        "user": { "score": user.score, "lastSignAt": user.last_sign_at },
        "rate": { "storage": storage_rate, "players": player_rate },
        "usage": { "players": players, "storage": storage },
        "signAfterZero": sign_after_zero,
        "signGapTime": sign_gap_time
    }))
    .into_response()
}

async fn user_sign(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let prefix = &state.config.database.table_prefix;
    let sign_after_zero = match database.option(prefix, "sign_after_zero").await {
        Ok(value) => legacy_option_bool(value.as_deref()),
        Err(error) => {
            tracing::error!(%error, "failed to read sign reset option");
            return unavailable();
        }
    };
    let sign_gap_time = match database.option(prefix, "sign_gap_time").await {
        Ok(value) => value
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(24)
            .max(0),
        Err(error) => {
            tracing::error!(%error, "failed to read sign gap option");
            return unavailable();
        }
    };
    let (minimum, maximum) = match database.option(prefix, "sign_score").await {
        Ok(value) => value
            .as_deref()
            .and_then(|value| value.split_once(','))
            .and_then(|(minimum, maximum)| {
                Some((
                    minimum.trim().parse::<i64>().ok()?,
                    maximum.trim().parse::<i64>().ok()?,
                ))
            })
            .unwrap_or((10, 100)),
        Err(error) => {
            tracing::error!(%error, "failed to read sign score range");
            return unavailable();
        }
    };
    let (minimum, maximum) = (minimum.min(maximum), minimum.max(maximum));
    let reward = rand::thread_rng().gen_range(minimum..=maximum);
    let now = shanghai_now();
    let eligible_before = if sign_after_zero {
        now.date().and_hms_opt(0, 0, 0).unwrap_or(now)
    } else {
        now - chrono::Duration::hours(sign_gap_time)
    };
    let now = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let eligible_before = eligible_before.format("%Y-%m-%d %H:%M:%S").to_string();
    match database
        .sign_user(prefix, user.uid, reward, &now, &eligible_before)
        .await
    {
        Ok(crate::database::UserSignOutcome::Signed(score)) => {
            let message = if state.config.locale.starts_with("zh") {
                format!("签到成功，获得了 {reward} 积分")
            } else {
                format!("Signed successfully. You got {reward} scores.")
            };
            login_result(0, &message, Some(serde_json::json!({ "score": score })))
        }
        Ok(crate::database::UserSignOutcome::NotEligible) => login_result(1, "", None),
        Err(error) => {
            tracing::error!(%error, user_id = user.uid, "failed to apply sign reward");
            unavailable()
        }
    }
}

async fn web_player_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if session_user_id(&state, &headers).is_none() {
        return Redirect::to("/auth/login").into_response();
    }
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let prefix = &state.config.database.table_prefix;
    let (min_length, max_length, rule, _) = match player_name_settings(database, prefix).await {
        Ok(settings) => settings,
        Err(error) => {
            tracing::error!(%error, "failed to load player-name settings");
            return unavailable();
        }
    };
    let score_per_player = match database.option(prefix, "score_per_player").await {
        Ok(value) => value
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(100),
        Err(error) => {
            tracing::error!(%error, "failed to load player score cost");
            return unavailable();
        }
    };
    let chinese = state.config.locale.starts_with("zh");
    let rule_label = match (chinese, rule.as_str()) {
        (true, "official") => "仅允许官方角色名字符".to_owned(),
        (true, "cjk") => "允许中文角色名".to_owned(),
        (true, "utf8") => "允许非空白 UTF-8 字符".to_owned(),
        (true, "custom") => "使用站点自定义正则规则".to_owned(),
        (false, "official") => "Official player-name characters only".to_owned(),
        (false, "cjk") => "CJK player names are allowed".to_owned(),
        (false, "utf8") => "Any non-whitespace UTF-8 characters".to_owned(),
        (false, "custom") => "Site-defined regular expression".to_owned(),
        (true, _) => "站点自定义角色名规则".to_owned(),
        (false, _) => "Site-defined player-name rule".to_owned(),
    };
    let page = PlayerManagementPage {
        site_name: site_name(&state).await,
        locale: state.config.locale.clone(),
        user,
        score_per_player,
        rule_label,
        min_length,
        max_length,
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to render player-management page");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn web_player_list(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    match database
        .players_for_user(&state.config.database.table_prefix, user.uid)
        .await
    {
        Ok(players) => Json(players).into_response(),
        Err(error) => {
            tracing::error!(%error, user_id = user.uid, "failed to load web player's list");
            unavailable()
        }
    }
}

async fn player_name_settings(
    database: &DatabasePool,
    prefix: &str,
) -> Result<(usize, usize, String, String), sqlx::Error> {
    let min_length = database
        .option(prefix, "player_name_length_min")
        .await?
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(3);
    let max_length = database
        .option(prefix, "player_name_length_max")
        .await?
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(16);
    let rule = database
        .option(prefix, "player_name_rule")
        .await?
        .unwrap_or_else(|| "official".to_owned());
    let custom_rule = database
        .option(prefix, "custom_player_name_regexp")
        .await?
        .unwrap_or_default();
    Ok((min_length, max_length, rule, custom_rule))
}

async fn web_add_player(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let request = match serde_json::from_slice::<RenamePlayerRequest>(&body) {
        Ok(request) => request,
        Err(_) => return validation_error("name", &state.config.locale),
    };
    let Some(name) = request.name.filter(|name| !name.is_empty()) else {
        return validation_error("name", &state.config.locale);
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let prefix = &state.config.database.table_prefix;
    let (min_length, max_length, rule, custom_rule) =
        match player_name_settings(database, prefix).await {
            Ok(settings) => settings,
            Err(error) => {
                tracing::error!(%error, "failed to load player-name settings");
                return unavailable();
            }
        };
    if !valid_player_name(&name, &rule, &custom_rule, min_length, max_length) {
        return validation_error("name", &state.config.locale);
    }
    let score_cost = match database.option(prefix, "score_per_player").await {
        Ok(value) => value
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or_default(),
        Err(error) => {
            tracing::error!(%error, "failed to load player score cost");
            return unavailable();
        }
    };
    match database
        .add_player(prefix, user.uid, &name, score_cost)
        .await
    {
        Ok(crate::database::PlayerAddOutcome::Added(player)) => {
            let message = if state.config.locale.starts_with("zh") {
                format!("成功添加了角色 {}", player.name)
            } else {
                format!("Player {} was added successfully.", player.name)
            };
            login_result(
                0,
                &message,
                Some(serde_json::to_value(player).unwrap_or(serde_json::Value::Null)),
            )
        }
        Ok(crate::database::PlayerAddOutcome::NameExists) => {
            duplicate_player_name_error(&state.config.locale)
        }
        Ok(crate::database::PlayerAddOutcome::InsufficientScore) => login_result(
            7,
            if state.config.locale.starts_with("zh") {
                "添加角色失败，积分不足"
            } else {
                "You don't have enough score to add a player."
            },
            None,
        ),
        Err(error) => {
            tracing::error!(%error, user_id = user.uid, "failed to add web player");
            unavailable()
        }
    }
}

async fn web_rename_player(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(raw_id): RoutePath<String>,
    body: Bytes,
) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Ok(player_id) = raw_id.parse::<i64>() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let request = match serde_json::from_slice::<RenamePlayerRequest>(&body) {
        Ok(request) => request,
        Err(_) => return validation_error("name", &state.config.locale),
    };
    let Some(name) = request.name.filter(|name| !name.is_empty()) else {
        return validation_error("name", &state.config.locale);
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let prefix = &state.config.database.table_prefix;
    let (min_length, max_length, rule, custom_rule) =
        match player_name_settings(database, prefix).await {
            Ok(settings) => settings,
            Err(error) => {
                tracing::error!(%error, "failed to load player-name settings");
                return unavailable();
            }
        };
    if !valid_player_name(&name, &rule, &custom_rule, min_length, max_length) {
        return validation_error("name", &state.config.locale);
    }
    match database
        .rename_player(prefix, user.uid, player_id, &name)
        .await
    {
        Ok(PlayerRenameOutcome::Renamed {
            previous_name,
            player,
        }) => {
            let message = if state.config.locale.starts_with("zh") {
                format!("角色名已从 {previous_name} 更新为 {name}")
            } else {
                format!("Player renamed from {previous_name} to {name}.")
            };
            login_result(
                0,
                &message,
                Some(serde_json::to_value(player).unwrap_or(serde_json::Value::Null)),
            )
        }
        Ok(PlayerRenameOutcome::NameExists) => duplicate_player_name_error(&state.config.locale),
        Ok(PlayerRenameOutcome::Forbidden) => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "code": 1,
                "message": if state.config.locale.starts_with("zh") {
                    "无权操作此角色"
                } else {
                    "You are not allowed to modify this player."
                }
            })),
        )
            .into_response(),
        Ok(PlayerRenameOutcome::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, user_id = user.uid, player_id, "failed to rename web player");
            unavailable()
        }
    }
}

async fn web_set_player_textures(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(raw_id): RoutePath<String>,
    body: Bytes,
) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Ok(player_id) = raw_id.parse::<i64>() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let request =
        serde_json::from_slice::<serde_json::Value>(&body).unwrap_or(serde_json::Value::Null);
    let Some(database) = &state.database else {
        return unavailable();
    };
    let result = database
        .set_player_textures(
            &state.config.database.table_prefix,
            user.uid,
            player_id,
            texture_request_id(request.get("skin")),
            texture_request_id(request.get("cape")),
        )
        .await;
    player_texture_response(result, &state.config.locale, false)
}

async fn web_clear_player_textures(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(raw_id): RoutePath<String>,
    Query(query): Query<BTreeMap<String, String>>,
) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Ok(player_id) = raw_id.parse::<i64>() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let clear_type = |kind: &str| {
        query.contains_key(kind)
            || query
                .get("type")
                .is_some_and(|types| types.split(',').any(|value| value == kind))
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let result = database
        .clear_player_textures(
            &state.config.database.table_prefix,
            user.uid,
            player_id,
            clear_type("skin"),
            clear_type("cape"),
        )
        .await;
    player_texture_response(result, &state.config.locale, true)
}

async fn web_delete_player(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(raw_id): RoutePath<String>,
) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Ok(player_id) = raw_id.parse::<i64>() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let prefix = &state.config.database.table_prefix;
    let return_score = match database.option(prefix, "return_score").await {
        Ok(value) => legacy_option_bool(value.as_deref()),
        Err(error) => {
            tracing::error!(%error, "failed to load player score refund option");
            return unavailable();
        }
    };
    let score_reward = if return_score {
        match database.option(prefix, "score_per_player").await {
            Ok(value) => value
                .and_then(|value| value.parse::<i64>().ok())
                .unwrap_or_default(),
            Err(error) => {
                tracing::error!(%error, "failed to load player score reward");
                return unavailable();
            }
        }
    } else {
        0
    };
    match database
        .delete_player(prefix, user.uid, player_id, return_score, score_reward)
        .await
    {
        Ok(crate::database::PlayerDeleteOutcome::Deleted(name)) => login_result(
            0,
            &if state.config.locale.starts_with("zh") {
                format!("角色 {name} 已被删除")
            } else {
                format!("Player {name} was deleted successfully.")
            },
            None,
        ),
        Ok(crate::database::PlayerDeleteOutcome::Forbidden) => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "code": 1,
                "message": if state.config.locale.starts_with("zh") {
                    "无权操作此角色"
                } else {
                    "You are not allowed to modify this player."
                }
            })),
        )
            .into_response(),
        Ok(crate::database::PlayerDeleteOutcome::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, user_id = user.uid, player_id, "failed to delete web player");
            unavailable()
        }
    }
}

async fn web_closet_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if session_user_id(&state, &headers).is_none() {
        return Redirect::to("/auth/login").into_response();
    }
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let page = ClosetManagementPage {
        site_name: site_name(&state).await,
        locale: state.config.locale.clone(),
        user,
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to render closet page");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn web_closet_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ClosetListQuery>,
) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(6).clamp(1, 100);
    let category = query.category.as_deref().unwrap_or("skin");
    let search = query
        .q
        .as_deref()
        .filter(|value| !value.is_empty() && *value != "0");
    match database
        .closet_items(
            &state.config.database.table_prefix,
            user.uid,
            category,
            search,
            page,
            per_page,
        )
        .await
    {
        Ok((items, total)) => {
            let data = items.into_iter().map(closet_item_json).collect::<Vec<_>>();
            let last_page = total.saturating_add(per_page - 1) / per_page;
            let offset = page.saturating_sub(1).saturating_mul(per_page);
            let from = (!data.is_empty()).then_some(offset + 1);
            let to = (!data.is_empty()).then_some(offset + data.len() as i64);
            Json(serde_json::json!({"current_page":page,"data":data,"last_page":last_page.max(1),"per_page":per_page,"from":from,"to":to,"total":total})).into_response()
        }
        Err(error) => {
            tracing::error!(%error, user_id=user.uid, "failed to load web closet items");
            unavailable()
        }
    }
}

async fn web_closet_ids(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    match database
        .closet_item_ids(&state.config.database.table_prefix, user.uid)
        .await
    {
        Ok(ids) => Json(ids).into_response(),
        Err(error) => {
            tracing::error!(%error, user_id=user.uid, "failed to load web closet texture IDs");
            unavailable()
        }
    }
}

async fn web_add_closet_item(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let request = match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(request) => request,
        Err(_) => return closet_validation_error("tid", &state.config.locale),
    };
    let Some(tid) = texture_id_from_request(request.get("tid")) else {
        return closet_validation_error("tid", &state.config.locale);
    };
    let Some(name) = request
        .get("name")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
    else {
        return closet_validation_error("name", &state.config.locale);
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let prefix = &state.config.database.table_prefix;
    let score_cost = match database.option(prefix, "score_per_closet_item").await {
        Ok(value) => value
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or_default(),
        Err(error) => {
            tracing::error!(%error, "failed to load closet score cost");
            return unavailable();
        }
    };
    let like_award = match database.option(prefix, "score_award_per_like").await {
        Ok(value) => value
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or_default(),
        Err(error) => {
            tracing::error!(%error, "failed to load texture like award");
            return unavailable();
        }
    };
    match database
        .add_closet_item(
            prefix,
            user.uid,
            tid,
            name,
            score_cost,
            user.permission >= 1,
            like_award,
        )
        .await
    {
        Ok(crate::database::ClosetAddOutcome::Added) => login_result(
            0,
            &if state.config.locale.starts_with("zh") {
                format!("材质 {name} 收藏成功")
            } else {
                format!("Added {name} to closet successfully.")
            },
            None,
        ),
        Ok(crate::database::ClosetAddOutcome::NameExists) => login_result(
            1,
            if state.config.locale.starts_with("zh") {
                "你已经收藏过这个材质啦"
            } else {
                "You have already added this texture."
            },
            None,
        ),
        Ok(crate::database::ClosetAddOutcome::InsufficientScore) => login_result(
            1,
            if state.config.locale.starts_with("zh") {
                "收藏失败，积分不足"
            } else {
                "You don't have enough score to add it to closet."
            },
            None,
        ),
        Ok(crate::database::ClosetAddOutcome::TextureNotFound) => login_result(
            1,
            if state.config.locale.starts_with("zh") {
                "该材质不存在"
            } else {
                "We cannot find this texture."
            },
            None,
        ),
        Ok(crate::database::ClosetAddOutcome::PrivateTexture) => login_result(
            1,
            if state.config.locale.starts_with("zh") {
                "请求的材质已经设为私密，仅上传者和管理员可查看"
            } else {
                "The requested texture is private and only visible to the uploader and admins."
            },
            None,
        ),
        Err(error) => {
            tracing::error!(%error, user_id=user.uid, tid, "failed to add web closet item");
            unavailable()
        }
    }
}

async fn web_rename_closet_item(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(raw_tid): RoutePath<String>,
    body: Bytes,
) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Ok(tid) = raw_tid.parse::<i64>() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let request = match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(request) => request,
        Err(_) => return closet_validation_error("name", &state.config.locale),
    };
    let Some(name) = request
        .get("name")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
    else {
        return closet_validation_error("name", &state.config.locale);
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    match database
        .rename_closet_item(&state.config.database.table_prefix, user.uid, tid, name)
        .await
    {
        Ok(crate::database::ClosetRenameOutcome::Renamed) => login_result(
            0,
            &if state.config.locale.starts_with("zh") {
                format!("衣柜物品成功重命名至 {name}")
            } else {
                format!("The item is successfully renamed to {name}")
            },
            None,
        ),
        Ok(crate::database::ClosetRenameOutcome::NotInCloset) => closet_item_missing(&state),
        Err(error) => {
            tracing::error!(%error, user_id=user.uid, tid, "failed to rename web closet item");
            unavailable()
        }
    }
}

async fn web_remove_closet_item(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(raw_tid): RoutePath<String>,
) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Ok(tid) = raw_tid.parse::<i64>() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let prefix = &state.config.database.table_prefix;
    let refund = match database.option(prefix, "return_score").await {
        Ok(value) => legacy_option_bool(value.as_deref()),
        Err(error) => {
            tracing::error!(%error, "failed to load closet refund option");
            return unavailable();
        }
    };
    let score_refund = if refund {
        match database.option(prefix, "score_per_closet_item").await {
            Ok(value) => value
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or_default(),
            Err(error) => {
                tracing::error!(%error, "failed to load closet refund score");
                return unavailable();
            }
        }
    } else {
        0
    };
    let like_award = match database.option(prefix, "score_award_per_like").await {
        Ok(value) => value
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or_default(),
        Err(error) => {
            tracing::error!(%error, "failed to load like award");
            return unavailable();
        }
    };
    match database
        .remove_closet_item(prefix, user.uid, tid, refund, score_refund, like_award)
        .await
    {
        Ok(crate::database::ClosetRemoveOutcome::Removed) => login_result(
            0,
            if state.config.locale.starts_with("zh") {
                "材质已从衣柜中移除"
            } else {
                "The texture was removed from closet successfully."
            },
            None,
        ),
        Ok(crate::database::ClosetRemoveOutcome::NotInCloset) => closet_item_missing(&state),
        Err(error) => {
            tracing::error!(%error, user_id=user.uid, tid, "failed to remove web closet item");
            unavailable()
        }
    }
}

fn shanghai_now() -> NaiveDateTime {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let timestamp = i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX);
    let utc = chrono::DateTime::<chrono::Utc>::from_timestamp(timestamp, elapsed.subsec_nanos())
        .unwrap_or_else(|| chrono::DateTime::<chrono::Utc>::from_timestamp(0, 0).unwrap());
    utc.with_timezone(&FixedOffset::east_opt(8 * 60 * 60).unwrap())
        .naive_local()
}

async fn user_profile_update(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let request = match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(request) => request,
        Err(_) => return login_result(1, illegal_parameters_message(&state.config.locale), None),
    };
    let Some(action) = request.get("action").and_then(serde_json::Value::as_str) else {
        return login_result(1, illegal_parameters_message(&state.config.locale), None);
    };
    let prefix = &state.config.database.table_prefix;
    let chinese = state.config.locale.starts_with("zh");
    match action {
        "nickname" => {
            let Some(nickname) = request
                .get("new_nickname")
                .and_then(serde_json::Value::as_str)
                .filter(|nickname| !nickname.is_empty())
            else {
                return profile_validation_error("new_nickname", "required", &state.config.locale);
            };
            if let Err(error) = database
                .update_user_text(prefix, user.uid, "nickname", nickname)
                .await
            {
                tracing::error!(%error, user_id = user.uid, "failed to update user nickname");
                return unavailable();
            }
            let message = if chinese {
                format!("昵称已成功设置为 {nickname}")
            } else {
                format!("Nickname is successfully updated to {nickname}")
            };
            login_result(0, &message, None)
        }
        "password" => {
            let Some(current_password) = request
                .get("current_password")
                .and_then(serde_json::Value::as_str)
                .filter(|password| (6..=32).contains(&password.chars().count()))
            else {
                return profile_validation_error(
                    "current_password",
                    "password",
                    &state.config.locale,
                );
            };
            let Some(new_password) = request
                .get("new_password")
                .and_then(serde_json::Value::as_str)
                .filter(|password| (8..=32).contains(&password.chars().count()))
            else {
                return profile_validation_error(
                    "new_password",
                    "new_password",
                    &state.config.locale,
                );
            };
            let credential = match database.credentials_by_user_id(prefix, user.uid).await {
                Ok(Some(credential)) => credential,
                Ok(None) => return unauthenticated(),
                Err(error) => {
                    tracing::error!(%error, user_id = user.uid, "failed to load user password for profile update");
                    return unavailable();
                }
            };
            if !verify_legacy_password(
                current_password,
                &credential.password,
                &state.config.password_method,
                &state.config.password_salt,
            ) {
                return login_result(
                    1,
                    if chinese {
                        "原密码错误"
                    } else {
                        "Wrong original password."
                    },
                    None,
                );
            }
            let Some(hash) = hash_legacy_password(
                new_password,
                &state.config.password_method,
                &state.config.password_salt,
            ) else {
                tracing::error!(method = %state.config.password_method, "unsupported configured legacy password method");
                return unavailable();
            };
            if let Err(error) = database
                .update_user_text(prefix, user.uid, "password", &hash)
                .await
            {
                tracing::error!(%error, user_id = user.uid, "failed to update user password");
                return unavailable();
            }
            let response = login_result(
                0,
                if chinese {
                    "密码修改成功，请重新登录"
                } else {
                    "Password updated successfully, please log in again."
                },
                None,
            );
            expire_web_session(&state, response)
        }
        "email" => {
            let Some(email) = request
                .get("email")
                .and_then(serde_json::Value::as_str)
                .filter(|email| valid_email_address(email) && email.len() <= 100)
            else {
                return profile_validation_error("email", "email", &state.config.locale);
            };
            let Some(password) = request
                .get("password")
                .and_then(serde_json::Value::as_str)
                .filter(|password| (6..=32).contains(&password.chars().count()))
            else {
                return profile_validation_error("password", "password", &state.config.locale);
            };
            let credential = match database.credentials_by_user_id(prefix, user.uid).await {
                Ok(Some(credential)) => credential,
                Ok(None) => return unauthenticated(),
                Err(error) => {
                    tracing::error!(%error, user_id = user.uid, "failed to load user password for email update");
                    return unavailable();
                }
            };
            if !verify_legacy_password(
                password,
                &credential.password,
                &state.config.password_method,
                &state.config.password_salt,
            ) {
                return login_result(
                    1,
                    if chinese {
                        "密码错误"
                    } else {
                        "Wrong password."
                    },
                    None,
                );
            }
            match database.user_email_exists(prefix, email, user.uid).await {
                Ok(true) => {
                    return login_result(
                        1,
                        if chinese {
                            "此邮箱已被占用"
                        } else {
                            "This email address is occupied."
                        },
                        None,
                    );
                }
                Ok(false) => {}
                Err(error) => {
                    tracing::error!(%error, user_id = user.uid, "failed to check email uniqueness");
                    return unavailable();
                }
            }
            if let Err(error) = database
                .update_user_email_and_reset_verification(prefix, user.uid, email)
                .await
            {
                tracing::error!(%error, user_id = user.uid, "failed to update user email");
                return unavailable();
            }
            let response = login_result(
                0,
                if chinese {
                    "邮箱修改成功，请重新登录"
                } else {
                    "Email address updated successfully, please log in again."
                },
                None,
            );
            expire_web_session(&state, response)
        }
        "delete" => {
            let Some(password) = request
                .get("password")
                .and_then(serde_json::Value::as_str)
                .filter(|password| (6..=32).contains(&password.chars().count()))
            else {
                return profile_validation_error("password", "password", &state.config.locale);
            };
            if user.permission >= 1 {
                return login_result(
                    1,
                    if chinese {
                        "拥有管理员权限的账号不能被删除"
                    } else {
                        "Admin account can not be deleted."
                    },
                    None,
                );
            }
            let credential = match database.credentials_by_user_id(prefix, user.uid).await {
                Ok(Some(credential)) => credential,
                Ok(None) => return unauthenticated(),
                Err(error) => {
                    tracing::error!(%error, user_id = user.uid, "failed to load user password for account deletion");
                    return unavailable();
                }
            };
            if !verify_legacy_password(
                password,
                &credential.password,
                &state.config.password_method,
                &state.config.password_salt,
            ) {
                return login_result(
                    1,
                    if chinese {
                        "密码错误"
                    } else {
                        "Wrong password."
                    },
                    None,
                );
            }
            match database.delete_user(prefix, user.uid).await {
                Ok(true) => {
                    let response = login_result(
                        0,
                        if chinese {
                            "账号已被成功删除"
                        } else {
                            "Your account is deleted successfully."
                        },
                        None,
                    );
                    expire_web_session(&state, response)
                }
                Ok(false) => unauthenticated(),
                Err(error) => {
                    tracing::error!(%error, user_id = user.uid, "failed to delete user account");
                    unavailable()
                }
            }
        }
        _ => login_result(1, illegal_parameters_message(&state.config.locale), None),
    }
}

async fn user_set_avatar(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let request = serde_json::from_slice::<serde_json::Value>(&body).ok();
    let Some(tid) = request
        .as_ref()
        .and_then(|value| value.get("tid"))
        .and_then(|value| request_i64(Some(value)))
    else {
        return profile_validation_error("tid", "integer", &state.config.locale);
    };
    if tid != 0 {
        let texture = match database
            .texture_info(&state.config.database.table_prefix, tid)
            .await
        {
            Ok(Some(texture)) => texture,
            Ok(None) => {
                return login_result(
                    1,
                    if state.config.locale.starts_with("zh") {
                        "材质不存在"
                    } else {
                        "No such texture."
                    },
                    None,
                );
            }
            Err(error) => {
                tracing::error!(%error, tid, "failed to load requested user avatar texture");
                return unavailable();
            }
        };
        if texture.texture_type == "cape" {
            return login_result(
                1,
                if state.config.locale.starts_with("zh") {
                    "披风不能被设置为头像"
                } else {
                    "You can't set a cape as avatar."
                },
                None,
            );
        }
        if !texture.is_public && texture.uploader != user.uid && user.permission < 1 {
            return login_result(
                1,
                if state.config.locale.starts_with("zh") {
                    "请求的材质已经设为私密，仅上传者和管理员可查看"
                } else {
                    "The requested texture is private and only visible to the uploader and admins."
                },
                None,
            );
        }
    }
    if let Err(error) = database
        .update_user_integer(&state.config.database.table_prefix, user.uid, "avatar", tid)
        .await
    {
        tracing::error!(%error, user_id = user.uid, tid, "failed to update user avatar");
        return unavailable();
    }
    login_result(
        0,
        if state.config.locale.starts_with("zh") {
            "设置成功"
        } else {
            "New avatar was set successfully."
        },
        None,
    )
}

async fn toggle_user_dark_mode(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    if let Err(error) = database
        .toggle_user_dark_mode(&state.config.database.table_prefix, user.uid)
        .await
    {
        tracing::error!(%error, user_id = user.uid, "failed to toggle user dark mode");
        return unavailable();
    }
    StatusCode::NO_CONTENT.into_response()
}

fn profile_validation_error(field: &str, rule: &str, locale: &str) -> Response {
    let chinese = locale.starts_with("zh");
    let message = if chinese {
        "给定数据无效。"
    } else {
        "The given data was invalid."
    };
    let error = match (field, rule, chinese) {
        ("new_nickname", _, true) => "昵称为必填项。",
        ("new_nickname", _, false) => "The new_nickname field is required.",
        ("email", _, true) => "邮箱必须是有效的电子邮件地址。",
        ("email", _, false) => "The email must be a valid email address.",
        ("current_password", _, true) => "当前密码为必填项且长度必须为 6 至 32 个字符。",
        ("current_password", _, false) => {
            "The current_password field is required and must be between 6 and 32 characters."
        }
        ("new_password", _, true) => "新密码长度必须为 8 至 32 个字符。",
        ("new_password", _, false) => "The new_password must be between 8 and 32 characters.",
        ("tid", _, true) => "tid 必须是整数。",
        ("tid", _, false) => "The tid must be an integer.",
        (_, _, true) => "密码为必填项且长度必须为 6 至 32 个字符。",
        (_, _, false) => "The password field is required and must be between 6 and 32 characters.",
    };
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(serde_json::json!({ "message": message, "errors": { field: [error] } })),
    )
        .into_response()
}

fn illegal_parameters_message(locale: &str) -> &'static str {
    if locale.starts_with("zh") {
        "非法参数"
    } else {
        "Illegal parameters."
    }
}

fn expire_web_session(state: &AppState, mut response: Response) -> Response {
    let secure = if state.config.app_url.starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    let cookie =
        format!("blessing_skin_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{secure}");
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().insert(SET_COOKIE, value);
    }
    response
}

async fn logout(State(state): State<AppState>) -> Response {
    let mut response = login_result(
        0,
        if state.config.locale.starts_with("zh") {
            "已退出登录"
        } else {
            "Logged out successfully."
        },
        None,
    );
    let secure = if state.config.app_url.starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    let cookie =
        format!("blessing_skin_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{secure}");
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().insert(SET_COOKIE, value);
    }
    response
}

fn session_user_id(state: &AppState, headers: &HeaderMap) -> Option<i64> {
    let cookie_header = headers.get(COOKIE)?.to_str().ok()?;
    let token = cookie_header.split(';').find_map(|cookie| {
        let (name, value) = cookie.trim().split_once('=')?;
        (name == "blessing_skin_session" && !value.is_empty()).then_some(value)
    })?;
    decode_web_session(token, state.config.app_key.as_deref()?)
}

fn looks_like_email(value: &str) -> bool {
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !value.chars().any(char::is_whitespace)
        && !domain.contains('@')
}

fn validation_error(field: &str, locale: &str) -> Response {
    let chinese = locale.starts_with("zh");
    let message = if chinese {
        "给定数据无效。"
    } else {
        "The given data was invalid."
    };
    let field_error = match (field, chinese) {
        ("identification", true) => "此项为必填项。",
        ("identification", false) => "The identification field is required.",
        ("name", true) => "角色名格式或长度无效。",
        ("name", false) => "The player name format or length is invalid.",
        (_, true) => "密码为必填项且长度必须为 6 至 32 个字符。",
        (_, false) => "The password field is required or has an invalid length.",
    };
    let mut errors = serde_json::Map::new();
    errors.insert(field.to_owned(), serde_json::json!([field_error]));
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(serde_json::json!({ "message": message, "errors": errors })),
    )
        .into_response()
}

fn duplicate_player_name_error(locale: &str) -> Response {
    let chinese = locale.starts_with("zh");
    let message = if chinese {
        "给定数据无效。"
    } else {
        "The given data was invalid."
    };
    let field_error = if chinese {
        "名称已经被占用。"
    } else {
        "The name has already been taken."
    };
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(serde_json::json!({
            "message": message,
            "errors": { "name": [field_error] }
        })),
    )
        .into_response()
}
fn login_result(code: i32, message: &str, data: Option<serde_json::Value>) -> Response {
    let mut body = serde_json::json!({ "code": code, "message": message });
    if let Some(data) = data {
        body["data"] = data;
    }
    Json(body).into_response()
}
#[derive(Serialize)]
struct Health {
    status: &'static str,
}

async fn live() -> Json<Health> {
    Json(Health { status: "ok" })
}

async fn ready(State(state): State<AppState>) -> Response {
    match &state.database {
        Some(database) if database.ping().await.is_ok() => {
            (StatusCode::OK, Json(Health { status: "ready" })).into_response()
        }
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(Health {
                status: "not_ready",
            }),
        )
            .into_response(),
    }
}

#[derive(Serialize)]
struct ApiRoot {
    blessing_skin: &'static str,
    spec: u8,
    copyright: &'static str,
    site_name: String,
}

async fn api_user(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_scope("User.Read") {
        return missing_scope();
    }
    let Some(database) = &state.database else {
        return unavailable();
    };

    match database
        .user_profile(&state.config.database.table_prefix, identity.user_id)
        .await
    {
        Ok(Some(user)) => Json(user).into_response(),
        Ok(None) => unauthenticated(),
        Err(error) => {
            tracing::error!(%error, "failed to load authenticated user");
            unavailable()
        }
    }
}

static NOTIFICATION_ID_SEQUENCE: AtomicU64 = AtomicU64::new(0);

async fn api_send_notification(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let prefix = &state.config.database.table_prefix;
    let user = match database.user_profile(prefix, identity.user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => return unauthenticated(),
        Err(error) => {
            tracing::error!(%error, "failed to load notification sender");
            return unavailable();
        }
    };
    if user.permission < 1 {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "message": "This action is unauthorized." })),
        )
            .into_response();
    }
    if !identity.has_scope("Notification.ReadWrite") {
        return missing_scope();
    }

    let request = match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(request) => request,
        Err(_) => return notification_validation_error("receiver", &state.config.locale),
    };
    let Some(receiver) = request.get("receiver").and_then(serde_json::Value::as_str) else {
        return notification_validation_error("receiver", &state.config.locale);
    };
    let receiver = receiver.trim();
    let audience = match receiver {
        "all" => crate::database::NotificationAudience::All,
        "normal" => crate::database::NotificationAudience::Normal,
        "uid" => {
            let Some(uid) = request_i64(request.get("uid")) else {
                return notification_validation_error("uid", &state.config.locale);
            };
            crate::database::NotificationAudience::User(uid)
        }
        "email" => {
            let Some(email) = request.get("email").and_then(serde_json::Value::as_str) else {
                return notification_validation_error("email", &state.config.locale);
            };
            let email = email.trim();
            if !valid_email_address(email) {
                return notification_validation_error("email", &state.config.locale);
            }
            crate::database::NotificationAudience::Email(email.to_owned())
        }
        _ => return notification_validation_error("receiver", &state.config.locale),
    };
    let Some(title) = request.get("title").and_then(serde_json::Value::as_str) else {
        return notification_validation_error("title", &state.config.locale);
    };
    let title = title.trim();
    if title.is_empty() || title.chars().count() > 20 {
        return notification_validation_error("title", &state.config.locale);
    }
    let content = match request.get("content") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(content)) => Some(content.trim()),
        _ => return notification_validation_error("content", &state.config.locale),
    };

    let recipients = match database.notification_recipients(prefix, &audience).await {
        Ok(Some(recipients)) => recipients,
        Ok(None) => {
            return notification_validation_error(
                match audience {
                    crate::database::NotificationAudience::User(_) => "uid",
                    crate::database::NotificationAudience::Email(_) => "email",
                    _ => "receiver",
                },
                &state.config.locale,
            );
        }
        Err(error) => {
            tracing::error!(%error, "failed to select notification recipients");
            return unavailable();
        }
    };
    let data = serde_json::json!({ "title": title, "content": content }).to_string();
    for recipient in recipients {
        if let Err(error) = database
            .create_site_notification(prefix, &new_notification_id(), recipient, &data)
            .await
        {
            tracing::error!(%error, recipient, "failed to store notification");
            return unavailable();
        }
    }
    let mut response = StatusCode::FOUND.into_response();
    response
        .headers_mut()
        .insert(LOCATION, HeaderValue::from_static("/admin"));
    response
}

fn request_i64(value: Option<&serde_json::Value>) -> Option<i64> {
    let value = value?;
    value.as_i64().or_else(|| {
        value
            .as_str()
            .and_then(|number| number.trim().parse::<i64>().ok())
    })
}
fn notification_validation_error(field: &str, locale: &str) -> Response {
    let chinese = locale.starts_with("zh");
    let message = if chinese {
        "给定数据无效。"
    } else {
        "The given data was invalid."
    };
    let field_error = match (field, chinese) {
        ("receiver", true) => "接收对象必须是 all、normal、uid 或 email。",
        ("receiver", false) => "The receiver must be all, normal, uid, or email.",
        ("uid", true) => "用户编号为必填整数且必须存在。",
        ("uid", false) => "The uid must be an integer identifying an existing user.",
        ("email", true) => "邮箱地址无效或不存在。",
        ("email", false) => "The email must be valid and belong to an existing user.",
        ("title", true) => "标题为必填项且不能超过 20 个字符。",
        ("title", false) => "The title is required and may not exceed 20 characters.",
        ("content", true) => "内容必须是字符串。",
        ("content", false) => "The content must be a string.",
        _ => "The given field is invalid.",
    };
    let mut errors = serde_json::Map::new();
    errors.insert(field.to_owned(), serde_json::json!([field_error]));
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(serde_json::json!({ "message": message, "errors": errors })),
    )
        .into_response()
}

fn valid_email_address(value: &str) -> bool {
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !value.chars().any(char::is_whitespace)
}

fn new_notification_id() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let sequence = NOTIFICATION_ID_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let source = format!("{timestamp}:{}:{sequence}", std::process::id());
    let digest = Md5::digest(source.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}
async fn api_user_notifications(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_scope("Notification.Read") {
        return missing_scope();
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    match database
        .unread_notifications(&state.config.database.table_prefix, identity.user_id)
        .await
    {
        Ok(notifications) => Json(notification_summaries(notifications)).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to list unread notifications");
            unavailable()
        }
    }
}

async fn api_read_notification(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(id): RoutePath<String>,
) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_scope("Notification.Read") {
        return missing_scope();
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    match database
        .read_notification(&state.config.database.table_prefix, identity.user_id, &id)
        .await
    {
        Ok(Some(notification)) => notification_detail(notification),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "message": "Notification not found." })),
        )
            .into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to read notification");
            unavailable()
        }
    }
}

fn notification_summaries(notifications: Vec<NotificationRecord>) -> Vec<serde_json::Value> {
    notifications
        .into_iter()
        .map(|notification| {
            let data = serde_json::from_str::<serde_json::Value>(&notification.data)
                .unwrap_or(serde_json::Value::Null);
            serde_json::json!({
                "id": notification.id,
                "title": data.get("title").cloned().unwrap_or(serde_json::Value::Null),
            })
        })
        .collect()
}

fn notification_detail(notification: NotificationRecord) -> Response {
    let data = serde_json::from_str::<serde_json::Value>(&notification.data)
        .unwrap_or(serde_json::Value::Null);
    let title = data
        .get("title")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let content = data
        .get("content")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    Json(serde_json::json!({
        "title": title,
        "content": render_notification_markdown(content),
        "time": notification.created_at,
    }))
    .into_response()
}

fn render_notification_markdown(markdown: &str) -> String {
    let parser = Parser::new_ext(
        markdown,
        Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH | Options::ENABLE_TASKLISTS,
    );
    let mut html = String::with_capacity(markdown.len().saturating_mul(2));
    markdown_html::push_html(&mut html, parser);
    ammonia::clean(&html)
}

#[derive(Deserialize)]
struct RenamePlayerRequest {
    name: Option<String>,
}

async fn api_rename_player(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(raw_id): RoutePath<String>,
    body: Bytes,
) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_scope("Player.ReadWrite") {
        return missing_scope();
    }
    let Ok(player_id) = raw_id.parse::<i64>() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let request: RenamePlayerRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return validation_error("name", &state.config.locale),
    };
    let Some(name) = request.name.filter(|name| !name.is_empty()) else {
        return validation_error("name", &state.config.locale);
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let options = &state.config.database.table_prefix;
    let min_length = database
        .option(options, "player_name_length_min")
        .await
        .ok()
        .flatten()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(3);
    let max_length = database
        .option(options, "player_name_length_max")
        .await
        .ok()
        .flatten()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(16);
    let name_rule = database
        .option(options, "player_name_rule")
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| "official".to_owned());
    let custom_rule = database
        .option(options, "custom_player_name_regexp")
        .await
        .ok()
        .flatten()
        .unwrap_or_default();
    if !valid_player_name(&name, &name_rule, &custom_rule, min_length, max_length) {
        return validation_error("name", &state.config.locale);
    }

    match database
        .rename_player(options, identity.user_id, player_id, &name)
        .await
    {
        Ok(PlayerRenameOutcome::Renamed {
            previous_name,
            player,
        }) => {
            let message = if state.config.locale.starts_with("zh") {
                format!("角色名已从 {previous_name} 更新为 {name}")
            } else {
                format!("Player renamed from {previous_name} to {name}.")
            };
            login_result(
                0,
                &message,
                Some(serde_json::to_value(player).unwrap_or(serde_json::Value::Null)),
            )
        }
        Ok(PlayerRenameOutcome::NameExists) => login_result(
            1,
            if state.config.locale.starts_with("zh") {
                "该角色名已被使用"
            } else {
                "That player name is already in use."
            },
            None,
        ),
        Ok(PlayerRenameOutcome::Forbidden) => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "code": 1,
                "message": if state.config.locale.starts_with("zh") {
                    "无权操作此角色"
                } else {
                    "You are not allowed to modify this player."
                }
            })),
        )
            .into_response(),
        Ok(PlayerRenameOutcome::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to rename player");
            unavailable()
        }
    }
}

async fn api_set_player_textures(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(raw_id): RoutePath<String>,
    body: Bytes,
) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_scope("Player.ReadWrite") {
        return missing_scope();
    }
    let Ok(player_id) = raw_id.parse::<i64>() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let request =
        serde_json::from_slice::<serde_json::Value>(&body).unwrap_or(serde_json::Value::Null);
    let skin = texture_request_id(request.get("skin"));
    let cape = texture_request_id(request.get("cape"));
    let Some(database) = &state.database else {
        return unavailable();
    };
    let result = database
        .set_player_textures(
            &state.config.database.table_prefix,
            identity.user_id,
            player_id,
            skin,
            cape,
        )
        .await;
    player_texture_response(result, &state.config.locale, false)
}

async fn api_clear_player_textures(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(raw_id): RoutePath<String>,
    body: Bytes,
) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_scope("Player.ReadWrite") {
        return missing_scope();
    }
    let Ok(player_id) = raw_id.parse::<i64>() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let request =
        serde_json::from_slice::<serde_json::Value>(&body).unwrap_or(serde_json::Value::Null);
    let clear_type = |kind: &str| {
        request.get(kind).is_some()
            || request
                .get("type")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|types| types.iter().any(|value| value.as_str() == Some(kind)))
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let result = database
        .clear_player_textures(
            &state.config.database.table_prefix,
            identity.user_id,
            player_id,
            clear_type("skin"),
            clear_type("cape"),
        )
        .await;
    player_texture_response(result, &state.config.locale, true)
}

fn texture_request_id(value: Option<&serde_json::Value>) -> Option<i64> {
    match value? {
        serde_json::Value::Null => None,
        serde_json::Value::Bool(false) => None,
        serde_json::Value::Bool(true) => Some(-1),
        serde_json::Value::Number(number) => Some(number.as_i64().unwrap_or(-1)),
        serde_json::Value::String(value) if value.is_empty() => None,
        serde_json::Value::String(value) => Some(value.parse::<i64>().unwrap_or(-1)),
        _ => Some(-1),
    }
}

fn player_texture_response(
    result: Result<PlayerTextureOutcome, sqlx::Error>,
    locale: &str,
    clear: bool,
) -> Response {
    let chinese = locale.starts_with("zh");
    match result {
        Ok(PlayerTextureOutcome::Updated(player)) => {
            let message = match (chinese, clear) {
                (true, true) => format!("角色 {} 的材质已被成功重置", player.name),
                (true, false) => format!("材质已成功应用至角色 {}", player.name),
                (false, true) => format!(
                    "The textures of player {} was resetted successfully.",
                    player.name
                ),
                (false, false) => format!(
                    "The texture was applied to player {} successfully.",
                    player.name
                ),
            };
            login_result(
                0,
                &message,
                Some(serde_json::to_value(player).unwrap_or(serde_json::Value::Null)),
            )
        }
        Ok(PlayerTextureOutcome::TextureNotFound) => login_result(
            1,
            if chinese {
                "材质不存在"
            } else {
                "No such texture."
            },
            None,
        ),
        Ok(PlayerTextureOutcome::TextureNotInCloset) => login_result(
            1,
            if chinese {
                "衣柜中不存在此材质"
            } else {
                "The texture does not exist in your closet."
            },
            None,
        ),
        Ok(PlayerTextureOutcome::Forbidden) => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "code": 1,
                "message": if chinese { "无权操作此角色" } else { "You are not allowed to modify this player." }
            })),
        )
            .into_response(),
        Ok(PlayerTextureOutcome::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to update player textures");
            unavailable()
        }
    }
}
fn valid_player_name(
    name: &str,
    rule: &str,
    custom_rule: &str,
    min_length: usize,
    max_length: usize,
) -> bool {
    let length = name.chars().count();
    if length < min_length || length > max_length {
        return false;
    }
    match rule {
        "official" => name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_'),
        "cjk" => name.chars().all(|ch| {
            ch.is_ascii_alphanumeric()
                || ch == '_'
                || ch == '§'
                || ('\u{4e00}'..='\u{9fff}').contains(&ch)
        }),
        "utf8" => !name.chars().any(char::is_whitespace),
        "custom" => custom_player_name_matches(name, custom_rule),
        _ => false,
    }
}

fn custom_player_name_matches(name: &str, pattern: &str) -> bool {
    if pattern.is_empty() {
        return true;
    }
    let (pattern, flags) = if let Some(inner) = pattern.strip_prefix('/') {
        let Some(end) = inner.rfind('/') else {
            return false;
        };
        (&inner[..end], &inner[end + 1..])
    } else {
        (pattern, "")
    };
    if pattern.len() > 512 {
        return false;
    }
    let mut builder = RegexBuilder::new(pattern);
    builder
        .case_insensitive(flags.contains('i'))
        .multi_line(flags.contains('m'))
        .dot_matches_new_line(flags.contains('s'))
        .ignore_whitespace(flags.contains('x'));
    builder.build().is_ok_and(|regex| regex.is_match(name))
}

async fn api_add_player(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_scope("Player.ReadWrite") {
        return missing_scope();
    }
    let request = match serde_json::from_slice::<RenamePlayerRequest>(&body) {
        Ok(request) => request,
        Err(_) => return validation_error("name", &state.config.locale),
    };
    let Some(name) = request.name.filter(|name| !name.is_empty()) else {
        return validation_error("name", &state.config.locale);
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let prefix = &state.config.database.table_prefix;
    let min_length = database
        .option(prefix, "player_name_length_min")
        .await
        .ok()
        .flatten()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(3);
    let max_length = database
        .option(prefix, "player_name_length_max")
        .await
        .ok()
        .flatten()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(16);
    let rule = database
        .option(prefix, "player_name_rule")
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| "official".to_owned());
    let custom_rule = database
        .option(prefix, "custom_player_name_regexp")
        .await
        .ok()
        .flatten()
        .unwrap_or_default();
    if !valid_player_name(&name, &rule, &custom_rule, min_length, max_length) {
        return validation_error("name", &state.config.locale);
    }
    let score_cost = match database.option(prefix, "score_per_player").await {
        Ok(value) => value
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or_default(),
        Err(error) => {
            tracing::error!(%error, "failed to load player score cost");
            return unavailable();
        }
    };
    match database
        .add_player(prefix, identity.user_id, &name, score_cost)
        .await
    {
        Ok(crate::database::PlayerAddOutcome::Added(player)) => {
            let message = if state.config.locale.starts_with("zh") {
                format!("成功添加了角色 {}", player.name)
            } else {
                format!("Player {} was added successfully.", player.name)
            };
            login_result(
                0,
                &message,
                Some(serde_json::to_value(player).unwrap_or(serde_json::Value::Null)),
            )
        }
        Ok(crate::database::PlayerAddOutcome::NameExists) => {
            duplicate_player_name_error(&state.config.locale)
        }
        Ok(crate::database::PlayerAddOutcome::InsufficientScore) => login_result(
            7,
            if state.config.locale.starts_with("zh") {
                "添加角色失败，积分不足"
            } else {
                "You don't have enough score to add a player."
            },
            None,
        ),
        Err(error) => {
            tracing::error!(%error, "failed to add player");
            unavailable()
        }
    }
}

async fn api_delete_player(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(raw_id): RoutePath<String>,
) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_scope("Player.ReadWrite") {
        return missing_scope();
    }
    let Ok(player_id) = raw_id.parse::<i64>() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let prefix = &state.config.database.table_prefix;
    let return_score = match database.option(prefix, "return_score").await {
        Ok(value) => legacy_option_bool(value.as_deref()),
        Err(error) => {
            tracing::error!(%error, "failed to load player score refund option");
            return unavailable();
        }
    };
    let score_reward = if return_score {
        match database.option(prefix, "score_per_player").await {
            Ok(value) => value
                .and_then(|value| value.parse::<i64>().ok())
                .unwrap_or_default(),
            Err(error) => {
                tracing::error!(%error, "failed to load player score reward");
                return unavailable();
            }
        }
    } else {
        0
    };
    match database
        .delete_player(
            prefix,
            identity.user_id,
            player_id,
            return_score,
            score_reward,
        )
        .await
    {
        Ok(crate::database::PlayerDeleteOutcome::Deleted(name)) => login_result(
            0,
            &if state.config.locale.starts_with("zh") {
                format!("角色 {name} 已被删除")
            } else {
                format!("Player {name} was deleted successfully.")
            },
            None,
        ),
        Ok(crate::database::PlayerDeleteOutcome::Forbidden) => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "code": 1,
                "message": if state.config.locale.starts_with("zh") { "无权操作此角色" } else { "You are not allowed to modify this player." }
            })),
        )
            .into_response(),
        Ok(crate::database::PlayerDeleteOutcome::NotFound) => {
            StatusCode::NOT_FOUND.into_response()
        }
        Err(error) => {
            tracing::error!(%error, "failed to delete player");
            unavailable()
        }
    }
}

fn legacy_option_bool(value: Option<&str>) -> bool {
    match value.map(str::to_ascii_lowercase).as_deref() {
        Some("true" | "(true)") => true,
        Some("" | "0" | "false" | "(false)" | "null" | "(null)") | None => false,
        Some(_) => true,
    }
}
fn closet_validation_error(field: &str, locale: &str) -> Response {
    let chinese = locale.starts_with("zh");
    let message = if chinese {
        "给定数据无效。"
    } else {
        "The given data was invalid."
    };
    let field_error = match (field, chinese) {
        ("tid", true) => "材质编号必须是整数。",
        ("tid", false) => "The tid field must be an integer.",
        ("name", true) => "名称为必填项。",
        ("name", false) => "The name field is required.",
        _ => "The given field is invalid.",
    };
    let mut errors = serde_json::Map::new();
    errors.insert(field.to_owned(), serde_json::json!([field_error]));
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(serde_json::json!({ "message": message, "errors": errors })),
    )
        .into_response()
}

fn texture_id_from_request(value: Option<&serde_json::Value>) -> Option<i64> {
    match value? {
        serde_json::Value::Number(value) => value.as_i64(),
        serde_json::Value::String(value) => value.trim().parse().ok(),
        _ => None,
    }
}

async fn api_add_closet_item(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_scope("Closet.ReadWrite") {
        return missing_scope();
    }
    let request = match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(request) => request,
        Err(_) => return closet_validation_error("tid", &state.config.locale),
    };
    let Some(tid) = texture_id_from_request(request.get("tid")) else {
        return closet_validation_error("tid", &state.config.locale);
    };
    let Some(name) = request.get("name").and_then(serde_json::Value::as_str) else {
        return closet_validation_error("name", &state.config.locale);
    };
    let name = name.trim();
    if name.is_empty() {
        return closet_validation_error("name", &state.config.locale);
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    let prefix = &state.config.database.table_prefix;
    let user = match database.user_profile(prefix, identity.user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => return unauthenticated(),
        Err(error) => {
            tracing::error!(%error, "failed to load closet owner");
            return unavailable();
        }
    };
    let score_cost = match database.option(prefix, "score_per_closet_item").await {
        Ok(value) => value
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or_default(),
        Err(error) => {
            tracing::error!(%error, "failed to load closet score cost");
            return unavailable();
        }
    };
    let like_award = match database.option(prefix, "score_award_per_like").await {
        Ok(value) => value
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or_default(),
        Err(error) => {
            tracing::error!(%error, "failed to load texture like award");
            return unavailable();
        }
    };
    match database
        .add_closet_item(
            prefix,
            identity.user_id,
            tid,
            name,
            score_cost,
            user.permission >= 1,
            like_award,
        )
        .await
    {
        Ok(crate::database::ClosetAddOutcome::Added) => login_result(
            0,
            &if state.config.locale.starts_with("zh") {
                format!("材质 {name} 收藏成功")
            } else {
                format!("Added {name} to closet successfully.")
            },
            None,
        ),
        Ok(crate::database::ClosetAddOutcome::NameExists) => login_result(
            1,
            if state.config.locale.starts_with("zh") {
                "你已经收藏过这个材质啦"
            } else {
                "You have already added this texture."
            },
            None,
        ),
        Ok(crate::database::ClosetAddOutcome::InsufficientScore) => login_result(
            1,
            if state.config.locale.starts_with("zh") {
                "收藏失败，积分不足"
            } else {
                "You don't have enough score to add it to closet."
            },
            None,
        ),
        Ok(crate::database::ClosetAddOutcome::TextureNotFound) => login_result(
            1,
            if state.config.locale.starts_with("zh") {
                "该材质不存在"
            } else {
                "We cannot find this texture."
            },
            None,
        ),
        Ok(crate::database::ClosetAddOutcome::PrivateTexture) => login_result(
            1,
            if state.config.locale.starts_with("zh") {
                "请求的材质已经设为私密，仅上传者和管理员可查看"
            } else {
                "The requested texture is private and only visible to the uploader and admins."
            },
            None,
        ),
        Err(error) => {
            tracing::error!(%error, "failed to add a texture to the closet");
            unavailable()
        }
    }
}

async fn api_rename_closet_item(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(raw_tid): RoutePath<String>,
    body: Bytes,
) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_scope("Closet.ReadWrite") {
        return missing_scope();
    }
    let Ok(tid) = raw_tid.parse::<i64>() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let request = match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(request) => request,
        Err(_) => return closet_validation_error("name", &state.config.locale),
    };
    let Some(name) = request.get("name").and_then(serde_json::Value::as_str) else {
        return closet_validation_error("name", &state.config.locale);
    };
    let name = name.trim();
    if name.is_empty() {
        return closet_validation_error("name", &state.config.locale);
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    match database
        .rename_closet_item(
            &state.config.database.table_prefix,
            identity.user_id,
            tid,
            name,
        )
        .await
    {
        Ok(crate::database::ClosetRenameOutcome::Renamed) => login_result(
            0,
            &if state.config.locale.starts_with("zh") {
                format!("衣柜物品成功重命名至 {name}")
            } else {
                format!("The item is successfully renamed to {name}")
            },
            None,
        ),
        Ok(crate::database::ClosetRenameOutcome::NotInCloset) => closet_item_missing(&state),
        Err(error) => {
            tracing::error!(%error, "failed to rename a closet item");
            unavailable()
        }
    }
}

async fn api_remove_closet_item(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(raw_tid): RoutePath<String>,
) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_scope("Closet.ReadWrite") {
        return missing_scope();
    }
    let Ok(tid) = raw_tid.parse::<i64>() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let prefix = &state.config.database.table_prefix;
    let return_score = match database.option(prefix, "return_score").await {
        Ok(value) => legacy_option_bool(value.as_deref()),
        Err(error) => {
            tracing::error!(%error, "failed to load closet score refund option");
            return unavailable();
        }
    };
    let score_refund = if return_score {
        match database.option(prefix, "score_per_closet_item").await {
            Ok(value) => value
                .and_then(|value| value.parse::<i64>().ok())
                .unwrap_or_default(),
            Err(error) => {
                tracing::error!(%error, "failed to load closet score refund");
                return unavailable();
            }
        }
    } else {
        0
    };
    let like_award = match database.option(prefix, "score_award_per_like").await {
        Ok(value) => value
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or_default(),
        Err(error) => {
            tracing::error!(%error, "failed to load texture like award");
            return unavailable();
        }
    };
    match database
        .remove_closet_item(
            prefix,
            identity.user_id,
            tid,
            return_score,
            score_refund,
            like_award,
        )
        .await
    {
        Ok(crate::database::ClosetRemoveOutcome::Removed) => login_result(
            0,
            if state.config.locale.starts_with("zh") {
                "材质已从衣柜中移除"
            } else {
                "The texture was removed from closet successfully."
            },
            None,
        ),
        Ok(crate::database::ClosetRemoveOutcome::NotInCloset) => closet_item_missing(&state),
        Err(error) => {
            tracing::error!(%error, "failed to remove a texture from the closet");
            unavailable()
        }
    }
}

fn closet_item_missing(state: &AppState) -> Response {
    login_result(
        1,
        if state.config.locale.starts_with("zh") {
            "衣柜中不存在此材质"
        } else {
            "The texture does not exist in your closet."
        },
        None,
    )
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClosetListQuery {
    category: Option<String>,
    q: Option<String>,
    page: Option<i64>,
    per_page: Option<i64>,
}

async fn skinlib_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let current_uid = session_user_id(&state, &headers).unwrap_or_default();
    let page = SkinLibraryPage {
        site_name: site_name(&state).await,
        locale: state.config.locale.clone(),
        logged_in: current_uid > 0,
        current_uid,
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to render skin library page");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn skinlib_show_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(raw_tid): RoutePath<String>,
) -> Response {
    let Ok(tid) = raw_tid.parse::<i64>() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let texture = match database
        .texture_info(&state.config.database.table_prefix, tid)
        .await
    {
        Ok(Some(texture)) => texture,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, tid, "failed to load texture for skin library page");
            return unavailable();
        }
    };
    let current_uid = session_user_id(&state, &headers);
    let (viewer_uid, is_admin) = match current_uid {
        Some(uid) => match database
            .user_profile(&state.config.database.table_prefix, uid)
            .await
        {
            Ok(Some(user)) => (Some(uid), user.permission >= 1),
            Ok(None) => (None, false),
            Err(error) => {
                tracing::error!(%error, "failed to load texture page viewer");
                return unavailable();
            }
        },
        None => (None, false),
    };
    if !texture.is_public && viewer_uid != Some(texture.uploader) && !is_admin {
        let code = match database
            .option(
                &state.config.database.table_prefix,
                "status_code_for_private",
            )
            .await
        {
            Ok(value) => value
                .and_then(|value| value.parse::<u16>().ok())
                .and_then(|value| StatusCode::from_u16(value).ok())
                .unwrap_or(StatusCode::FORBIDDEN),
            Err(error) => {
                tracing::error!(%error, "failed to read private texture status option");
                return unavailable();
            }
        };
        return code.into_response();
    }
    if !valid_texture_hash(&texture.hash) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let page = SkinLibraryShowPage {
        site_name: site_name(&state).await,
        locale: state.config.locale.clone(),
        tid: texture.tid,
        name: texture.name,
        texture_type: texture.texture_type,
        hash: texture.hash,
        size: texture.size,
        uploader: texture.uploader,
        is_public: texture.is_public,
        upload_at: texture.upload_at,
        likes: texture.likes,
        logged_in: viewer_uid.is_some(),
        can_manage: viewer_uid == Some(texture.uploader) || is_admin,
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, tid, "failed to render skin library detail page");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn texture_upload_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if session_user_id(&state, &headers).is_none() {
        return Redirect::to("/auth/login").into_response();
    }
    let user = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let prefix = &state.config.database.table_prefix;
    let read_number = async |name: &str, default: i64| match database.option(prefix, name).await {
        Ok(value) => Ok(value
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(default)),
        Err(error) => Err(error),
    };
    let public_rate = match read_number("score_per_storage", 1).await {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(%error, "failed to read public upload cost");
            return unavailable();
        }
    };
    let private_rate = match read_number("private_score_per_storage", 10).await {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(%error, "failed to read private upload cost");
            return unavailable();
        }
    };
    let closet_cost = match read_number("score_per_closet_item", 0).await {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(%error, "failed to read closet upload cost");
            return unavailable();
        }
    };
    let upload_award = match read_number("score_award_per_texture", 0).await {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(%error, "failed to read upload award");
            return unavailable();
        }
    };
    let max_upload_kb = match read_number("max_upload_file_size", 1024).await {
        Ok(value) => value.max(0),
        Err(error) => {
            tracing::error!(%error, "failed to read maximum upload size");
            return unavailable();
        }
    };
    let localized_policy_key = format!("content_policy_{}", state.config.locale);
    let content_policy = match database.option(prefix, &localized_policy_key).await {
        Ok(Some(value)) if !value.is_empty() => value,
        Ok(_) => match database.option(prefix, "content_policy").await {
            Ok(value) => value.unwrap_or_default(),
            Err(error) => {
                tracing::error!(%error, "failed to read texture content policy");
                return unavailable();
            }
        },
        Err(error) => {
            tracing::error!(%error, "failed to read localized texture content policy");
            return unavailable();
        }
    };
    let page = TextureUploadPage {
        site_name: site_name(&state).await,
        locale: state.config.locale.clone(),
        user,
        public_rate,
        private_rate,
        closet_cost,
        upload_award,
        max_upload_kb,
        content_policy,
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to render texture upload page");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn skinlib_info(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(tid): RoutePath<String>,
) -> Response {
    let Some(database) = &state.database else {
        return unavailable();
    };
    let Ok(tid) = tid.parse::<i64>() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let texture = match database
        .texture_info(&state.config.database.table_prefix, tid)
        .await
    {
        Ok(Some(texture)) => texture,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, tid, "failed to load legacy texture details");
            return unavailable();
        }
    };
    let session_user_id = session_user_id(&state, &headers);
    let (user_id, is_admin) = match session_user_id {
        Some(user_id) => match database
            .user_profile(&state.config.database.table_prefix, user_id)
            .await
        {
            Ok(Some(user)) => (Some(user_id), user.permission >= 1),
            Ok(None) => (None, false),
            Err(error) => {
                tracing::error!(%error, "failed to load texture viewer");
                return unavailable();
            }
        },
        None => (None, false),
    };
    if !texture.is_public && user_id != Some(texture.uploader) && !is_admin {
        let status_code = match database
            .option(
                &state.config.database.table_prefix,
                "status_code_for_private",
            )
            .await
        {
            Ok(value) => value.and_then(|value| value.parse::<u16>().ok()),
            Err(error) => {
                tracing::error!(%error, "failed to read private texture status option");
                return unavailable();
            }
        };
        let status = status_code
            .and_then(|code| StatusCode::from_u16(code).ok())
            .unwrap_or(StatusCode::FORBIDDEN);
        let message = if state.config.locale.starts_with("zh") {
            if status == StatusCode::NOT_FOUND {
                "请求的材质文件已经被删除"
            } else {
                "请求的材质已经设为私密，仅上传者和管理员可查看"
            }
        } else if status == StatusCode::NOT_FOUND {
            "The requested texture was already deleted."
        } else {
            "The requested texture is private and only visible to the uploader and admins."
        };
        return (status, message).into_response();
    }
    Json(texture_info_json(texture)).into_response()
}

fn texture_info_json(texture: TextureInfoRecord) -> serde_json::Value {
    serde_json::json!({
        "tid": texture.tid,
        "name": texture.name,
        "type": texture.texture_type,
        "hash": texture.hash,
        "size": texture.size,
        "uploader": texture.uploader,
        "public": texture.is_public,
        "upload_at": texture.upload_at,
        "likes": texture.likes,
    })
}

async fn authenticated_web_user(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<UserProfile, Response> {
    let database = state.database.as_ref().ok_or_else(unavailable)?;
    let user_id = session_user_id(state, headers).ok_or_else(unauthenticated)?;
    let user = match database
        .user_profile(&state.config.database.table_prefix, user_id)
        .await
    {
        Ok(Some(user)) => user,
        Ok(None) => return Err(unauthenticated()),
        Err(error) => {
            tracing::error!(%error, "failed to load authenticated web user");
            return Err(unavailable());
        }
    };
    if user.permission == -1 {
        let message = if state.config.locale.starts_with("zh") {
            "你已被本站封禁，详情请联系站点管理员"
        } else {
            "You are banned on this site. Please contact the admin."
        };
        let mut response = login_result(-1, message, None);
        *response.status_mut() = StatusCode::FORBIDDEN;
        return Err(response);
    }
    if user.email.is_empty() {
        return Err(Redirect::to("/auth/bind").into_response());
    }
    match database
        .option(&state.config.database.table_prefix, "require_verification")
        .await
    {
        Ok(value) if legacy_option_bool(value.as_deref()) && !user.verified => {
            let message = if state.config.locale.starts_with("zh") {
                "你必须验证邮箱后才能访问此页面"
            } else {
                "To access this page, you should verify your email address first."
            };
            return Err((
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({ "message": message })),
            )
                .into_response());
        }
        Ok(_) => {}
        Err(error) => {
            tracing::error!(%error, "failed to read email verification option");
            return Err(unavailable());
        }
    }
    Ok(user)
}

fn parse_legacy_form_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "(true)" => Some(true),
        "0" | "false" | "(false)" => Some(false),
        _ => None,
    }
}

fn upload_validation_error(field: &str, locale: &str) -> Response {
    let chinese = locale.starts_with("zh");
    let message = if chinese {
        "给定数据无效。"
    } else {
        "The given data was invalid."
    };
    let field_error = match (field, chinese) {
        ("name", true) => "材质名称为必填项且必须符合本站规则。",
        ("name", false) => "The name field is required or does not match the configured rule.",
        ("file", true) => "必须上传有效的 PNG 文件，且不能超过大小限制。",
        ("file", false) => "The file must be a valid PNG and within the size limit.",
        ("type", true) => "type 字段必须为 steve、alex 或 cape。",
        ("type", false) => "The type field must be steve, alex, or cape.",
        ("public", true) => "public 字段必须是布尔值。",
        ("public", false) => "The public field must be true or false.",
        _ => "The given field is invalid.",
    };
    let mut errors = serde_json::Map::new();
    errors.insert(field.to_owned(), serde_json::json!([field_error]));
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(serde_json::json!({ "message": message, "errors": errors })),
    )
        .into_response()
}

fn png_dimensions(bytes: &[u8]) -> Option<(u32, u32)> {
    let reader = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .ok()?;
    if reader.format() != Some(ImageFormat::Png) {
        return None;
    }
    reader.into_dimensions().ok()
}

fn sanitize_png(bytes: &[u8]) -> Result<Vec<u8>, image::ImageError> {
    let image = image::load_from_memory_with_format(bytes, ImageFormat::Png)?;
    let mut sanitized = Vec::new();
    image.write_to(&mut Cursor::new(&mut sanitized), ImageFormat::Png)?;
    Ok(sanitized)
}

fn valid_texture_dimensions(texture_type: &str, width: u32, height: u32) -> bool {
    width > 0
        && height > 0
        && width % 64 == 0
        && height % 32 == 0
        && match texture_type {
            "steve" => width == height || width == height.saturating_mul(2),
            "alex" => width == height,
            "cape" => width == height.saturating_mul(2),
            _ => false,
        }
}

fn upload_size_error(locale: &str, texture_type: &str, width: u32, height: u32) -> Response {
    let message = if locale.starts_with("zh") {
        let label = if texture_type == "cape" {
            "披风"
        } else {
            "皮肤"
        };
        format!("不是有效的 {label} 文件（宽 {width}，高 {height}）")
    } else {
        let label = if texture_type == "cape" {
            "cape"
        } else {
            "skin"
        };
        format!("Invalid {label} file (width {width}, height {height}).")
    };
    login_result(1, &message, None)
}
async fn upload_texture(
    State(state): State<AppState>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    let Some(database) = &state.database else {
        return unavailable();
    };
    let reporter = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let mut name = None;
    let mut texture_type = None;
    let mut public = None;
    let mut file_bytes = None;
    loop {
        let field = match multipart.next_field().await {
            Ok(Some(field)) => field,
            Ok(None) => break,
            Err(error) => {
                tracing::warn!(%error, "invalid texture upload multipart body");
                return upload_validation_error("file", &state.config.locale);
            }
        };
        let Some(field_name) = field.name().map(str::to_owned) else {
            continue;
        };
        let bytes = match field.bytes().await {
            Ok(bytes) => bytes,
            Err(error) => {
                tracing::warn!(%error, field = field_name, "failed to read texture upload field");
                return upload_validation_error(&field_name, &state.config.locale);
            }
        };
        if field_name == "file" {
            file_bytes = Some(bytes.to_vec());
            continue;
        }
        let Ok(value) = String::from_utf8(bytes.to_vec()) else {
            return upload_validation_error(&field_name, &state.config.locale);
        };
        match field_name.as_str() {
            "name" => name = Some(value),
            "type" => texture_type = Some(value),
            "public" => public = Some(value),
            _ => {}
        }
    }
    let Some(name) = name
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
    else {
        return upload_validation_error("name", &state.config.locale);
    };
    let Some(file_bytes) = file_bytes.filter(|bytes: &Vec<u8>| !bytes.is_empty()) else {
        return upload_validation_error("file", &state.config.locale);
    };
    let Some(texture_type) = texture_type else {
        return upload_validation_error("type", &state.config.locale);
    };
    if !valid_texture_type(&texture_type) {
        return upload_validation_error("type", &state.config.locale);
    }
    let Some(is_public) = public.as_deref().and_then(parse_legacy_form_bool) else {
        return upload_validation_error("public", &state.config.locale);
    };
    let name_rule = match database
        .option(&state.config.database.table_prefix, "texture_name_regexp")
        .await
    {
        Ok(value) => value.unwrap_or_default(),
        Err(error) => {
            tracing::error!(%error, "failed to read texture name validation rule");
            return unavailable();
        }
    };
    if !name_rule.is_empty() {
        if RegexBuilder::new(&name_rule).build().is_err() {
            tracing::error!("invalid legacy texture name validation regex");
            return unavailable();
        }
        if !valid_texture_name(&name, &name_rule) {
            return upload_validation_error("name", &state.config.locale);
        }
    }
    let max_upload_kb = match database
        .option(&state.config.database.table_prefix, "max_upload_file_size")
        .await
    {
        Ok(value) => value
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(1024)
            .max(0),
        Err(error) => {
            tracing::error!(%error, "failed to read maximum texture upload size");
            return unavailable();
        }
    };
    if file_bytes.len() as u64 > max_upload_kb.saturating_mul(1024) as u64 {
        return upload_validation_error("file", &state.config.locale);
    }
    let Some((width, height)) = png_dimensions(&file_bytes) else {
        return upload_validation_error("file", &state.config.locale);
    };
    let max_width = match database
        .option(&state.config.database.table_prefix, "max_texture_width")
        .await
    {
        Ok(value) => value
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(8192),
        Err(error) => {
            tracing::error!(%error, "failed to read maximum texture width");
            return unavailable();
        }
    };
    if width > max_width {
        let message = if state.config.locale.starts_with("zh") {
            format!("材质过宽（{width}px），本站允许的最大宽度为 {max_width}px")
        } else {
            format!("The texture is too wide ({width}px). Maximum width allowed is {max_width}px")
        };
        return login_result(1, &message, None);
    }
    if !valid_texture_dimensions(&texture_type, width, height) {
        return upload_size_error(&state.config.locale, &texture_type, width, height);
    }
    let sanitized = match sanitize_png(&file_bytes) {
        Ok(sanitized) => sanitized,
        Err(error) => {
            tracing::warn!(%error, "failed to decode uploaded PNG texture");
            return upload_validation_error("file", &state.config.locale);
        }
    };
    let hash = Sha256::digest(&sanitized)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let size_kb = ((sanitized.len() as i64).saturating_add(1023) / 1024).max(1);
    let public_cost_per_kb = match database
        .option(&state.config.database.table_prefix, "score_per_storage")
        .await
    {
        Ok(value) => value
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(0),
        Err(error) => {
            tracing::error!(%error, "failed to read public texture storage score");
            return unavailable();
        }
    };
    let private_cost_per_kb = match database
        .option(
            &state.config.database.table_prefix,
            "private_score_per_storage",
        )
        .await
    {
        Ok(value) => value
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(10),
        Err(error) => {
            tracing::error!(%error, "failed to read private texture storage score");
            return unavailable();
        }
    };
    let closet_cost = match database
        .option(&state.config.database.table_prefix, "score_per_closet_item")
        .await
    {
        Ok(value) => value
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(0),
        Err(error) => {
            tracing::error!(%error, "failed to read closet item score");
            return unavailable();
        }
    };
    let award = match database
        .option(
            &state.config.database.table_prefix,
            "score_award_per_texture",
        )
        .await
    {
        Ok(value) => value
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(0),
        Err(error) => {
            tracing::error!(%error, "failed to read texture upload award");
            return unavailable();
        }
    };
    let storage_cost = if is_public {
        public_cost_per_kb
    } else {
        private_cost_per_kb
    };
    let score_cost = size_kb
        .saturating_mul(storage_cost)
        .saturating_add(closet_cost)
        .saturating_sub(award);
    if reporter.score < score_cost {
        return login_result(
            1,
            if state.config.locale.starts_with("zh") {
                "积分不足"
            } else {
                "You don't have enough score to upload this texture."
            },
            None,
        );
    }
    let file_path = state.config.textures_dir.join(&hash);
    let file_was_missing = match tokio::fs::metadata(&file_path).await {
        Ok(_) => false,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
        Err(error) => {
            tracing::error!(%error, hash, "failed to inspect texture file");
            return unavailable();
        }
    };
    if file_was_missing {
        if let Err(error) = tokio::fs::create_dir_all(&state.config.textures_dir).await {
            tracing::error!(%error, "failed to create texture storage directory");
            return unavailable();
        }
        if let Err(error) = tokio::fs::write(&file_path, &sanitized).await {
            tracing::error!(%error, hash, "failed to store sanitized texture file");
            return unavailable();
        }
    }
    match database
        .upload_texture(
            &state.config.database.table_prefix,
            &name,
            &texture_type,
            &hash,
            size_kb,
            reporter.uid,
            is_public,
            score_cost,
        )
        .await
    {
        Ok(crate::database::TextureUploadOutcome::Uploaded(tid)) => {
            let message = if state.config.locale.starts_with("zh") {
                format!("材质 {name} 上传成功")
            } else {
                format!("Texture {name} was uploaded successfully.")
            };
            login_result(0, &message, Some(serde_json::json!({ "tid": tid })))
        }
        Ok(crate::database::TextureUploadOutcome::AlreadyUploaded(tid)) => login_result(
            2,
            if state.config.locale.starts_with("zh") {
                "已经有人上传过这个材质了，直接添加到衣柜使用吧~"
            } else {
                "The texture is already uploaded by someone else. You can add it to your closet directly."
            },
            Some(serde_json::json!({ "tid": tid })),
        ),
        Ok(crate::database::TextureUploadOutcome::InsufficientScore) => {
            cleanup_unreferenced_upload(&state, database, &hash, file_was_missing).await;
            login_result(
                1,
                if state.config.locale.starts_with("zh") {
                    "积分不足"
                } else {
                    "You don't have enough score to upload this texture."
                },
                None,
            )
        }
        Err(error) => {
            tracing::error!(%error, hash, "failed to create uploaded texture record");
            cleanup_unreferenced_upload(&state, database, &hash, file_was_missing).await;
            unavailable()
        }
    }
}

async fn cleanup_unreferenced_upload(
    state: &AppState,
    database: &DatabasePool,
    hash: &str,
    file_was_missing: bool,
) {
    if !file_was_missing {
        return;
    }
    match database
        .texture_hash_reference_count(&state.config.database.table_prefix, hash)
        .await
    {
        Ok(0) => {
            if let Err(error) = tokio::fs::remove_file(state.config.textures_dir.join(hash)).await {
                if error.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(%error, hash, "failed to clean an unreferenced upload file");
                }
            }
        }
        Ok(_) => {}
        Err(error) => tracing::warn!(%error, hash, "failed to check uploaded texture references"),
    }
}

async fn texture_mutation_context(
    state: &AppState,
    headers: &HeaderMap,
    tid_path: &str,
) -> Result<(i64, TextureInfoRecord), Response> {
    let database = state.database.as_ref().ok_or_else(unavailable)?;
    let user = authenticated_web_user(state, headers).await?;
    let tid = tid_path
        .parse::<i64>()
        .map_err(|_| StatusCode::NOT_FOUND.into_response())?;
    let texture = match database
        .texture_info(&state.config.database.table_prefix, tid)
        .await
    {
        Ok(Some(texture)) => texture,
        Ok(None) => return Err(StatusCode::NOT_FOUND.into_response()),
        Err(error) => {
            tracing::error!(%error, tid, "failed to load texture for mutation");
            return Err(unavailable());
        }
    };
    if texture.uploader != user.uid && user.permission < 1 {
        let message = if state.config.locale.starts_with("zh") {
            "你没有权限修改此材质"
        } else {
            "You have no permission to moderate this texture."
        };
        let mut response = login_result(1, message, None);
        *response.status_mut() = StatusCode::FORBIDDEN;
        return Err(response);
    }
    Ok((tid, texture))
}
async fn submit_skinlib_report(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<serde_json::Value>,
) -> Response {
    let Some(database) = &state.database else {
        return unavailable();
    };
    let reporter = match authenticated_web_user(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Some(tid) = texture_id_from_request(request.get("tid")) else {
        return report_validation_error("tid", &state.config.locale);
    };
    let Some(reason) = request.get("reason").and_then(serde_json::Value::as_str) else {
        return report_validation_error("reason", &state.config.locale);
    };
    let reason = reason.trim();
    if reason.is_empty() {
        return report_validation_error("reason", &state.config.locale);
    }
    let texture = match database
        .texture_info(&state.config.database.table_prefix, tid)
        .await
    {
        Ok(Some(texture)) => texture,
        Ok(None) => return report_validation_error("tid", &state.config.locale),
        Err(error) => {
            tracing::error!(%error, tid, "failed to load reported texture");
            return unavailable();
        }
    };
    let score_modification = match database
        .option(
            &state.config.database.table_prefix,
            "reporter_score_modification",
        )
        .await
    {
        Ok(value) => value
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(0),
        Err(error) => {
            tracing::error!(%error, "failed to read report score option");
            return unavailable();
        }
    };
    match database
        .submit_report(
            &state.config.database.table_prefix,
            tid,
            texture.uploader,
            reporter.uid,
            reason,
            score_modification,
        )
        .await
    {
        Ok(crate::database::ReportSubmissionOutcome::Submitted) => login_result(
            0,
            if state.config.locale.starts_with("zh") {
                "举报已提交，请等待管理员处理"
            } else {
                "Thanks for reporting! The administrators will review it as soon as possible."
            },
            None,
        ),
        Ok(crate::database::ReportSubmissionOutcome::AlreadyReported) => login_result(
            1,
            if state.config.locale.starts_with("zh") {
                "您已经举报过该材质了，请耐心等待管理员处理。您可以在用户中心查看举报的处理进度。"
            } else {
                "You have already reported this texture. The administrators will review it as soon as possible. You can also track the status of your report at User Center."
            },
            None,
        ),
        Ok(crate::database::ReportSubmissionOutcome::InsufficientScore) => login_result(
            1,
            if state.config.locale.starts_with("zh") {
                "积分不足"
            } else {
                "You don't have enough score to upload this texture."
            },
            None,
        ),
        Err(error) => {
            tracing::error!(%error, tid, "failed to submit skin library report");
            unavailable()
        }
    }
}

fn report_validation_error(field: &str, locale: &str) -> Response {
    let chinese = locale.starts_with("zh");
    let message = if chinese {
        "给定数据无效。"
    } else {
        "The given data was invalid."
    };
    let field_error = match (field, chinese) {
        ("tid", true) => "材质编号必须是存在的整数。",
        ("tid", false) => "The tid field must reference an existing texture.",
        ("reason", true) => "举报理由为必填项。",
        ("reason", false) => "The reason field is required.",
        _ => "The given field is invalid.",
    };
    let mut errors = serde_json::Map::new();
    errors.insert(field.to_owned(), serde_json::json!([field_error]));
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(serde_json::json!({ "message": message, "errors": errors })),
    )
        .into_response()
}

fn valid_texture_name(name: &str, rule: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    rule.is_empty()
        || RegexBuilder::new(rule)
            .build()
            .is_ok_and(|regex| regex.is_match(name))
}

fn valid_texture_type(texture_type: &str) -> bool {
    matches!(texture_type, "steve" | "alex" | "cape")
}

async fn rename_texture(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(tid_path): RoutePath<String>,
    Json(request): Json<serde_json::Value>,
) -> Response {
    let (tid, _texture) = match texture_mutation_context(&state, &headers, &tid_path).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let Some(name) = request.get("name").and_then(serde_json::Value::as_str) else {
        return texture_name_validation_error(&state.config.locale);
    };
    let name = name.trim();
    if name.is_empty() {
        return texture_name_validation_error(&state.config.locale);
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    let name_rule = match database
        .option(&state.config.database.table_prefix, "texture_name_regexp")
        .await
    {
        Ok(value) => value.unwrap_or_default(),
        Err(error) => {
            tracing::error!(%error, "failed to read texture name validation rule");
            return unavailable();
        }
    };
    if !name_rule.is_empty() {
        if RegexBuilder::new(&name_rule).build().is_err() {
            tracing::error!("invalid legacy texture name validation regex");
            return unavailable();
        }
        if !valid_texture_name(name, &name_rule) {
            return texture_name_validation_error(&state.config.locale);
        }
    }
    if let Err(error) = database
        .rename_texture(&state.config.database.table_prefix, tid, name)
        .await
    {
        tracing::error!(%error, tid, "failed to rename texture");
        return unavailable();
    }
    let message = if state.config.locale.starts_with("zh") {
        format!("材质名称已被成功设置为 {name}")
    } else {
        format!("The texture was renamed to {name} successfully.")
    };
    login_result(0, &message, None)
}

fn texture_delete_score_refund(
    texture: &TextureInfoRecord,
    return_score: bool,
    public_cost_per_kb: i64,
    private_cost_per_kb: i64,
    public_award: i64,
    take_back_public_award: bool,
) -> i64 {
    let mut refund = if return_score {
        texture.size.saturating_mul(if texture.is_public {
            public_cost_per_kb
        } else {
            private_cost_per_kb
        })
    } else {
        0
    };
    if texture.is_public && take_back_public_award {
        refund = refund.saturating_sub(public_award);
    }
    refund
}

async fn delete_texture(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(tid_path): RoutePath<String>,
) -> Response {
    let (tid, texture) = match texture_mutation_context(&state, &headers, &tid_path).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let return_score = match database
        .option(&state.config.database.table_prefix, "return_score")
        .await
    {
        Ok(value) => value
            .as_deref()
            .map(|value| legacy_option_bool(Some(value)))
            .unwrap_or(true),
        Err(error) => {
            tracing::error!(%error, "failed to read texture deletion score option");
            return unavailable();
        }
    };
    let public_cost_per_kb = match database
        .option(&state.config.database.table_prefix, "score_per_storage")
        .await
    {
        Ok(value) => value
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(0),
        Err(error) => {
            tracing::error!(%error, "failed to read public texture storage score");
            return unavailable();
        }
    };
    let private_cost_per_kb = match database
        .option(
            &state.config.database.table_prefix,
            "private_score_per_storage",
        )
        .await
    {
        Ok(value) => value
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(10),
        Err(error) => {
            tracing::error!(%error, "failed to read private texture storage score");
            return unavailable();
        }
    };
    let public_award = match database
        .option(
            &state.config.database.table_prefix,
            "score_award_per_texture",
        )
        .await
    {
        Ok(value) => value
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(0),
        Err(error) => {
            tracing::error!(%error, "failed to read texture score award");
            return unavailable();
        }
    };
    let take_back_award = match database
        .option(
            &state.config.database.table_prefix,
            "take_back_scores_after_deletion",
        )
        .await
    {
        Ok(value) => value
            .as_deref()
            .map(|value| legacy_option_bool(Some(value)))
            .unwrap_or(true),
        Err(error) => {
            tracing::error!(%error, "failed to read texture score return option");
            return unavailable();
        }
    };
    let closet_score_refund = if return_score {
        match database
            .option(&state.config.database.table_prefix, "score_per_closet_item")
            .await
        {
            Ok(value) => value
                .and_then(|value| value.parse::<i64>().ok())
                .unwrap_or(0),
            Err(error) => {
                tracing::error!(%error, "failed to read closet item score");
                return unavailable();
            }
        }
    } else {
        0
    };
    let uploader_score_refund = texture_delete_score_refund(
        &texture,
        return_score,
        public_cost_per_kb,
        private_cost_per_kb,
        public_award,
        take_back_award,
    );
    let remove_texture_file = match database
        .delete_texture(
            &state.config.database.table_prefix,
            &texture,
            uploader_score_refund,
            closet_score_refund,
        )
        .await
    {
        Ok(remove_texture_file) => remove_texture_file,
        Err(error) => {
            tracing::error!(%error, tid, "failed to delete legacy texture row");
            return unavailable();
        }
    };
    if remove_texture_file && valid_texture_hash(&texture.hash) {
        let path = state.config.textures_dir.join(&texture.hash);
        if let Err(error) = tokio::fs::remove_file(path).await {
            if error.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(%error, hash = texture.hash, "failed to remove texture file");
            }
        }
    }
    login_result(
        0,
        if state.config.locale.starts_with("zh") {
            "材质已被成功删除"
        } else {
            "The texture was deleted successfully."
        },
        None,
    )
}

fn texture_privacy_score_diff(
    texture: &TextureInfoRecord,
    public_cost_per_kb: i64,
    private_cost_per_kb: i64,
    public_award: i64,
    take_back_public_award: bool,
) -> i64 {
    let cost_difference = texture
        .size
        .saturating_mul(private_cost_per_kb.saturating_sub(public_cost_per_kb));
    let mut score_diff = if texture.is_public {
        cost_difference.saturating_neg()
    } else {
        cost_difference
    };
    if texture.is_public && take_back_public_award {
        score_diff = score_diff.saturating_sub(public_award);
    }
    score_diff
}

async fn toggle_texture_privacy(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(tid_path): RoutePath<String>,
) -> Response {
    let (tid, texture) = match texture_mutation_context(&state, &headers, &tid_path).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let public_cost_per_kb = match database
        .option(&state.config.database.table_prefix, "score_per_storage")
        .await
    {
        Ok(value) => value
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(0),
        Err(error) => {
            tracing::error!(%error, "failed to read public texture storage score");
            return unavailable();
        }
    };
    let private_cost_per_kb = match database
        .option(
            &state.config.database.table_prefix,
            "private_score_per_storage",
        )
        .await
    {
        Ok(value) => value
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(10),
        Err(error) => {
            tracing::error!(%error, "failed to read private texture storage score");
            return unavailable();
        }
    };
    let public_award = match database
        .option(
            &state.config.database.table_prefix,
            "score_award_per_texture",
        )
        .await
    {
        Ok(value) => value
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(0),
        Err(error) => {
            tracing::error!(%error, "failed to read texture score award");
            return unavailable();
        }
    };
    let take_back_award = match database
        .option(
            &state.config.database.table_prefix,
            "take_back_scores_after_deletion",
        )
        .await
    {
        Ok(value) => value
            .as_deref()
            .map(|value| legacy_option_bool(Some(value)))
            .unwrap_or(true),
        Err(error) => {
            tracing::error!(%error, "failed to read texture score return option");
            return unavailable();
        }
    };
    let score_diff = texture_privacy_score_diff(
        &texture,
        public_cost_per_kb,
        private_cost_per_kb,
        public_award,
        take_back_award,
    );
    match database
        .toggle_texture_privacy(
            &state.config.database.table_prefix,
            tid,
            texture.uploader,
            &texture.hash,
            texture.is_public,
            score_diff,
        )
        .await
    {
        Ok(crate::database::TexturePrivacyOutcome::Updated { is_public }) => {
            let privacy = if state.config.locale.starts_with("zh") {
                if is_public { "公开" } else { "私密" }
            } else if is_public {
                "Public"
            } else {
                "Private"
            };
            let message = if state.config.locale.starts_with("zh") {
                format!("材质已被设为 {privacy}")
            } else {
                format!("The texture was set to {privacy} successfully.")
            };
            login_result(0, &message, None)
        }
        Ok(crate::database::TexturePrivacyOutcome::DuplicatePublicTexture(duplicate_tid)) => {
            let message = if state.config.locale.starts_with("zh") {
                "已经有人上传过这个材质了，直接添加到衣柜使用吧~"
            } else {
                "The texture is already uploaded by someone else. You can add it to your closet directly."
            };
            login_result(
                2,
                message,
                Some(serde_json::json!({ "tid": duplicate_tid })),
            )
        }
        Ok(crate::database::TexturePrivacyOutcome::InsufficientScore) => login_result(
            1,
            if state.config.locale.starts_with("zh") {
                "积分不足"
            } else {
                "You don't have enough score to upload this texture."
            },
            None,
        ),
        Err(error) => {
            tracing::error!(%error, tid, "failed to update texture privacy");
            unavailable()
        }
    }
}

async fn update_texture_type(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(tid_path): RoutePath<String>,
    Json(request): Json<serde_json::Value>,
) -> Response {
    let (tid, _texture) = match texture_mutation_context(&state, &headers, &tid_path).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let Some(texture_type) = request.get("type").and_then(serde_json::Value::as_str) else {
        return texture_type_validation_error(&state.config.locale);
    };
    if !valid_texture_type(texture_type) {
        return texture_type_validation_error(&state.config.locale);
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    if let Err(error) = database
        .set_texture_type(&state.config.database.table_prefix, tid, texture_type)
        .await
    {
        tracing::error!(%error, tid, "failed to update texture type");
        return unavailable();
    }
    let message = if state.config.locale.starts_with("zh") {
        format!("材质的适用模型已被修改为 {texture_type}")
    } else {
        format!("The texture's model was changed to {texture_type} successfully.")
    };
    login_result(0, &message, None)
}

fn texture_name_validation_error(locale: &str) -> Response {
    let (message, field_error) = if locale.starts_with("zh") {
        ("给定数据无效。", "材质名称为必填项或不符合本站规则。")
    } else {
        (
            "The given data was invalid.",
            "The name field is required or does not match the configured rule.",
        )
    };
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(serde_json::json!({
            "message": message,
            "errors": { "name": [field_error] }
        })),
    )
        .into_response()
}

fn texture_type_validation_error(locale: &str) -> Response {
    let (message, field_error) = if locale.starts_with("zh") {
        ("给定数据无效。", "type 字段必须为 steve、alex 或 cape。")
    } else {
        (
            "The given data was invalid.",
            "The type field must be steve, alex, or cape.",
        )
    };
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(serde_json::json!({
            "message": message,
            "errors": { "type": [field_error] }
        })),
    )
        .into_response()
}
#[derive(Deserialize)]
struct SkinLibraryQuery {
    filter: Option<String>,
    keyword: Option<String>,
    uploader: Option<String>,
    sort: Option<String>,
    page: Option<i64>,
}

async fn skinlib_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SkinLibraryQuery>,
) -> Response {
    let Some(database) = &state.database else {
        return unavailable();
    };
    let session_user_id = session_user_id(&state, &headers);
    let (user_id, is_admin) = match session_user_id {
        Some(user_id) => match database
            .user_profile(&state.config.database.table_prefix, user_id)
            .await
        {
            Ok(Some(user)) => (Some(user_id), user.permission >= 1),
            Ok(None) => (None, false),
            Err(error) => {
                tracing::error!(%error, "failed to load skin library viewer");
                return unavailable();
            }
        },
        None => (None, false),
    };
    let filter = query.filter.as_deref().unwrap_or("skin");
    let keyword = query
        .keyword
        .as_deref()
        .filter(|value| !value.is_empty() && *value != "0");
    let uploader = query
        .uploader
        .as_deref()
        .filter(|value| !value.is_empty() && *value != "0")
        .and_then(|value| value.parse::<i64>().ok());
    let sort = query.sort.as_deref().unwrap_or("time");
    let page = query.page.unwrap_or(1).max(1);
    let per_page = 20_i64;
    match database
        .skinlib_items(
            &state.config.database.table_prefix,
            user_id,
            is_admin,
            filter,
            keyword,
            uploader,
            sort,
            page,
            per_page,
        )
        .await
    {
        Ok((items, total)) => {
            let data = items
                .into_iter()
                .map(skin_library_item_json)
                .collect::<Vec<_>>();
            let last_page = total.saturating_add(per_page - 1) / per_page;
            let offset = page.saturating_sub(1).saturating_mul(per_page);
            let from = (!data.is_empty()).then_some(offset + 1);
            let to = (!data.is_empty()).then_some(offset + data.len() as i64);
            Json(serde_json::json!({
                "current_page": page,
                "data": data,
                "last_page": last_page.max(1),
                "per_page": per_page,
                "from": from,
                "to": to,
                "total": total
            }))
            .into_response()
        }
        Err(error) => {
            tracing::error!(%error, "failed to query the skin library");
            unavailable()
        }
    }
}

fn skin_library_item_json(item: crate::database::SkinLibraryRecord) -> serde_json::Value {
    serde_json::json!({
        "tid": item.tid,
        "name": item.name,
        "type": item.texture_type,
        "uploader": item.uploader,
        "public": item.is_public,
        "likes": item.likes,
        "nickname": item.nickname,
    })
}

#[derive(Clone, Copy)]
enum AdminUserMutation {
    Email,
    Verification,
    Nickname,
    Password,
    Score,
    Permission,
    Delete,
}

macro_rules! define_admin_user_mutation_handlers {
    ($(($web:ident, $api:ident, $kind:ident)),+ $(,)?) => {
        $(
            async fn $web(
                State(state): State<AppState>,
                headers: HeaderMap,
                RoutePath(uid): RoutePath<i64>,
                body: Bytes,
            ) -> Response {
                web_admin_user_mutation(state, headers, uid, body, AdminUserMutation::$kind).await
            }

            async fn $api(
                State(state): State<AppState>,
                headers: HeaderMap,
                RoutePath(uid): RoutePath<i64>,
                body: Bytes,
            ) -> Response {
                api_admin_user_mutation(state, headers, uid, body, AdminUserMutation::$kind).await
            }
        )+
    };
}

define_admin_user_mutation_handlers!(
    (web_admin_user_email, api_admin_user_email, Email),
    (
        web_admin_user_verification,
        api_admin_user_verification,
        Verification
    ),
    (web_admin_user_nickname, api_admin_user_nickname, Nickname),
    (web_admin_user_password, api_admin_user_password, Password),
    (web_admin_user_score, api_admin_user_score, Score),
    (
        web_admin_user_permission,
        api_admin_user_permission,
        Permission
    ),
    (web_admin_user_delete, api_admin_user_delete, Delete),
);

async fn web_admin_user_mutation(
    state: AppState,
    headers: HeaderMap,
    target_uid: i64,
    body: Bytes,
    mutation: AdminUserMutation,
) -> Response {
    let Some(actor_uid) = session_user_id(&state, &headers) else {
        return Redirect::to("/auth/login").into_response();
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let actor = match database
        .user_profile(&state.config.database.table_prefix, actor_uid)
        .await
    {
        Ok(Some(user)) if user.permission >= 1 => user,
        Ok(Some(_)) => return forbidden_action(),
        Ok(None) => return Redirect::to("/auth/login").into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to load user administrator");
            return unavailable();
        }
    };
    apply_admin_user_mutation(
        &state,
        actor.uid,
        actor.permission,
        target_uid,
        &body,
        mutation,
    )
    .await
}

async fn api_admin_user_mutation(
    state: AppState,
    headers: HeaderMap,
    target_uid: i64,
    body: Bytes,
    mutation: AdminUserMutation,
) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_scope("UsersManagement.ReadWrite") {
        return missing_scope();
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    let actor = match database
        .user_profile(&state.config.database.table_prefix, identity.user_id)
        .await
    {
        Ok(Some(user)) if user.permission >= 1 => user,
        Ok(Some(_)) | Ok(None) => return forbidden_action(),
        Err(error) => {
            tracing::error!(%error, "failed to load API user administrator");
            return unavailable();
        }
    };
    apply_admin_user_mutation(
        &state,
        actor.uid,
        actor.permission,
        target_uid,
        &body,
        mutation,
    )
    .await
}

async fn apply_admin_user_mutation(
    state: &AppState,
    actor_uid: i64,
    actor_permission: i32,
    target_uid: i64,
    body: &[u8],
    mutation: AdminUserMutation,
) -> Response {
    let Some(database) = &state.database else {
        return unavailable();
    };
    let target = match database
        .user_profile(&state.config.database.table_prefix, target_uid)
        .await
    {
        Ok(Some(user)) => user,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, target_uid, "failed to load managed user");
            return unavailable();
        }
    };
    if target.uid != actor_uid && target.permission >= actor_permission {
        return admin_user_permission_error(&state.config.locale);
    }

    match mutation {
        AdminUserMutation::Email => {
            let request = serde_json::from_slice::<serde_json::Value>(body).ok();
            let Some(email) = request
                .as_ref()
                .and_then(|value| value.get("email"))
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
            else {
                return admin_user_validation_error("email", "required", &state.config.locale);
            };
            if !valid_email_address(email) {
                return admin_user_validation_error("email", "email", &state.config.locale);
            }
            match database
                .user_email_exists(&state.config.database.table_prefix, email, target_uid)
                .await
            {
                Ok(true) => {
                    return admin_user_validation_error("email", "unique", &state.config.locale);
                }
                Ok(false) => {}
                Err(error) => {
                    tracing::error!(%error, target_uid, "failed to check user email uniqueness");
                    return unavailable();
                }
            }
            if let Err(error) = database
                .update_user_text(
                    &state.config.database.table_prefix,
                    target_uid,
                    "email",
                    email,
                )
                .await
            {
                tracing::error!(%error, target_uid, "failed to update user email");
                return unavailable();
            }
            admin_user_success(AdminUserMutation::Email, &state.config.locale, None)
        }
        AdminUserMutation::Verification => {
            if let Err(error) = database
                .toggle_user_verification(&state.config.database.table_prefix, target_uid)
                .await
            {
                tracing::error!(%error, target_uid, "failed to toggle user verification");
                return unavailable();
            }
            admin_user_success(AdminUserMutation::Verification, &state.config.locale, None)
        }
        AdminUserMutation::Nickname => {
            let request = serde_json::from_slice::<serde_json::Value>(body).ok();
            let Some(nickname) = request
                .as_ref()
                .and_then(|value| value.get("nickname"))
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
            else {
                return admin_user_validation_error("nickname", "required", &state.config.locale);
            };
            if let Err(error) = database
                .update_user_text(
                    &state.config.database.table_prefix,
                    target_uid,
                    "nickname",
                    nickname,
                )
                .await
            {
                tracing::error!(%error, target_uid, "failed to update user nickname");
                return unavailable();
            }
            admin_user_success(
                AdminUserMutation::Nickname,
                &state.config.locale,
                Some(nickname),
            )
        }
        AdminUserMutation::Password => {
            let request = serde_json::from_slice::<serde_json::Value>(body).ok();
            let Some(password) = request
                .as_ref()
                .and_then(|value| value.get("password"))
                .and_then(serde_json::Value::as_str)
            else {
                return admin_user_validation_error("password", "required", &state.config.locale);
            };
            if !(8..=16).contains(&password.chars().count()) {
                return admin_user_validation_error("password", "length", &state.config.locale);
            }
            let Some(hash) = hash_legacy_password(
                password,
                &state.config.password_method,
                &state.config.password_salt,
            ) else {
                tracing::error!(method = %state.config.password_method, "unsupported configured legacy password method");
                return unavailable();
            };
            if let Err(error) = database
                .update_user_text(
                    &state.config.database.table_prefix,
                    target_uid,
                    "password",
                    &hash,
                )
                .await
            {
                tracing::error!(%error, target_uid, "failed to update user password");
                return unavailable();
            }
            admin_user_success(AdminUserMutation::Password, &state.config.locale, None)
        }
        AdminUserMutation::Score => {
            let request = serde_json::from_slice::<serde_json::Value>(body).ok();
            let Some(score) = request
                .as_ref()
                .and_then(|value| value.get("score"))
                .and_then(|value| request_i64(Some(value)))
            else {
                return admin_user_validation_error("score", "integer", &state.config.locale);
            };
            if let Err(error) = database
                .update_user_integer(
                    &state.config.database.table_prefix,
                    target_uid,
                    "score",
                    score,
                )
                .await
            {
                tracing::error!(%error, target_uid, "failed to update user score");
                return unavailable();
            }
            admin_user_success(AdminUserMutation::Score, &state.config.locale, None)
        }
        AdminUserMutation::Permission => {
            let request = serde_json::from_slice::<serde_json::Value>(body).ok();
            let Some(permission) = request
                .as_ref()
                .and_then(|value| value.get("permission"))
                .and_then(|value| request_i64(Some(value)))
                .filter(|value| matches!(*value, -1 | 0 | 1))
            else {
                return admin_user_validation_error("permission", "in", &state.config.locale);
            };
            if target_uid == actor_uid || (permission == 1 && actor_permission < 2) {
                return admin_user_permission_error(&state.config.locale);
            }
            if let Err(error) = database
                .update_user_integer(
                    &state.config.database.table_prefix,
                    target_uid,
                    "permission",
                    permission,
                )
                .await
            {
                tracing::error!(%error, target_uid, "failed to update user permission");
                return unavailable();
            }
            admin_user_success(AdminUserMutation::Permission, &state.config.locale, None)
        }
        AdminUserMutation::Delete => match database
            .delete_user(&state.config.database.table_prefix, target_uid)
            .await
        {
            Ok(true) => admin_user_success(AdminUserMutation::Delete, &state.config.locale, None),
            Ok(false) => StatusCode::NOT_FOUND.into_response(),
            Err(error) => {
                tracing::error!(%error, target_uid, "failed to delete user");
                unavailable()
            }
        },
    }
}

fn admin_user_success(mutation: AdminUserMutation, locale: &str, value: Option<&str>) -> Response {
    let chinese = locale.starts_with("zh");
    let message = match (mutation, chinese) {
        (AdminUserMutation::Email, true) => "邮箱修改成功".to_owned(),
        (AdminUserMutation::Email, false) => "Email changed successfully.".to_owned(),
        (AdminUserMutation::Verification, true) => "用户的邮箱验证状态已修改".to_owned(),
        (AdminUserMutation::Verification, false) => {
            "Account verification status toggled successfully.".to_owned()
        }
        (AdminUserMutation::Nickname, true) => {
            format!("昵称已成功设置为 {}", value.unwrap_or_default())
        }
        (AdminUserMutation::Nickname, false) => "Nickname changed successfully.".to_owned(),
        (AdminUserMutation::Password, true) => "密码修改成功".to_owned(),
        (AdminUserMutation::Password, false) => "Password changed successfully.".to_owned(),
        (AdminUserMutation::Score, true) => "积分修改成功".to_owned(),
        (AdminUserMutation::Score, false) => "Score changed successfully.".to_owned(),
        (AdminUserMutation::Permission, true) => "权限已更改".to_owned(),
        (AdminUserMutation::Permission, false) => "Permission updated.".to_owned(),
        (AdminUserMutation::Delete, true) => "账号已被成功删除".to_owned(),
        (AdminUserMutation::Delete, false) => {
            "The account has been deleted successfully.".to_owned()
        }
    };
    login_result(0, &message, None)
}

fn admin_user_permission_error(locale: &str) -> Response {
    let message = if locale.starts_with("zh") {
        "你无权操作此用户"
    } else {
        "You have no permission to operate this user."
    };
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({ "code": 1, "message": message })),
    )
        .into_response()
}

fn admin_user_validation_error(field: &str, rule: &str, locale: &str) -> Response {
    let chinese = locale.starts_with("zh");
    let message = if chinese {
        "给定数据无效。"
    } else {
        "The given data was invalid."
    };
    let field_error = match (field, rule, chinese) {
        ("email", "required", true) => "邮箱为必填项。",
        ("email", "required", false) => "The email field is required.",
        ("email", "email", true) => "邮箱格式无效。",
        ("email", "email", false) => "The email must be a valid email address.",
        ("email", "unique", true) => "该邮箱已被使用。",
        ("email", "unique", false) => "The email has already been taken.",
        ("nickname", "required", true) => "昵称为必填项。",
        ("nickname", "required", false) => "The nickname field is required.",
        ("password", "required", true) => "密码为必填项。",
        ("password", "required", false) => "The password field is required.",
        ("password", "length", true) => "密码长度必须为 8 至 16 个字符。",
        ("password", "length", false) => "The password must be between 8 and 16 characters.",
        ("score", "integer", true) => "积分必须是整数。",
        ("score", "integer", false) => "The score must be an integer.",
        ("permission", "in", true) => "权限值无效。",
        ("permission", "in", false) => "The selected permission is invalid.",
        _ => "The given field is invalid.",
    };
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(serde_json::json!({ "message": message, "errors": { field: [field_error] } })),
    )
        .into_response()
}

#[derive(Deserialize)]
struct AdminPlayerListQuery {
    q: Option<String>,
    page: Option<i64>,
}

#[derive(Deserialize)]
struct AdminUserListQuery {
    q: Option<String>,
    page: Option<i64>,
}

#[derive(Deserialize)]
struct AdminReportListQuery {
    q: Option<String>,
    page: Option<i64>,
}

struct ParsedReportSearch {
    filters: ReportSearchFilters,
    sort_field: String,
    descending: bool,
}

fn parse_report_search(query: Option<&str>) -> ParsedReportSearch {
    let mut parsed = ParsedReportSearch {
        filters: ReportSearchFilters::default(),
        sort_field: "report_at".to_owned(),
        descending: true,
    };
    let mut free_text = Vec::new();
    for token in query.unwrap_or_default().split_whitespace() {
        let Some((field, value)) = token.split_once(':') else {
            free_text.push(token);
            continue;
        };
        match field {
            "sort" => {
                let (descending, field) = value
                    .strip_prefix('-')
                    .map_or((false, value), |field| (true, field));
                if matches!(
                    field,
                    "id" | "tid" | "uploader" | "reporter" | "reason" | "status" | "report_at"
                ) {
                    parsed.sort_field = field.to_owned();
                    parsed.descending = descending;
                }
            }
            "status" => parsed.filters.status = value.parse().ok(),
            "id" => parsed.filters.id = value.parse().ok(),
            "tid" => parsed.filters.tid = value.parse().ok(),
            "uploader" => parsed.filters.uploader = value.parse().ok(),
            "reporter" => parsed.filters.reporter = value.parse().ok(),
            "reason" if !value.is_empty() => free_text.push(value),
            _ => {}
        }
    }
    if !free_text.is_empty() {
        parsed.filters.reason = Some(free_text.join(" "));
    }
    parsed
}

async fn admin_player_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AdminPlayerListQuery>,
) -> Response {
    let Some(user_id) = session_user_id(&state, &headers) else {
        return Redirect::to("/auth/login").into_response();
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    match database
        .user_profile(&state.config.database.table_prefix, user_id)
        .await
    {
        Ok(Some(user)) if user.permission >= 1 => {
            admin_players_response(&state, query, "/admin/players/list").await
        }
        Ok(Some(_)) => forbidden_action(),
        Ok(None) => Redirect::to("/auth/login").into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to load player administrator");
            unavailable()
        }
    }
}

async fn api_admin_player_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AdminPlayerListQuery>,
) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_any_scope(&["PlayersManagement.Read", "PlayersManagement.ReadWrite"]) {
        return missing_scope();
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    match database
        .user_profile(&state.config.database.table_prefix, identity.user_id)
        .await
    {
        Ok(Some(user)) if user.permission >= 1 => {
            admin_players_response(&state, query, "/api/admin/players").await
        }
        Ok(Some(_)) | Ok(None) => forbidden_action(),
        Err(error) => {
            tracing::error!(%error, "failed to load API player administrator");
            unavailable()
        }
    }
}

async fn admin_players_response(
    state: &AppState,
    query: AdminPlayerListQuery,
    path: &str,
) -> Response {
    let Some(database) = &state.database else {
        return unavailable();
    };
    let page = query.page.unwrap_or(1).max(1);
    let per_page = 10_i64;
    let offset = page.saturating_sub(1).saturating_mul(per_page);
    let (players, total) = match database
        .admin_players(
            &state.config.database.table_prefix,
            query.q.as_deref(),
            per_page,
            offset,
        )
        .await
    {
        Ok(result) => result,
        Err(error) => {
            tracing::error!(%error, "failed to list managed players");
            return unavailable();
        }
    };
    let last_page = (total.saturating_add(per_page - 1) / per_page).max(1);
    let first_page_url = admin_users_page_url(path, query.q.as_deref(), 1);
    let last_page_url = admin_users_page_url(path, query.q.as_deref(), last_page);
    let prev_page_url =
        (page > 1).then(|| admin_users_page_url(path, query.q.as_deref(), page - 1));
    let next_page_url =
        (page < last_page).then(|| admin_users_page_url(path, query.q.as_deref(), page + 1));
    let from = (!players.is_empty()).then_some(offset + 1);
    let to = (!players.is_empty()).then_some(offset + players.len() as i64);
    let mut links = vec![
        serde_json::json!({"url": prev_page_url, "label": "&laquo; Previous", "active": false}),
    ];
    for number in 1..=last_page.min(100) {
        links.push(serde_json::json!({
            "url": admin_users_page_url(path, query.q.as_deref(), number),
            "label": number.to_string(),
            "active": number == page
        }));
    }
    links.push(serde_json::json!({"url": next_page_url, "label": "Next &raquo;", "active": false}));
    Json(serde_json::json!({
        "current_page": page,
        "data": players,
        "first_page_url": first_page_url,
        "from": from,
        "last_page": last_page,
        "last_page_url": last_page_url,
        "links": links,
        "next_page_url": next_page_url,
        "path": path,
        "per_page": per_page,
        "prev_page_url": prev_page_url,
        "to": to,
        "total": total
    }))
    .into_response()
}

#[derive(Clone, Copy)]
enum AdminPlayerMutation {
    Name,
    Owner,
    Texture,
    Delete,
}

macro_rules! define_admin_player_mutation_handlers {
    ($(($web:ident, $api:ident, $kind:ident)),+ $(,)?) => {
        $(
            async fn $web(
                State(state): State<AppState>,
                headers: HeaderMap,
                RoutePath(pid): RoutePath<i64>,
                body: Bytes,
            ) -> Response {
                web_admin_player_mutation(state, headers, pid, body, AdminPlayerMutation::$kind).await
            }

            async fn $api(
                State(state): State<AppState>,
                headers: HeaderMap,
                RoutePath(pid): RoutePath<i64>,
                body: Bytes,
            ) -> Response {
                api_admin_player_mutation(state, headers, pid, body, AdminPlayerMutation::$kind).await
            }
        )+
    };
}

define_admin_player_mutation_handlers!(
    (web_admin_player_name, api_admin_player_name, Name),
    (web_admin_player_owner, api_admin_player_owner, Owner),
    (web_admin_player_texture, api_admin_player_texture, Texture),
    (web_admin_player_delete, api_admin_player_delete, Delete),
);

async fn web_admin_player_mutation(
    state: AppState,
    headers: HeaderMap,
    pid: i64,
    body: Bytes,
    mutation: AdminPlayerMutation,
) -> Response {
    let Some(actor_uid) = session_user_id(&state, &headers) else {
        return Redirect::to("/auth/login").into_response();
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let actor = match database
        .user_profile(&state.config.database.table_prefix, actor_uid)
        .await
    {
        Ok(Some(user)) if user.permission >= 1 => user,
        Ok(Some(_)) => return forbidden_action(),
        Ok(None) => return Redirect::to("/auth/login").into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to load player administrator");
            return unavailable();
        }
    };
    apply_admin_player_mutation(&state, actor.uid, actor.permission, pid, &body, mutation).await
}

async fn api_admin_player_mutation(
    state: AppState,
    headers: HeaderMap,
    pid: i64,
    body: Bytes,
    mutation: AdminPlayerMutation,
) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_scope("PlayersManagement.ReadWrite") {
        return missing_scope();
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    let actor = match database
        .user_profile(&state.config.database.table_prefix, identity.user_id)
        .await
    {
        Ok(Some(user)) if user.permission >= 1 => user,
        Ok(Some(_)) | Ok(None) => return forbidden_action(),
        Err(error) => {
            tracing::error!(%error, "failed to load API player administrator");
            return unavailable();
        }
    };
    apply_admin_player_mutation(&state, actor.uid, actor.permission, pid, &body, mutation).await
}

async fn apply_admin_player_mutation(
    state: &AppState,
    actor_uid: i64,
    actor_permission: i32,
    pid: i64,
    body: &[u8],
    mutation: AdminPlayerMutation,
) -> Response {
    let Some(database) = &state.database else {
        return unavailable();
    };
    let prefix = &state.config.database.table_prefix;
    let player = match database.admin_player_for_update(prefix, pid).await {
        Ok(Some(player)) => player,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, pid, "failed to load managed player");
            return unavailable();
        }
    };
    if player.uid != actor_uid && player.owner_permission >= actor_permission {
        return admin_player_permission_error(&state.config.locale);
    }
    match mutation {
        AdminPlayerMutation::Name => {
            let request = serde_json::from_slice::<serde_json::Value>(body).ok();
            let Some(name) = request
                .as_ref()
                .and_then(|value| value.get("player_name"))
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
            else {
                return admin_player_validation_error("player_name", &state.config.locale);
            };
            let min_length = database
                .option(prefix, "player_name_length_min")
                .await
                .ok()
                .flatten()
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(3);
            let max_length = database
                .option(prefix, "player_name_length_max")
                .await
                .ok()
                .flatten()
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(16);
            let rule = database
                .option(prefix, "player_name_rule")
                .await
                .ok()
                .flatten()
                .unwrap_or_else(|| "official".to_owned());
            let custom_rule = database
                .option(prefix, "custom_player_name_regexp")
                .await
                .ok()
                .flatten()
                .unwrap_or_default();
            if !valid_player_name(name, &rule, &custom_rule, min_length, max_length) {
                return admin_player_validation_error("player_name", &state.config.locale);
            }
            match database.admin_player_name_exists(prefix, name).await {
                Ok(true) => {
                    return admin_player_validation_error("player_name", &state.config.locale);
                }
                Ok(false) => {}
                Err(error) => {
                    tracing::error!(%error, pid, "failed to check player-name uniqueness");
                    return unavailable();
                }
            }
            if let Err(error) = database
                .update_admin_player_text(prefix, pid, "name", name)
                .await
            {
                tracing::error!(%error, pid, "failed to rename managed player");
                return unavailable();
            }
            admin_player_success(AdminPlayerMutation::Name, &state.config.locale, name, None)
        }
        AdminPlayerMutation::Owner => {
            let request = serde_json::from_slice::<serde_json::Value>(body).ok();
            let Some(uid) = request
                .as_ref()
                .and_then(|value| value.get("uid"))
                .and_then(|value| request_i64(Some(value)))
            else {
                return admin_player_validation_error("uid", &state.config.locale);
            };
            let owner = match database.user_profile(prefix, uid).await {
                Ok(Some(owner)) => owner,
                Ok(None) => {
                    return login_result(1, admin_user_missing_message(&state.config.locale), None);
                }
                Err(error) => {
                    tracing::error!(%error, uid, "failed to load new player owner");
                    return unavailable();
                }
            };
            if let Err(error) = database
                .update_admin_player_integer(prefix, pid, "uid", uid)
                .await
            {
                tracing::error!(%error, pid, "failed to transfer player ownership");
                return unavailable();
            }
            admin_player_success(
                AdminPlayerMutation::Owner,
                &state.config.locale,
                &player.name,
                Some(&owner.nickname),
            )
        }
        AdminPlayerMutation::Texture => {
            let request = serde_json::from_slice::<serde_json::Value>(body).ok();
            let Some(tid) = request
                .as_ref()
                .and_then(|value| value.get("tid"))
                .and_then(|value| request_i64(Some(value)))
            else {
                return admin_player_validation_error("tid", &state.config.locale);
            };
            let Some(texture_type) = request
                .as_ref()
                .and_then(|value| value.get("type"))
                .and_then(serde_json::Value::as_str)
                .filter(|value| matches!(*value, "skin" | "cape"))
            else {
                return admin_player_validation_error("type", &state.config.locale);
            };
            if tid != 0 {
                match database.texture_info(prefix, tid).await {
                    Ok(Some(_)) => {}
                    Ok(None) => {
                        let message = admin_texture_missing_message(tid, &state.config.locale);
                        return login_result(1, &message, None);
                    }
                    Err(error) => {
                        tracing::error!(%error, tid, "failed to check managed texture");
                        return unavailable();
                    }
                }
            }
            let column = if texture_type == "skin" {
                "tid_skin"
            } else {
                "tid_cape"
            };
            if let Err(error) = database
                .update_admin_player_integer(prefix, pid, column, tid)
                .await
            {
                tracing::error!(%error, pid, "failed to update managed player texture");
                return unavailable();
            }
            admin_player_success(
                AdminPlayerMutation::Texture,
                &state.config.locale,
                &player.name,
                None,
            )
        }
        AdminPlayerMutation::Delete => match database.delete_admin_player(prefix, pid).await {
            Ok(true) => admin_player_success(
                AdminPlayerMutation::Delete,
                &state.config.locale,
                &player.name,
                None,
            ),
            Ok(false) => StatusCode::NOT_FOUND.into_response(),
            Err(error) => {
                tracing::error!(%error, pid, "failed to delete managed player");
                unavailable()
            }
        },
    }
}

fn admin_user_missing_message(locale: &str) -> &'static str {
    if locale.starts_with("zh") {
        "用户不存在"
    } else {
        "No such user."
    }
}

fn admin_texture_missing_message(tid: i64, locale: &str) -> String {
    if locale.starts_with("zh") {
        format!("材质 tid.{tid} 不存在")
    } else {
        format!("No such texture tid.{tid}")
    }
}

fn admin_player_permission_error(locale: &str) -> Response {
    let message = if locale.starts_with("zh") {
        "你无权操作此角色"
    } else {
        "You have no permission to operate this player."
    };
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({"code": 1, "message": message})),
    )
        .into_response()
}

fn admin_player_validation_error(field: &str, locale: &str) -> Response {
    let chinese = locale.starts_with("zh");
    let message = if chinese {
        "给定数据无效。"
    } else {
        "The given data was invalid."
    };
    let field_error = match (field, chinese) {
        ("player_name", true) => "角色名格式或长度无效。",
        ("player_name", false) => "The player name format or length is invalid.",
        ("uid", true) => "UID 必须是整数。",
        ("uid", false) => "The uid field must be an integer.",
        ("tid", true) => "材质 tid 必须是整数。",
        ("tid", false) => "The tid field must be an integer.",
        ("type", true) => "材质类型必须是 skin 或 cape。",
        ("type", false) => "The type field must be skin or cape.",
        _ => "The given field is invalid.",
    };
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(serde_json::json!({"message": message, "errors": {field: [field_error]}})),
    )
        .into_response()
}

fn admin_player_success(
    mutation: AdminPlayerMutation,
    locale: &str,
    player: &str,
    owner: Option<&str>,
) -> Response {
    let message = match (mutation, locale.starts_with("zh")) {
        (AdminPlayerMutation::Name, true) => format!("角色名成功更改为 {player}"),
        (AdminPlayerMutation::Name, false) => format!("Player name has been updated to {player}"),
        (AdminPlayerMutation::Owner, true) => format!(
            "角色 {player} 已被转给用户 {} 。",
            owner.unwrap_or_default()
        ),
        (AdminPlayerMutation::Owner, false) => format!(
            "The player {player} was transferred to user {}.",
            owner.unwrap_or_default()
        ),
        (AdminPlayerMutation::Texture, true) => format!("角色 {player} 的材质修改成功"),
        (AdminPlayerMutation::Texture, false) => {
            format!("The textures of {player} has been updated.")
        }
        (AdminPlayerMutation::Delete, true) => "角色已删除".to_owned(),
        (AdminPlayerMutation::Delete, false) => {
            "The player has been deleted successfully.".to_owned()
        }
    };
    login_result(0, &message, None)
}

async fn admin_user_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AdminUserListQuery>,
) -> Response {
    let Some(user_id) = session_user_id(&state, &headers) else {
        return Redirect::to("/auth/login").into_response();
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    match database
        .user_profile(&state.config.database.table_prefix, user_id)
        .await
    {
        Ok(Some(user)) if user.permission >= 1 => {
            admin_users_response(&state, query, "/admin/users/list").await
        }
        Ok(Some(_)) => forbidden_action(),
        Ok(None) => Redirect::to("/auth/login").into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to load user administrator");
            unavailable()
        }
    }
}

async fn api_admin_user_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AdminUserListQuery>,
) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_any_scope(&["UsersManagement.Read", "UsersManagement.ReadWrite"]) {
        return missing_scope();
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    match database
        .user_profile(&state.config.database.table_prefix, identity.user_id)
        .await
    {
        Ok(Some(user)) if user.permission >= 1 => {
            admin_users_response(&state, query, "/api/admin/users").await
        }
        Ok(Some(_)) | Ok(None) => forbidden_action(),
        Err(error) => {
            tracing::error!(%error, "failed to load API user administrator");
            unavailable()
        }
    }
}

async fn admin_users_response(state: &AppState, query: AdminUserListQuery, path: &str) -> Response {
    let Some(database) = &state.database else {
        return unavailable();
    };
    let page = query.page.unwrap_or(1).max(1);
    let per_page = 10_i64;
    let offset = page.saturating_sub(1).saturating_mul(per_page);
    let (users, total): (Vec<AdminUserRecord>, i64) = match database
        .admin_users(
            &state.config.database.table_prefix,
            query.q.as_deref(),
            per_page,
            offset,
        )
        .await
    {
        Ok(result) => result,
        Err(error) => {
            tracing::error!(%error, "failed to list users");
            return unavailable();
        }
    };
    let last_page = (total.saturating_add(per_page - 1) / per_page).max(1);
    let first_page_url = admin_users_page_url(path, query.q.as_deref(), 1);
    let last_page_url = admin_users_page_url(path, query.q.as_deref(), last_page);
    let prev_page_url =
        (page > 1).then(|| admin_users_page_url(path, query.q.as_deref(), page - 1));
    let next_page_url =
        (page < last_page).then(|| admin_users_page_url(path, query.q.as_deref(), page + 1));
    let from = (!users.is_empty()).then_some(offset + 1);
    let to = (!users.is_empty()).then_some(offset + users.len() as i64);
    let mut links = vec![
        serde_json::json!({"url": prev_page_url, "label": "&laquo; Previous", "active": false}),
    ];
    for number in 1..=last_page.min(100) {
        links.push(serde_json::json!({
            "url": admin_users_page_url(path, query.q.as_deref(), number),
            "label": number.to_string(),
            "active": number == page
        }));
    }
    links.push(serde_json::json!({"url": next_page_url, "label": "Next &raquo;", "active": false}));
    Json(serde_json::json!({
        "current_page": page,
        "data": users,
        "first_page_url": first_page_url,
        "from": from,
        "last_page": last_page,
        "last_page_url": last_page_url,
        "links": links,
        "next_page_url": next_page_url,
        "path": path,
        "per_page": per_page,
        "prev_page_url": prev_page_url,
        "to": to,
        "total": total
    }))
    .into_response()
}

fn admin_users_page_url(path: &str, query: Option<&str>, page: i64) -> String {
    let mut params = vec![format!("page={page}")];
    if let Some(query) = query.filter(|query| !query.is_empty()) {
        params.push(format!("q={}", encode_query_value(query)));
    }
    format!("{path}?{}", params.join("&"))
}

fn encode_query_value(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

fn forbidden_action() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({ "message": "This action is unauthorized." })),
    )
        .into_response()
}

async fn web_admin_closet_add(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(uid): RoutePath<i64>,
    body: Bytes,
) -> Response {
    let Some(actor_uid) = session_user_id(&state, &headers) else {
        return Redirect::to("/auth/login").into_response();
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    match database
        .user_profile(&state.config.database.table_prefix, actor_uid)
        .await
    {
        Ok(Some(user)) if user.permission >= 1 => {
            admin_closet_mutation(&state, uid, body, false).await
        }
        Ok(Some(_)) => forbidden_action(),
        Ok(None) => Redirect::to("/auth/login").into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to load closet administrator");
            unavailable()
        }
    }
}

async fn web_admin_closet_remove(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(uid): RoutePath<i64>,
    body: Bytes,
) -> Response {
    let Some(actor_uid) = session_user_id(&state, &headers) else {
        return Redirect::to("/auth/login").into_response();
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    match database
        .user_profile(&state.config.database.table_prefix, actor_uid)
        .await
    {
        Ok(Some(user)) if user.permission >= 1 => {
            admin_closet_mutation(&state, uid, body, true).await
        }
        Ok(Some(_)) => forbidden_action(),
        Ok(None) => Redirect::to("/auth/login").into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to load closet administrator");
            unavailable()
        }
    }
}

async fn api_admin_closet_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(uid): RoutePath<i64>,
) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_any_scope(&["ClosetManagement.Read", "ClosetManagement.ReadWrite"]) {
        return missing_scope();
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    match database
        .user_profile(&state.config.database.table_prefix, identity.user_id)
        .await
    {
        Ok(Some(user)) if user.permission >= 1 => {}
        Ok(Some(_)) | Ok(None) => return forbidden_action(),
        Err(error) => {
            tracing::error!(%error, "failed to load API closet administrator");
            return unavailable();
        }
    }
    match database
        .admin_closet_user(&state.config.database.table_prefix, uid)
        .await
    {
        Ok(Some(_)) => {}
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, uid, "failed to load managed closet owner");
            return unavailable();
        }
    }
    match database
        .admin_closet_items(&state.config.database.table_prefix, uid)
        .await
    {
        Ok(items) => Json(serde_json::Value::Array(
            items.into_iter().map(admin_closet_texture_json).collect(),
        ))
        .into_response(),
        Err(error) => {
            tracing::error!(%error, uid, "failed to list managed closet");
            unavailable()
        }
    }
}

async fn api_admin_closet_add(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(uid): RoutePath<i64>,
    body: Bytes,
) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_scope("ClosetManagement.ReadWrite") {
        return missing_scope();
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    match database
        .user_profile(&state.config.database.table_prefix, identity.user_id)
        .await
    {
        Ok(Some(user)) if user.permission >= 1 => {
            admin_closet_mutation(&state, uid, body, false).await
        }
        Ok(Some(_)) | Ok(None) => forbidden_action(),
        Err(error) => {
            tracing::error!(%error, "failed to load API closet administrator");
            unavailable()
        }
    }
}

async fn api_admin_closet_remove(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(uid): RoutePath<i64>,
    body: Bytes,
) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_scope("ClosetManagement.ReadWrite") {
        return missing_scope();
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    match database
        .user_profile(&state.config.database.table_prefix, identity.user_id)
        .await
    {
        Ok(Some(user)) if user.permission >= 1 => {
            admin_closet_mutation(&state, uid, body, true).await
        }
        Ok(Some(_)) | Ok(None) => forbidden_action(),
        Err(error) => {
            tracing::error!(%error, "failed to load API closet administrator");
            unavailable()
        }
    }
}

async fn admin_closet_mutation(state: &AppState, uid: i64, body: Bytes, remove: bool) -> Response {
    let Some(database) = &state.database else {
        return unavailable();
    };
    let user = match database
        .admin_closet_user(&state.config.database.table_prefix, uid)
        .await
    {
        Ok(Some(user)) => user,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, uid, "failed to load managed closet owner");
            return unavailable();
        }
    };
    let request = serde_json::from_slice::<serde_json::Value>(&body).ok();
    let tid = request
        .as_ref()
        .and_then(|value| value.get("tid"))
        .and_then(|value| request_i64(Some(value)));
    let chinese = state.config.locale.starts_with("zh");
    let Some(tid) = tid else {
        let message = if remove {
            if chinese {
                "衣柜中不存在此材质"
            } else {
                "The texture does not exist in your closet."
            }
        } else if chinese {
            "该材质不存在"
        } else {
            "We cannot find this texture."
        };
        return login_result(1, message, None);
    };
    if remove {
        match database
            .remove_admin_closet_item(&state.config.database.table_prefix, uid, tid)
            .await
        {
            Ok(crate::database::AdminClosetRemoveOutcome::NonExistent) => {
                let message = if chinese {
                    "衣柜中不存在此材质"
                } else {
                    "The texture does not exist in your closet."
                };
                login_result(1, message, None)
            }
            Ok(crate::database::AdminClosetRemoveOutcome::Removed) => {
                let texture = match database
                    .texture_info(&state.config.database.table_prefix, tid)
                    .await
                {
                    Ok(texture) => texture.map(texture_info_json),
                    Err(error) => {
                        tracing::error!(%error, tid, "failed to load removed closet texture");
                        return unavailable();
                    }
                };
                login_result(
                    0,
                    "",
                    Some(serde_json::json!({"user": user, "texture": texture})),
                )
            }
            Err(error) => {
                tracing::error!(%error, uid, tid, "failed to remove admin closet item");
                unavailable()
            }
        }
    } else {
        match database
            .add_admin_closet_item(&state.config.database.table_prefix, uid, tid)
            .await
        {
            Ok(crate::database::AdminClosetAddOutcome::TextureNotFound) => {
                let message = if chinese {
                    "该材质不存在"
                } else {
                    "We cannot find this texture."
                };
                login_result(1, message, None)
            }
            Ok(crate::database::AdminClosetAddOutcome::Repeated) => {
                let message = if chinese {
                    "你已经收藏过这个材质啦"
                } else {
                    "You have already added this texture."
                };
                login_result(1, message, None)
            }
            Ok(crate::database::AdminClosetAddOutcome::Added) => {
                let texture = match database
                    .texture_info(&state.config.database.table_prefix, tid)
                    .await
                {
                    Ok(Some(texture)) => texture,
                    Ok(None) => return unavailable(),
                    Err(error) => {
                        tracing::error!(%error, tid, "failed to load added closet texture");
                        return unavailable();
                    }
                };
                let texture_json = texture_info_json(texture);
                login_result(
                    0,
                    "",
                    Some(serde_json::json!({"user": user, "texture": texture_json})),
                )
            }
            Err(error) => {
                tracing::error!(%error, uid, tid, "failed to add admin closet item");
                unavailable()
            }
        }
    }
}

fn admin_closet_texture_json(item: ClosetTextureRecord) -> serde_json::Value {
    serde_json::json!({
        "tid": item.tid,
        "name": item.name,
        "type": item.texture_type,
        "hash": item.hash,
        "size": item.size,
        "uploader": item.uploader,
        "public": item.is_public,
        "upload_at": item.upload_at,
        "likes": item.likes,
        "pivot": {
            "user_uid": item.user_uid,
            "texture_tid": item.texture_tid,
            "item_name": item.item_name,
        }
    })
}

async fn admin_report_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AdminReportListQuery>,
) -> Response {
    let Some(user_id) = session_user_id(&state, &headers) else {
        return Redirect::to("/auth/login").into_response();
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    match database
        .user_profile(&state.config.database.table_prefix, user_id)
        .await
    {
        Ok(Some(user)) if user.permission >= 1 => admin_reports_response(&state, query).await,
        Ok(Some(_)) => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "message": "This action is unauthorized." })),
        )
            .into_response(),
        Ok(None) => Redirect::to("/auth/login").into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to load report administrator");
            unavailable()
        }
    }
}

async fn api_admin_report_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AdminReportListQuery>,
) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_any_scope(&["ReportsManagement.Read", "ReportsManagement.ReadWrite"]) {
        return missing_scope();
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    match database
        .user_profile(&state.config.database.table_prefix, identity.user_id)
        .await
    {
        Ok(Some(user)) if user.permission >= 1 => admin_reports_response(&state, query).await,
        Ok(Some(_)) | Ok(None) => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "message": "This action is unauthorized." })),
        )
            .into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to load API report administrator");
            unavailable()
        }
    }
}

async fn web_review_report(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(id): RoutePath<i64>,
    body: Bytes,
) -> Response {
    let Some(user_id) = session_user_id(&state, &headers) else {
        return Redirect::to("/auth/login").into_response();
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    match database
        .user_profile(&state.config.database.table_prefix, user_id)
        .await
    {
        Ok(Some(user)) if user.permission >= 1 => {
            return review_report_action(&state, id, &body, user.permission).await;
        }
        Ok(Some(_)) => {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({ "message": "This action is unauthorized." })),
            )
                .into_response();
        }
        Ok(None) => return Redirect::to("/auth/login").into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to load report administrator");
            return unavailable();
        }
    }
}

async fn api_review_report(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(id): RoutePath<i64>,
    body: Bytes,
) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_scope("ReportsManagement.ReadWrite") {
        return missing_scope();
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    match database
        .user_profile(&state.config.database.table_prefix, identity.user_id)
        .await
    {
        Ok(Some(user)) if user.permission >= 1 => {
            return review_report_action(&state, id, &body, user.permission).await;
        }
        Ok(Some(_)) | Ok(None) => {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({ "message": "This action is unauthorized." })),
            )
                .into_response();
        }
        Err(error) => {
            tracing::error!(%error, "failed to load API report administrator");
            return unavailable();
        }
    }
}

async fn review_report_action(
    state: &AppState,
    id: i64,
    body: &[u8],
    admin_permission: i32,
) -> Response {
    let request = serde_json::from_slice::<serde_json::Value>(body).ok();
    let Some(action) = request
        .as_ref()
        .and_then(|request| request.get("action"))
        .and_then(serde_json::Value::as_str)
        .filter(|action| matches!(*action, "reject" | "ban" | "delete"))
    else {
        return report_review_validation_error(&state.config.locale);
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let reporter_score_modification = match read_score_option(
        database,
        &state.config.database.table_prefix,
        "reporter_score_modification",
        0,
    )
    .await
    {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(%error, "failed to read report score modifier");
            return unavailable();
        }
    };
    if action == "delete" {
        return delete_reported_texture(state, id, reporter_score_modification).await;
    }
    let outcome = if action == "reject" {
        database
            .reject_report(
                &state.config.database.table_prefix,
                id,
                reporter_score_modification,
            )
            .await
    } else {
        let reporter_reward_score = match database
            .option(&state.config.database.table_prefix, "reporter_reward_score")
            .await
        {
            Ok(value) => value
                .as_deref()
                .and_then(|value| value.parse::<i64>().ok())
                .unwrap_or_default(),
            Err(error) => {
                tracing::error!(%error, "failed to read reporter reward score");
                return unavailable();
            }
        };
        database
            .ban_report_uploader(
                &state.config.database.table_prefix,
                id,
                admin_permission,
                reporter_score_modification,
                reporter_reward_score,
            )
            .await
    };
    match outcome {
        Ok(crate::database::ReportReviewOutcome::Rejected) => report_review_success(state, 2),
        Ok(crate::database::ReportReviewOutcome::Resolved) => report_review_success(state, 1),
        Ok(crate::database::ReportReviewOutcome::UploaderNotFound) => {
            let message = if state.config.locale.starts_with("zh") {
                "用户不存在"
            } else {
                "No such user."
            };
            login_result(1, message, None)
        }
        Ok(crate::database::ReportReviewOutcome::UploaderPermissionDenied) => {
            let message = if state.config.locale.starts_with("zh") {
                "你无权操作此用户"
            } else {
                "You have no permission to operate this user."
            };
            login_result(1, message, None)
        }
        Ok(crate::database::ReportReviewOutcome::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, report_id = id, "failed to review report");
            unavailable()
        }
    }
}

fn report_review_success(state: &AppState, status: i32) -> Response {
    let message = if state.config.locale.starts_with("zh") {
        "操作成功"
    } else {
        "Operated successfully."
    };
    login_result(0, message, Some(serde_json::json!({ "status": status })))
}

fn report_review_validation_error(locale: &str) -> Response {
    let chinese = locale.starts_with("zh");
    let message = if chinese {
        "给定数据无效。"
    } else {
        "The given data was invalid."
    };
    let field_error = if chinese {
        "所选操作无效。"
    } else {
        "The selected action is invalid."
    };
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(serde_json::json!({
            "message": message,
            "errors": { "action": [field_error] }
        })),
    )
        .into_response()
}

async fn delete_reported_texture(
    state: &AppState,
    report_id: i64,
    reporter_score_modification: i64,
) -> Response {
    let Some(database) = &state.database else {
        return unavailable();
    };
    let filters = ReportSearchFilters {
        id: Some(report_id),
        ..Default::default()
    };
    let mut reports = match database
        .report_management_items(
            &state.config.database.table_prefix,
            &filters,
            "report_at",
            true,
            1,
            1,
        )
        .await
    {
        Ok((reports, _)) => reports,
        Err(error) => {
            tracing::error!(%error, report_id, "failed to load report for texture deletion");
            return unavailable();
        }
    };
    let Some(report) = reports.pop() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let texture = if let Some(tid) = report.texture_tid {
        match database
            .texture_info(&state.config.database.table_prefix, tid)
            .await
        {
            Ok(texture) => texture,
            Err(error) => {
                tracing::error!(%error, tid, "failed to load texture reported for deletion");
                return unavailable();
            }
        }
    } else {
        None
    };
    let Some(texture) = texture else {
        return match database
            .resolve_report_without_texture(
                &state.config.database.table_prefix,
                report_id,
                reporter_score_modification,
            )
            .await
        {
            Ok(crate::database::ReportReviewOutcome::Resolved) => login_result(
                0,
                if state.config.locale.starts_with("zh") {
                    "请求的材质已被删除"
                } else {
                    "The requested texture has been deleted."
                },
                Some(serde_json::json!({ "status": 1 })),
            ),
            Ok(crate::database::ReportReviewOutcome::NotFound) => {
                StatusCode::NOT_FOUND.into_response()
            }
            Ok(_) => unreachable!("missing texture resolution has no other outcome"),
            Err(error) => {
                tracing::error!(%error, report_id, "failed to resolve report with deleted texture");
                unavailable()
            }
        };
    };
    let prefix = &state.config.database.table_prefix;
    let return_score = match read_bool_option(database, prefix, "return_score", true).await {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(%error, "failed to read texture score return option");
            return unavailable();
        }
    };
    let public_cost = match read_score_option(database, prefix, "score_per_storage", 0).await {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(%error, "failed to read public texture storage score");
            return unavailable();
        }
    };
    let private_cost =
        match read_score_option(database, prefix, "private_score_per_storage", 10).await {
            Ok(value) => value,
            Err(error) => {
                tracing::error!(%error, "failed to read private texture storage score");
                return unavailable();
            }
        };
    let public_award = match read_score_option(database, prefix, "score_award_per_texture", 0).await
    {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(%error, "failed to read texture score award");
            return unavailable();
        }
    };
    let take_back_award =
        match read_bool_option(database, prefix, "take_back_scores_after_deletion", true).await {
            Ok(value) => value,
            Err(error) => {
                tracing::error!(%error, "failed to read texture award return option");
                return unavailable();
            }
        };
    let closet_refund = if return_score {
        match read_score_option(database, prefix, "score_per_closet_item", 0).await {
            Ok(value) => value,
            Err(error) => {
                tracing::error!(%error, "failed to read closet item score");
                return unavailable();
            }
        }
    } else {
        0
    };
    let reporter_reward = if report.status == 0 {
        match read_score_option(database, prefix, "reporter_reward_score", 0).await {
            Ok(value) => value,
            Err(error) => {
                tracing::error!(%error, "failed to read reporter reward score");
                return unavailable();
            }
        }
    } else {
        0
    };
    let reporter_adjustment = if report.status == 0 {
        reporter_score_modification
            .min(0)
            .saturating_neg()
            .saturating_add(reporter_reward)
    } else {
        0
    };
    let uploader_refund = texture_delete_score_refund(
        &texture,
        return_score,
        public_cost,
        private_cost,
        public_award,
        take_back_award,
    );
    let remove_texture_file = match database
        .delete_reported_texture(
            prefix,
            &texture,
            report_id,
            reporter_adjustment,
            uploader_refund,
            closet_refund,
        )
        .await
    {
        Ok(crate::database::TextureDeleteOutcome::Deleted(remove_file)) => remove_file,
        Ok(crate::database::TextureDeleteOutcome::ReportNotFound) => {
            return StatusCode::NOT_FOUND.into_response();
        }
        Err(error) => {
            tracing::error!(%error, tid = texture.tid, report_id, "failed to delete reported texture");
            return unavailable();
        }
    };
    if remove_texture_file && valid_texture_hash(&texture.hash) {
        let file_path = state.config.textures_dir.join(&texture.hash);
        if let Err(error) = tokio::fs::remove_file(file_path).await {
            if error.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(%error, hash = texture.hash, "failed to remove reported texture file");
            }
        }
    }
    report_review_success(state, 1)
}

async fn read_score_option(
    database: &DatabasePool,
    prefix: &str,
    name: &str,
    default: i64,
) -> Result<i64, sqlx::Error> {
    Ok(database
        .option(prefix, name)
        .await?
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(default))
}

async fn read_bool_option(
    database: &DatabasePool,
    prefix: &str,
    name: &str,
    default: bool,
) -> Result<bool, sqlx::Error> {
    Ok(database
        .option(prefix, name)
        .await?
        .as_deref()
        .map(|value| parse_legacy_form_bool(value).unwrap_or(false))
        .unwrap_or(default))
}

async fn admin_reports_response(state: &AppState, query: AdminReportListQuery) -> Response {
    let Some(database) = &state.database else {
        return unavailable();
    };
    let parsed = parse_report_search(query.q.as_deref());
    let page = query.page.unwrap_or(1).max(1);
    const PER_PAGE: i64 = 9;
    match database
        .report_management_items(
            &state.config.database.table_prefix,
            &parsed.filters,
            &parsed.sort_field,
            parsed.descending,
            page,
            PER_PAGE,
        )
        .await
    {
        Ok((reports, total)) => {
            let data = reports
                .into_iter()
                .map(report_management_json)
                .collect::<Vec<_>>();
            let last_page = total.saturating_add(PER_PAGE - 1) / PER_PAGE;
            let offset = page.saturating_sub(1).saturating_mul(PER_PAGE);
            let from = (!data.is_empty()).then_some(offset + 1);
            let to = (!data.is_empty()).then_some(offset + data.len() as i64);
            Json(serde_json::json!({
                "current_page": page,
                "data": data,
                "last_page": last_page.max(1),
                "per_page": PER_PAGE,
                "from": from,
                "to": to,
                "total": total
            }))
            .into_response()
        }
        Err(error) => {
            tracing::error!(%error, "failed to query admin reports");
            unavailable()
        }
    }
}

fn report_management_json(report: ReportManagementRecord) -> serde_json::Value {
    let texture = report.texture_tid.map(|tid| {
        serde_json::json!({
            "tid": tid,
            "name": report.texture_name,
            "type": report.texture_type,
            "hash": report.texture_hash,
            "size": report.texture_size,
            "uploader": report.texture_uploader,
            "public": report.texture_public,
            "upload_at": report.texture_upload_at,
            "likes": report.texture_likes,
        })
    });
    let texture_uploader = report.texture_uploader_uid.map(|uid| {
        serde_json::json!({
            "uid": uid,
            "email": report.texture_uploader_email,
            "nickname": report.texture_uploader_nickname,
            "locale": report.texture_uploader_locale,
            "score": report.texture_uploader_score,
            "avatar": report.texture_uploader_avatar,
            "permission": report.texture_uploader_permission,
            "ip": report.texture_uploader_ip,
            "last_sign_at": report.texture_uploader_last_sign_at,
            "register_at": report.texture_uploader_register_at,
            "verified": report.texture_uploader_verified,
            "is_dark_mode": report.texture_uploader_is_dark_mode,
        })
    });
    let informer = report.informer_uid.map(|uid| {
        serde_json::json!({
            "uid": uid,
            "email": report.informer_email,
            "nickname": report.informer_nickname,
            "locale": report.informer_locale,
            "score": report.informer_score,
            "avatar": report.informer_avatar,
            "permission": report.informer_permission,
            "ip": report.informer_ip,
            "last_sign_at": report.informer_last_sign_at,
            "register_at": report.informer_register_at,
            "verified": report.informer_verified,
            "is_dark_mode": report.informer_is_dark_mode,
        })
    });
    serde_json::json!({
        "id": report.id,
        "tid": report.tid,
        "texture": texture,
        "uploader": report.uploader,
        "texture_uploader": texture_uploader,
        "reporter": report.reporter,
        "informer": informer,
        "reason": report.reason,
        "status": report.status,
        "report_at": report.report_at,
    })
}
async fn api_closet(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ClosetListQuery>,
) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_any_scope(&["Closet.Read", "Closet.ReadWrite"]) {
        return missing_scope();
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(6).max(1);
    let category = query.category.as_deref().unwrap_or("skin");
    let search = query
        .q
        .as_deref()
        .filter(|value| !value.is_empty() && *value != "0");
    match database
        .closet_items(
            &state.config.database.table_prefix,
            identity.user_id,
            category,
            search,
            page,
            per_page,
        )
        .await
    {
        Ok((items, total)) => {
            let data = items.into_iter().map(closet_item_json).collect::<Vec<_>>();
            let last_page = total.saturating_add(per_page - 1) / per_page;
            let offset = page.saturating_sub(1).saturating_mul(per_page);
            let from = (!data.is_empty()).then_some(offset + 1);
            let to = (!data.is_empty()).then_some(offset + data.len() as i64);
            Json(serde_json::json!({
                "current_page": page,
                "data": data,
                "last_page": last_page.max(1),
                "per_page": per_page,
                "from": from,
                "to": to,
                "total": total
            }))
            .into_response()
        }
        Err(error) => {
            tracing::error!(%error, "failed to load user's texture closet");
            unavailable()
        }
    }
}

fn closet_item_json(item: crate::database::ClosetTextureRecord) -> serde_json::Value {
    serde_json::json!({
        "tid": item.tid,
        "name": item.name,
        "type": item.texture_type,
        "hash": item.hash,
        "size": item.size,
        "uploader": item.uploader,
        "public": item.is_public,
        "upload_at": item.upload_at,
        "likes": item.likes,
        "pivot": {
            "user_uid": item.user_uid,
            "texture_tid": item.texture_tid,
            "item_name": item.item_name
        }
    })
}
async fn api_players(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !identity.has_any_scope(&["Player.Read", "Player.ReadWrite"]) {
        return missing_scope();
    }
    let Some(database) = &state.database else {
        return unavailable();
    };

    match database
        .players_for_user(&state.config.database.table_prefix, identity.user_id)
        .await
    {
        Ok(players) => Json(players).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to load authenticated player's list");
            unavailable()
        }
    }
}

struct AuthenticatedToken {
    user_id: i64,
    scopes: Vec<String>,
}

impl AuthenticatedToken {
    fn has_scope(&self, required: &str) -> bool {
        self.scopes.iter().any(|scope| scope == required)
    }

    fn has_any_scope(&self, required: &[&str]) -> bool {
        required.iter().any(|scope| self.has_scope(scope))
    }
}

async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthenticatedToken, Response> {
    let Some(key) = &state.passport_key else {
        return Err(unauthenticated());
    };
    let Some(token) = bearer_token(headers) else {
        return Err(unauthenticated());
    };
    let Some(database) = &state.database else {
        return Err(unavailable());
    };
    let Some(claims) = decode_access_token(token, key) else {
        return Err(unauthenticated());
    };
    if claims.exp <= jsonwebtoken::get_current_timestamp() {
        return Err(unauthenticated());
    }
    let token_record = match database
        .access_token(&state.config.database.table_prefix, &claims.jti)
        .await
    {
        Ok(Some(record)) => record,
        Ok(None) => return Err(unauthenticated()),
        Err(error) => {
            tracing::error!(%error, "failed to load Passport access token");
            return Err(unavailable());
        }
    };
    let user_id = match claims.sub.parse::<i64>() {
        Ok(user_id) => user_id,
        Err(_) => return Err(unauthenticated()),
    };
    if token_record.revoked
        || token_record.user_id != Some(user_id)
        || !audience_matches(claims.aud.as_ref(), token_record.client_id)
    {
        return Err(unauthenticated());
    }

    Ok(AuthenticatedToken {
        user_id,
        scopes: claims.scopes,
    })
}

fn missing_scope() -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "code": 403,
            "message": "Invalid scope(s) provided."
        })),
    )
        .into_response()
}
fn unauthenticated() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({ "message": "Unauthenticated." })),
    )
        .into_response()
}
async fn api_root(State(state): State<AppState>) -> Response {
    let Some(database) = &state.database else {
        return unavailable();
    };
    match build_api_root(database, &state).await {
        Ok(root) => Json(root).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to load public API metadata");
            unavailable()
        }
    }
}

async fn build_api_root(database: &DatabasePool, state: &AppState) -> Result<ApiRoot, sqlx::Error> {
    let locale_key = format!("copyright_prefer_{}", state.config.locale);
    let preference = database
        .option(&state.config.database.table_prefix, &locale_key)
        .await?
        .or(database
            .option(&state.config.database.table_prefix, "copyright_prefer")
            .await?);
    let copyright_index = preference
        .as_deref()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or_default();
    let copyright = COPYRIGHTS
        .get(copyright_index)
        .copied()
        .unwrap_or(COPYRIGHTS[0]);
    let site_name = database
        .option(&state.config.database.table_prefix, "site_name")
        .await?
        .unwrap_or_else(|| "Blessing Skin".to_owned());

    Ok(ApiRoot {
        blessing_skin: state.config.version,
        spec: 0,
        copyright,
        site_name,
    })
}

#[derive(Serialize)]
struct SkinProfile {
    username: String,
    skins: BTreeMap<String, Option<String>>,
    cape: Option<String>,
}

async fn player_json(
    State(state): State<AppState>,
    RoutePath(profile_path): RoutePath<String>,
    request_headers: HeaderMap,
) -> Response {
    let Some(player_name) = profile_path.strip_suffix(".json") else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(database) = &state.database else {
        return unavailable();
    };
    let profile = match database
        .player_profile(&state.config.database.table_prefix, &player_name)
        .await
    {
        Ok(Some(profile)) => profile,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to load player profile");
            return unavailable();
        }
    };

    if profile.permission == -1 {
        let message = if state.config.locale.starts_with("zh") {
            "该角色拥有者已被本站封禁"
        } else {
            "The owner of this player has been banned."
        };
        return (StatusCode::FORBIDDEN, message).into_response();
    }

    let last_modified = profile
        .last_modified
        .as_deref()
        .and_then(parse_legacy_datetime);
    let ttl = cache_ttl(&state).await;
    let mut response = Json(to_skin_profile(profile)).into_response();
    response.headers_mut().insert(
        CACHE_CONTROL,
        HeaderValue::from_str(&format!("public, max-age={ttl}")).unwrap(),
    );
    if let Some(last_modified) = last_modified {
        response.headers_mut().insert(
            LAST_MODIFIED,
            HeaderValue::from_str(&httpdate::fmt_http_date(last_modified)).unwrap(),
        );
        if !request_headers.contains_key(IF_NONE_MATCH)
            && not_modified_since(&request_headers, last_modified)
        {
            *response.status_mut() = StatusCode::NOT_MODIFIED;
            *response.body_mut() = Body::empty();
            response.headers_mut().remove(CONTENT_TYPE);
            response.headers_mut().remove(CONTENT_LENGTH);
        }
    }
    response
}

fn to_skin_profile(profile: PlayerProfile) -> SkinProfile {
    let model = if profile.skin_type.as_deref() == Some("alex") {
        "slim"
    } else {
        "default"
    };
    let mut skins = BTreeMap::new();
    skins.insert(model.to_owned(), profile.skin_hash);
    SkinProfile {
        username: profile.name,
        skins,
        cape: profile.cape_hash,
    }
}

async fn texture(
    State(state): State<AppState>,
    RoutePath(hash): RoutePath<String>,
    request_headers: HeaderMap,
) -> Response {
    if !valid_texture_hash(&hash) {
        return StatusCode::NOT_FOUND.into_response();
    }
    serve_texture(&state, &hash, &request_headers).await
}

async fn raw_texture(
    State(state): State<AppState>,
    RoutePath(tid): RoutePath<i64>,
    request_headers: HeaderMap,
) -> Response {
    let Some(database) = &state.database else {
        return unavailable();
    };
    let allowed = database
        .option(
            &state.config.database.table_prefix,
            "allow_downloading_texture",
        )
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| "true".to_owned());
    if matches!(
        allowed.to_ascii_lowercase().as_str(),
        "false" | "0" | "off" | "no"
    ) {
        return StatusCode::FORBIDDEN.into_response();
    }

    let hash = match database
        .texture_hash(&state.config.database.table_prefix, tid)
        .await
    {
        Ok(Some(hash)) if valid_texture_hash(&hash) => hash,
        Ok(_) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to load texture metadata");
            return unavailable();
        }
    };
    serve_texture(&state, &hash, &request_headers).await
}

#[derive(Debug)]
struct AvatarSource {
    hash: String,
    texture_type: String,
}

async fn preview_by_texture(
    State(state): State<AppState>,
    RoutePath(tid): RoutePath<String>,
    Query(query): Query<HashMap<String, String>>,
    request_headers: HeaderMap,
) -> Response {
    let Some(tid) = tid.parse::<i64>().ok() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    preview_for_texture(&state, tid, &query, &request_headers).await
}

async fn preview_by_hash(
    State(state): State<AppState>,
    RoutePath(hash): RoutePath<String>,
    Query(query): Query<HashMap<String, String>>,
    request_headers: HeaderMap,
) -> Response {
    if !valid_texture_hash(&hash) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(database) = &state.database else {
        return unavailable();
    };
    let tid = match database
        .texture_id_by_hash(&state.config.database.table_prefix, &hash)
        .await
    {
        Ok(Some(tid)) => tid,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, hash, "failed to find preview texture");
            return unavailable();
        }
    };
    preview_for_texture(&state, tid, &query, &request_headers).await
}

async fn preview_for_texture(
    state: &AppState,
    tid: i64,
    query: &HashMap<String, String>,
    request_headers: &HeaderMap,
) -> Response {
    let Some(database) = &state.database else {
        return unavailable();
    };
    let texture = match database
        .texture_info(&state.config.database.table_prefix, tid)
        .await
    {
        Ok(Some(texture)) => texture,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, tid, "failed to load preview texture metadata");
            return unavailable();
        }
    };
    if !valid_texture_hash(&texture.hash) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let path = state.config.textures_dir.join(&texture.hash);
    let metadata = match tokio::fs::metadata(&path).await {
        Ok(metadata) if metadata.is_file() => metadata,
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    let source = match tokio::fs::read(path).await {
        Ok(bytes) => match image::load_from_memory_with_format(&bytes, ImageFormat::Png) {
            Ok(image) => image.to_rgba8(),
            Err(error) => {
                tracing::warn!(%error, tid, "preview source is not a valid PNG");
                return StatusCode::NOT_FOUND.into_response();
            }
        },
        Err(error) => {
            tracing::warn!(%error, tid, "preview source could not be read");
            return StatusCode::NOT_FOUND.into_response();
        }
    };
    let is_cape = texture.texture_type == "cape";
    if (is_cape && (source.width() < 12 || source.height() < 17))
        || (!is_cape && (source.width() != 64 || (source.height() != 64 && source.height() != 32)))
    {
        return StatusCode::UNPROCESSABLE_ENTITY.into_response();
    }
    let height = query
        .get("height")
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|height| (1..=1024).contains(height))
        .unwrap_or(200);
    let use_png = query.contains_key("png");
    let format = if use_png {
        ImageFormat::Png
    } else {
        ImageFormat::WebP
    };
    let rendered = if is_cape {
        render_cape_preview(&source, height)
    } else {
        render_skin_preview(&source, texture.texture_type == "alex", height)
    };
    let mut bytes = Vec::new();
    if rendered
        .write_to(&mut Cursor::new(&mut bytes), format)
        .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let etag = content_etag(&bytes);
    let ttl = cache_ttl(state).await;
    let modified = metadata.modified().ok();
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static(if use_png { "image/png" } else { "image/webp" }),
    );
    headers.insert(ETAG, HeaderValue::from_str(&etag).unwrap());
    headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_str(&format!("public, max-age={ttl}")).unwrap(),
    );
    headers.insert(
        CONTENT_LENGTH,
        HeaderValue::from_str(&bytes.len().to_string()).unwrap(),
    );
    if let Some(modified) = modified {
        headers.insert(
            LAST_MODIFIED,
            HeaderValue::from_str(&httpdate::fmt_http_date(modified)).unwrap(),
        );
    }
    if (request_headers.contains_key(IF_NONE_MATCH) && header_has_etag(request_headers, &etag))
        || (!request_headers.contains_key(IF_NONE_MATCH)
            && modified.is_some_and(|time| not_modified_since(request_headers, time)))
    {
        let mut response = StatusCode::NOT_MODIFIED.into_response();
        *response.headers_mut() = headers;
        response.headers_mut().remove(CONTENT_TYPE);
        response.headers_mut().remove(CONTENT_LENGTH);
        return response;
    }
    let mut response = Response::new(Body::from(bytes));
    *response.headers_mut() = headers;
    response
}

fn render_skin_preview(skin: &RgbaImage, is_alex: bool, height: u32) -> DynamicImage {
    let mut character = RgbaImage::from_pixel(64, 128, Rgba([0, 0, 0, 0]));
    draw_skin_part(
        &mut character,
        skin,
        (8, 8),
        Some((40, 8)),
        (16, 0),
        8,
        8,
        4,
    );
    draw_skin_part(
        &mut character,
        skin,
        (20, 20),
        Some((20, 36)),
        (16, 32),
        8,
        12,
        4,
    );

    let arm_width = if is_alex { 3 } else { 4 };
    let arm_pixels = arm_width * 4;
    let arm_left_x = 16_i64 - i64::from(arm_pixels);
    let arm_right_x = 48;
    let (left_arm_base, left_arm_overlay) = if skin.height() >= 64 {
        ((36, 52), Some((52, 52)))
    } else {
        ((44, 20), None)
    };
    let mut left_arm = skin_part(skin, left_arm_base, left_arm_overlay, arm_width, 12);
    if skin.height() < 64 {
        left_arm = image::imageops::flip_horizontal(&left_arm);
    }
    draw_scaled_skin_part(&mut character, &left_arm, (arm_left_x, 32), 4);
    let right_arm = skin_part(
        skin,
        (44, 20),
        (skin.height() >= 64).then_some((44, 36)),
        arm_width,
        12,
    );
    draw_scaled_skin_part(&mut character, &right_arm, (arm_right_x, 32), 4);

    let left_leg = if skin.height() >= 64 {
        skin_part(skin, (20, 52), Some((4, 52)), 4, 12)
    } else {
        image::imageops::flip_horizontal(&skin_part(skin, (4, 20), None, 4, 12))
    };
    let right_leg = skin_part(
        skin,
        (4, 20),
        (skin.height() >= 64).then_some((4, 36)),
        4,
        12,
    );
    draw_scaled_skin_part(&mut character, &left_leg, (16, 80), 4);
    draw_scaled_skin_part(&mut character, &right_leg, (32, 80), 4);

    let mut square = RgbaImage::from_pixel(256, 256, Rgba([0, 0, 0, 0]));
    let character =
        image::imageops::resize(&character, 128, 256, image::imageops::FilterType::Nearest);
    image::imageops::overlay(&mut square, &character, 64, 0);
    DynamicImage::ImageRgba8(square).resize_exact(
        height,
        height,
        image::imageops::FilterType::Nearest,
    )
}

fn render_cape_preview(cape: &RgbaImage, height: u32) -> DynamicImage {
    let front = image::imageops::crop_imm(cape, 1, 1, 10, 16).to_image();
    let width = (height.saturating_mul(10) / 16).max(1);
    DynamicImage::ImageRgba8(image::imageops::resize(
        &front,
        width,
        height,
        image::imageops::FilterType::Nearest,
    ))
}

fn draw_skin_part(
    destination: &mut RgbaImage,
    source: &RgbaImage,
    base: (u32, u32),
    overlay: Option<(u32, u32)>,
    position: (i64, i64),
    width: u32,
    height: u32,
    scale: u32,
) {
    let part = skin_part(source, base, overlay, width, height);
    draw_scaled_skin_part(destination, &part, position, scale);
}

fn skin_part(
    source: &RgbaImage,
    base: (u32, u32),
    overlay: Option<(u32, u32)>,
    width: u32,
    height: u32,
) -> RgbaImage {
    let mut part = image::imageops::crop_imm(source, base.0, base.1, width, height).to_image();
    if let Some((x, y)) =
        overlay.filter(|(x, y)| x + width <= source.width() && y + height <= source.height())
    {
        let layer = image::imageops::crop_imm(source, x, y, width, height).to_image();
        image::imageops::overlay(&mut part, &layer, 0, 0);
    }
    part
}

fn draw_scaled_skin_part(
    destination: &mut RgbaImage,
    part: &RgbaImage,
    position: (i64, i64),
    scale: u32,
) {
    let part = image::imageops::resize(
        part,
        part.width() * scale,
        part.height() * scale,
        image::imageops::FilterType::Nearest,
    );
    image::imageops::overlay(destination, &part, position.0, position.1);
}

async fn avatar_by_player(
    State(state): State<AppState>,
    RoutePath(name): RoutePath<String>,
    Query(query): Query<HashMap<String, String>>,
    request_headers: HeaderMap,
) -> Response {
    let Some(database) = &state.database else {
        return unavailable();
    };
    let profile = match database
        .player_profile(&state.config.database.table_prefix, &name)
        .await
    {
        Ok(Some(profile)) => profile,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, player = %name, "failed to load player avatar");
            return unavailable();
        }
    };
    if profile.permission == -1 {
        return StatusCode::FORBIDDEN.into_response();
    }
    let source = profile
        .skin_hash
        .zip(profile.skin_type)
        .map(|(hash, texture_type)| AvatarSource { hash, texture_type });
    render_avatar_response(&state, source, &query, &request_headers).await
}

async fn avatar_by_user(
    State(state): State<AppState>,
    RoutePath(uid): RoutePath<String>,
    Query(query): Query<HashMap<String, String>>,
    request_headers: HeaderMap,
) -> Response {
    let Some(database) = &state.database else {
        return unavailable();
    };
    let Some(uid) = uid.parse::<i64>().ok() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let user = match database
        .user_profile(&state.config.database.table_prefix, uid)
        .await
    {
        Ok(user) => user,
        Err(error) => {
            tracing::error!(%error, uid, "failed to load user avatar");
            return unavailable();
        }
    };
    let texture_id = user.map(|user| user.avatar).filter(|tid| *tid > 0);
    let source = match texture_id {
        Some(tid) => match database
            .texture_info(&state.config.database.table_prefix, tid)
            .await
        {
            Ok(Some(texture)) => Some(AvatarSource {
                hash: texture.hash,
                texture_type: texture.texture_type,
            }),
            Ok(None) => None,
            Err(error) => {
                tracing::error!(%error, tid, "failed to load user avatar texture");
                return unavailable();
            }
        },
        None => None,
    };
    render_avatar_response(&state, source, &query, &request_headers).await
}

async fn avatar_by_hash(
    State(state): State<AppState>,
    RoutePath(hash): RoutePath<String>,
    Query(query): Query<HashMap<String, String>>,
    request_headers: HeaderMap,
) -> Response {
    let Some(database) = &state.database else {
        return unavailable();
    };
    let source = if valid_texture_hash(&hash) {
        match database
            .texture_id_by_hash(&state.config.database.table_prefix, &hash)
            .await
        {
            Ok(Some(tid)) => match database
                .texture_info(&state.config.database.table_prefix, tid)
                .await
            {
                Ok(Some(texture)) => Some(AvatarSource {
                    hash: texture.hash,
                    texture_type: texture.texture_type,
                }),
                Ok(None) => None,
                Err(error) => {
                    tracing::error!(%error, tid, "failed to load avatar texture");
                    return unavailable();
                }
            },
            Ok(None) => None,
            Err(error) => {
                tracing::error!(%error, hash, "failed to find avatar texture");
                return unavailable();
            }
        }
    } else {
        None
    };
    render_avatar_response(&state, source, &query, &request_headers).await
}

async fn avatar_by_texture(
    State(state): State<AppState>,
    RoutePath(tid): RoutePath<String>,
    Query(query): Query<HashMap<String, String>>,
    request_headers: HeaderMap,
) -> Response {
    let Some(database) = &state.database else {
        return unavailable();
    };
    let Some(tid) = tid.parse::<i64>().ok() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let source = match database
        .texture_info(&state.config.database.table_prefix, tid)
        .await
    {
        Ok(Some(texture)) => Some(AvatarSource {
            hash: texture.hash,
            texture_type: texture.texture_type,
        }),
        Ok(None) => None,
        Err(error) => {
            tracing::error!(%error, tid, "failed to load avatar texture");
            return unavailable();
        }
    };
    render_avatar_response(&state, source, &query, &request_headers).await
}

async fn render_avatar_response(
    state: &AppState,
    source: Option<AvatarSource>,
    query: &HashMap<String, String>,
    request_headers: &HeaderMap,
) -> Response {
    let three_d = query.contains_key("3d");
    let size = query
        .get("size")
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|size| (1..=1024).contains(size))
        .unwrap_or(100);
    let use_png = query.contains_key("png");
    let format = if use_png {
        ImageFormat::Png
    } else {
        ImageFormat::WebP
    };
    let mut modified = None;
    let mut source_skin = None;
    if let Some(source) = source {
        if source.texture_type != "steve" && source.texture_type != "alex" {
            return StatusCode::UNPROCESSABLE_ENTITY.into_response();
        }
        if valid_texture_hash(&source.hash) {
            let path = state.config.textures_dir.join(&source.hash);
            if let Ok(metadata) = tokio::fs::metadata(&path).await {
                if metadata.is_file() {
                    modified = metadata.modified().ok();
                    if let Ok(bytes) = tokio::fs::read(path).await {
                        source_skin = image::load_from_memory_with_format(&bytes, ImageFormat::Png)
                            .ok()
                            .filter(|image| {
                                image.width() == 64
                                    && (image.height() == 64 || image.height() == 32)
                            });
                    }
                }
            }
        }
    }

    let image = match source_skin {
        Some(skin) => render_skin_avatar(&skin.to_rgba8(), three_d),
        None => default_avatar(three_d),
    };
    let image = image.resize_exact(size, size, image::imageops::FilterType::Nearest);
    let mut bytes = Vec::new();
    if image
        .write_to(&mut Cursor::new(&mut bytes), format)
        .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let etag = content_etag(&bytes);
    let ttl = cache_ttl(state).await;
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static(if use_png { "image/png" } else { "image/webp" }),
    );
    headers.insert(ETAG, HeaderValue::from_str(&etag).unwrap());
    headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_str(&format!("public, max-age={ttl}")).unwrap(),
    );
    headers.insert(
        CONTENT_LENGTH,
        HeaderValue::from_str(&bytes.len().to_string()).unwrap(),
    );
    if let Some(modified) = modified {
        headers.insert(
            LAST_MODIFIED,
            HeaderValue::from_str(&httpdate::fmt_http_date(modified)).unwrap(),
        );
    }
    if (request_headers.contains_key(IF_NONE_MATCH) && header_has_etag(request_headers, &etag))
        || (!request_headers.contains_key(IF_NONE_MATCH)
            && modified.is_some_and(|time| not_modified_since(request_headers, time)))
    {
        let mut response = StatusCode::NOT_MODIFIED.into_response();
        *response.headers_mut() = headers;
        response.headers_mut().remove(CONTENT_TYPE);
        response.headers_mut().remove(CONTENT_LENGTH);
        return response;
    }
    let mut response = Response::new(Body::from(bytes));
    *response.headers_mut() = headers;
    response
}

fn default_avatar(three_d: bool) -> DynamicImage {
    let bytes = if three_d {
        include_bytes!("../resources/misc/textures/avatar3d.png").as_slice()
    } else {
        include_bytes!("../resources/misc/textures/avatar2d.png").as_slice()
    };
    image::load_from_memory_with_format(bytes, ImageFormat::Png).expect("built-in avatar is valid")
}

fn render_skin_avatar(skin: &RgbaImage, three_d: bool) -> DynamicImage {
    if skin.width() < 64 || skin.height() < 32 {
        return default_avatar(three_d);
    }
    if !three_d {
        let mut face = image::imageops::crop_imm(skin, 8, 8, 8, 8).to_image();
        let hat = image::imageops::crop_imm(skin, 40, 8, 8, 8).to_image();
        image::imageops::overlay(&mut face, &hat, 0, 0);
        return DynamicImage::ImageRgba8(face);
    }

    let mut canvas = RgbaImage::from_pixel(64, 64, Rgba([0, 0, 0, 0]));
    let right = textured_head_face(skin, (16, 8), Some((48, 8)));
    let top = textured_head_face(skin, (8, 0), Some((40, 0)));
    let front = textured_head_face(skin, (8, 8), Some((40, 8)));
    draw_textured_quad(&mut canvas, &right, (43.0, 24.0), (11.0, -7.0), (0.0, 30.0));
    draw_textured_quad(&mut canvas, &top, (13.0, 24.0), (30.0, 0.0), (11.0, -7.0));
    draw_textured_quad(&mut canvas, &front, (13.0, 24.0), (30.0, 0.0), (0.0, 30.0));
    DynamicImage::ImageRgba8(canvas)
}

fn textured_head_face(
    skin: &RgbaImage,
    base: (u32, u32),
    overlay: Option<(u32, u32)>,
) -> RgbaImage {
    let mut face = image::imageops::crop_imm(skin, base.0, base.1, 8, 8).to_image();
    if let Some((x, y)) = overlay {
        let hat = image::imageops::crop_imm(skin, x, y, 8, 8).to_image();
        image::imageops::overlay(&mut face, &hat, 0, 0);
    }
    face
}

fn draw_textured_quad(
    destination: &mut RgbaImage,
    texture: &RgbaImage,
    origin: (f32, f32),
    axis_u: (f32, f32),
    axis_v: (f32, f32),
) {
    let determinant = axis_u.0 * axis_v.1 - axis_u.1 * axis_v.0;
    if determinant.abs() < f32::EPSILON {
        return;
    }
    for y in 0..destination.height() {
        for x in 0..destination.width() {
            let dx = x as f32 + 0.5 - origin.0;
            let dy = y as f32 + 0.5 - origin.1;
            let u = (dx * axis_v.1 - dy * axis_v.0) / determinant;
            let v = (axis_u.0 * dy - axis_u.1 * dx) / determinant;
            if (0.0..1.0).contains(&u) && (0.0..1.0).contains(&v) {
                let sx = (u * texture.width() as f32) as u32;
                let sy = (v * texture.height() as f32) as u32;
                let foreground = texture.get_pixel(sx.min(7), sy.min(7));
                let background = destination.get_pixel(x, y);
                let alpha = u32::from(foreground[3]);
                if alpha == 255 {
                    destination.put_pixel(x, y, *foreground);
                } else if alpha > 0 {
                    let background_alpha = u32::from(background[3]);
                    let inverse_alpha = 255 - alpha;
                    let output_alpha = alpha + (background_alpha * inverse_alpha + 127) / 255;
                    let mut blended = [0_u8; 4];
                    for channel in 0..3 {
                        let front = u32::from(foreground[channel]) * alpha;
                        let back =
                            (u32::from(background[channel]) * background_alpha * inverse_alpha
                                + 127)
                                / 255;
                        blended[channel] = ((front + back) / output_alpha.max(1)).min(255) as u8;
                    }
                    blended[3] = output_alpha.min(255) as u8;
                    destination.put_pixel(x, y, Rgba(blended));
                }
            }
        }
    }
}

async fn serve_texture(state: &AppState, hash: &str, request_headers: &HeaderMap) -> Response {
    let file_path = state.config.textures_dir.join(hash);
    let metadata = match tokio::fs::metadata(&file_path).await {
        Ok(metadata) if metadata.is_file() => metadata,
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    let bytes = match tokio::fs::read(&file_path).await {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::warn!(%error, hash, "texture file could not be read");
            return StatusCode::NOT_FOUND.into_response();
        }
    };
    let modified = metadata.modified().ok();
    let etag = content_etag(&bytes);
    let ttl = cache_ttl(state).await;
    let mut response_headers = HeaderMap::new();
    response_headers.insert(CONTENT_TYPE, HeaderValue::from_static("image/png"));
    response_headers.insert(ETAG, HeaderValue::from_str(&etag).unwrap());
    response_headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_str(&format!("public, max-age={ttl}")).unwrap(),
    );
    response_headers.insert(
        CONTENT_LENGTH,
        HeaderValue::from_str(&metadata.len().to_string()).unwrap(),
    );
    if let Some(modified) = modified {
        response_headers.insert(
            LAST_MODIFIED,
            HeaderValue::from_str(&httpdate::fmt_http_date(modified)).unwrap(),
        );
    }

    let has_if_none_match = request_headers.contains_key(IF_NONE_MATCH);
    if (has_if_none_match && header_has_etag(request_headers, &etag))
        || (!has_if_none_match
            && modified.is_some_and(|time| not_modified_since(request_headers, time)))
    {
        let mut response = StatusCode::NOT_MODIFIED.into_response();
        *response.headers_mut() = response_headers;
        response.headers_mut().remove(CONTENT_TYPE);
        response.headers_mut().remove(CONTENT_LENGTH);
        return response;
    }

    let mut response = Response::new(Body::from(bytes));
    *response.headers_mut() = response_headers;
    response
}

fn content_etag(bytes: &[u8]) -> String {
    format!("\"{:x}\"", Md5::digest(bytes))
}
async fn cache_ttl(state: &AppState) -> u64 {
    let Some(database) = &state.database else {
        return 31_536_000;
    };
    database
        .option(&state.config.database.table_prefix, "cache_expire_time")
        .await
        .ok()
        .flatten()
        .and_then(|value| value.parse().ok())
        .unwrap_or(31_536_000)
}

fn header_has_etag(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get(IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|item| item.trim() == "*" || item.trim() == etag)
        })
}

fn not_modified_since(headers: &HeaderMap, modified: SystemTime) -> bool {
    headers
        .get(IF_MODIFIED_SINCE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| httpdate::parse_http_date(value).ok())
        .is_some_and(|since| {
            modified
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                <= since
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
        })
}

fn valid_texture_hash(hash: &str) -> bool {
    hash.len() == 64 && hash.chars().all(|character| character.is_ascii_hexdigit())
}

fn parse_legacy_datetime(value: &str) -> Option<SystemTime> {
    let naive = NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S").ok()?;
    let offset = FixedOffset::east_opt(8 * 60 * 60)?;
    let datetime = offset.from_local_datetime(&naive).single()?;
    let timestamp = datetime.timestamp();
    if timestamp >= 0 {
        Some(SystemTime::UNIX_EPOCH + Duration::from_secs(timestamp as u64))
    } else {
        SystemTime::UNIX_EPOCH.checked_sub(Duration::from_secs(timestamp.unsigned_abs()))
    }
}

fn unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(Health {
            status: "not_ready",
        }),
    )
        .into_response()
}

const COPYRIGHTS: [&str; 7] = [
    "Powered with ❤ by Blessing Skin Server.",
    "Powered by Blessing Skin Server.",
    "Proudly powered by Blessing Skin Server.",
    "由 Blessing Skin Server 强力驱动。",
    "采用 Blessing Skin Server 搭建。",
    "使用 Blessing Skin Server 稳定运行。",
    "自豪地采用 Blessing Skin Server。",
];

#[cfg(test)]
mod tests {
    use image::{GenericImageView, ImageFormat};

    use super::{
        Rgba, RgbaImage, content_etag, parse_legacy_datetime, render_cape_preview,
        render_skin_avatar, render_skin_preview, router, valid_texture_hash,
    };

    async fn submit_test_registration(
        app: &axum::Router,
        cookie: &str,
        captcha: &str,
        email: &str,
        player_name: &str,
        ip: &str,
    ) -> axum::response::Response {
        use axum::body::Body;
        use tower::ServiceExt;

        app.clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/auth/register")
                    .header("cookie", cookie)
                    .header("x-real-ip", ip)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "email": email,
                            "password": "secure pass 123",
                            "player_name": player_name,
                            "captcha": captcha
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    async fn session_request(
        app: &axum::Router,
        cookie: &str,
        method: &str,
        uri: &str,
        body: Option<&str>,
    ) -> axum::response::Response {
        use axum::body::Body;
        use tower::ServiceExt;

        let mut builder = axum::http::Request::builder()
            .method(method)
            .uri(uri)
            .header("cookie", cookie)
            .header("accept", "application/json");
        let body = if let Some(body) = body {
            builder = builder.header("content-type", "application/json");
            Body::from(body.to_owned())
        } else {
            Body::empty()
        };
        app.clone()
            .oneshot(builder.body(body).unwrap())
            .await
            .unwrap()
    }

    async fn issue_test_captcha(
        app: &axum::Router,
        challenges: &std::sync::Arc<
            std::sync::Mutex<std::collections::HashMap<String, (String, std::time::Instant)>>,
        >,
    ) -> (String, String) {
        use axum::{
            body::{Body, to_bytes},
            http::{Request, header::SET_COOKIE},
        };
        use tower::ServiceExt;

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/auth/captcha")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "image/jpeg");
        let set_cookie = response
            .headers()
            .get(SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        let cookie = set_cookie.split(';').next().unwrap().to_owned();
        let jpeg = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert!(jpeg.starts_with(&[0xff, 0xd8]));
        let id = cookie.split_once('=').unwrap().1.to_owned();
        let answer = challenges.lock().unwrap().get(&id).unwrap().0.clone();
        (cookie, answer)
    }

    #[tokio::test]
    async fn closet_validation_errors_use_the_requested_field_name() {
        use axum::body::to_bytes;

        let response = super::closet_validation_error("tid", "en");
        assert_eq!(
            response.status(),
            axum::http::StatusCode::UNPROCESSABLE_ENTITY
        );
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(value["errors"]["tid"][0].as_str().is_some());
        assert!(value["errors"]["field"].is_null());
    }
    #[test]
    fn creates_unique_legacy_notification_ids() {
        let first = super::new_notification_id();
        let second = super::new_notification_id();
        assert_eq!(first.len(), 36);
        assert_eq!(second.len(), 36);
        assert_eq!(first.as_bytes()[14], b'4');
        assert_ne!(first, second);
    }
    #[test]
    fn parses_legacy_boolean_options() {
        assert!(super::legacy_option_bool(Some("true")));
        assert!(super::legacy_option_bool(Some("(true)")));
        assert!(!super::legacy_option_bool(Some("false")));
        assert!(!super::legacy_option_bool(Some("0")));
        assert!(!super::legacy_option_bool(None));
    }
    #[test]
    fn parses_legacy_texture_ids_and_clear_request_shapes() {
        use serde_json::json;

        assert_eq!(super::texture_request_id(Some(&json!(0))), Some(0));
        assert_eq!(super::texture_request_id(Some(&json!("12"))), Some(12));
        assert_eq!(super::texture_request_id(Some(&json!(""))), None);
        assert_eq!(super::texture_request_id(Some(&json!(null))), None);

        let by_field = json!({"skin": null});
        assert!(by_field.get("skin").is_some());
        let by_type = json!({"type": ["cape"]});
        assert!(
            by_type["type"]
                .as_array()
                .is_some_and(|types| types.iter().any(|value| value.as_str() == Some("cape")))
        );
    }
    #[test]
    fn serializes_legacy_closet_item_texture_and_pivot_fields() {
        let item = super::closet_item_json(crate::database::ClosetTextureRecord {
            tid: 13,
            name: "Other skin".to_owned(),
            texture_type: "alex".to_owned(),
            hash: "skin-hash".to_owned(),
            size: 10,
            uploader: 8,
            is_public: true,
            upload_at: "2026-10-01 10:02:00".to_owned(),
            likes: 2,
            user_uid: 7,
            texture_tid: 13,
            item_name: Some("Saved name".to_owned()),
        });
        assert_eq!(item["tid"], 13);
        assert_eq!(item["type"], "alex");
        assert_eq!(item["public"], true);
        assert_eq!(item["pivot"]["user_uid"], 7);
        assert_eq!(item["pivot"]["texture_tid"], 13);
        assert_eq!(item["pivot"]["item_name"], "Saved name");
    }
    #[test]
    fn validates_legacy_texture_name_rules() {
        assert!(super::valid_texture_name("skin_01", ""));
        assert!(!super::valid_texture_name("", ""));
        assert!(super::valid_texture_name("skin_01", "^[a-z0-9_]+$"));
        assert!(!super::valid_texture_name("Skin 01", "^[a-z0-9_]+$"));
        assert!(!super::valid_texture_name("anything", "["));
    }

    #[test]
    fn parses_legacy_admin_report_search_tokens() {
        let parsed =
            super::parse_report_search(Some("status:0 sort:-report_at tid:41 stolen skin"));
        assert_eq!(parsed.filters.status, Some(0));
        assert_eq!(parsed.filters.tid, Some(41));
        assert_eq!(parsed.filters.reason.as_deref(), Some("stolen skin"));
        assert_eq!(parsed.sort_field, "report_at");
        assert!(parsed.descending);

        let parsed = super::parse_report_search(None);
        assert_eq!(parsed.sort_field, "report_at");
        assert!(parsed.descending);
        assert!(parsed.filters.status.is_none());
    }

    #[test]
    fn serializes_legacy_admin_report_list_fields() {
        let report = super::report_management_json(crate::database::ReportManagementRecord {
            id: 5,
            tid: 41,
            uploader: 7,
            reporter: 8,
            reason: "stolen skin".to_owned(),
            status: 0,
            report_at: "2026-10-02 14:00:00".to_owned(),
            texture_tid: Some(41),
            texture_name: Some("Skin".to_owned()),
            texture_type: Some("alex".to_owned()),
            texture_hash: Some("skin-hash".to_owned()),
            texture_size: Some(8),
            texture_uploader: Some(7),
            texture_public: Some(true),
            texture_upload_at: Some("2026-10-01 10:00:00".to_owned()),
            texture_likes: Some(1),
            texture_uploader_uid: Some(7),
            texture_uploader_email: Some("alex@example.test".to_owned()),
            texture_uploader_nickname: Some("Alex User".to_owned()),
            texture_uploader_locale: Some("zh_CN".to_owned()),
            texture_uploader_score: Some(42),
            texture_uploader_avatar: Some(11),
            texture_uploader_permission: Some(0),
            texture_uploader_ip: Some("192.0.2.1".to_owned()),
            texture_uploader_last_sign_at: Some("2026-10-01 10:00:00".to_owned()),
            texture_uploader_register_at: Some("2025-01-02 03:04:05".to_owned()),
            texture_uploader_verified: Some(true),
            texture_uploader_is_dark_mode: Some(false),
            informer_uid: Some(8),
            informer_email: Some("admin@example.test".to_owned()),
            informer_nickname: Some("Admin".to_owned()),
            informer_locale: Some("en".to_owned()),
            informer_score: Some(50),
            informer_avatar: Some(0),
            informer_permission: Some(1),
            informer_ip: Some("192.0.2.2".to_owned()),
            informer_last_sign_at: Some(String::new()),
            informer_register_at: Some(String::new()),
            informer_verified: Some(true),
            informer_is_dark_mode: Some(false),
        });
        assert_eq!(report["id"], 5);
        assert_eq!(report["tid"], 41);
        assert_eq!(report["texture"]["type"], "alex");
        assert_eq!(report["texture_uploader"]["nickname"], "Alex User");
        assert_eq!(report["texture_uploader"]["ip"], "192.0.2.1");
        assert_eq!(report["informer"]["uid"], 8);
        assert_eq!(report["informer"]["email"], "admin@example.test");
        assert_eq!(report["reason"], "stolen skin");
    }

    #[tokio::test]
    async fn formats_report_review_validation_errors_by_action() {
        use axum::body::to_bytes;

        let response = super::report_review_validation_error("en");
        assert_eq!(
            response.status(),
            axum::http::StatusCode::UNPROCESSABLE_ENTITY
        );
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(value["errors"]["action"][0].as_str().is_some());
    }

    #[tokio::test]
    async fn formats_report_validation_errors_by_field() {
        use axum::body::to_bytes;

        let response = super::report_validation_error("reason", "en");
        assert_eq!(
            response.status(),
            axum::http::StatusCode::UNPROCESSABLE_ENTITY
        );
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(value["errors"]["reason"][0].as_str().is_some());
        assert!(value["errors"]["field"].is_null());
    }
    #[test]
    fn sanitizes_png_uploads_and_checks_skin_dimensions() {
        use image::ImageFormat;
        use std::io::Cursor;

        let mut encoded = Vec::new();
        image::DynamicImage::new_rgba8(64, 32)
            .write_to(&mut Cursor::new(&mut encoded), ImageFormat::Png)
            .unwrap();
        assert_eq!(super::png_dimensions(&encoded), Some((64, 32)));
        assert!(super::valid_texture_dimensions("steve", 64, 32));
        assert!(!super::valid_texture_dimensions("alex", 64, 32));
        assert!(super::valid_texture_dimensions("alex", 64, 64));
        assert!(super::valid_texture_dimensions("cape", 64, 32));
        assert!(!super::valid_texture_dimensions("steve", 63, 32));
        let sanitized = super::sanitize_png(&encoded).unwrap();
        assert_eq!(super::png_dimensions(&sanitized), Some((64, 32)));
        assert!(super::png_dimensions(b"not an image").is_none());
    }

    #[test]
    fn parses_legacy_multipart_boolean_values() {
        assert_eq!(super::parse_legacy_form_bool("1"), Some(true));
        assert_eq!(super::parse_legacy_form_bool("true"), Some(true));
        assert_eq!(super::parse_legacy_form_bool("0"), Some(false));
        assert_eq!(super::parse_legacy_form_bool("false"), Some(false));
        assert_eq!(super::parse_legacy_form_bool("maybe"), None);
    }

    #[test]
    fn calculates_legacy_texture_deletion_score_refunds() {
        let texture = crate::database::TextureInfoRecord {
            tid: 1,
            name: "Public".to_owned(),
            texture_type: "alex".to_owned(),
            hash: "hash".to_owned(),
            size: 4,
            uploader: 7,
            is_public: true,
            upload_at: String::new(),
            likes: 0,
        };
        assert_eq!(
            super::texture_delete_score_refund(&texture, true, 0, 10, 3, true),
            -3
        );
        assert_eq!(
            super::texture_delete_score_refund(&texture, true, 0, 10, 3, false),
            0
        );
        assert_eq!(
            super::texture_delete_score_refund(&texture, false, 0, 10, 3, true),
            -3
        );
    }

    #[test]
    fn calculates_legacy_texture_privacy_score_changes() {
        let public_texture = crate::database::TextureInfoRecord {
            tid: 1,
            name: "Public".to_owned(),
            texture_type: "alex".to_owned(),
            hash: "hash".to_owned(),
            size: 4,
            uploader: 7,
            is_public: true,
            upload_at: String::new(),
            likes: 0,
        };
        assert_eq!(
            super::texture_privacy_score_diff(&public_texture, 0, 10, 3, true),
            -43
        );
        assert_eq!(
            super::texture_privacy_score_diff(&public_texture, 0, 10, 3, false),
            -40
        );
        let private_texture = crate::database::TextureInfoRecord {
            is_public: false,
            ..public_texture
        };
        assert_eq!(
            super::texture_privacy_score_diff(&private_texture, 0, 10, 3, true),
            40
        );
    }

    #[test]
    fn renders_square_skin_and_aspect_preserving_cape_previews() {
        let skin = RgbaImage::from_pixel(64, 64, Rgba([40, 80, 120, 255]));
        let skin_preview = render_skin_preview(&skin, true, 200);
        assert_eq!((skin_preview.width(), skin_preview.height()), (200, 200));
        assert!(skin_preview.pixels().any(|(_, _, pixel)| pixel[3] > 0));

        let cape = RgbaImage::from_pixel(64, 32, Rgba([10, 120, 30, 255]));
        let cape_preview = render_cape_preview(&cape, 160);
        assert_eq!((cape_preview.width(), cape_preview.height()), (100, 160));
        assert_eq!(cape_preview.get_pixel(0, 0), Rgba([10, 120, 30, 255]));
    }

    #[test]
    fn renders_skin_face_and_isometric_avatar_layers() {
        let mut skin = RgbaImage::from_pixel(64, 64, Rgba([0, 0, 0, 0]));
        for y in 8..16 {
            for x in 8..16 {
                skin.put_pixel(x, y, Rgba([220, 30, 40, 255]));
            }
        }
        for y in 8..16 {
            for x in 40..48 {
                skin.put_pixel(x, y, Rgba([0, 0, 0, 0]));
            }
        }
        let flat = render_skin_avatar(&skin, false);
        assert_eq!((flat.width(), flat.height()), (8, 8));
        assert_eq!(flat.get_pixel(0, 0), Rgba([220, 30, 40, 255]));

        let isometric = render_skin_avatar(&skin, true);
        assert_eq!((isometric.width(), isometric.height()), (64, 64));
        assert_eq!(isometric.get_pixel(20, 30), Rgba([220, 30, 40, 255]));
        assert!(isometric.pixels().any(|(_, _, pixel)| pixel[3] > 0));
    }

    #[test]
    fn validates_legacy_texture_types() {
        assert!(super::valid_texture_type("steve"));
        assert!(super::valid_texture_type("alex"));
        assert!(super::valid_texture_type("cape"));
        assert!(!super::valid_texture_type("slim"));
        assert!(!super::valid_texture_type("Cape"));
    }

    #[test]
    fn serializes_legacy_texture_info_fields() {
        use serde_json::json;

        let texture = super::texture_info_json(crate::database::TextureInfoRecord {
            tid: 13,
            name: "Other skin".to_owned(),
            texture_type: "alex".to_owned(),
            hash: "texture-hash".to_owned(),
            size: 10,
            uploader: 8,
            is_public: true,
            upload_at: "2026-10-01 10:02:00".to_owned(),
            likes: 2,
        });
        assert_eq!(
            texture,
            json!({
                "tid": 13,
                "name": "Other skin",
                "type": "alex",
                "hash": "texture-hash",
                "size": 10,
                "uploader": 8,
                "public": true,
                "upload_at": "2026-10-01 10:02:00",
                "likes": 2
            })
        );
    }

    #[test]
    fn validates_texture_hashes_before_joining_them_to_storage_paths() {
        assert!(valid_texture_hash(&"a".repeat(64)));
        assert!(!valid_texture_hash("../textures"));
        assert!(!valid_texture_hash(&"a".repeat(63)));
    }

    #[test]
    fn parses_legacy_local_datetime_as_shanghai_time() {
        let parsed = parse_legacy_datetime("2026-10-02 12:00:00").unwrap();
        assert_eq!(
            httpdate::fmt_http_date(parsed),
            "Fri, 02 Oct 2026 04:00:00 GMT"
        );
    }

    #[test]
    fn uses_content_md5_for_legacy_texture_etags() {
        assert_eq!(content_etag(b"abc"), "\"900150983cd24fb0d6963f7d28e17f72\"");
    }

    #[tokio::test]
    async fn api_user_rejects_requests_without_a_bearer_token() {
        use axum::{
            body::Body,
            http::{Request, StatusCode},
        };
        use sqlx::sqlite::SqliteConnectOptions;
        use std::{path::PathBuf, sync::Arc};
        use tower::ServiceExt;

        let config = crate::config::Config {
            bind: "127.0.0.1:3000".parse().unwrap(),
            version: "test",
            locale: "en".to_owned(),
            database: crate::config::DatabaseConfig {
                connection: crate::config::DatabaseConnection::Sqlite(SqliteConnectOptions::new()),
                table_prefix: String::new(),
            },
            textures_dir: PathBuf::new(),
            plugins_dir: PathBuf::new(),
            app_url: "http://localhost".to_owned(),
            passport_public_key: None,
            password_method: "BCRYPT".to_owned(),
            password_salt: String::new(),
            app_key: None,
            mail: crate::config::MailConfig::default(),
        };
        let app = router(crate::AppState {
            config: Arc::new(config),
            database: None,
            passport_key: None,
            session_key: None,
            login_failures: Default::default(),
            captcha_challenges: Default::default(),
            mail_limits: Default::default(),
        });
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/user")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let users_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/admin/users")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(users_response.status(), StatusCode::UNAUTHORIZED);
        let closet_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/admin/closet/7")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(closet_response.status(), StatusCode::UNAUTHORIZED);
        let report_response = app
            .oneshot(
                Request::builder()
                    .uri("/api/admin/reports")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(report_response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn login_issues_a_session_that_opens_the_user_dashboard() {
        use axum::{
            body::{Body, to_bytes},
            http::{Request, StatusCode, header::SET_COOKIE},
        };
        use bcrypt;
        use sqlx::sqlite::SqlitePoolOptions;
        use std::{path::PathBuf, sync::Arc};
        use tower::ServiceExt;

        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query("CREATE TABLE users (uid INTEGER PRIMARY KEY, email TEXT NOT NULL, nickname TEXT NOT NULL, locale TEXT, score INTEGER NOT NULL, avatar INTEGER NOT NULL, password TEXT NOT NULL, ip TEXT NOT NULL DEFAULT '', permission INTEGER NOT NULL, last_sign_at TEXT NOT NULL, register_at TEXT NOT NULL, verified BOOLEAN NOT NULL, is_dark_mode BOOLEAN NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE players (pid INTEGER PRIMARY KEY, uid INTEGER NOT NULL, name TEXT NOT NULL, tid_skin INTEGER NOT NULL, tid_cape INTEGER NOT NULL, last_modified TEXT NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE textures (tid INTEGER PRIMARY KEY, name TEXT NOT NULL, type TEXT NOT NULL, hash TEXT NOT NULL, size INTEGER NOT NULL, uploader INTEGER NOT NULL, public BOOLEAN NOT NULL, upload_at TEXT NOT NULL, likes INTEGER NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE reports (id INTEGER PRIMARY KEY AUTOINCREMENT, tid INTEGER NOT NULL, uploader INTEGER NOT NULL, reporter INTEGER NOT NULL, reason TEXT NOT NULL, status INTEGER NOT NULL, report_at TEXT NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE user_closet (user_uid INTEGER NOT NULL, texture_tid INTEGER NOT NULL, item_name TEXT NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE options (id INTEGER PRIMARY KEY AUTOINCREMENT, option_name TEXT NOT NULL, option_value TEXT NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE oauth_clients (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, name TEXT NOT NULL, secret TEXT NOT NULL, provider TEXT, redirect TEXT NOT NULL, personal_access_client BOOLEAN NOT NULL, password_client BOOLEAN NOT NULL, revoked BOOLEAN NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE oauth_access_tokens (id TEXT PRIMARY KEY, user_id INTEGER, client_id INTEGER NOT NULL, scopes TEXT NOT NULL, revoked BOOLEAN NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE oauth_refresh_tokens (id TEXT PRIMARY KEY, access_token_id TEXT NOT NULL, revoked BOOLEAN NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE notifications (id TEXT PRIMARY KEY, type TEXT NOT NULL, notifiable_type TEXT NOT NULL, notifiable_id INTEGER NOT NULL, data TEXT NOT NULL, read_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE oauth_auth_codes (id TEXT PRIMARY KEY, user_id INTEGER, client_id INTEGER NOT NULL, scopes TEXT NOT NULL, revoked BOOLEAN NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        let password_hash = bcrypt::hash("correct horse", 4).unwrap();
        sqlx::query("INSERT INTO users (uid,email,nickname,locale,score,avatar,password,permission,last_sign_at,register_at,verified,is_dark_mode) VALUES (7,'alex@example.test','Alex User','en',5,0,?,1,'','',1,0)")
            .bind(password_hash)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO users (uid,email,nickname,locale,score,avatar,password,permission,last_sign_at,register_at,verified,is_dark_mode) VALUES (8,'uploader@example.test','Uploader','en',20,0,'',0,'','',1,0)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO players (pid,uid,name,tid_skin,tid_cape,last_modified) VALUES (3,7,'Alex',0,0,'2026-10-02 12:00:00')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO textures (tid,name,type,hash,size,uploader,public,upload_at,likes) VALUES (2,'Reported skin','alex','reported-hash',8,7,1,'2026-10-01 10:00:00',1)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO reports (id,tid,uploader,reporter,reason,status,report_at) VALUES (1,2,7,7,'stolen skin',0,'2026-10-02 14:00:00'), (2,2,8,7,'second report',0,'2026-10-02 15:00:00'), (3,2,7,7,'third report',0,'2026-10-02 13:00:00'), (4,99,8,7,'texture already deleted',0,'2026-10-02 12:00:00')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO options (option_name,option_value) VALUES ('reporter_score_modification','2'), ('reporter_reward_score','3')")
            .execute(&pool)
            .await
            .unwrap();

        let texture_test_dir = std::env::temp_dir().join(format!(
            "blessing-skin-rs-preview-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&texture_test_dir).unwrap();
        let preview_skin_hash = "a".repeat(64);
        let preview_cape_hash = "b".repeat(64);
        for (hash, width, height, color) in [
            (&preview_skin_hash, 64, 64, Rgba([40, 80, 120, 255])),
            (&preview_cape_hash, 64, 32, Rgba([10, 120, 30, 255])),
        ] {
            let mut image_bytes = Vec::new();
            image::DynamicImage::ImageRgba8(RgbaImage::from_pixel(width, height, color))
                .write_to(
                    &mut std::io::Cursor::new(&mut image_bytes),
                    ImageFormat::Png,
                )
                .unwrap();
            std::fs::write(texture_test_dir.join(hash), image_bytes).unwrap();
        }

        let secret = "a test APP_KEY with enough entropy".to_owned();
        let config = crate::config::Config {
            bind: "127.0.0.1:3000".parse().unwrap(),
            version: "test",
            locale: "en".to_owned(),
            database: crate::config::DatabaseConfig {
                connection: crate::config::DatabaseConnection::Sqlite(
                    sqlx::sqlite::SqliteConnectOptions::new(),
                ),
                table_prefix: String::new(),
            },
            textures_dir: texture_test_dir.clone(),
            plugins_dir: PathBuf::new(),
            app_url: "http://localhost".to_owned(),
            passport_public_key: None,
            password_method: "BCRYPT".to_owned(),
            password_salt: String::new(),
            app_key: Some(secret.clone()),
            mail: crate::config::MailConfig {
                mailer: "array".to_owned(),
                ..crate::config::MailConfig::default()
            },
        };
        let captcha_challenges = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let app = router(crate::AppState {
            config: Arc::new(config),
            database: Some(crate::database::DatabasePool::Sqlite(pool.clone())),
            passport_key: None,
            session_key: Some(jsonwebtoken::EncodingKey::from_secret(secret.as_bytes())),
            login_failures: Default::default(),
            captcha_challenges: captcha_challenges.clone(),
            mail_limits: Default::default(),
        });
        let homepage = app
            .clone()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(homepage.status(), StatusCode::OK);
        let homepage_html = to_bytes(homepage.into_body(), usize::MAX).await.unwrap();
        let homepage_html = String::from_utf8(homepage_html.to_vec()).unwrap();
        assert!(homepage_html.contains("Skin Server"));
        assert!(homepage_html.contains("/skinlib"));

        let avatar = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/avatar/user/7?png&size=16")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(avatar.status(), StatusCode::OK);
        assert_eq!(
            avatar
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap(),
            "image/png"
        );
        assert!(
            avatar
                .headers()
                .get(axum::http::header::CACHE_CONTROL)
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("public, max-age=")
        );
        let avatar_etag = avatar
            .headers()
            .get(axum::http::header::ETAG)
            .unwrap()
            .clone();
        let avatar_bytes = to_bytes(avatar.into_body(), usize::MAX).await.unwrap();
        let decoded_avatar =
            image::load_from_memory_with_format(&avatar_bytes, ImageFormat::Png).unwrap();
        assert_eq!((decoded_avatar.width(), decoded_avatar.height()), (16, 16));
        let cached_avatar = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/avatar/user/7?png&size=16")
                    .header(axum::http::header::IF_NONE_MATCH, avatar_etag)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cached_avatar.status(), StatusCode::NOT_MODIFIED);

        let avatar_webp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/avatar/player/Alex?3d&size=24")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(avatar_webp.status(), StatusCode::OK);
        assert_eq!(
            avatar_webp
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap(),
            "image/webp"
        );
        let avatar_webp = to_bytes(avatar_webp.into_body(), usize::MAX).await.unwrap();
        let decoded_avatar = image::load_from_memory(&avatar_webp).unwrap();
        assert_eq!((decoded_avatar.width(), decoded_avatar.height()), (24, 24));

        let login_page = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/auth/login")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login_page.status(), StatusCode::OK);
        let login_html = to_bytes(login_page.into_body(), usize::MAX).await.unwrap();
        assert!(
            String::from_utf8(login_html.to_vec())
                .unwrap()
                .contains("Email or player name")
        );

        let forgot_page = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/auth/forgot")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(forgot_page.status(), StatusCode::OK);
        let forgot_page = String::from_utf8(
            to_bytes(forgot_page.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(forgot_page.contains("/auth/forgot"));

        let register_page = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/auth/register")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(register_page.status(), StatusCode::OK);
        let register_html = to_bytes(register_page.into_body(), usize::MAX)
            .await
            .unwrap();
        let register_html = String::from_utf8(register_html.to_vec()).unwrap();
        assert!(register_html.contains("Player name"));
        assert!(register_html.contains("/auth/captcha"));
        sqlx::query("INSERT INTO options (option_name,option_value) VALUES ('register_with_player_name','true'), ('user_initial_score','73'), ('regs_per_ip','2')")
            .execute(&pool)
            .await
            .unwrap();

        let (captcha_cookie, captcha_answer) = issue_test_captcha(&app, &captcha_challenges).await;
        let registration = submit_test_registration(
            &app,
            &captcha_cookie,
            &captcha_answer,
            "first@example.test",
            "NewGuy",
            "203.0.113.40",
        )
        .await;
        assert_eq!(registration.status(), StatusCode::OK);
        let registered_cookie = registration
            .headers()
            .get(SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let registration_body: serde_json::Value = serde_json::from_slice(
            &to_bytes(registration.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(registration_body["code"], 0);
        let registered_user: (i64, String, i64, String, i32, bool, i64, String, String) =
            sqlx::query_as("SELECT uid,nickname,score,ip,permission,verified,avatar,last_sign_at,register_at FROM users WHERE email = 'first@example.test'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(registered_user.1, "NewGuy");
        assert_eq!(registered_user.2, 73);
        assert_eq!(registered_user.3, "203.0.113.40");
        assert_eq!(registered_user.4, 0);
        assert!(!registered_user.5);
        assert_eq!(registered_user.6, 0);
        assert!(registered_user.7 < registered_user.8);
        let registered_player: (i64, String, i64, i64) =
            sqlx::query_as("SELECT uid,name,tid_skin,tid_cape FROM players WHERE name = 'NewGuy'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            registered_player,
            (registered_user.0, "NewGuy".to_owned(), 0, 0)
        );
        let registered_password: String =
            sqlx::query_scalar("SELECT password FROM users WHERE uid = ?")
                .bind(registered_user.0)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(crate::auth::verify_legacy_password(
            "secure pass 123",
            &registered_password,
            "BCRYPT",
            ""
        ));
        sqlx::query("INSERT INTO notifications (id,type,notifiable_type,notifiable_id,data,read_at,created_at,updated_at) VALUES (?,'App\\Notifications\\SiteMessage','App\\Models\\User',?,?,NULL,'2026-10-02 14:00:00','2026-10-02 14:00:00')")
            .bind("welcome-1")
            .bind(registered_user.0)
            .bind(r#"{"title":"Welcome note","content":"**Hello**"}"#)
            .execute(&pool)
            .await
            .unwrap();
        let registered_dashboard = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/user")
                    .header("cookie", registered_cookie.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(registered_dashboard.status(), StatusCode::OK);
        let registered_dashboard = String::from_utf8(
            to_bytes(registered_dashboard.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(registered_dashboard.contains("Welcome note"));
        let read_notification = session_request(
            &app,
            &registered_cookie,
            "POST",
            "/user/notifications/welcome-1",
            None,
        )
        .await;
        assert_eq!(read_notification.status(), StatusCode::OK);
        let read_notification: serde_json::Value = serde_json::from_slice(
            &to_bytes(read_notification.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(read_notification["title"], "Welcome note");
        assert!(
            read_notification["content"]
                .as_str()
                .unwrap()
                .contains("<strong>Hello</strong>")
        );
        let reread_notification = session_request(
            &app,
            &registered_cookie,
            "POST",
            "/user/notifications/welcome-1",
            None,
        )
        .await;
        assert_eq!(reread_notification.status(), StatusCode::NOT_FOUND);

        let (forgot_captcha_cookie, forgot_captcha_answer) =
            issue_test_captcha(&app, &captcha_challenges).await;
        let forgot_request = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/forgot")
                    .header("cookie", forgot_captcha_cookie)
                    .header("x-real-ip", "203.0.113.41")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "email": "first@example.test",
                            "captcha": forgot_captcha_answer
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(forgot_request.status(), StatusCode::OK);
        let forgot_body: serde_json::Value = serde_json::from_slice(
            &to_bytes(forgot_request.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(forgot_body["code"], 0);

        sqlx::query("INSERT INTO options (option_name,option_value) VALUES ('require_verification','true'), ('score_per_player','10'), ('return_score','true')")
            .execute(&pool)
            .await
            .unwrap();
        let verification_dashboard =
            session_request(&app, &registered_cookie, "GET", "/user", None).await;
        let verification_dashboard = String::from_utf8(
            to_bytes(verification_dashboard.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(verification_dashboard.contains("Send verification email"));
        let sent_verification = session_request(
            &app,
            &registered_cookie,
            "POST",
            "/user/email-verification",
            None,
        )
        .await;
        let sent_verification: serde_json::Value = serde_json::from_slice(
            &to_bytes(sent_verification.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(sent_verification["code"], 0);
        let repeated_verification = session_request(
            &app,
            &registered_cookie,
            "POST",
            "/user/email-verification",
            None,
        )
        .await;
        let repeated_verification: serde_json::Value = serde_json::from_slice(
            &to_bytes(repeated_verification.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(repeated_verification["code"], 1);

        let unverified_player_page =
            session_request(&app, &registered_cookie, "GET", "/user/player", None).await;
        assert_eq!(unverified_player_page.status(), StatusCode::FORBIDDEN);
        let unverified_upload_page =
            session_request(&app, &registered_cookie, "GET", "/skinlib/upload", None).await;
        assert_eq!(unverified_upload_page.status(), StatusCode::FORBIDDEN);
        let verification_path = format!("/auth/verify/{}", registered_user.0);
        let verification_signature = super::signature_hex(&secret, &verification_path).unwrap();
        let verification_uri = format!("{verification_path}?signature={verification_signature}");
        let verification_page = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&verification_uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(verification_page.status(), StatusCode::OK);
        let verification_html = String::from_utf8(
            to_bytes(verification_page.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(verification_html.contains("Verify email"));
        let tampered_verification = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("{verification_uri}&extra=changed"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(tampered_verification.status(), StatusCode::FORBIDDEN);
        let verified = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&verification_uri)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({"email":"first@example.test"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let verified: serde_json::Value =
            serde_json::from_slice(&to_bytes(verified.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(verified["code"], 0);
        let verified_state: bool = sqlx::query_scalar("SELECT verified FROM users WHERE uid = ?")
            .bind(registered_user.0)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(verified_state);

        let reset_path = format!("/auth/reset/{}", registered_user.0);
        let reset_expiry = super::unix_timestamp() + 3600;
        let reset_unsigned = format!("{reset_path}?expires={reset_expiry}");
        let reset_signature = super::signature_hex(&secret, &reset_unsigned).unwrap();
        let reset_uri = format!("{reset_unsigned}&signature={reset_signature}");
        let reset_page = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&reset_uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(reset_page.status(), StatusCode::OK);
        let reset_html = String::from_utf8(
            to_bytes(reset_page.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(reset_html.contains("reset your password here"));
        let reset = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&reset_uri)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({"password":"new secure password"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let reset: serde_json::Value =
            serde_json::from_slice(&to_bytes(reset.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(reset["code"], 0);
        let reset_hash: String = sqlx::query_scalar("SELECT password FROM users WHERE uid = ?")
            .bind(registered_user.0)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(crate::auth::verify_legacy_password(
            "new secure password",
            &reset_hash,
            "BCRYPT",
            ""
        ));
        let expired = super::unix_timestamp().saturating_sub(1);
        let expired_unsigned = format!("{reset_path}?expires={expired}");
        let expired_signature = super::signature_hex(&secret, &expired_unsigned).unwrap();
        let expired_reset = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("{expired_unsigned}&signature={expired_signature}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(expired_reset.status(), StatusCode::FORBIDDEN);

        let player_page =
            session_request(&app, &registered_cookie, "GET", "/user/player", None).await;
        assert_eq!(player_page.status(), StatusCode::OK);
        let player_page = to_bytes(player_page.into_body(), usize::MAX).await.unwrap();
        let player_page = String::from_utf8(player_page.to_vec()).unwrap();
        assert!(player_page.contains("Add player"));
        assert!(player_page.contains("/user/player/list"));

        let player_list =
            session_request(&app, &registered_cookie, "GET", "/user/player/list", None).await;
        assert_eq!(player_list.status(), StatusCode::OK);
        let player_list: serde_json::Value =
            serde_json::from_slice(&to_bytes(player_list.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert!(
            player_list
                .as_array()
                .unwrap()
                .iter()
                .any(|player| { player["name"] == "NewGuy" && player["uid"] == registered_user.0 })
        );

        let forbidden_player = session_request(
            &app,
            &registered_cookie,
            "PUT",
            "/user/player/3/name",
            Some(r#"{"name":"NotMine"}"#),
        )
        .await;
        assert_eq!(forbidden_player.status(), StatusCode::FORBIDDEN);

        let added_player = session_request(
            &app,
            &registered_cookie,
            "POST",
            "/user/player",
            Some(r#"{"name":"WebPlayer"}"#),
        )
        .await;
        assert_eq!(added_player.status(), StatusCode::OK);
        let added_player: serde_json::Value = serde_json::from_slice(
            &to_bytes(added_player.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(added_player["code"], 0);
        let added_pid = added_player["data"]["pid"].as_i64().unwrap();

        let duplicate_player = session_request(
            &app,
            &registered_cookie,
            "POST",
            "/user/player",
            Some(r#"{"name":"Alex"}"#),
        )
        .await;
        assert_eq!(duplicate_player.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let renamed_player = session_request(
            &app,
            &registered_cookie,
            "PUT",
            &format!("/user/player/{added_pid}/name"),
            Some(r#"{"name":"WebRenamed"}"#),
        )
        .await;
        let renamed_player: serde_json::Value = serde_json::from_slice(
            &to_bytes(renamed_player.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(renamed_player["code"], 0);
        assert_eq!(renamed_player["data"]["name"], "WebRenamed");

        sqlx::query(
            "INSERT INTO user_closet (user_uid,texture_tid,item_name) VALUES (?,2,'Reported skin')",
        )
        .bind(registered_user.0)
        .execute(&pool)
        .await
        .unwrap();
        let applied_texture = session_request(
            &app,
            &registered_cookie,
            "PUT",
            &format!("/user/player/{added_pid}/textures"),
            Some(r#"{"skin":2}"#),
        )
        .await;
        let applied_texture: serde_json::Value = serde_json::from_slice(
            &to_bytes(applied_texture.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(applied_texture["code"], 0);
        assert_eq!(applied_texture["data"]["tid_skin"], 2);

        let cleared_texture = session_request(
            &app,
            &registered_cookie,
            "DELETE",
            &format!("/user/player/{added_pid}/textures?skin=true&cape=true"),
            None,
        )
        .await;
        let cleared_texture: serde_json::Value = serde_json::from_slice(
            &to_bytes(cleared_texture.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(cleared_texture["code"], 0);
        assert_eq!(cleared_texture["data"]["tid_skin"], 0);
        assert_eq!(cleared_texture["data"]["tid_cape"], 0);

        let deleted_player = session_request(
            &app,
            &registered_cookie,
            "DELETE",
            &format!("/user/player/{added_pid}"),
            None,
        )
        .await;
        let deleted_player: serde_json::Value = serde_json::from_slice(
            &to_bytes(deleted_player.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(deleted_player["code"], 0);
        let refunded_score: i64 = sqlx::query_scalar("SELECT score FROM users WHERE uid = ?")
            .bind(registered_user.0)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(refunded_score, 73);

        let closet_page =
            session_request(&app, &registered_cookie, "GET", "/user/closet", None).await;
        assert_eq!(closet_page.status(), StatusCode::OK);
        let closet_page = String::from_utf8(
            to_bytes(closet_page.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(closet_page.contains("Closet"));
        assert!(closet_page.contains("/user/closet/list"));
        sqlx::query("INSERT INTO textures (tid,name,type,hash,size,uploader,public,upload_at,likes) VALUES (20,'Closet texture','steve','0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',8,?,1,'2026-10-02 14:00:00',0)")
            .bind(registered_user.0)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO options (option_name,option_value) VALUES ('score_per_closet_item','5'), ('score_award_per_like','0')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE options SET option_value = 'true' WHERE option_name = 'return_score'")
            .execute(&pool)
            .await
            .unwrap();

        let initial_closet_ids =
            session_request(&app, &registered_cookie, "GET", "/user/closet/ids", None).await;
        let initial_closet_ids: serde_json::Value = serde_json::from_slice(
            &to_bytes(initial_closet_ids.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(initial_closet_ids, serde_json::json!([2]));

        let added_closet_item = session_request(
            &app,
            &registered_cookie,
            "POST",
            "/user/closet",
            Some(r#"{"tid":20,"name":"Closet item"}"#),
        )
        .await;
        let added_closet_item: serde_json::Value = serde_json::from_slice(
            &to_bytes(added_closet_item.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(added_closet_item["code"], 0);

        let closet_list = session_request(
            &app,
            &registered_cookie,
            "GET",
            "/user/closet/list?category=skin&q=Closet&page=1&perPage=6",
            None,
        )
        .await;
        assert_eq!(closet_list.status(), StatusCode::OK);
        let closet_list: serde_json::Value =
            serde_json::from_slice(&to_bytes(closet_list.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(closet_list["total"], 1);
        assert_eq!(closet_list["data"][0]["pivot"]["item_name"], "Closet item");
        assert_eq!(
            closet_list["data"][0]["hash"],
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );

        let all_closet_ids =
            session_request(&app, &registered_cookie, "GET", "/user/closet/ids", None).await;
        let all_closet_ids: serde_json::Value = serde_json::from_slice(
            &to_bytes(all_closet_ids.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(all_closet_ids, serde_json::json!([2, 20]));

        let renamed_closet_item = session_request(
            &app,
            &registered_cookie,
            "PUT",
            "/user/closet/20",
            Some(r#"{"name":"Renamed closet item"}"#),
        )
        .await;
        let renamed_closet_item: serde_json::Value = serde_json::from_slice(
            &to_bytes(renamed_closet_item.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(renamed_closet_item["code"], 0);

        let removed_closet_item =
            session_request(&app, &registered_cookie, "DELETE", "/user/closet/20", None).await;
        let removed_closet_item: serde_json::Value = serde_json::from_slice(
            &to_bytes(removed_closet_item.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(removed_closet_item["code"], 0);
        let closet_refunded_score: i64 =
            sqlx::query_scalar("SELECT score FROM users WHERE uid = ?")
                .bind(registered_user.0)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(closet_refunded_score, 73);
        sqlx::query("UPDATE options SET option_value = 'false' WHERE option_name = 'return_score'")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE options SET option_value = '0' WHERE option_name = 'score_per_closet_item'",
        )
        .execute(&pool)
        .await
        .unwrap();

        let skinlib_page = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/skinlib")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(skinlib_page.status(), StatusCode::OK);
        let skinlib_page = String::from_utf8(
            to_bytes(skinlib_page.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(skinlib_page.contains("/skinlib/list"));
        assert!(skinlib_page.contains("</title><style>"));

        let skinlib_list = session_request(
            &app,
            &registered_cookie,
            "GET",
            "/skinlib/list?filter=skin&sort=time&page=1",
            None,
        )
        .await;
        assert_eq!(skinlib_list.status(), StatusCode::OK);
        let skinlib_list: serde_json::Value = serde_json::from_slice(
            &to_bytes(skinlib_list.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(
            skinlib_list["data"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["tid"] == 20 && item["nickname"] == "NewGuy")
        );

        let skinlib_show =
            session_request(&app, &registered_cookie, "GET", "/skinlib/show/20", None).await;
        assert_eq!(skinlib_show.status(), StatusCode::OK);
        let skinlib_show = String::from_utf8(
            to_bytes(skinlib_show.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(
            skinlib_show
                .contains("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        );
        assert!(skinlib_show.contains("Add to closet"));

        let upload_page =
            session_request(&app, &registered_cookie, "GET", "/skinlib/upload", None).await;
        assert_eq!(upload_page.status(), StatusCode::OK);
        let upload_page = String::from_utf8(
            to_bytes(upload_page.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(upload_page.contains("/texture"));
        assert!(upload_page.contains("Current score"));
        assert!(upload_page.contains("</title><style>"));

        sqlx::query("INSERT INTO textures (tid,name,type,hash,size,uploader,public,upload_at,likes) VALUES (21,'Private texture','steve','private-hash',8,8,0,'2026-10-02 15:00:00',0)")
            .execute(&pool)
            .await
            .unwrap();
        let hidden_texture =
            session_request(&app, &registered_cookie, "GET", "/skinlib/show/21", None).await;
        assert_eq!(hidden_texture.status(), StatusCode::FORBIDDEN);

        sqlx::query(
            "UPDATE options SET option_value = '100' WHERE option_name = 'score_per_player'",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("UPDATE options SET option_value = 'false' WHERE option_name IN ('require_verification','return_score')")
            .execute(&pool)
            .await
            .unwrap();

        let (second_captcha_cookie, second_captcha_answer) =
            issue_test_captcha(&app, &captcha_challenges).await;
        let second_registration = submit_test_registration(
            &app,
            &second_captcha_cookie,
            &second_captcha_answer,
            "second@example.test",
            "NewGuy2",
            "203.0.113.40",
        )
        .await;
        let second_registration: serde_json::Value = serde_json::from_slice(
            &to_bytes(second_registration.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(second_registration["code"], 0);
        let (third_captcha_cookie, third_captcha_answer) =
            issue_test_captcha(&app, &captcha_challenges).await;
        let limited_registration = submit_test_registration(
            &app,
            &third_captcha_cookie,
            &third_captcha_answer,
            "third@example.test",
            "NewGuy3",
            "203.0.113.40",
        )
        .await;
        let limited_registration: serde_json::Value = serde_json::from_slice(
            &to_bytes(limited_registration.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(limited_registration["code"], 1);
        assert!(
            limited_registration["message"]
                .as_str()
                .unwrap()
                .contains("2 accounts")
        );

        let login = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"identification":"alex@example.test","password":"correct horse","keep":true}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login.status(), StatusCode::OK);
        let cookie = login
            .headers()
            .get(SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        assert!(
            login
                .headers()
                .get(SET_COOKIE)
                .unwrap()
                .to_str()
                .unwrap()
                .contains("Max-Age=2592000")
        );
        let body = to_bytes(login.into_body(), usize::MAX).await.unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["code"], 0);
        assert_eq!(result["data"]["redirectTo"], "/user");

        let dashboard = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/user")
                    .header("cookie", cookie.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(dashboard.status(), StatusCode::OK);
        let dashboard_html = to_bytes(dashboard.into_body(), usize::MAX).await.unwrap();
        let dashboard_html = String::from_utf8(dashboard_html.to_vec()).unwrap();
        assert!(dashboard_html.contains("alex@example.test"));
        assert!(dashboard_html.contains("Alex"));
        sqlx::query("INSERT INTO options (option_name,option_value) VALUES ('score_per_storage','2'), ('score_per_player','100'), ('sign_after_zero','false'), ('sign_gap_time','24'), ('sign_score','10,10')")
            .execute(&pool)
            .await
            .unwrap();
        let score_info = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/user/score-info")
                    .header("cookie", cookie.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(score_info.status(), StatusCode::OK);
        let score_info: serde_json::Value =
            serde_json::from_slice(&to_bytes(score_info.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(score_info["user"]["score"], 5);
        assert_eq!(score_info["user"]["lastSignAt"], "");
        assert_eq!(score_info["rate"]["storage"], 2);
        assert_eq!(score_info["rate"]["players"], 100);
        assert_eq!(score_info["usage"]["players"], 1);
        assert_eq!(score_info["usage"]["storage"], 8);
        let sign = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/user/sign")
                    .header("cookie", cookie.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let sign: serde_json::Value =
            serde_json::from_slice(&to_bytes(sign.into_body(), usize::MAX).await.unwrap()).unwrap();
        assert_eq!(sign["code"], 0);
        assert_eq!(sign["data"]["score"], 15);
        let duplicate_sign = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/user/sign")
                    .header("cookie", cookie.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let duplicate_sign: serde_json::Value = serde_json::from_slice(
            &to_bytes(duplicate_sign.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(duplicate_sign["code"], 1);
        let yesterday = super::shanghai_now()
            .date()
            .pred_opt()
            .unwrap()
            .and_hms_opt(23, 59, 59)
            .unwrap()
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        sqlx::query("UPDATE users SET last_sign_at = ? WHERE uid = 7")
            .bind(yesterday)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE options SET option_value = 'true' WHERE option_name = 'sign_after_zero'",
        )
        .execute(&pool)
        .await
        .unwrap();
        let daily_sign = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/user/sign")
                    .header("cookie", cookie.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let daily_sign: serde_json::Value =
            serde_json::from_slice(&to_bytes(daily_sign.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(daily_sign["code"], 0);
        let duplicate_daily_sign = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/user/sign")
                    .header("cookie", cookie.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let duplicate_daily_sign: serde_json::Value = serde_json::from_slice(
            &to_bytes(duplicate_daily_sign.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(duplicate_daily_sign["code"], 1);
        sqlx::query("UPDATE users SET score = 5, last_sign_at = '' WHERE uid = 7")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE options SET option_value = 'false' WHERE option_name = 'sign_after_zero'",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("UPDATE options SET option_value = '0' WHERE option_name IN ('score_per_storage', 'score_per_player')")
            .execute(&pool)
            .await
            .unwrap();

        for nickname in ["Changed nickname", "Alex User"] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/user/profile")
                        .header("cookie", cookie.clone())
                        .header("content-type", "application/json")
                        .body(Body::from(format!(
                            r#"{{"action":"nickname","new_nickname":"{nickname}"}}"#
                        )))
                        .unwrap(),
                )
                .await
                .unwrap();
            let body: serde_json::Value =
                serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                    .unwrap();
            assert_eq!(body["code"], 0);
        }

        let changed_password = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/user/profile")
                    .header("cookie", cookie.clone())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"action":"password","current_password":"correct horse","new_password":"new secure password"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            changed_password
                .headers()
                .get(SET_COOKIE)
                .unwrap()
                .to_str()
                .unwrap()
                .contains("Max-Age=0")
        );
        let changed_password: serde_json::Value = serde_json::from_slice(
            &to_bytes(changed_password.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(changed_password["code"], 0);
        let restored_password = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/user/profile")
                    .header("cookie", cookie.clone())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"action":"password","current_password":"new secure password","new_password":"correct horse"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let restored_password: serde_json::Value = serde_json::from_slice(
            &to_bytes(restored_password.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(restored_password["code"], 0);
        let stored_password: String =
            sqlx::query_scalar("SELECT password FROM users WHERE uid = 7")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(crate::auth::verify_legacy_password(
            "correct horse",
            &stored_password,
            "BCRYPT",
            ""
        ));

        let changed_email = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/user/profile")
                    .header("cookie", cookie.clone())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"action":"email","email":"changed@example.test","password":"correct horse"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            changed_email
                .headers()
                .get(SET_COOKIE)
                .unwrap()
                .to_str()
                .unwrap()
                .contains("Max-Age=0")
        );
        let changed_email: serde_json::Value = serde_json::from_slice(
            &to_bytes(changed_email.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(changed_email["code"], 0);
        let changed_email_state: (String, bool) =
            sqlx::query_as("SELECT email,verified FROM users WHERE uid = 7")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            changed_email_state,
            ("changed@example.test".to_owned(), false)
        );
        let restored_email = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/user/profile")
                    .header("cookie", cookie.clone())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"action":"email","email":"alex@example.test","password":"correct horse"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let restored_email: serde_json::Value = serde_json::from_slice(
            &to_bytes(restored_email.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(restored_email["code"], 0);
        sqlx::query("UPDATE users SET verified = 1 WHERE uid = 7")
            .execute(&pool)
            .await
            .unwrap();

        let set_avatar = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/user/profile/avatar")
                    .header("cookie", cookie.clone())
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"tid":2}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let set_avatar: serde_json::Value =
            serde_json::from_slice(&to_bytes(set_avatar.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(set_avatar["code"], 0);
        let avatar: i64 = sqlx::query_scalar("SELECT avatar FROM users WHERE uid = 7")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(avatar, 2);
        let reset_avatar = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/user/profile/avatar")
                    .header("cookie", cookie.clone())
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"tid":0}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(reset_avatar.status(), StatusCode::OK);

        for expected_dark_mode in [true, false] {
            let dark_mode = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("PUT")
                        .uri("/user/dark-mode")
                        .header("cookie", cookie.clone())
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(dark_mode.status(), StatusCode::NO_CONTENT);
            let is_dark_mode: bool =
                sqlx::query_scalar("SELECT is_dark_mode FROM users WHERE uid = 7")
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            assert_eq!(is_dark_mode, expected_dark_mode);
        }
        let refused_admin_deletion = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/user/profile")
                    .header("cookie", cookie.clone())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"action":"delete","password":"correct horse"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let refused_admin_deletion: serde_json::Value = serde_json::from_slice(
            &to_bytes(refused_admin_deletion.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(refused_admin_deletion["code"], 1);

        let clients_before = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/oauth/clients")
                    .header("cookie", cookie.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(clients_before.status(), StatusCode::OK);
        let clients_before: serde_json::Value = serde_json::from_slice(
            &to_bytes(clients_before.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(clients_before, serde_json::json!([]));

        let created_client = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth/clients")
                    .header("cookie", cookie.clone())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"name":"Desktop app","redirect":"https://client.test/callback"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(created_client.status(), StatusCode::OK);
        let created_client: serde_json::Value = serde_json::from_slice(
            &to_bytes(created_client.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let client_id = created_client["id"].as_i64().unwrap();
        let client_secret = created_client["secret"].as_str().unwrap();
        assert_eq!(client_secret.len(), 40);
        assert!(client_secret.chars().all(|ch| ch.is_ascii_alphanumeric()));
        assert_eq!(created_client["name"], "Desktop app");
        assert_eq!(created_client["redirect"], "https://client.test/callback");

        let updated_client = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/oauth/clients/{client_id}"))
                    .header("cookie", cookie.clone())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"name":"Updated app","redirect":"https://client.test/return"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(updated_client.status(), StatusCode::OK);
        let updated_client: serde_json::Value = serde_json::from_slice(
            &to_bytes(updated_client.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(updated_client["name"], "Updated app");
        assert_eq!(updated_client["secret"], client_secret);
        assert_eq!(updated_client["redirect"], "https://client.test/return");

        sqlx::query("INSERT INTO oauth_access_tokens (id,user_id,client_id,scopes,revoked) VALUES ('issued-access',7,?,'User.Read',0)")
            .bind(client_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO oauth_refresh_tokens (id,access_token_id,revoked) VALUES ('issued-refresh','issued-access',0)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO oauth_auth_codes (id,user_id,client_id,scopes,revoked) VALUES ('issued-code',7,?,'User.Read',0)")
            .bind(client_id)
            .execute(&pool)
            .await
            .unwrap();
        let deleted_client = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/oauth/clients/{client_id}"))
                    .header("cookie", cookie.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(deleted_client.status(), StatusCode::NO_CONTENT);
        for query in [
            "SELECT revoked FROM oauth_clients WHERE id = ?",
            "SELECT revoked FROM oauth_access_tokens WHERE id = 'issued-access'",
            "SELECT revoked FROM oauth_refresh_tokens WHERE id = 'issued-refresh'",
            "SELECT revoked FROM oauth_auth_codes WHERE id = 'issued-code'",
        ] {
            let revoked: bool = if query.contains("id = ?") {
                sqlx::query_scalar(query)
                    .bind(client_id)
                    .fetch_one(&pool)
                    .await
                    .unwrap()
            } else {
                sqlx::query_scalar(query).fetch_one(&pool).await.unwrap()
            };
            assert!(revoked, "expected revocation for {query}");
        }
        let clients_after = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/oauth/clients")
                    .header("cookie", cookie.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(clients_after.status(), StatusCode::OK);
        let clients_after: serde_json::Value = serde_json::from_slice(
            &to_bytes(clients_after.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(clients_after, serde_json::json!([]));

        let managed_players = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/admin/players/list?q=name%3AAlex&page=1")
                    .header("cookie", cookie.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(managed_players.status(), StatusCode::OK);
        let managed_players: serde_json::Value = serde_json::from_slice(
            &to_bytes(managed_players.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(managed_players["total"], 1);
        assert_eq!(managed_players["data"][0]["pid"], 3);
        assert_eq!(managed_players["data"][0]["uid"], 7);

        sqlx::query("INSERT INTO textures (tid,name,type,hash,size,uploader,public,upload_at,likes) VALUES (13,'Admin texture','alex','admin-hash',8,7,1,'2026-10-01 10:05:00',0)")
            .execute(&pool)
            .await
            .unwrap();
        for (uri, body) in [
            ("/admin/players/3/name", r#"{"player_name":"AlexRenamed"}"#),
            ("/admin/players/3/owner", r#"{"uid":8}"#),
            ("/admin/players/3/textures", r#"{"type":"skin","tid":13}"#),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("PUT")
                        .uri(uri)
                        .header("cookie", cookie.clone())
                        .header("content-type", "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{uri}");
            let response: serde_json::Value =
                serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                    .unwrap();
            assert_eq!(response["code"], 0, "{uri}");
        }
        let managed_player: (i64, String, i64, i64) =
            sqlx::query_as("SELECT uid,name,tid_skin,tid_cape FROM players WHERE pid = 3")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(managed_player, (8, "AlexRenamed".to_owned(), 13, 0));
        let removed_player = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/admin/players/3")
                    .header("cookie", cookie.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(removed_player.status(), StatusCode::OK);
        let player_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM players WHERE pid = 3")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(player_count, 0);

        let managed_closet_add = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/closet/8")
                    .header("cookie", cookie.clone())
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"tid":2}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(managed_closet_add.status(), StatusCode::OK);
        let managed_closet_add: serde_json::Value = serde_json::from_slice(
            &to_bytes(managed_closet_add.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(managed_closet_add["code"], 0);
        assert_eq!(managed_closet_add["message"], "");
        assert_eq!(managed_closet_add["data"]["user"]["uid"], 8);
        assert_eq!(managed_closet_add["data"]["user"]["ip"], "");
        assert_eq!(managed_closet_add["data"]["texture"]["tid"], 2);
        let closet_row: (String,) = sqlx::query_as(
            "SELECT item_name FROM user_closet WHERE user_uid = 8 AND texture_tid = 2",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(closet_row.0, "Reported skin");
        let admin_closet_items = crate::database::DatabasePool::Sqlite(pool.clone())
            .admin_closet_items("", 8)
            .await
            .unwrap();
        assert_eq!(admin_closet_items.len(), 1);
        assert_eq!(
            admin_closet_items[0].item_name.as_deref(),
            Some("Reported skin")
        );

        let repeated_closet_add = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/closet/8")
                    .header("cookie", cookie.clone())
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"tid":2}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let repeated_closet_add: serde_json::Value = serde_json::from_slice(
            &to_bytes(repeated_closet_add.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(repeated_closet_add["code"], 1);

        let managed_closet_remove = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/admin/closet/8")
                    .header("cookie", cookie.clone())
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"tid":2}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let managed_closet_remove: serde_json::Value = serde_json::from_slice(
            &to_bytes(managed_closet_remove.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(managed_closet_remove["code"], 0);
        assert_eq!(managed_closet_remove["message"], "");
        assert_eq!(managed_closet_remove["data"]["user"]["uid"], 8);
        assert_eq!(managed_closet_remove["data"]["texture"]["tid"], 2);
        let closet_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM user_closet WHERE user_uid = 8 AND texture_tid = 2",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(closet_count, 0);

        let users = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/admin/users/list?q=alex&page=1")
                    .header("cookie", cookie.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(users.status(), StatusCode::OK);
        let users: serde_json::Value =
            serde_json::from_slice(&to_bytes(users.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(users["current_page"], 1);
        assert_eq!(users["last_page"], 1);
        assert_eq!(users["total"], 1);
        assert_eq!(users["data"][0]["uid"], 7);
        assert_eq!(users["data"][0]["email"], "alex@example.test");
        assert_eq!(users["data"][0]["ip"], "");
        assert!(users["data"][0].get("password").is_none());

        let combined_user_filter = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/admin/users/list?q=email%3Aalex%40example.test%20or%20uid%3A8&page=1")
                    .header("cookie", cookie.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(combined_user_filter.status(), StatusCode::OK);
        let combined_user_filter: serde_json::Value = serde_json::from_slice(
            &to_bytes(combined_user_filter.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(combined_user_filter["total"], 2);
        assert_eq!(combined_user_filter["data"][0]["uid"], 7);
        assert_eq!(combined_user_filter["data"][1]["uid"], 8);

        let reports = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/admin/reports/list?q=status%3A0%20sort%3A-report_at")
                    .header("cookie", cookie.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(reports.status(), StatusCode::OK);
        let report_page = to_bytes(reports.into_body(), usize::MAX).await.unwrap();
        let report_page: serde_json::Value = serde_json::from_slice(&report_page).unwrap();
        assert_eq!(report_page["current_page"], 1);
        assert_eq!(report_page["last_page"], 1);
        assert_eq!(report_page["total"], 4);
        assert_eq!(report_page["data"][0]["tid"], 2);
        assert_eq!(report_page["data"][0]["texture"]["hash"], "reported-hash");
        assert_eq!(report_page["data"][0]["informer"]["ip"], "");

        let rejected = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/admin/reports/1")
                    .header("cookie", cookie.clone())
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"action":"reject"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rejected.status(), StatusCode::OK);
        let rejected_body = to_bytes(rejected.into_body(), usize::MAX).await.unwrap();
        let rejected_body: serde_json::Value = serde_json::from_slice(&rejected_body).unwrap();
        assert_eq!(rejected_body["code"], 0);
        assert_eq!(rejected_body["data"]["status"], 2);
        let score: i64 = sqlx::query_scalar("SELECT score FROM users WHERE uid = 7")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(score, 3);
        let report_status: i64 = sqlx::query_scalar("SELECT status FROM reports WHERE id = 1")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(report_status, 2);

        let banned = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/admin/reports/2")
                    .header("cookie", cookie.clone())
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"action":"ban"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(banned.status(), StatusCode::OK);
        let banned_body = to_bytes(banned.into_body(), usize::MAX).await.unwrap();
        let banned_body: serde_json::Value = serde_json::from_slice(&banned_body).unwrap();
        assert_eq!(banned_body["code"], 0);
        assert_eq!(banned_body["data"]["status"], 1);
        let uploader_permission: i64 =
            sqlx::query_scalar("SELECT permission FROM users WHERE uid = 8")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(uploader_permission, -1);
        let rewarded_score: i64 = sqlx::query_scalar("SELECT score FROM users WHERE uid = 7")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(rewarded_score, 6);

        let deleted = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/admin/reports/3")
                    .header("cookie", cookie.clone())
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"action":"delete"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(deleted.status(), StatusCode::OK);
        let deleted_body = to_bytes(deleted.into_body(), usize::MAX).await.unwrap();
        let deleted_body: serde_json::Value = serde_json::from_slice(&deleted_body).unwrap();
        assert_eq!(deleted_body["code"], 0);
        assert_eq!(deleted_body["data"]["status"], 1);
        let texture_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM textures WHERE tid = 2")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(texture_count, 0);
        let deletion_report_status: i64 =
            sqlx::query_scalar("SELECT status FROM reports WHERE id = 3")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(deletion_report_status, 1);
        let final_reporter_score: i64 = sqlx::query_scalar("SELECT score FROM users WHERE uid = 7")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(final_reporter_score, 9);

        let missing_texture_report = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/admin/reports/4")
                    .header("cookie", cookie.clone())
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"action":"delete"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing_texture_report.status(), StatusCode::OK);
        let missing_body = to_bytes(missing_texture_report.into_body(), usize::MAX)
            .await
            .unwrap();
        let missing_body: serde_json::Value = serde_json::from_slice(&missing_body).unwrap();
        assert_eq!(missing_body["code"], 0);
        assert_eq!(
            missing_body["message"],
            "The requested texture has been deleted."
        );
        assert_eq!(missing_body["data"]["status"], 1);
        let final_reporter_score: i64 = sqlx::query_scalar("SELECT score FROM users WHERE uid = 7")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(final_reporter_score, 9);

        let duplicate_email = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/admin/users/8/email")
                    .header("cookie", cookie.clone())
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"email":"alex@example.test"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(duplicate_email.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let duplicate_body = to_bytes(duplicate_email.into_body(), usize::MAX)
            .await
            .unwrap();
        let duplicate_body: serde_json::Value = serde_json::from_slice(&duplicate_body).unwrap();
        assert!(duplicate_body["errors"]["email"].is_array());

        for (uri, body, expected) in [
            (
                "/admin/users/8/email",
                r#"{"email":"uploader2@example.test"}"#,
                "Email changed successfully.",
            ),
            (
                "/admin/users/8/nickname",
                r#"{"nickname":"Target User"}"#,
                "Nickname changed successfully.",
            ),
            (
                "/admin/users/8/score",
                r#"{"score":17}"#,
                "Score changed successfully.",
            ),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("PUT")
                        .uri(uri)
                        .header("cookie", cookie.clone())
                        .header("content-type", "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let response: serde_json::Value =
                serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                    .unwrap();
            assert_eq!(response["code"], 0);
            assert_eq!(response["message"], expected);
        }

        let promoted = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/admin/users/8/permission")
                    .header("cookie", cookie.clone())
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"permission":1}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(promoted.status(), StatusCode::FORBIDDEN);
        let self_role_change = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/admin/users/7/permission")
                    .header("cookie", cookie.clone())
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"permission":0}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(self_role_change.status(), StatusCode::FORBIDDEN);

        let verified_before: bool = sqlx::query_scalar("SELECT verified FROM users WHERE uid = 8")
            .fetch_one(&pool)
            .await
            .unwrap();
        let verification = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/admin/users/8/verification")
                    .header("cookie", cookie.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(verification.status(), StatusCode::OK);
        let verified_after: bool = sqlx::query_scalar("SELECT verified FROM users WHERE uid = 8")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(verified_after, !verified_before);

        let password_change = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/admin/users/8/password")
                    .header("cookie", cookie.clone())
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"password":"NewPass123"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(password_change.status(), StatusCode::OK);
        let changed_hash: String = sqlx::query_scalar("SELECT password FROM users WHERE uid = 8")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(crate::auth::verify_legacy_password(
            "NewPass123",
            &changed_hash,
            "BCRYPT",
            ""
        ));

        let set_permission = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/admin/users/8/permission")
                    .header("cookie", cookie.clone())
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"permission":0}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(set_permission.status(), StatusCode::OK);
        let user_eight_player = sqlx::query(
            "INSERT INTO players (pid,uid,name,tid_skin,tid_cape,last_modified) VALUES (99,8,'Uploader player',0,0,'2026-10-02 12:00:00')",
        );
        user_eight_player.execute(&pool).await.unwrap();
        let removed_user = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/admin/users/8")
                    .header("cookie", cookie.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(removed_user.status(), StatusCode::OK);
        let removed_body: serde_json::Value = serde_json::from_slice(
            &to_bytes(removed_user.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(removed_body["code"], 0);
        let deleted_users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE uid = 8")
            .fetch_one(&pool)
            .await
            .unwrap();
        let deleted_players: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM players WHERE uid = 8")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(deleted_users, 0);
        assert_eq!(deleted_players, 0);

        sqlx::query("INSERT INTO textures (tid,name,type,hash,size,uploader,public,upload_at,likes) VALUES (900001,'Preview skin','alex',?,4096,7,1,'2026-10-02 12:00:00',0),(900002,'Preview cape','cape',?,4096,7,1,'2026-10-02 12:00:00',0)")
            .bind(&preview_skin_hash)
            .bind(&preview_cape_hash)
            .execute(&pool)
            .await
            .unwrap();
        let skin_preview = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/preview/900001?png")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(skin_preview.status(), StatusCode::OK);
        assert_eq!(
            skin_preview
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap(),
            "image/png"
        );
        let skin_preview_etag = skin_preview
            .headers()
            .get(axum::http::header::ETAG)
            .unwrap()
            .clone();
        let skin_preview_bytes = to_bytes(skin_preview.into_body(), usize::MAX)
            .await
            .unwrap();
        let decoded_skin_preview =
            image::load_from_memory_with_format(&skin_preview_bytes, ImageFormat::Png).unwrap();
        assert_eq!(
            (decoded_skin_preview.width(), decoded_skin_preview.height()),
            (200, 200)
        );
        let cached_skin_preview = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/preview/900001?png")
                    .header(axum::http::header::IF_NONE_MATCH, skin_preview_etag)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cached_skin_preview.status(), StatusCode::NOT_MODIFIED);

        let cape_preview = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/preview/hash/{preview_cape_hash}?png&height=160"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cape_preview.status(), StatusCode::OK);
        let cape_preview_bytes = to_bytes(cape_preview.into_body(), usize::MAX)
            .await
            .unwrap();
        let decoded_cape_preview =
            image::load_from_memory_with_format(&cape_preview_bytes, ImageFormat::Png).unwrap();
        assert_eq!(
            (decoded_cape_preview.width(), decoded_cape_preview.height()),
            (100, 160)
        );
        std::fs::remove_dir_all(&texture_test_dir).unwrap();

        let logout = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/logout")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(logout.status(), StatusCode::OK);
        assert!(
            logout
                .headers()
                .get(SET_COOKIE)
                .unwrap()
                .to_str()
                .unwrap()
                .contains("Max-Age=0")
        );
    }

    #[test]
    fn renders_github_flavored_notification_markdown_without_unsafe_html() {
        use super::render_notification_markdown;

        let html = render_notification_markdown(
            "## Notice

~~old~~ **new**

|a|b|
|-|-|
|1|2|

<script>alert(1)</script>

[bad](javascript:alert(1))",
        );
        assert!(html.contains("<h2>Notice</h2>"));
        assert!(html.contains("<del>old</del>"));
        assert!(html.contains("<strong>new</strong>"));
        assert!(html.contains("<table>"));
        assert!(!html.contains("<script"));
        assert!(!html.contains("alert(1)"));
    }

    #[tokio::test]
    async fn notification_detail_keeps_the_legacy_json_fields() {
        use axum::body::to_bytes;

        let response = super::notification_detail(crate::database::NotificationRecord {
            id: "notice-id".to_owned(),
            data: r#"{"title":"Site notice","content":"Hello **skin**"}"#.to_owned(),
            created_at: "2026-10-01 10:00:00".to_owned(),
        });
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["title"], "Site notice");
        assert_eq!(value["time"], "2026-10-01 10:00:00");
        assert!(
            value["content"]
                .as_str()
                .unwrap()
                .contains("<strong>skin</strong>")
        );
    }

    #[test]
    fn applies_the_legacy_player_name_rules() {
        use super::valid_player_name;

        assert!(valid_player_name("Alex_2", "official", "", 3, 16));
        assert!(!valid_player_name("Alex!", "official", "", 3, 16));
        assert!(valid_player_name("玩家§2", "cjk", "", 3, 16));
        assert!(!valid_player_name("bad name", "utf8", "", 3, 16));
        assert!(valid_player_name("ABC", "custom", "/^[a-z]+$/i", 3, 16));
        assert!(!valid_player_name("ABC1", "custom", "/^[a-z]+$/i", 3, 16));
    }
}
