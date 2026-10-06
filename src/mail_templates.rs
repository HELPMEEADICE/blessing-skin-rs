#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MailContent {
    pub subject: String,
    pub text: String,
    pub html: String,
}

#[derive(Clone, Copy)]
enum TemplateKind {
    EmailVerification,
    PasswordReset,
}

struct LocaleFiles {
    locale: &'static str,
    user: &'static str,
    skinlib: &'static str,
    auth: &'static str,
    errors: &'static str,
    setup: &'static str,
    general: &'static str,
    front_end: &'static str,
    admin: &'static str,
}

const LOCALES: &[LocaleFiles] = &[
    LocaleFiles {
        locale: "de_DE",
        user: include_str!("../resources/lang/de_DE/user.yml"),
        skinlib: include_str!("../resources/lang/de_DE/skinlib.yml"),
        auth: include_str!("../resources/lang/de_DE/auth.yml"),
        errors: include_str!("../resources/lang/de_DE/errors.yml"),
        setup: include_str!("../resources/lang/de_DE/setup.yml"),
        general: include_str!("../resources/lang/de_DE/general.yml"),
        front_end: include_str!("../resources/lang/de_DE/front-end.yml"),
        admin: include_str!("../resources/lang/de_DE/admin.yml"),
    },
    LocaleFiles {
        locale: "el_GR",
        user: include_str!("../resources/lang/el_GR/user.yml"),
        skinlib: include_str!("../resources/lang/el_GR/skinlib.yml"),
        auth: include_str!("../resources/lang/el_GR/auth.yml"),
        errors: include_str!("../resources/lang/el_GR/errors.yml"),
        setup: include_str!("../resources/lang/el_GR/setup.yml"),
        general: include_str!("../resources/lang/el_GR/general.yml"),
        front_end: include_str!("../resources/lang/el_GR/front-end.yml"),
        admin: include_str!("../resources/lang/el_GR/admin.yml"),
    },
    LocaleFiles {
        locale: "en",
        user: include_str!("../resources/lang/en/user.yml"),
        skinlib: include_str!("../resources/lang/en/skinlib.yml"),
        auth: include_str!("../resources/lang/en/auth.yml"),
        errors: include_str!("../resources/lang/en/errors.yml"),
        setup: include_str!("../resources/lang/en/setup.yml"),
        general: include_str!("../resources/lang/en/general.yml"),
        front_end: include_str!("../resources/lang/en/front-end.yml"),
        admin: include_str!("../resources/lang/en/admin.yml"),
    },
    LocaleFiles {
        locale: "es_ES",
        user: include_str!("../resources/lang/es_ES/user.yml"),
        skinlib: include_str!("../resources/lang/es_ES/skinlib.yml"),
        auth: include_str!("../resources/lang/es_ES/auth.yml"),
        errors: include_str!("../resources/lang/es_ES/errors.yml"),
        setup: include_str!("../resources/lang/es_ES/setup.yml"),
        general: include_str!("../resources/lang/es_ES/general.yml"),
        front_end: include_str!("../resources/lang/es_ES/front-end.yml"),
        admin: include_str!("../resources/lang/es_ES/admin.yml"),
    },
    LocaleFiles {
        locale: "fr_FR",
        user: include_str!("../resources/lang/fr_FR/user.yml"),
        skinlib: include_str!("../resources/lang/fr_FR/skinlib.yml"),
        auth: include_str!("../resources/lang/fr_FR/auth.yml"),
        errors: include_str!("../resources/lang/fr_FR/errors.yml"),
        setup: include_str!("../resources/lang/fr_FR/setup.yml"),
        general: include_str!("../resources/lang/fr_FR/general.yml"),
        front_end: include_str!("../resources/lang/fr_FR/front-end.yml"),
        admin: include_str!("../resources/lang/fr_FR/admin.yml"),
    },
    LocaleFiles {
        locale: "it_IT",
        user: include_str!("../resources/lang/it_IT/user.yml"),
        skinlib: include_str!("../resources/lang/it_IT/skinlib.yml"),
        auth: include_str!("../resources/lang/it_IT/auth.yml"),
        errors: include_str!("../resources/lang/it_IT/errors.yml"),
        setup: include_str!("../resources/lang/it_IT/setup.yml"),
        general: include_str!("../resources/lang/it_IT/general.yml"),
        front_end: include_str!("../resources/lang/it_IT/front-end.yml"),
        admin: include_str!("../resources/lang/it_IT/admin.yml"),
    },
    LocaleFiles {
        locale: "ja_JP",
        user: include_str!("../resources/lang/ja_JP/user.yml"),
        skinlib: include_str!("../resources/lang/ja_JP/skinlib.yml"),
        auth: include_str!("../resources/lang/ja_JP/auth.yml"),
        errors: include_str!("../resources/lang/ja_JP/errors.yml"),
        setup: include_str!("../resources/lang/ja_JP/setup.yml"),
        general: include_str!("../resources/lang/ja_JP/general.yml"),
        front_end: include_str!("../resources/lang/ja_JP/front-end.yml"),
        admin: include_str!("../resources/lang/ja_JP/admin.yml"),
    },
    LocaleFiles {
        locale: "ko_KR",
        user: include_str!("../resources/lang/ko_KR/user.yml"),
        skinlib: include_str!("../resources/lang/ko_KR/skinlib.yml"),
        auth: include_str!("../resources/lang/ko_KR/auth.yml"),
        errors: include_str!("../resources/lang/ko_KR/errors.yml"),
        setup: include_str!("../resources/lang/ko_KR/setup.yml"),
        general: include_str!("../resources/lang/ko_KR/general.yml"),
        front_end: include_str!("../resources/lang/ko_KR/front-end.yml"),
        admin: include_str!("../resources/lang/ko_KR/admin.yml"),
    },
    LocaleFiles {
        locale: "nl_NL",
        user: include_str!("../resources/lang/nl_NL/user.yml"),
        skinlib: include_str!("../resources/lang/nl_NL/skinlib.yml"),
        auth: include_str!("../resources/lang/nl_NL/auth.yml"),
        errors: include_str!("../resources/lang/nl_NL/errors.yml"),
        setup: include_str!("../resources/lang/nl_NL/setup.yml"),
        general: include_str!("../resources/lang/nl_NL/general.yml"),
        front_end: include_str!("../resources/lang/nl_NL/front-end.yml"),
        admin: include_str!("../resources/lang/nl_NL/admin.yml"),
    },
    LocaleFiles {
        locale: "pt_PT",
        user: include_str!("../resources/lang/pt_PT/user.yml"),
        skinlib: include_str!("../resources/lang/pt_PT/skinlib.yml"),
        auth: include_str!("../resources/lang/pt_PT/auth.yml"),
        errors: include_str!("../resources/lang/pt_PT/errors.yml"),
        setup: include_str!("../resources/lang/pt_PT/setup.yml"),
        general: include_str!("../resources/lang/pt_PT/general.yml"),
        front_end: include_str!("../resources/lang/pt_PT/front-end.yml"),
        admin: include_str!("../resources/lang/pt_PT/admin.yml"),
    },
    LocaleFiles {
        locale: "ru_RU",
        user: include_str!("../resources/lang/ru_RU/user.yml"),
        skinlib: include_str!("../resources/lang/ru_RU/skinlib.yml"),
        auth: include_str!("../resources/lang/ru_RU/auth.yml"),
        errors: include_str!("../resources/lang/ru_RU/errors.yml"),
        setup: include_str!("../resources/lang/ru_RU/setup.yml"),
        general: include_str!("../resources/lang/ru_RU/general.yml"),
        front_end: include_str!("../resources/lang/ru_RU/front-end.yml"),
        admin: include_str!("../resources/lang/ru_RU/admin.yml"),
    },
    LocaleFiles {
        locale: "zh_CN",
        user: include_str!("../resources/lang/zh_CN/user.yml"),
        skinlib: include_str!("../resources/lang/zh_CN/skinlib.yml"),
        auth: include_str!("../resources/lang/zh_CN/auth.yml"),
        errors: include_str!("../resources/lang/zh_CN/errors.yml"),
        setup: include_str!("../resources/lang/zh_CN/setup.yml"),
        general: include_str!("../resources/lang/zh_CN/general.yml"),
        front_end: include_str!("../resources/lang/zh_CN/front-end.yml"),
        admin: include_str!("../resources/lang/zh_CN/admin.yml"),
    },
    LocaleFiles {
        locale: "zh_TW",
        user: include_str!("../resources/lang/zh_TW/user.yml"),
        skinlib: include_str!("../resources/lang/zh_TW/skinlib.yml"),
        auth: include_str!("../resources/lang/zh_TW/auth.yml"),
        errors: include_str!("../resources/lang/zh_TW/errors.yml"),
        setup: include_str!("../resources/lang/zh_TW/setup.yml"),
        general: include_str!("../resources/lang/zh_TW/general.yml"),
        front_end: include_str!("../resources/lang/zh_TW/front-end.yml"),
        admin: include_str!("../resources/lang/zh_TW/admin.yml"),
    },
];

pub(crate) fn email_verification(locale: &str, site_name: &str, url: &str) -> MailContent {
    render(TemplateKind::EmailVerification, locale, site_name, url)
}

pub(crate) fn password_reset(locale: &str, site_name: &str, url: &str) -> MailContent {
    render(TemplateKind::PasswordReset, locale, site_name, url)
}

pub(crate) fn legacy_translation(
    locale: &str,
    catalog: &str,
    parent_path: &[&str],
    key: &str,
) -> Option<String> {
    let language = LOCALES
        .iter()
        .find(|files| files.locale == locale)
        .or_else(|| LOCALES.iter().find(|files| files.locale == "en"))?;
    let english = LOCALES.iter().find(|files| files.locale == "en")?;
    let (source, english_source) = match catalog {
        "skinlib" => (language.skinlib, english.skinlib),
        "auth" => (language.auth, english.auth),
        "user" => (language.user, english.user),
        "errors" => (language.errors, english.errors),
        "setup" => (language.setup, english.setup),
        "general" => (language.general, english.general),
        "front-end" => (language.front_end, english.front_end),
        "admin" => (language.admin, english.admin),
        _ => return None,
    };
    yaml_scalar(source, parent_path, key).or_else(|| yaml_scalar(english_source, parent_path, key))
}

pub(crate) fn legacy_translation_item(
    locale: &str,
    parent_path: &[&str],
    key: &str,
    index: usize,
) -> Option<String> {
    let language = LOCALES
        .iter()
        .find(|files| files.locale == locale)
        .or_else(|| LOCALES.iter().find(|files| files.locale == "en"))?;
    let english = LOCALES.iter().find(|files| files.locale == "en")?;
    yaml_sequence_item(language.front_end, parent_path, key, index)
        .or_else(|| yaml_sequence_item(english.front_end, parent_path, key, index))
}

fn render(kind: TemplateKind, locale: &str, site_name: &str, url: &str) -> MailContent {
    let language = LOCALES
        .iter()
        .find(|files| files.locale == locale)
        .or_else(|| LOCALES.iter().find(|files| files.locale == "en"))
        .expect("English email translations are bundled");
    let (source, section) = match kind {
        TemplateKind::EmailVerification => (language.user, "verification"),
        TemplateKind::PasswordReset => (language.auth, "forgot"),
    };
    let (english_source, english_section) = match kind {
        TemplateKind::EmailVerification => (
            include_str!("../resources/lang/en/user.yml"),
            "verification",
        ),
        TemplateKind::PasswordReset => (include_str!("../resources/lang/en/auth.yml"), "forgot"),
    };
    let translation = |key: &str| {
        yaml_scalar(source, &[section, "mail"], key)
            .or_else(|| yaml_scalar(english_source, &[english_section, "mail"], key))
            .unwrap_or_default()
    };

    let subject_template = translation("title");
    let message_template = translation("message");
    let reset_template = translation("reset");
    let ignore_template = translation("ignore");

    let subject = message_substitution(&subject_template, site_name);
    let message = message_substitution(&message_template, site_name);
    let reset_text = reset_template
        .replace(r#"<a href=":url">:url</a>"#, url)
        .replace(":url", url);
    let text = format!("{message}\n\n{reset_text}\n\n{ignore_template}");

    let html_site_name = escape_html(site_name);
    let html_url = escape_html(url);
    let html_message = message_template.replace(":sitename", &html_site_name);
    let html_reset = reset_template.replace(":url", &html_url);
    let html = ammonia::clean(&format!(
        "<p>{html_message}</p><p>{html_reset}</p><p>{ignore_template}</p>"
    ))
    .to_string();

    MailContent {
        subject,
        text,
        html,
    }
}

fn message_substitution(template: &str, site_name: &str) -> String {
    template.replace(":sitename", site_name)
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn yaml_scalar(source: &str, parent_path: &[&str], target_key: &str) -> Option<String> {
    let mut sections: Vec<(usize, &str)> = Vec::new();
    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        let Some((key, value)) = trimmed.split_once(':') else {
            continue;
        };
        let key = key.trim();
        while sections
            .last()
            .is_some_and(|(section_indent, _)| indent <= *section_indent)
        {
            sections.pop();
        }
        let value = value.trim();
        if value.is_empty() {
            sections.push((indent, key));
            continue;
        }
        if key == target_key
            && sections.len() == parent_path.len()
            && sections
                .iter()
                .zip(parent_path)
                .all(|((_, section), expected)| section == expected)
        {
            return parse_yaml_scalar(value);
        }
    }
    None
}

fn yaml_sequence_item(
    source: &str,
    parent_path: &[&str],
    target_key: &str,
    target_index: usize,
) -> Option<String> {
    let mut sections: Vec<(usize, &str)> = Vec::new();
    let mut list_indent = None;
    let mut item_index = 0;
    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if let Some(parent_indent) = list_indent {
            if indent > parent_indent {
                if let Some(item) = trimmed.strip_prefix("-") {
                    if item_index == target_index {
                        return parse_yaml_scalar(item.trim());
                    }
                    item_index += 1;
                }
                continue;
            }
            list_indent = None;
        }
        let Some((key, value)) = trimmed.split_once(':') else {
            continue;
        };
        let key = key.trim();
        while sections
            .last()
            .is_some_and(|(section_indent, _)| indent <= *section_indent)
        {
            sections.pop();
        }
        if key == target_key
            && sections.len() == parent_path.len()
            && sections
                .iter()
                .zip(parent_path)
                .all(|((_, section), expected)| section == expected)
            && value.trim().is_empty()
        {
            list_indent = Some(indent);
            item_index = 0;
            continue;
        }
        if value.trim().is_empty() {
            sections.push((indent, key));
        }
    }
    None
}

fn parse_yaml_scalar(value: &str) -> Option<String> {
    if let Some(inner) = value.strip_prefix('\'') {
        let end = inner.rfind('\'')?;
        return Some(inner[..end].replace("''", "'"));
    }
    if value.starts_with('"') {
        return serde_json::from_str(value).ok();
    }
    Some(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::{
        LOCALES, email_verification, legacy_translation, legacy_translation_item, password_reset,
    };

    #[test]
    fn resolves_legacy_page_errors_from_all_supported_locale_files() {
        for locale in LOCALES {
            assert!(
                legacy_translation(locale.locale, "errors", &["general"], "title").is_some(),
                "{}",
                locale.locale
            );
            assert!(
                legacy_translation(locale.locale, "auth", &["forgot"], "disabled").is_some(),
                "{}",
                locale.locale
            );
            assert!(
                legacy_translation(locale.locale, "user", &["verification"], "disabled").is_some(),
                "{}",
                locale.locale
            );
            assert!(
                legacy_translation(locale.locale, "setup", &["database"], "connection-error")
                    .is_some(),
                "{}",
                locale.locale
            );
        }
        assert_eq!(
            legacy_translation("zh_CN", "auth", &["forgot"], "disabled").as_deref(),
            Some("本站已关闭重置密码功能")
        );
        assert_eq!(
            legacy_translation("zh_TW", "user", &["verification"], "disabled").as_deref(),
            Some("電子郵件驗證不可用。")
        );
        assert_eq!(
            legacy_translation("missing", "errors", &["general"], "title").as_deref(),
            Some("Error occurred")
        );
        assert_eq!(
            legacy_translation("zh_CN", "setup", &["database"], "connection-error").as_deref(),
            Some("无法连接至 :type 目标数据库，请检查你的配置。服务器返回的信息：:msg")
        );
    }

    #[test]
    fn reads_general_and_front_end_report_translations_for_all_locales() {
        for locale in LOCALES {
            assert!(
                legacy_translation(locale.locale, "general", &[], "my-reports").is_some(),
                "{}",
                locale.locale
            );
            assert!(
                legacy_translation(locale.locale, "front-end", &["report"], "reason").is_some(),
                "{}",
                locale.locale
            );
            assert!(
                legacy_translation(locale.locale, "admin", &["status", "db"], "prefix").is_some(),
                "{}",
                locale.locale
            );
            for index in 0..3 {
                assert!(
                    super::legacy_translation_item(locale.locale, &["report"], "status", index)
                        .is_some(),
                    "{} status {index}",
                    locale.locale
                );
            }
        }
        assert_eq!(
            legacy_translation_item("es_ES", &["report"], "status", 0).as_deref(),
            Some("Pendiente")
        );
        assert_eq!(
            legacy_translation_item("ru_RU", &["report"], "status", 2).as_deref(),
            Some("Отклонено")
        );
        assert_eq!(
            legacy_translation("es_ES", "admin", &["status", "db"], "prefix").as_deref(),
            Some("Prefijo de tabla")
        );
        assert_eq!(
            legacy_translation("es_ES", "skinlib", &["show"], "private").as_deref(),
            Some(
                "La textura solicitada es privada y sólo visible para el subidor y los administradores."
            )
        );
    }

    #[test]
    fn bundles_all_legacy_email_locales_and_falls_back_to_english() {
        for locale in LOCALES {
            let verification = email_verification(
                locale.locale,
                "Blessing Skin",
                "https://skin.example.test/auth/verify/4?signature=abc",
            );
            let reset = password_reset(
                locale.locale,
                "Blessing Skin",
                "https://skin.example.test/auth/reset/4?signature=abc",
            );
            assert!(!verification.subject.is_empty(), "{}", locale.locale);
            assert!(!reset.subject.is_empty(), "{}", locale.locale);
            assert!(
                !verification.subject.contains(":sitename"),
                "{}",
                locale.locale
            );
            assert!(!reset.subject.contains(":sitename"), "{}", locale.locale);
            assert!(
                verification.text.contains("Blessing Skin"),
                "{}",
                locale.locale
            );
            assert!(!reset.text.is_empty(), "{}", locale.locale);
            assert!(
                verification
                    .text
                    .contains("https://skin.example.test/auth/verify/4")
            );
            assert!(
                reset
                    .text
                    .contains("https://skin.example.test/auth/reset/4")
            );
            assert!(verification.html.contains("<a "), "{}", locale.locale);
            assert!(reset.html.contains("<a "), "{}", locale.locale);
            assert!(!verification.text.contains("<a "), "{}", locale.locale);
            assert!(!reset.text.contains("<a "), "{}", locale.locale);
        }
        let chinese = email_verification(
            "zh_CN",
            "皮肤站",
            "https://skin.example.test/auth/verify/4?signature=abc",
        );
        assert_eq!(chinese.subject, "验证您在 皮肤站 上的账户邮箱");
        assert!(
            chinese
                .text
                .contains("有人在 皮肤站 注册时使用了本邮箱地址")
        );
        let german_reset = password_reset(
            "de_DE",
            "Blessing Skin",
            "https://skin.example.test/auth/reset/4?signature=abc",
        );
        assert!(german_reset.subject.contains("Passworts zurücksetzen"));

        let fallback = email_verification("unknown", "Example", "https://example.test/verify");
        assert!(fallback.subject.starts_with("Verify Your Account"));
    }

    #[test]
    fn email_templates_escape_site_values_and_keep_signed_links_clickable() {
        let content = password_reset(
            "zh_CN",
            "<img src=x onerror=alert(1)>",
            "https://skin.example.test/reset?a=1&signature=abc",
        );
        assert!(!content.html.contains("<img"));
        assert!(content.html.contains("&lt;img"));
        assert!(
            content
                .html
                .contains("href=\"https://skin.example.test/reset?a=1&amp;signature=abc\"")
        );
        assert!(
            content
                .text
                .contains("https://skin.example.test/reset?a=1&signature=abc")
        );
    }
}
