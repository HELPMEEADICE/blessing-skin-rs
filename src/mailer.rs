use std::time::Duration;

use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, header::ContentType},
    transport::smtp::{
        authentication::Credentials,
        client::{Tls, TlsParameters},
        extension::ClientId,
    },
};
use percent_encoding::percent_decode_str;
use url::Url;

use crate::config::MailConfig;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SmtpMode {
    ImplicitTls,
    StartTls,
    OpportunisticStartTls,
    Plain,
}

fn smtp_mode(encryption: &str, port: u16) -> Result<SmtpMode, String> {
    match encryption.trim().to_ascii_lowercase().as_str() {
        "smtps" => Ok(SmtpMode::ImplicitTls),
        "ssl" if port == 465 => Ok(SmtpMode::ImplicitTls),
        "ssl" => Ok(SmtpMode::Plain),
        "tls" if port == 465 => Ok(SmtpMode::ImplicitTls),
        "tls" => Ok(SmtpMode::OpportunisticStartTls),
        "starttls" => Ok(SmtpMode::StartTls),
        "" if port == 465 => Ok(SmtpMode::ImplicitTls),
        "" => Ok(SmtpMode::Plain),
        other => Err(format!("Unsupported MAIL_ENCRYPTION value: {other}")),
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct SmtpSettings {
    host: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    mode: SmtpMode,
    local_domain: Option<String>,
    timeout: Option<Duration>,
}

fn smtp_settings(config: &MailConfig) -> Result<SmtpSettings, String> {
    let mut host = config.host.clone();
    let mut port = config.port;
    let mut username = config.username.clone();
    let mut password = config.password.clone();
    let mut encryption = config.encryption.clone();
    let mut local_domain = config.local_domain.clone();
    let mut timeout = None;
    let mut scheme = None;

    if let Some(connection_url) = config.url.as_deref() {
        let url =
            Url::parse(connection_url).map_err(|error| format!("Invalid MAIL_URL: {error}"))?;
        if url.scheme() != "smtp" {
            return Err(format!("Unsupported MAIL_URL scheme: {}", url.scheme()));
        }
        if let Some(url_host) = url.host_str() {
            host = url_host.to_owned();
        }
        if let Some(url_port) = url.port() {
            port = url_port;
        }

        let authority = url
            .as_str()
            .split_once("://")
            .map(|(_, remainder)| remainder.split(['/', '?', '#']).next().unwrap_or_default())
            .unwrap_or_default();
        if authority.contains('@') {
            username = Some(decode_url_component(url.username())?);
            if let Some(url_password) = url.password() {
                password = Some(decode_url_component(url_password)?);
            }
        }

        // Laravel's ConfigurationUrlParser applies query options after URL
        // authority fields, so query values take precedence over both.
        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "host" => host = value.into_owned(),
                "port" => {
                    port = value.parse::<u16>().map_err(|_| {
                        "MAIL_URL port must be an integer from 0 to 65535".to_owned()
                    })?;
                }
                "username" => username = Some(value.into_owned()),
                "password" => password = Some(value.into_owned()),
                "encryption" => encryption = value.into_owned(),
                "scheme" => scheme = Some(value.into_owned()),
                "local_domain" => local_domain = Some(value.into_owned()),
                "timeout" => {
                    let seconds = value
                        .parse::<f64>()
                        .map_err(|_| "MAIL_URL timeout must be a non-negative number".to_owned())?;
                    if !seconds.is_finite() || seconds < 0.0 {
                        return Err("MAIL_URL timeout must be a non-negative number".to_owned());
                    }
                    timeout = Some(
                        Duration::try_from_secs_f64(seconds)
                            .map_err(|_| "MAIL_URL timeout is out of range".to_owned())?,
                    );
                }
                _ => {}
            }
        }
    }

    let mode = match scheme.as_deref() {
        Some("smtp") => {
            if port == 465 {
                SmtpMode::ImplicitTls
            } else {
                SmtpMode::OpportunisticStartTls
            }
        }
        Some("smtps") => SmtpMode::ImplicitTls,
        Some("") | None => smtp_mode(&encryption, port)?,
        Some(value) => return Err(format!("Unsupported SMTP scheme: {value}")),
    };

    Ok(SmtpSettings {
        host,
        port,
        username,
        password,
        mode,
        local_domain,
        timeout,
    })
}

fn decode_url_component(value: &str) -> Result<String, String> {
    percent_decode_str(value)
        .decode_utf8()
        .map(|value| value.into_owned())
        .map_err(|error| format!("MAIL_URL contains invalid UTF-8 credentials: {error}"))
}

pub async fn send_email(
    config: &MailConfig,
    recipient: &str,
    subject: &str,
    body: &str,
) -> Result<(), String> {
    match config.mailer.trim().to_ascii_lowercase().as_str() {
        "log" => {
            log_email(recipient, subject, body);
            Ok(())
        }
        "array" => Ok(()),
        "failover" => {
            let mut smtp_config = config.clone();
            smtp_config.mailer = "smtp".to_owned();
            if let Err(error) = send_smtp_email(&smtp_config, recipient, subject, body).await {
                tracing::warn!(%error, "SMTP delivery failed; falling back to the log mailer");
                log_email(recipient, subject, body);
            }
            Ok(())
        }
        "smtp" => send_smtp_email(config, recipient, subject, body).await,
        "" => Err("Email delivery is not configured.".to_owned()),
        mailer => Err(format!("Unsupported mailer: {mailer}")),
    }
}

fn log_email(recipient: &str, subject: &str, body: &str) {
    tracing::info!(
        to = recipient,
        subject,
        body,
        "email captured by log mailer"
    );
}

async fn send_smtp_email(
    config: &MailConfig,
    recipient: &str,
    subject: &str,
    body: &str,
) -> Result<(), String> {
    let settings = smtp_settings(config)?;
    if settings.host.trim().is_empty() {
        return Err("MAIL_HOST is not configured.".to_owned());
    }
    if settings.username.is_some() != settings.password.is_some() {
        return Err("MAIL_USERNAME and MAIL_PASSWORD must be configured together.".to_owned());
    }
    let from_address = config
        .from_address
        .parse()
        .map_err(|error| format!("Invalid MAIL_FROM_ADDRESS: {error}"))?;
    let to_address = recipient
        .parse()
        .map_err(|error| format!("Invalid recipient address: {error}"))?;
    let from = Mailbox::new(Some(config.from_name.clone()), from_address);
    let to = Mailbox::new(None, to_address);
    let message = Message::builder()
        .from(from)
        .to(to)
        .subject(subject)
        .header(ContentType::TEXT_PLAIN)
        .body(body.to_owned())
        .map_err(|error| format!("Could not construct email: {error}"))?;

    let mut transport = match settings.mode {
        SmtpMode::ImplicitTls => AsyncSmtpTransport::<Tokio1Executor>::relay(&settings.host),
        SmtpMode::StartTls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&settings.host),
        SmtpMode::OpportunisticStartTls => {
            let tls = TlsParameters::new(settings.host.clone())
                .map_err(|error| format!("Could not configure SMTP TLS: {error}"))?;
            Ok(
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&settings.host)
                    .tls(Tls::Opportunistic(tls)),
            )
        }
        SmtpMode::Plain => Ok(AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(
            &settings.host,
        )),
    }
    .map_err(|error| format!("Could not configure SMTP transport: {error}"))?
    .port(settings.port);
    if let Some(timeout) = settings.timeout {
        transport = transport.timeout(Some(timeout));
    }
    if let Some(local_domain) = settings.local_domain {
        transport = transport.hello_name(ClientId::Domain(local_domain));
    }
    if let (Some(username), Some(password)) = (&settings.username, &settings.password) {
        transport = transport.credentials(Credentials::new(username.clone(), password.clone()));
    }
    transport
        .build()
        .send(message)
        .await
        .map(|_| ())
        .map_err(|error| format!("SMTP delivery failed: {error}"))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{SmtpMode, smtp_mode, smtp_settings};
    use crate::config::MailConfig;

    #[test]
    fn mail_url_overrides_legacy_smtp_settings_and_decodes_credentials() {
        let config = MailConfig {
            url: Some(
                "smtp://url%40user:p%40ss@smtp.example.test:465?local_domain=mail.example.test&timeout=25"
                    .to_owned(),
            ),
            host: "legacy.example.test".to_owned(),
            port: 587,
            username: Some("legacy-user".to_owned()),
            password: Some("legacy-password".to_owned()),
            encryption: "tls".to_owned(),
            local_domain: Some("legacy-domain.test".to_owned()),
            ..MailConfig::default()
        };
        let settings = smtp_settings(&config).unwrap();
        assert_eq!(settings.host, "smtp.example.test");
        assert_eq!(settings.port, 465);
        assert_eq!(settings.username.as_deref(), Some("url@user"));
        assert_eq!(settings.password.as_deref(), Some("p@ss"));
        assert_eq!(settings.mode, SmtpMode::ImplicitTls);
        assert_eq!(settings.local_domain.as_deref(), Some("mail.example.test"));
        assert_eq!(settings.timeout, Some(Duration::from_secs(25)));
    }

    #[test]
    fn mail_url_scheme_and_credentials_can_fall_back_to_legacy_settings() {
        let config = MailConfig {
            url: Some("smtp://smtp-url.example.test".to_owned()),
            username: Some("legacy-user".to_owned()),
            password: Some("legacy-password".to_owned()),
            ..MailConfig::default()
        };
        let settings = smtp_settings(&config).unwrap();
        assert_eq!(settings.host, "smtp-url.example.test");
        assert_eq!(settings.port, 587);
        assert_eq!(settings.username.as_deref(), Some("legacy-user"));
        assert_eq!(settings.password.as_deref(), Some("legacy-password"));
        assert_eq!(settings.mode, SmtpMode::OpportunisticStartTls);
    }

    #[test]
    fn mail_url_query_options_override_url_and_split_settings() {
        let config = MailConfig {
            url: Some(
                "smtp://url-user:url-pass@smtp-url.example.test:2525?host=query.example.test&port=25&username=query%40user&password=p%2Bss&encryption=&local_domain=query.example.test&timeout=1.5"
                    .to_owned(),
            ),
            username: Some("legacy-user".to_owned()),
            password: Some("legacy-password".to_owned()),
            encryption: "tls".to_owned(),
            ..MailConfig::default()
        };
        let settings = smtp_settings(&config).unwrap();
        assert_eq!(settings.host, "query.example.test");
        assert_eq!(settings.port, 25);
        assert_eq!(settings.username.as_deref(), Some("query@user"));
        assert_eq!(settings.password.as_deref(), Some("p+ss"));
        assert_eq!(settings.mode, SmtpMode::Plain);
        assert_eq!(settings.local_domain.as_deref(), Some("query.example.test"));
        assert_eq!(settings.timeout, Some(Duration::from_millis(1500)));
    }

    #[test]
    fn rejects_malformed_or_unsupported_mail_urls() {
        for connection_url in [
            "not a URL",
            "sendmail://default",
            "smtps://smtp.example.test",
        ] {
            let config = MailConfig {
                url: Some(connection_url.to_owned()),
                ..MailConfig::default()
            };
            assert!(smtp_settings(&config).is_err());
        }
    }

    #[tokio::test]
    async fn failover_mailer_logs_when_smtp_is_misconfigured() {
        let config = MailConfig {
            mailer: "failover".to_owned(),
            username: Some("smtp-user".to_owned()),
            password: None,
            ..MailConfig::default()
        };

        assert!(
            super::send_email(
                &config,
                "skin-user@example.test",
                "Test notification",
                "Fallback body",
            )
            .await
            .is_ok()
        );
        assert_eq!(config.mailer, "failover");
    }

    #[test]
    fn infers_tls_modes_from_legacy_mail_settings() {
        assert_eq!(smtp_mode("", 465).unwrap(), SmtpMode::ImplicitTls);
        assert_eq!(smtp_mode("ssl", 465).unwrap(), SmtpMode::ImplicitTls);
        assert_eq!(smtp_mode("ssl", 2525).unwrap(), SmtpMode::Plain);
        assert_eq!(smtp_mode("tls", 465).unwrap(), SmtpMode::ImplicitTls);
        assert_eq!(
            smtp_mode("tls", 587).unwrap(),
            SmtpMode::OpportunisticStartTls
        );
        assert_eq!(smtp_mode("", 587).unwrap(), SmtpMode::Plain);
        assert_eq!(smtp_mode("", 25).unwrap(), SmtpMode::Plain);
        assert!(smtp_mode("unknown", 465).is_err());
    }
}
