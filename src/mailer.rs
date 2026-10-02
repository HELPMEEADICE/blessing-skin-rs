use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, header::ContentType},
    transport::smtp::authentication::Credentials,
};

use crate::config::MailConfig;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SmtpMode {
    ImplicitTls,
    StartTls,
    Plain,
}

fn smtp_mode(encryption: &str, port: u16) -> Result<SmtpMode, String> {
    match encryption.trim().to_ascii_lowercase().as_str() {
        "ssl" | "smtps" => Ok(SmtpMode::ImplicitTls),
        "tls" | "starttls" => Ok(SmtpMode::StartTls),
        "" if port == 465 => Ok(SmtpMode::ImplicitTls),
        "" if port == 587 => Ok(SmtpMode::StartTls),
        "" => Ok(SmtpMode::Plain),
        other => Err(format!("unsupported MAIL_ENCRYPTION value: {other}")),
    }
}

pub async fn send_email(
    config: &MailConfig,
    recipient: &str,
    subject: &str,
    body: &str,
) -> Result<(), String> {
    match config.mailer.trim().to_ascii_lowercase().as_str() {
        "log" => {
            tracing::info!(
                to = recipient,
                subject,
                body,
                "email captured by log mailer"
            );
            return Ok(());
        }
        "array" => return Ok(()),
        "smtp" => {}
        "" => return Err("Email delivery is not configured.".to_owned()),
        mailer => return Err(format!("Unsupported mailer: {mailer}")),
    }
    if config.host.trim().is_empty() {
        return Err("MAIL_HOST is not configured.".to_owned());
    }
    if config.username.is_some() != config.password.is_some() {
        return Err("MAIL_USERNAME and MAIL_PASSWORD must be configured together.".to_owned());
    }
    let mode = smtp_mode(&config.encryption, config.port)?;
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

    let mut transport = match mode {
        SmtpMode::ImplicitTls => AsyncSmtpTransport::<Tokio1Executor>::relay(&config.host),
        SmtpMode::StartTls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.host),
        SmtpMode::Plain => Ok(AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(
            &config.host,
        )),
    }
    .map_err(|error| format!("Could not configure SMTP transport: {error}"))?
    .port(config.port);
    if let (Some(username), Some(password)) = (&config.username, &config.password) {
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
    use super::{SmtpMode, smtp_mode};

    #[test]
    fn infers_tls_modes_from_legacy_mail_settings() {
        assert_eq!(smtp_mode("", 465).unwrap(), SmtpMode::ImplicitTls);
        assert_eq!(smtp_mode("", 587).unwrap(), SmtpMode::StartTls);
        assert_eq!(smtp_mode("ssl", 2525).unwrap(), SmtpMode::ImplicitTls);
        assert_eq!(smtp_mode("tls", 465).unwrap(), SmtpMode::StartTls);
        assert_eq!(smtp_mode("", 25).unwrap(), SmtpMode::Plain);
        assert!(smtp_mode("unknown", 465).is_err());
    }
}
