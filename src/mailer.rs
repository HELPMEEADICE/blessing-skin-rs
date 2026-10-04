use std::{process::Stdio, time::Duration};

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
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    process::Command,
    time::timeout,
};
use url::Url;

use crate::config::MailConfig;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SmtpMode {
    ImplicitTls,
    StartTls,
    OpportunisticStartTls,
    Plain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SendmailMode {
    Smtp,
    Direct,
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
        "sendmail" => send_sendmail_email(config, recipient, subject, body).await,
        "" => Err("Email delivery is not configured.".to_owned()),
        mailer => Err(format!("Unsupported mailer: {mailer}")),
    }
}

fn split_sendmail_command(command: &str) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut started = false;
    let mut chars = command.chars().peekable();

    while let Some(ch) = chars.next() {
        match quote {
            Some('\'') if ch == '\'' => quote = None,
            Some('\'') => word.push(ch),
            Some('"') if ch == '"' => quote = None,
            Some('"') if ch == '\\' && matches!(chars.peek(), Some('"' | '\\')) => {
                word.push(chars.next().expect("peeked character"));
            }
            Some('"') => word.push(ch),
            Some(_) => return Err("MAIL_SENDMAIL_PATH contains an unsupported quote.".to_owned()),
            None if ch.is_whitespace() => {
                if started {
                    words.push(std::mem::take(&mut word));
                    started = false;
                }
            }
            None if ch == '\'' || ch == '"' => {
                quote = Some(ch);
                started = true;
            }
            None if ch == '\\'
                && matches!(chars.peek(), Some(next) if next.is_whitespace() || *next == '\'' || *next == '"' || *next == '\\') =>
            {
                word.push(chars.next().expect("peeked character"));
                started = true;
            }
            None => {
                word.push(ch);
                started = true;
            }
        }
    }

    if quote.is_some() {
        return Err("MAIL_SENDMAIL_PATH contains an unmatched quote.".to_owned());
    }
    if started {
        words.push(word);
    }
    if words.is_empty() {
        return Err("MAIL_SENDMAIL_PATH is empty.".to_owned());
    }
    Ok(words)
}

fn sendmail_mode(arguments: &[String]) -> Result<SendmailMode, String> {
    if arguments.iter().any(|argument| argument == "-bs") {
        Ok(SendmailMode::Smtp)
    } else if arguments.iter().any(|argument| argument == "-t") {
        Ok(SendmailMode::Direct)
    } else {
        Err("MAIL_SENDMAIL_PATH must include either -bs or -t.".to_owned())
    }
}

async fn send_sendmail_email(
    config: &MailConfig,
    recipient: &str,
    subject: &str,
    body: &str,
) -> Result<(), String> {
    let mut arguments = split_sendmail_command(&config.sendmail_path)?;
    let executable = arguments.remove(0);
    let mode = sendmail_mode(&arguments)?;
    if mode == SendmailMode::Direct {
        arguments.retain(|argument| argument != "-t");
        if !arguments
            .iter()
            .any(|argument| argument == "-f" || argument.starts_with("-f"))
        {
            arguments.push("-f".to_owned());
            arguments.push(config.from_address.clone());
        }
        arguments.push("--".to_owned());
        arguments.push(recipient.to_owned());
    }

    let message = build_message(config, recipient, subject, body)?;
    let mut child = Command::new(executable)
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(if mode == SendmailMode::Smtp {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| format!("Could not start sendmail: {error}"))?;

    let delivery = timeout(Duration::from_secs(60), async {
        match mode {
            SendmailMode::Smtp => {
                let stdin = child
                    .stdin
                    .take()
                    .ok_or_else(|| "sendmail stdin is unavailable".to_owned())?;
                let stdout = child
                    .stdout
                    .take()
                    .ok_or_else(|| "sendmail stdout is unavailable".to_owned())?;
                let mut reader = BufReader::new(stdout);
                let mut stdin = stdin;
                smtp_sendmail_session(
                    &mut stdin,
                    &mut reader,
                    &message,
                    &config.from_address,
                    recipient,
                    config.local_domain.as_deref().unwrap_or("localhost"),
                )
                .await?;
                drop(stdin);
                let status = child
                    .wait()
                    .await
                    .map_err(|error| format!("Could not wait for sendmail: {error}"))?;
                if status.success() {
                    Ok(())
                } else {
                    Err(format!("sendmail exited with status {status}"))
                }
            }
            SendmailMode::Direct => {
                let mut stdin = child
                    .stdin
                    .take()
                    .ok_or_else(|| "sendmail stdin is unavailable".to_owned())?;
                stdin
                    .write_all(&message.formatted())
                    .await
                    .map_err(|error| format!("Could not write message to sendmail: {error}"))?;
                drop(stdin);
                let status = child
                    .wait()
                    .await
                    .map_err(|error| format!("Could not wait for sendmail: {error}"))?;
                if status.success() {
                    Ok(())
                } else {
                    Err(format!("sendmail exited with status {status}"))
                }
            }
        }
    })
    .await;

    match delivery {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            Err(error)
        }
        Err(_) => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            Err("sendmail delivery timed out after 60 seconds.".to_owned())
        }
    }
}

async fn smtp_sendmail_session<W, R>(
    stdin: &mut W,
    reader: &mut R,
    message: &Message,
    sender: &str,
    recipient: &str,
    local_domain: &str,
) -> Result<(), String>
where
    W: AsyncWrite + Unpin,
    R: AsyncBufRead + Unpin,
{
    if local_domain.chars().any(char::is_control) {
        return Err("MAIL_EHLO_DOMAIN contains a control character.".to_owned());
    }
    expect_smtp_reply(reader, 220).await?;
    let ehlo = smtp_command(stdin, reader, &format!("EHLO {local_domain}")).await?;
    if ehlo != 250 {
        let helo = smtp_command(stdin, reader, &format!("HELO {local_domain}")).await?;
        if helo != 250 {
            return Err(format!(
                "sendmail rejected EHLO/HELO with SMTP status {helo}"
            ));
        }
    }
    smtp_expect_command(stdin, reader, &format!("MAIL FROM:<{sender}>"), 250).await?;
    let recipient_status = smtp_command(stdin, reader, &format!("RCPT TO:<{recipient}>")).await?;
    if !matches!(recipient_status, 250 | 251 | 252) {
        return Err(format!(
            "sendmail rejected recipient with SMTP status {recipient_status}"
        ));
    }
    smtp_expect_command(stdin, reader, "DATA", 354).await?;
    stdin
        .write_all(&smtp_data(message.formatted().as_slice()))
        .await
        .map_err(|error| format!("Could not write message to sendmail: {error}"))?;
    stdin
        .flush()
        .await
        .map_err(|error| format!("Could not flush message to sendmail: {error}"))?;
    expect_smtp_reply(reader, 250).await?;
    smtp_expect_command(stdin, reader, "QUIT", 221).await
}

async fn smtp_command<W, R>(stdin: &mut W, reader: &mut R, command: &str) -> Result<u16, String>
where
    W: AsyncWrite + Unpin,
    R: AsyncBufRead + Unpin,
{
    stdin
        .write_all(format!("{command}\r\n").as_bytes())
        .await
        .map_err(|error| format!("Could not write SMTP command to sendmail: {error}"))?;
    stdin
        .flush()
        .await
        .map_err(|error| format!("Could not flush SMTP command to sendmail: {error}"))?;
    read_smtp_reply(reader).await
}

async fn smtp_expect_command<W, R>(
    stdin: &mut W,
    reader: &mut R,
    command: &str,
    expected: u16,
) -> Result<(), String>
where
    W: AsyncWrite + Unpin,
    R: AsyncBufRead + Unpin,
{
    let status = smtp_command(stdin, reader, command).await?;
    if status == expected {
        Ok(())
    } else {
        Err(format!(
            "sendmail rejected SMTP command with status {status}"
        ))
    }
}

async fn expect_smtp_reply<R>(reader: &mut R, expected: u16) -> Result<(), String>
where
    R: AsyncBufRead + Unpin,
{
    let status = read_smtp_reply(reader).await?;
    if status == expected {
        Ok(())
    } else {
        Err(format!("sendmail returned unexpected SMTP status {status}"))
    }
}

async fn read_smtp_reply<R>(reader: &mut R) -> Result<u16, String>
where
    R: AsyncBufRead + Unpin,
{
    let mut expected_code = None;
    loop {
        let mut line = String::new();
        let length = reader
            .read_line(&mut line)
            .await
            .map_err(|error| format!("Could not read sendmail SMTP response: {error}"))?;
        if length == 0 {
            return Err("sendmail closed its SMTP response stream unexpectedly.".to_owned());
        }
        let code = line
            .get(..3)
            .and_then(|value| value.parse::<u16>().ok())
            .ok_or_else(|| {
                format!(
                    "sendmail returned an invalid SMTP response: {}",
                    line.trim()
                )
            })?;
        if let Some(expected) = expected_code {
            if code != expected {
                return Err(format!(
                    "sendmail returned a malformed multiline SMTP response: {}",
                    line.trim()
                ));
            }
        } else {
            expected_code = Some(code);
        }
        if line.as_bytes().get(3) != Some(&b'-') {
            return Ok(code);
        }
    }
}

fn smtp_data(message: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(message.len() + 8);
    let mut at_line_start = true;
    let mut index = 0;
    while index < message.len() {
        let byte = message[index];
        if byte == b'\r' && message.get(index + 1) == Some(&b'\n') {
            data.extend_from_slice(b"\r\n");
            at_line_start = true;
            index += 2;
        } else if byte == b'\n' {
            data.extend_from_slice(b"\r\n");
            at_line_start = true;
            index += 1;
        } else {
            if at_line_start && byte == b'.' {
                data.push(b'.');
            }
            data.push(byte);
            at_line_start = false;
            index += 1;
        }
    }
    if !data.ends_with(b"\r\n") {
        data.extend_from_slice(b"\r\n");
    }
    data.extend_from_slice(b".\r\n");
    data
}

fn build_message(
    config: &MailConfig,
    recipient: &str,
    subject: &str,
    body: &str,
) -> Result<Message, String> {
    let from_address = config
        .from_address
        .parse()
        .map_err(|error| format!("Invalid MAIL_FROM_ADDRESS: {error}"))?;
    let to_address = recipient
        .parse()
        .map_err(|error| format!("Invalid recipient address: {error}"))?;
    let from = Mailbox::new(Some(config.from_name.clone()), from_address);
    let to = Mailbox::new(None, to_address);
    Message::builder()
        .from(from)
        .to(to)
        .subject(subject)
        .header(ContentType::TEXT_PLAIN)
        .body(body.to_owned())
        .map_err(|error| format!("Could not construct email: {error}"))
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
    let message = build_message(config, recipient, subject, body)?;

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

    use super::{
        SendmailMode, SmtpMode, build_message, sendmail_mode, smtp_data, smtp_mode,
        smtp_sendmail_session, smtp_settings, split_sendmail_command,
    };
    use crate::config::MailConfig;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

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
    async fn sends_a_complete_smtp_transaction_to_sendmail() {
        let message = build_message(
            &MailConfig::default(),
            "recipient@example.test",
            "SMTP test",
            "body\n.dot",
        )
        .unwrap();
        let (client, server) = tokio::io::duplex(8192);
        let (client_read, mut client_write) = tokio::io::split(client);
        let mut client_reader = BufReader::new(client_read);
        let (server_read, mut server_write) = tokio::io::split(server);
        let mut server_reader = BufReader::new(server_read);

        let server_task = tokio::spawn(async move {
            async fn read_command(
                reader: &mut BufReader<tokio::io::ReadHalf<tokio::io::DuplexStream>>,
            ) -> String {
                let mut line = String::new();
                reader.read_line(&mut line).await.unwrap();
                line
            }
            async fn reply(
                writer: &mut tokio::io::WriteHalf<tokio::io::DuplexStream>,
                text: &[u8],
            ) {
                writer.write_all(text).await.unwrap();
                writer.flush().await.unwrap();
            }

            reply(&mut server_write, b"220 sendmail ready\r\n").await;
            assert_eq!(
                read_command(&mut server_reader).await,
                "EHLO test.example\r\n"
            );
            reply(&mut server_write, b"250-sendmail\r\n250 OK\r\n").await;
            assert_eq!(
                read_command(&mut server_reader).await,
                "MAIL FROM:<hello@example.com>\r\n"
            );
            reply(&mut server_write, b"250 sender accepted\r\n").await;
            assert_eq!(
                read_command(&mut server_reader).await,
                "RCPT TO:<recipient@example.test>\r\n"
            );
            reply(&mut server_write, b"250 recipient accepted\r\n").await;
            assert_eq!(read_command(&mut server_reader).await, "DATA\r\n");
            reply(&mut server_write, b"354 send message\r\n").await;

            let mut data = String::new();
            loop {
                let line = read_command(&mut server_reader).await;
                if line == ".\r\n" {
                    break;
                }
                data.push_str(&line);
            }
            reply(&mut server_write, b"250 queued\r\n").await;
            assert_eq!(read_command(&mut server_reader).await, "QUIT\r\n");
            reply(&mut server_write, b"221 bye\r\n").await;
            data
        });

        smtp_sendmail_session(
            &mut client_write,
            &mut client_reader,
            &message,
            "hello@example.com",
            "recipient@example.test",
            "test.example",
        )
        .await
        .unwrap();

        let data = server_task.await.unwrap();
        assert!(data.contains("..dot\r\n"));
    }

    #[test]
    fn parses_laravel_sendmail_command_and_quoted_executable_paths() {
        assert_eq!(
            split_sendmail_command("/usr/sbin/sendmail -bs -i").unwrap(),
            vec!["/usr/sbin/sendmail", "-bs", "-i"]
        );
        assert_eq!(
            split_sendmail_command(r#""C:\Program Files\sendmail.exe" -t -i"#).unwrap(),
            vec![r"C:\Program Files\sendmail.exe", "-t", "-i"]
        );
        assert!(split_sendmail_command("sendmail -t '").is_err());
    }

    #[test]
    fn identifies_supported_sendmail_modes_and_rejects_others() {
        assert_eq!(
            sendmail_mode(&["-bs".to_owned(), "-i".to_owned()]).unwrap(),
            SendmailMode::Smtp
        );
        assert_eq!(
            sendmail_mode(&["-t".to_owned(), "-i".to_owned()]).unwrap(),
            SendmailMode::Direct
        );
        assert!(sendmail_mode(&["-i".to_owned()]).is_err());
    }

    #[test]
    fn dot_stuffs_smtp_data_and_normalizes_line_endings() {
        assert_eq!(
            smtp_data(b"Subject: test\r\n\r\n.line\nbody\r\n"),
            b"Subject: test\r\n\r\n..line\r\nbody\r\n.\r\n"
        );
        assert_eq!(smtp_data(b"body"), b"body\r\n.\r\n");
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
