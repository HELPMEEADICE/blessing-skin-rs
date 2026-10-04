use std::{process::Stdio, time::Duration};

use hmac::{Hmac, Mac};
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
use reqwest::{Client, multipart::Form, redirect::Policy};
use sha2::{Digest, Sha256};
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SesApiVersion {
    Query,
    V2,
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
        "mailgun" => send_mailgun_email(config, recipient, subject, body).await,
        "postmark" => send_postmark_email(config, recipient, subject, body).await,
        "ses" => send_ses_email(config, recipient, subject, body, SesApiVersion::Query).await,
        "ses-v2" => send_ses_email(config, recipient, subject, body, SesApiVersion::V2).await,
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

fn mailgun_url(domain: &str, endpoint: &str) -> Result<Url, String> {
    let domain = domain.trim();
    if domain.is_empty()
        || !domain
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '.' | '-'))
    {
        return Err("MAILGUN_DOMAIN must be a valid DNS name.".to_owned());
    }

    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        return Err("MAILGUN_ENDPOINT is empty.".to_owned());
    }
    let raw_url = if endpoint.contains("://") {
        endpoint.to_owned()
    } else {
        format!("https://{endpoint}")
    };
    let mut url =
        Url::parse(&raw_url).map_err(|error| format!("Invalid MAILGUN_ENDPOINT: {error}"))?;
    let host = url
        .host_str()
        .ok_or_else(|| "MAILGUN_ENDPOINT must include a host.".to_owned())?;
    if url.scheme() != "https"
        || (!host.eq_ignore_ascii_case("mailgun.net")
            && !host.to_ascii_lowercase().ends_with(".mailgun.net"))
        || !url.username().is_empty()
        || url.password().is_some()
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("MAILGUN_ENDPOINT must be an HTTPS Mailgun API host.".to_owned());
    }

    url.set_path("");
    url.path_segments_mut()
        .map_err(|_| "MAILGUN_ENDPOINT cannot be used as a base URL.".to_owned())?
        .extend(["v3", domain, "messages"]);
    Ok(url)
}

fn mailgun_fields(
    config: &MailConfig,
    recipient: &str,
    subject: &str,
    body: &str,
) -> Result<Vec<(String, String)>, String> {
    let from = from_mailbox(config)?.to_string();
    Ok(vec![
        ("from".to_owned(), from),
        ("to".to_owned(), recipient.to_owned()),
        ("subject".to_owned(), subject.to_owned()),
        ("text".to_owned(), body.to_owned()),
    ])
}

fn postmark_payload(
    config: &MailConfig,
    recipient: &str,
    subject: &str,
    body: &str,
) -> Result<serde_json::Value, String> {
    let mut payload = serde_json::json!({
        "From": from_mailbox(config)?.to_string(),
        "To": recipient,
        "Subject": subject,
        "TextBody": body,
    });
    if let Some(message_stream) = &config.postmark_message_stream {
        payload["MessageStream"] = serde_json::Value::String(message_stream.clone());
    }
    Ok(payload)
}

fn mail_api_client() -> Result<Client, String> {
    Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(Policy::none())
        .build()
        .map_err(|error| format!("Could not configure mail API client: {error}"))
}

async fn check_mail_api_response(
    provider: &str,
    response: reqwest::Response,
) -> Result<(), String> {
    let status = response.status();
    if status.is_success() {
        Ok(())
    } else {
        Err(format!("{provider} mail API returned HTTP {status}"))
    }
}

async fn send_mailgun_email(
    config: &MailConfig,
    recipient: &str,
    subject: &str,
    body: &str,
) -> Result<(), String> {
    let domain = config
        .mailgun_domain
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "MAILGUN_DOMAIN is not configured.".to_owned())?;
    let secret = config
        .mailgun_secret
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "MAILGUN_SECRET is not configured.".to_owned())?;
    let url = mailgun_url(domain, &config.mailgun_endpoint)?;
    let fields = mailgun_fields(config, recipient, subject, body)?;
    let form = fields
        .into_iter()
        .fold(Form::new(), |form, (name, value)| form.text(name, value));
    let response = mail_api_client()?
        .post(url)
        .basic_auth("api", Some(secret))
        .multipart(form)
        .send()
        .await
        .map_err(|error| format!("Mailgun delivery failed: {error}"))?;
    check_mail_api_response("Mailgun", response).await
}

async fn send_postmark_email(
    config: &MailConfig,
    recipient: &str,
    subject: &str,
    body: &str,
) -> Result<(), String> {
    let token = config
        .postmark_token
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "POSTMARK_TOKEN is not configured.".to_owned())?;
    let payload = postmark_payload(config, recipient, subject, body)?;
    let response = mail_api_client()?
        .post("https://api.postmarkapp.com/email")
        .header("Accept", "application/json")
        .header("X-Postmark-Server-Token", token)
        .json(&payload)
        .send()
        .await
        .map_err(|error| format!("Postmark delivery failed: {error}"))?;
    check_mail_api_response("Postmark", response).await
}

fn ses_region_host(region: &str) -> Result<String, String> {
    let region = region.trim();
    if region.is_empty()
        || !region.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
    {
        return Err("AWS_DEFAULT_REGION must be a lowercase AWS region name.".to_owned());
    }
    let dns_suffix = if region.starts_with("cn-") {
        "amazonaws.com.cn"
    } else {
        "amazonaws.com"
    };
    Ok(format!("email.{region}.{dns_suffix}"))
}

fn ses_query_form(
    config: &MailConfig,
    recipient: &str,
    subject: &str,
    body: &str,
) -> Result<String, String> {
    let from = from_mailbox(config)?.to_string();
    let fields = [
        ("Action", "SendEmail".to_owned()),
        ("Version", "2010-12-01".to_owned()),
        ("Source", from),
        ("Destination.ToAddresses.member.1", recipient.to_owned()),
        ("Message.Subject.Data", subject.to_owned()),
        ("Message.Subject.Charset", "UTF-8".to_owned()),
        ("Message.Body.Text.Data", body.to_owned()),
        ("Message.Body.Text.Charset", "UTF-8".to_owned()),
    ];
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    serializer.extend_pairs(fields);
    Ok(serializer.finish())
}

fn ses_v2_payload(
    config: &MailConfig,
    recipient: &str,
    subject: &str,
    body: &str,
) -> Result<serde_json::Value, String> {
    Ok(serde_json::json!({
        "FromEmailAddress": from_mailbox(config)?.to_string(),
        "Destination": {
            "ToAddresses": [recipient],
        },
        "Content": {
            "Simple": {
                "Subject": {
                    "Data": subject,
                    "Charset": "UTF-8",
                },
                "Body": {
                    "Text": {
                        "Data": body,
                        "Charset": "UTF-8",
                    },
                },
            },
        },
    }))
}

fn sha256_hex(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}

fn hmac_sha256(key: &[u8], value: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts arbitrary key lengths");
    mac.update(value);
    mac.finalize().into_bytes().to_vec()
}

fn aws_v4_authorization(
    access_key: &str,
    secret_key: &str,
    session_token: Option<&str>,
    region: &str,
    host: &str,
    path: &str,
    content_type: &str,
    timestamp: &str,
    payload: &[u8],
) -> Result<String, String> {
    let date = timestamp
        .get(..8)
        .filter(|date| date.bytes().all(|byte| byte.is_ascii_digit()))
        .ok_or_else(|| "Invalid AWS signing timestamp.".to_owned())?;
    if [access_key, secret_key, host, path, content_type, timestamp]
        .iter()
        .any(|value| value.chars().any(char::is_control))
        || session_token.is_some_and(|value| value.chars().any(char::is_control))
    {
        return Err(
            "AWS SES credentials or signing values contain a control character.".to_owned(),
        );
    }

    let scope = format!("{date}/{region}/ses/aws4_request");
    let mut canonical_headers =
        format!("content-type:{content_type}\nhost:{host}\nx-amz-date:{timestamp}");
    let mut signed_headers = "content-type;host;x-amz-date".to_owned();
    if let Some(token) = session_token {
        canonical_headers.push_str(&format!("\nx-amz-security-token:{token}"));
        signed_headers.push_str(";x-amz-security-token");
    }
    let canonical_request = format!(
        "POST\n{path}\n\n{canonical_headers}\n{signed_headers}\n{}",
        sha256_hex(payload)
    );
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{timestamp}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );

    let initial_key = format!("AWS4{secret_key}");
    let date_key = hmac_sha256(initial_key.as_bytes(), date.as_bytes());
    let region_key = hmac_sha256(&date_key, region.as_bytes());
    let service_key = hmac_sha256(&region_key, b"ses");
    let signing_key = hmac_sha256(&service_key, b"aws4_request");
    let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));
    Ok(format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"
    ))
}

async fn send_ses_email(
    config: &MailConfig,
    recipient: &str,
    subject: &str,
    body: &str,
    version: SesApiVersion,
) -> Result<(), String> {
    let access_key = config
        .ses_access_key
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "AWS_ACCESS_KEY_ID is not configured.".to_owned())?;
    let secret_key = config
        .ses_secret_key
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "AWS_SECRET_ACCESS_KEY is not configured.".to_owned())?;
    let host = ses_region_host(&config.ses_region)?;
    let (path, content_type, payload) = match version {
        SesApiVersion::Query => (
            "/",
            "application/x-www-form-urlencoded",
            ses_query_form(config, recipient, subject, body)?.into_bytes(),
        ),
        SesApiVersion::V2 => (
            "/v2/email/outbound-emails",
            "application/json",
            serde_json::to_vec(&ses_v2_payload(config, recipient, subject, body)?)
                .map_err(|error| format!("Could not encode SES v2 request: {error}"))?,
        ),
    };
    let url = Url::parse(&format!("https://{host}{path}"))
        .map_err(|error| format!("Invalid Amazon SES endpoint: {error}"))?;
    let timestamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let authorization = aws_v4_authorization(
        access_key,
        secret_key,
        config.ses_session_token.as_deref(),
        &config.ses_region,
        &host,
        path,
        content_type,
        &timestamp,
        &payload,
    )?;

    let mut request = mail_api_client()?
        .post(url)
        .header("Host", &host)
        .header("Content-Type", content_type)
        .header("X-Amz-Date", timestamp)
        .header("Authorization", authorization)
        .body(payload);
    if let Some(session_token) = &config.ses_session_token {
        request = request.header("X-Amz-Security-Token", session_token);
    }
    let response = request
        .send()
        .await
        .map_err(|error| format!("Amazon SES delivery failed: {error}"))?;
    check_mail_api_response("Amazon SES", response).await
}

fn from_mailbox(config: &MailConfig) -> Result<Mailbox, String> {
    let address = config
        .from_address
        .parse()
        .map_err(|error| format!("Invalid MAIL_FROM_ADDRESS: {error}"))?;
    Ok(Mailbox::new(Some(config.from_name.clone()), address))
}

fn build_message(
    config: &MailConfig,
    recipient: &str,
    subject: &str,
    body: &str,
) -> Result<Message, String> {
    let from = from_mailbox(config)?;
    let to_address = recipient
        .parse()
        .map_err(|error| format!("Invalid recipient address: {error}"))?;
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
        SendmailMode, SmtpMode, aws_v4_authorization, build_message, mailgun_fields, mailgun_url,
        postmark_payload, sendmail_mode, ses_query_form, ses_region_host, ses_v2_payload,
        smtp_data, smtp_mode, smtp_sendmail_session, smtp_settings, split_sendmail_command,
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
    fn builds_ses_query_and_v2_message_payloads() {
        let config = MailConfig {
            from_address: "noreply@example.test".to_owned(),
            from_name: "Blessing Skin".to_owned(),
            ..MailConfig::default()
        };
        let query = ses_query_form(
            &config,
            "skin-user@example.test",
            "Verify account",
            "Use this code: 123",
        )
        .unwrap();
        let fields = form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(fields["Action"], "SendEmail");
        assert_eq!(fields["Version"], "2010-12-01");
        assert_eq!(fields["Source"], "Blessing Skin <noreply@example.test>");
        assert_eq!(
            fields["Destination.ToAddresses.member.1"],
            "skin-user@example.test"
        );
        assert_eq!(fields["Message.Subject.Data"], "Verify account");
        assert_eq!(fields["Message.Body.Text.Data"], "Use this code: 123");

        assert_eq!(
            ses_v2_payload(
                &config,
                "skin-user@example.test",
                "Verify account",
                "Use this code: 123",
            )
            .unwrap(),
            serde_json::json!({
                "FromEmailAddress": "Blessing Skin <noreply@example.test>",
                "Destination": { "ToAddresses": ["skin-user@example.test"] },
                "Content": {
                    "Simple": {
                        "Subject": { "Data": "Verify account", "Charset": "UTF-8" },
                        "Body": {
                            "Text": { "Data": "Use this code: 123", "Charset": "UTF-8" }
                        }
                    }
                }
            })
        );
    }

    #[test]
    fn resolves_ses_regional_endpoints_and_rejects_invalid_regions() {
        assert_eq!(
            ses_region_host("us-east-1").unwrap(),
            "email.us-east-1.amazonaws.com"
        );
        assert_eq!(
            ses_region_host("cn-north-1").unwrap(),
            "email.cn-north-1.amazonaws.com.cn"
        );
        assert!(ses_region_host("https://attacker.example").is_err());
        assert!(ses_region_host("us-east-1/attacker").is_err());
    }

    #[test]
    fn signs_ses_requests_with_optional_session_credentials() {
        let authorization = aws_v4_authorization(
            "AKIDEXAMPLE",
            "secret-example",
            Some("session-token"),
            "us-east-1",
            "email.us-east-1.amazonaws.com",
            "/v2/email/outbound-emails",
            "application/json",
            "20261005T120000Z",
            br#"{"test":true}"#,
        )
        .unwrap();
        assert_eq!(
            authorization,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261005/us-east-1/ses/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-security-token, Signature=d1a759f341c6808321e7825567f9a925173d8955dd1d48808b7c140958fb1d16"
        );
        assert!(
            aws_v4_authorization(
                "AKIDEXAMPLE",
                "secret-example",
                Some("bad\r\ntoken"),
                "us-east-1",
                "email.us-east-1.amazonaws.com",
                "/",
                "application/x-www-form-urlencoded",
                "20261005T120000Z",
                b"Action=SendEmail",
            )
            .is_err()
        );
    }

    #[test]
    fn builds_mailgun_requests_for_the_configured_region() {
        let config = MailConfig {
            from_address: "noreply@example.test".to_owned(),
            from_name: "Blessing Skin".to_owned(),
            ..MailConfig::default()
        };
        assert_eq!(
            mailgun_url("mg.example.test", "api.eu.mailgun.net")
                .unwrap()
                .as_str(),
            "https://api.eu.mailgun.net/v3/mg.example.test/messages"
        );
        let fields = mailgun_fields(
            &config,
            "skin-user@example.test",
            "Verify account",
            "Use this code: 123",
        )
        .unwrap();
        assert_eq!(
            fields,
            vec![
                (
                    "from".to_owned(),
                    "Blessing Skin <noreply@example.test>".to_owned()
                ),
                ("to".to_owned(), "skin-user@example.test".to_owned()),
                ("subject".to_owned(), "Verify account".to_owned()),
                ("text".to_owned(), "Use this code: 123".to_owned()),
            ]
        );
    }

    #[test]
    fn rejects_insecure_or_non_mailgun_api_endpoints() {
        for endpoint in [
            "http://api.mailgun.net",
            "https://attacker.example.test",
            "https://api.mailgun.net/other-path",
            "https://user:secret@api.mailgun.net",
        ] {
            assert!(mailgun_url("mg.example.test", endpoint).is_err());
        }
        assert!(mailgun_url("mg.example.test/path", "api.mailgun.net").is_err());
    }

    #[test]
    fn builds_postmark_plain_text_payload_and_optional_stream() {
        let config = MailConfig {
            from_address: "noreply@example.test".to_owned(),
            from_name: "Blessing Skin".to_owned(),
            postmark_message_stream: Some("transactional".to_owned()),
            ..MailConfig::default()
        };
        assert_eq!(
            postmark_payload(
                &config,
                "skin-user@example.test",
                "Verify account",
                "Use this code: 123",
            )
            .unwrap(),
            serde_json::json!({
                "From": "Blessing Skin <noreply@example.test>",
                "To": "skin-user@example.test",
                "Subject": "Verify account",
                "TextBody": "Use this code: 123",
                "MessageStream": "transactional",
            })
        );
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
