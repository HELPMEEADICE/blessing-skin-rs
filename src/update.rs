use reqwest::{header::ACCEPT, redirect::Policy};
use semver::Version;
use serde::Deserialize;
use std::time::Duration;

const MAX_RELEASE_RESPONSE_BYTES: usize = 64 * 1024;
const RELEASE_CHECK_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LatestRelease {
    pub version: String,
    pub update_available: bool,
}

#[derive(Deserialize)]
struct ReleaseMetadata {
    tag_name: String,
}

pub async fn check_latest_release(
    api_url: &str,
    current_version: &str,
) -> Result<Option<LatestRelease>, String> {
    let url =
        url::Url::parse(api_url).map_err(|error| format!("invalid releases API URL: {error}"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(
            "releases API URL must be an HTTPS URL without credentials, query, or fragment"
                .to_owned(),
        );
    }

    let client = reqwest::Client::builder()
        .timeout(RELEASE_CHECK_TIMEOUT)
        .redirect(Policy::none())
        .user_agent(concat!("blessing-skin-rs/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|error| format!("could not create releases HTTP client: {error}"))?;
    let mut response = client
        .get(url)
        .header(ACCEPT, "application/vnd.github+json")
        .header("x-github-api-version", "2022-11-28")
        .send()
        .await
        .map_err(|error| format!("could not query latest release: {error}"))?;
    if !status_has_release_body(response.status())? {
        return Ok(None);
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RELEASE_RESPONSE_BYTES as u64)
    {
        return Err("releases API response exceeds 64 KiB".to_owned());
    }

    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| format!("could not read latest release response: {error}"))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_RELEASE_RESPONSE_BYTES {
            return Err("releases API response exceeds 64 KiB".to_owned());
        }
        body.extend_from_slice(&chunk);
    }
    latest_release_from_json(&body, current_version).map(Some)
}

fn status_has_release_body(status: reqwest::StatusCode) -> Result<bool, String> {
    if status.is_success() {
        Ok(true)
    } else if status == reqwest::StatusCode::NOT_FOUND {
        Ok(false)
    } else {
        Err(format!("releases API returned HTTP {status}"))
    }
}

fn latest_release_from_json(body: &[u8], current_version: &str) -> Result<LatestRelease, String> {
    let release: ReleaseMetadata = serde_json::from_slice(body)
        .map_err(|error| format!("invalid latest release response: {error}"))?;
    if release.tag_name.is_empty() || release.tag_name.len() > 128 {
        return Err("latest release tag must be between 1 and 128 bytes".to_owned());
    }
    let current = parse_version(current_version)?;
    let latest = parse_version(&release.tag_name)?;
    Ok(LatestRelease {
        version: release.tag_name,
        update_available: latest > current,
    })
}

fn parse_version(value: &str) -> Result<Version, String> {
    Version::parse(value.strip_prefix('v').unwrap_or(value))
        .map_err(|error| format!("invalid semantic version {value:?}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn treats_missing_latest_release_as_no_published_release() {
        assert!(!status_has_release_body(reqwest::StatusCode::NOT_FOUND).unwrap());
        assert!(status_has_release_body(reqwest::StatusCode::OK).unwrap());
        assert!(status_has_release_body(reqwest::StatusCode::INTERNAL_SERVER_ERROR).is_err());
    }

    #[test]
    fn parses_latest_github_release_and_detects_newer_versions() {
        let latest = latest_release_from_json(br#"{"tag_name":"v0.2.0"}"#, "0.1.9").unwrap();
        assert_eq!(latest.version, "v0.2.0");
        assert!(latest.update_available);
    }

    #[test]
    fn reports_current_or_newer_installed_versions_as_up_to_date() {
        for current_version in ["0.2.0", "0.3.0"] {
            let latest =
                latest_release_from_json(br#"{"tag_name":"0.2.0"}"#, current_version).unwrap();
            assert!(!latest.update_available);
        }
    }

    #[test]
    fn semver_prereleases_compare_before_their_final_release() {
        assert!(
            latest_release_from_json(br#"{"tag_name":"1.0.0"}"#, "1.0.0-rc.1")
                .unwrap()
                .update_available
        );
        assert!(
            !latest_release_from_json(br#"{"tag_name":"1.0.0-rc.1"}"#, "1.0.0")
                .unwrap()
                .update_available
        );
    }

    #[test]
    fn rejects_invalid_metadata_and_versions() {
        assert!(latest_release_from_json(b"{}", "0.1.0").is_err());
        assert!(latest_release_from_json(br#"{"tag_name":"next"}"#, "0.1.0").is_err());
        assert!(latest_release_from_json(br#"{"tag_name":"1.0.0"}"#, "dev").is_err());
    }

    #[tokio::test]
    async fn rejects_non_https_and_credentialed_release_sources() {
        for source in [
            "http://127.0.0.1/releases/latest",
            "https://user:password@example.com/releases/latest",
        ] {
            assert!(check_latest_release(source, "0.1.0").await.is_err());
        }
    }
}
