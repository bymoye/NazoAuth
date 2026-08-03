use std::{fs, path::Path};

use anyhow::{Context, bail};
use url::Url;

use crate::filesystem::{PrivateTempDir, atomic_write};

pub(crate) struct PostgresProvider {
    work: PrivateTempDir,
}

impl PostgresProvider {
    pub(crate) fn from_url_file(path: &Path) -> anyhow::Result<Self> {
        let raw = read_single_line(path)?;
        let url = Url::parse(&raw).context("PostgreSQL secret provider URL is invalid")?;
        if !matches!(url.scheme(), "postgres" | "postgresql") {
            bail!("PostgreSQL secret provider has an unsupported scheme");
        }
        let host = url.host_str().context("PostgreSQL URL has no host")?;
        let user = decode(url.username(), "PostgreSQL user")?;
        let password = decode(
            url.password().context("PostgreSQL URL has no password")?,
            "PostgreSQL password",
        )?;
        let database = decode(url.path().trim_start_matches('/'), "PostgreSQL database")?;
        if user.is_empty() || password.is_empty() || database.is_empty() || database.contains('/') {
            bail!("PostgreSQL URL must contain one database, user, and password");
        }
        let port = url.port().unwrap_or(5432).to_string();
        let work = PrivateTempDir::new("nazoauth-pg-provider")?;
        let mut service = format!(
            "[nazoauth]\nhost={}\nport={}\ndbname={}\nuser={}\n",
            service_value(host, "PostgreSQL host")?,
            service_value(&port, "PostgreSQL port")?,
            service_value(&database, "PostgreSQL database")?,
            service_value(&user, "PostgreSQL user")?
        );
        for (key, value) in url.query_pairs() {
            if key == "password"
                || key.is_empty()
                || !key
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '_')
            {
                bail!("PostgreSQL URL contains an unsafe service option");
            }
            service.push_str(&format!(
                "{}={}\n",
                key,
                service_value(&value, "PostgreSQL service option")?
            ));
        }
        let service_path = work.path().join("pg_service.conf");
        let pass_path = work.path().join("pgpass");
        atomic_write(&service_path, service.as_bytes(), 0o400)?;
        atomic_write(
            &pass_path,
            format!(
                "{}:{}:{}:{}:{}\n",
                pgpass_escape(host),
                pgpass_escape(&port),
                pgpass_escape(&database),
                pgpass_escape(&user),
                pgpass_escape(&password)
            )
            .as_bytes(),
            0o400,
        )?;
        Ok(Self { work })
    }

    pub(crate) fn service_file(&self) -> std::path::PathBuf {
        self.work.path().join("pg_service.conf")
    }

    pub(crate) fn password_file(&self) -> std::path::PathBuf {
        self.work.path().join("pgpass")
    }
}

pub(crate) struct ValkeyProvider {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) username: Option<String>,
    pub(crate) database: u32,
    pub(crate) tls: bool,
    password: String,
}

impl ValkeyProvider {
    pub(crate) fn from_url_file(path: &Path) -> anyhow::Result<Self> {
        let raw = read_single_line(path)?;
        let url = Url::parse(&raw).context("Valkey secret provider URL is invalid")?;
        if !matches!(url.scheme(), "redis" | "rediss") || url.query().is_some() {
            bail!("Valkey secret provider has an unsupported URL");
        }
        let username = (!url.username().is_empty())
            .then(|| decode(url.username(), "Valkey user"))
            .transpose()?;
        let password = decode(
            url.password().context("Valkey URL has no password")?,
            "Valkey password",
        )?;
        let database = url
            .path()
            .trim_start_matches('/')
            .parse::<u32>()
            .context("Valkey database is invalid")?;
        Ok(Self {
            host: url.host_str().context("Valkey URL has no host")?.to_owned(),
            port: url.port().unwrap_or(6379),
            username,
            database,
            tls: url.scheme() == "rediss",
            password,
        })
    }

    pub(crate) fn password_stdin(&self) -> Vec<u8> {
        format!("{}\n", self.password).into_bytes()
    }
}

fn read_single_line(path: &Path) -> anyhow::Result<String> {
    let value = fs::read_to_string(path)
        .with_context(|| format!("failed to read secret provider {}", path.display()))?;
    if value.is_empty() || value.contains(['\r', '\n']) {
        bail!("secret provider input must be one non-empty line");
    }
    Ok(value)
}

fn decode(value: &str, label: &str) -> anyhow::Result<String> {
    urlencoding::decode(value)
        .map(|value| value.into_owned())
        .with_context(|| format!("{label} has invalid percent encoding"))
}

fn service_value<'a>(value: &'a str, label: &str) -> anyhow::Result<&'a str> {
    if value.contains(['\0', '\r', '\n'])
        || value.chars().next_back().is_some_and(char::is_whitespace)
    {
        bail!("{label} cannot be represented safely in a PostgreSQL service file");
    }
    Ok(value)
}

fn pgpass_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace(':', "\\:")
}

#[cfg(test)]
#[path = "../tests/unit/secret_provider.rs"]
mod tests;
