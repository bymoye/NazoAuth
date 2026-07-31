use std::{env, path::PathBuf};

use anyhow::{Context, bail};

use crate::model::semantic_tag;

pub(crate) const DEFAULT_CONFIG: &str = "/etc/nazoauth/update.json";

#[derive(Debug)]
pub(crate) struct Cli {
    pub(crate) config: PathBuf,
    pub(crate) command: Command,
}

#[derive(Debug)]
pub(crate) enum Command {
    Install(InstallOptions),
    Status,
    Doctor,
    Check(Option<String>),
    Update(UpdateOptions),
    Rollback { yes: bool },
    Recover { yes: bool },
    Migrate { yes: bool },
    Keys(KeysCommand),
    AuditVerify,
    AuditShow { request_id: Option<String> },
    IdentityRotate { yes: bool },
    BreakGlassRecover { yes: bool, reason: String },
}

#[derive(Debug)]
pub(crate) enum KeysCommand {
    List,
    Validate,
    GenerateLocal {
        alg: String,
        purposes: Vec<String>,
        yes: bool,
    },
    RegisterExternal {
        kid: String,
        alg: String,
        key_ref: String,
        public_jwk: PathBuf,
        yes: bool,
    },
}

#[derive(Debug)]
pub(crate) struct UpdateOptions {
    pub(crate) version: Option<String>,
    pub(crate) plan: bool,
    pub(crate) yes: bool,
    pub(crate) accept_migration_barrier: bool,
}

#[derive(Debug)]
pub(crate) struct InstallOptions {
    pub(crate) runtime: String,
    pub(crate) public_url: String,
    pub(crate) profile: String,
    pub(crate) profile_material: Option<PathBuf>,
    pub(crate) data_root: PathBuf,
    pub(crate) port: u16,
    pub(crate) database_url: Option<String>,
    pub(crate) migration_database_url: Option<String>,
    pub(crate) valkey_url: Option<String>,
    pub(crate) external_dependencies: bool,
    pub(crate) secrets_stdin: bool,
    pub(crate) secret_fd: Option<u32>,
    pub(crate) version: Option<String>,
}

impl Cli {
    pub(crate) fn parse(args: impl IntoIterator<Item = String>) -> anyhow::Result<Option<Self>> {
        let mut args = args.into_iter();
        let _program = args.next();
        let mut values = args.collect::<Vec<_>>();
        if values.is_empty()
            || values
                .iter()
                .any(|value| matches!(value.as_str(), "-h" | "--help"))
        {
            return Ok(None);
        }
        let mut config = env::var_os("NAZOAUTH_UPDATE_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG));
        if values.first().is_some_and(|value| value == "--config") {
            if values.len() < 2 {
                bail!("--config requires a path");
            }
            config = PathBuf::from(values.remove(1));
            values.remove(0);
        }
        let command = values.first().cloned().context("a command is required")?;
        values.remove(0);
        let command = match command.as_str() {
            "install" => Command::Install(parse_install(values)?),
            "status" => {
                no_arguments(&values, "status")?;
                Command::Status
            }
            "doctor" => {
                no_arguments(&values, "doctor")?;
                Command::Doctor
            }
            "check" => Command::Check(parse_version_option(values)?),
            "update" => Command::Update(parse_update_options(values)?),
            "rollback" => Command::Rollback {
                yes: parse_yes(values, "rollback")?,
            },
            "recover" => Command::Recover {
                yes: parse_yes(values, "recover")?,
            },
            "migrate" => Command::Migrate {
                yes: parse_yes(values, "migrate")?,
            },
            "keys" => Command::Keys(parse_keys(values)?),
            "audit" if values == ["verify"] => Command::AuditVerify,
            "audit" if values.first().is_some_and(|value| value == "show") => {
                values.remove(0);
                let request_id = if values.is_empty() {
                    None
                } else if values.len() == 2 && values[0] == "--request-id" {
                    let value = values[1].clone();
                    if value.is_empty()
                        || value.len() > 128
                        || !value.chars().all(|character| {
                            character.is_ascii_alphanumeric() || "._-".contains(character)
                        })
                    {
                        bail!("audit request ID is unsafe");
                    }
                    Some(value)
                } else {
                    bail!("audit show accepts only --request-id ID");
                };
                Command::AuditShow { request_id }
            }
            "identity" if values.first().is_some_and(|value| value == "rotate") => {
                values.remove(0);
                Command::IdentityRotate {
                    yes: parse_yes(values, "identity rotate")?,
                }
            }
            "break-glass"
                if values
                    .first()
                    .is_some_and(|value| value == "recover-controller") =>
            {
                values.remove(0);
                let mut yes = false;
                let mut reason = None;
                let mut index = 0;
                while index < values.len() {
                    match values[index].as_str() {
                        "--yes" => {
                            yes = true;
                            index += 1;
                        }
                        "--reason" => {
                            reason = Some(
                                values
                                    .get(index + 1)
                                    .context("--reason requires lost or stolen")?
                                    .clone(),
                            );
                            index += 2;
                        }
                        other => bail!("unknown break-glass option {other}"),
                    }
                }
                let reason =
                    reason.context("break-glass recovery requires --reason lost|stolen")?;
                if !matches!(reason.as_str(), "lost" | "stolen") {
                    bail!("--reason must be lost or stolen");
                }
                Command::BreakGlassRecover { yes, reason }
            }
            other => bail!("unknown command {other}"),
        };
        Ok(Some(Self { config, command }))
    }
}

fn parse_keys(values: Vec<String>) -> anyhow::Result<KeysCommand> {
    let mut values = values.into_iter();
    let command = values.next().context("keys requires an operation")?;
    let values = values.collect::<Vec<_>>();
    match command.as_str() {
        "list" if values.is_empty() => Ok(KeysCommand::List),
        "validate" if values.is_empty() => Ok(KeysCommand::Validate),
        "generate-local" => {
            let (values, yes) = take_yes(values)?;
            let values = parse_named_options(values, &["--alg", "--purposes"])?;
            Ok(KeysCommand::GenerateLocal {
                alg: values["--alg"].clone(),
                purposes: values["--purposes"].split(',').map(str::to_owned).collect(),
                yes,
            })
        }
        "register-external" => {
            let (values, yes) = take_yes(values)?;
            let values =
                parse_named_options(values, &["--kid", "--alg", "--key-ref", "--public-jwk"])?;
            Ok(KeysCommand::RegisterExternal {
                kid: values["--kid"].clone(),
                alg: values["--alg"].clone(),
                key_ref: values["--key-ref"].clone(),
                public_jwk: PathBuf::from(&values["--public-jwk"]),
                yes,
            })
        }
        _ => bail!("unsupported keys operation or arguments"),
    }
}

fn take_yes(mut values: Vec<String>) -> anyhow::Result<(Vec<String>, bool)> {
    let positions = values
        .iter()
        .enumerate()
        .filter_map(|(index, value)| (value == "--yes").then_some(index))
        .collect::<Vec<_>>();
    if positions.len() > 1 {
        bail!("--yes may be supplied only once");
    }
    let yes = !positions.is_empty();
    if let Some(index) = positions.first().copied() {
        values.remove(index);
    }
    Ok((values, yes))
}

fn parse_named_options(
    values: Vec<String>,
    expected: &[&str],
) -> anyhow::Result<std::collections::BTreeMap<String, String>> {
    if values.len() != expected.len() * 2 {
        bail!("keys operation has missing or unexpected options");
    }
    let mut parsed = std::collections::BTreeMap::new();
    let mut values = values.into_iter();
    while let Some(key) = values.next() {
        let value = values.next().context("keys option has no value")?;
        if !expected.contains(&key.as_str()) || parsed.insert(key, value).is_some() {
            bail!("keys operation has duplicate or unexpected options");
        }
    }
    Ok(parsed)
}

fn parse_update_options(values: Vec<String>) -> anyhow::Result<UpdateOptions> {
    let mut version = None;
    let mut plan = false;
    let mut yes = false;
    let mut accept_migration_barrier = false;
    let mut index = 0;
    while index < values.len() {
        match values[index].as_str() {
            "--plan" => {
                plan = true;
                index += 1;
            }
            "--yes" => {
                yes = true;
                index += 1;
            }
            "--accept-migration-barrier" => {
                accept_migration_barrier = true;
                index += 1;
            }
            "--to" => {
                let value = values.get(index + 1).context("--to requires VERSION")?;
                validate_version(value)?;
                version = Some(value.clone());
                index += 2;
            }
            other => bail!("unknown update option {other}"),
        }
    }
    if plan && (yes || accept_migration_barrier) {
        bail!("update --plan cannot be combined with mutation authorization flags");
    }
    Ok(UpdateOptions {
        version,
        plan,
        yes,
        accept_migration_barrier,
    })
}

fn parse_yes(values: Vec<String>, command: &str) -> anyhow::Result<bool> {
    if values.is_empty() {
        return Ok(false);
    }
    if values == ["--yes"] {
        return Ok(true);
    }
    bail!("{command} accepts only --yes")
}

fn parse_install(values: Vec<String>) -> anyhow::Result<InstallOptions> {
    let mut runtime = "auto".to_owned();
    let mut public_url = "http://127.0.0.1:8000".to_owned();
    let mut profile = "baseline".to_owned();
    let mut profile_material = None;
    let mut data_root = PathBuf::from("/var/lib/nazoauth");
    let mut port = 8000;
    let database_url = None;
    let migration_database_url = None;
    let valkey_url = None;
    let mut external_dependencies = false;
    let mut secrets_stdin = false;
    let mut secret_fd = None;
    let mut version = None;
    let mut index = 0;
    while index < values.len() {
        let flag = values[index].as_str();
        if flag == "--external-dependencies" {
            external_dependencies = true;
            index += 1;
            continue;
        }
        if flag == "--secrets-stdin" {
            secrets_stdin = true;
            index += 1;
            continue;
        }
        let value = values
            .get(index + 1)
            .with_context(|| format!("{flag} requires a value"))?
            .clone();
        match flag {
            "--runtime" => runtime = value,
            "--public-url" => public_url = value,
            "--profile" => profile = value,
            "--profile-material" => profile_material = Some(PathBuf::from(value)),
            "--data-root" => data_root = PathBuf::from(value),
            "--port" => {
                port = value
                    .parse()
                    .context("--port must be an integer from 1 through 65535")?;
                if port == 0 {
                    bail!("--port must be an integer from 1 through 65535");
                }
            }
            "--secret-fd" => {
                secret_fd = Some(value.parse().context("--secret-fd must be an integer")?);
            }
            "--to" => {
                validate_version(&value)?;
                version = Some(value);
            }
            other => bail!("unknown install option {other}"),
        }
        index += 2;
    }
    if !matches!(runtime.as_str(), "auto" | "podman" | "docker" | "host") {
        bail!("--runtime must be auto, podman, docker, or host");
    }
    if !matches!(profile.as_str(), "baseline" | "standards-full") {
        bail!("--profile must be baseline or standards-full");
    }
    if profile == "standards-full" && profile_material.is_none() {
        bail!("--profile standards-full requires --profile-material PATH");
    }
    if profile == "baseline" && profile_material.is_some() {
        bail!("--profile-material is accepted only with --profile standards-full");
    }
    Ok(InstallOptions {
        runtime,
        public_url,
        profile,
        profile_material,
        data_root,
        port,
        database_url,
        migration_database_url,
        valkey_url,
        external_dependencies,
        secrets_stdin,
        secret_fd,
        version,
    })
}

fn parse_version_option(values: Vec<String>) -> anyhow::Result<Option<String>> {
    if values.is_empty() {
        return Ok(None);
    }
    if values.len() != 2 || values[0] != "--to" {
        bail!("expected only --to VERSION");
    }
    validate_version(&values[1])?;
    Ok(Some(values[1].clone()))
}

fn validate_version(version: &str) -> anyhow::Result<()> {
    if !semantic_tag(version) {
        bail!("release version is not an immutable semantic tag");
    }
    Ok(())
}

fn no_arguments(values: &[String], command: &str) -> anyhow::Result<()> {
    if let Some(argument) = values.first() {
        bail!("{command} does not accept argument {argument}");
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/unit/cli.rs"]
mod tests;
