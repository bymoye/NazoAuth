use std::{env, path::PathBuf};

use anyhow::{Context, bail};

use crate::model::semantic_tag;

pub(crate) const DEFAULT_CONFIG: &str = "/etc/nazoauth/update.json";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HelpTopic {
    TopLevel,
    Install,
    BootstrapAdmin,
    Update,
    Keys,
    Conformance,
    Audit,
    Identity,
    BreakGlass,
}

pub(crate) fn help_topic(args: &[String]) -> Option<HelpTopic> {
    if !args
        .iter()
        .any(|value| matches!(value.as_str(), "-h" | "--help"))
    {
        return None;
    }
    let mut values = args.iter().skip(1);
    let first = values.next()?;
    let command = if first == "--config" {
        values.next()?;
        values.next().map(String::as_str)
    } else {
        Some(first.as_str())
    };
    Some(match command {
        Some("install") => HelpTopic::Install,
        Some("bootstrap-admin") => HelpTopic::BootstrapAdmin,
        Some(
            "update" | "check" | "rollback" | "recover" | "recover-update" | "recover-identity"
            | "migrate",
        ) => HelpTopic::Update,
        Some("keys") => HelpTopic::Keys,
        Some("conformance") => HelpTopic::Conformance,
        Some("audit") => HelpTopic::Audit,
        Some("identity") => HelpTopic::Identity,
        Some("break-glass") => HelpTopic::BreakGlass,
        _ => HelpTopic::TopLevel,
    })
}

pub(crate) struct Cli {
    pub(crate) config: PathBuf,
    pub(crate) command: Command,
}

pub(crate) enum Command {
    Install(Box<InstallOptions>),
    BootstrapAdmin(BootstrapAdminOptions),
    Status,
    Doctor,
    Check(Option<String>),
    Update(UpdateOptions),
    Rollback { yes: bool },
    Recover { yes: bool },
    RecoverUpdate { yes: bool },
    RecoverIdentity { yes: bool },
    Migrate { yes: bool },
    Keys(KeysCommand),
    Conformance(ConformanceLeaseCommand),
    AuditVerify,
    AuditShow { request_id: Option<String> },
    IdentityRotate { yes: bool },
    BreakGlassControllerAvailability,
    BreakGlassRehearseControllerLoss { yes: bool },
    BreakGlassRecover { yes: bool, reason: String },
}

#[derive(Debug)]
pub(crate) enum KeysCommand {
    List,
    Validate,
    ExportOpenid4vcTrust {
        output: PathBuf,
    },
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
pub(crate) enum ConformanceLeaseCommand {
    Create {
        profile: String,
        material: PathBuf,
        ttl_seconds: u64,
        yes: bool,
    },
    List,
    Revoke {
        lease_id: String,
        yes: bool,
    },
    Cleanup {
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

pub(crate) struct InstallOptions {
    pub(crate) runtime: String,
    pub(crate) public_url: String,
    pub(crate) profile: String,
    pub(crate) profile_material: Option<PathBuf>,
    pub(crate) data_root: PathBuf,
    pub(crate) port: u16,
    pub(crate) network_subnet: Option<String>,
    pub(crate) runtime_ip: Option<String>,
    pub(crate) database_url: Option<String>,
    pub(crate) migration_database_url: Option<String>,
    pub(crate) valkey_url: Option<String>,
    pub(crate) external_dependencies: bool,
    pub(crate) secrets_stdin: bool,
    pub(crate) secret_fd: Option<u32>,
    pub(crate) profile_secrets_stdin: bool,
    pub(crate) profile_secret_fd: Option<u32>,
    pub(crate) profile_secrets: Option<StandardsProfileSecrets>,
    pub(crate) version: Option<String>,
}

/// Profile-scoped bearer secrets. This deliberately has no `Debug` implementation,
/// and its owned values are zeroized on drop: command parsing and error paths must
/// never render its contents or retain avoidable plaintext copies.
#[derive(serde::Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub(crate) struct StandardsProfileSecrets {
    pub(crate) dynamic_registration_initial_access_token: String,
    pub(crate) ciba_automated_decision_token: String,
    pub(crate) openid4vci_management_token: String,
    pub(crate) openid4vp_management_token: String,
}

#[derive(Debug)]
pub(crate) struct BootstrapAdminOptions {
    pub(crate) credentials_stdin: bool,
    pub(crate) yes: bool,
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
            "install" => Command::Install(Box::new(parse_install(values)?)),
            "bootstrap-admin" => Command::BootstrapAdmin(parse_bootstrap_admin(values)?),
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
            "recover-update" => Command::RecoverUpdate {
                yes: parse_yes(values, "recover-update")?,
            },
            "recover-identity" => Command::RecoverIdentity {
                yes: parse_yes(values, "recover-identity")?,
            },
            "migrate" => Command::Migrate {
                yes: parse_yes(values, "migrate")?,
            },
            "keys" => Command::Keys(parse_keys(values)?),
            "conformance" => Command::Conformance(parse_conformance(values)?),
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
                    .is_some_and(|value| value == "controller-availability") =>
            {
                values.remove(0);
                no_arguments(&values, "break-glass controller-availability")?;
                Command::BreakGlassControllerAvailability
            }
            "break-glass"
                if values
                    .first()
                    .is_some_and(|value| value == "rehearse-controller-loss") =>
            {
                values.remove(0);
                Command::BreakGlassRehearseControllerLoss {
                    yes: parse_yes(values, "break-glass controller-loss rehearsal")?,
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

fn parse_bootstrap_admin(values: Vec<String>) -> anyhow::Result<BootstrapAdminOptions> {
    let mut credentials_stdin = false;
    let mut yes = false;
    for value in values {
        match value.as_str() {
            "--credentials-stdin" if !credentials_stdin => credentials_stdin = true,
            "--yes" if !yes => yes = true,
            "--credentials-stdin" => bail!("--credentials-stdin may be supplied only once"),
            "--yes" => bail!("--yes may be supplied only once"),
            other => bail!("unknown bootstrap-admin option {other}"),
        }
    }
    Ok(BootstrapAdminOptions {
        credentials_stdin,
        yes,
    })
}

fn parse_keys(values: Vec<String>) -> anyhow::Result<KeysCommand> {
    let mut values = values.into_iter();
    let command = values.next().context("keys requires an operation")?;
    let values = values.collect::<Vec<_>>();
    match command.as_str() {
        "list" if values.is_empty() => Ok(KeysCommand::List),
        "validate" if values.is_empty() => Ok(KeysCommand::Validate),
        "export-openid4vc-trust" => {
            let values = parse_named_options(values, &["--output"])?;
            Ok(KeysCommand::ExportOpenid4vcTrust {
                output: PathBuf::from(&values["--output"]),
            })
        }
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

fn parse_conformance(mut values: Vec<String>) -> anyhow::Result<ConformanceLeaseCommand> {
    if values.first().map(String::as_str) != Some("lease") {
        bail!("conformance requires the lease resource");
    }
    values.remove(0);
    let operation = values
        .first()
        .cloned()
        .context("conformance lease requires an operation")?;
    values.remove(0);
    match operation.as_str() {
        "list" => {
            no_arguments(&values, "conformance lease list")?;
            Ok(ConformanceLeaseCommand::List)
        }
        "create" => {
            let (values, yes) = take_yes(values)?;
            let values = parse_named_options_for(
                values,
                &["--profile", "--material", "--ttl-seconds"],
                "conformance lease create",
            )?;
            let ttl_seconds = values["--ttl-seconds"]
                .parse::<u64>()
                .context("--ttl-seconds must be an integer")?;
            if !(60..=86_400).contains(&ttl_seconds) {
                bail!("--ttl-seconds must be between 60 and 86400");
            }
            Ok(ConformanceLeaseCommand::Create {
                profile: values["--profile"].clone(),
                material: PathBuf::from(&values["--material"]),
                ttl_seconds,
                yes,
            })
        }
        "revoke" => {
            let (values, yes) = take_yes(values)?;
            let values =
                parse_named_options_for(values, &["--lease-id"], "conformance lease revoke")?;
            let lease_id = values["--lease-id"].clone();
            uuid::Uuid::parse_str(&lease_id).context("--lease-id must be a UUID")?;
            Ok(ConformanceLeaseCommand::Revoke { lease_id, yes })
        }
        "cleanup" => {
            let yes = parse_yes(values, "conformance lease cleanup")?;
            Ok(ConformanceLeaseCommand::Cleanup { yes })
        }
        _ => bail!("unsupported conformance lease operation or arguments"),
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
    parse_named_options_for(values, expected, "keys operation")
}

fn parse_named_options_for(
    values: Vec<String>,
    expected: &[&str],
    command: &str,
) -> anyhow::Result<std::collections::BTreeMap<String, String>> {
    if values.len() != expected.len() * 2 {
        bail!("{command} has missing or unexpected options");
    }
    let mut parsed = std::collections::BTreeMap::new();
    let mut values = values.into_iter();
    while let Some(key) = values.next() {
        let value = values
            .next()
            .with_context(|| format!("{command} option has no value"))?;
        if !expected.contains(&key.as_str()) || parsed.insert(key, value).is_some() {
            bail!("{command} has duplicate or unexpected options");
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
    let mut network_subnet = None;
    let mut runtime_ip = None;
    let database_url = None;
    let migration_database_url = None;
    let valkey_url = None;
    let mut external_dependencies = false;
    let mut secrets_stdin = false;
    let mut secret_fd = None;
    let mut profile_secrets_stdin = false;
    let mut profile_secret_fd = None;
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
            if secrets_stdin {
                bail!("--secrets-stdin may be supplied only once");
            }
            secrets_stdin = true;
            index += 1;
            continue;
        }
        if flag == "--profile-secrets-stdin" {
            if profile_secrets_stdin {
                bail!("--profile-secrets-stdin may be supplied only once");
            }
            profile_secrets_stdin = true;
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
            "--network-subnet" => {
                validate_network_subnet(&value)?;
                network_subnet = Some(value);
            }
            "--runtime-ip" => {
                value
                    .parse::<std::net::IpAddr>()
                    .context("--runtime-ip must be an IPv4 or IPv6 address")?;
                runtime_ip = Some(value);
            }
            "--secret-fd" => {
                if secret_fd.is_some() {
                    bail!("--secret-fd may be supplied only once");
                }
                secret_fd = Some(parse_secret_fd(&value, "--secret-fd")?);
            }
            "--profile-secret-fd" => {
                if profile_secret_fd.is_some() {
                    bail!("--profile-secret-fd may be supplied only once");
                }
                profile_secret_fd = Some(parse_secret_fd(&value, "--profile-secret-fd")?);
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
    if profile != "standards-full" && (profile_secrets_stdin || profile_secret_fd.is_some()) {
        bail!("secure profile secret input requires --profile standards-full");
    }
    if network_subnet.is_some() != runtime_ip.is_some() {
        bail!("--network-subnet and --runtime-ip must be supplied together");
    }
    if let (Some(subnet), Some(address)) = (&network_subnet, &runtime_ip) {
        validate_network_assignment(subnet, address)?;
    }
    if runtime == "host" && network_subnet.is_some() {
        bail!("container network options are unavailable with --runtime host");
    }
    Ok(InstallOptions {
        runtime,
        public_url,
        profile,
        profile_material,
        data_root,
        port,
        network_subnet,
        runtime_ip,
        database_url,
        migration_database_url,
        valkey_url,
        external_dependencies,
        secrets_stdin,
        secret_fd,
        profile_secrets_stdin,
        profile_secret_fd,
        profile_secrets: None,
        version,
    })
}

fn validate_network_subnet(value: &str) -> anyhow::Result<()> {
    let (address, prefix) = value
        .split_once('/')
        .context("--network-subnet must be an IPv4 or IPv6 CIDR")?;
    let address: std::net::IpAddr = address
        .parse()
        .context("--network-subnet must be an IPv4 or IPv6 CIDR")?;
    let prefix: u8 = prefix
        .parse()
        .context("--network-subnet must be an IPv4 or IPv6 CIDR")?;
    let maximum = if address.is_ipv4() { 32 } else { 128 };
    if prefix > maximum {
        bail!("--network-subnet must be an IPv4 or IPv6 CIDR");
    }
    Ok(())
}

fn validate_network_assignment(subnet: &str, address: &str) -> anyhow::Result<()> {
    let (network, prefix) = subnet
        .split_once('/')
        .context("--network-subnet must be an IPv4 or IPv6 CIDR")?;
    let network: std::net::IpAddr = network.parse()?;
    let address: std::net::IpAddr = address.parse()?;
    let prefix: u8 = prefix.parse()?;
    let contains = match (network, address) {
        (std::net::IpAddr::V4(network), std::net::IpAddr::V4(address)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            u32::from(network) & mask == u32::from(address) & mask
        }
        (std::net::IpAddr::V6(network), std::net::IpAddr::V6(address)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            u128::from(network) & mask == u128::from(address) & mask
        }
        _ => false,
    };
    if !contains {
        bail!("--runtime-ip must belong to --network-subnet");
    }
    Ok(())
}

fn parse_secret_fd(value: &str, flag: &str) -> anyhow::Result<u32> {
    let fd: u32 = value
        .parse()
        .with_context(|| format!("{flag} must be an integer >= 3"))?;
    if fd < 3 {
        bail!("{flag} must be an integer >= 3");
    }
    Ok(fd)
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
