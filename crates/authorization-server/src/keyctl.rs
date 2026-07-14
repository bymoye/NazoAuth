//! JWT key inspection and external signing-key registration CLI implementation.

use std::path::PathBuf;

use anyhow::bail;

use crate::config::ConfigSource;
use crate::settings::Settings;
use nazo_key_management::signing_algorithm_from_name;

pub async fn run(args: impl IntoIterator<Item = String>) -> anyhow::Result<()> {
    let mut args = args.into_iter();
    let _program = args.next();
    let Some(command) = args.next() else {
        bail!("usage: nazo-oauth-keyctl <list|register-external|validate>");
    };
    match command.as_str() {
        "list" => {
            let settings = load_settings()?;
            list_keys(&settings).await
        }
        "register-external" => {
            let options = parse_register_external_args(args.collect::<Vec<_>>())?;
            let settings = load_settings()?;
            register_external_key(&settings, options).await
        }
        "validate" => {
            let settings = load_settings()?;
            validate_keyset(&settings).await
        }
        _ => bail!("unknown keyctl command {command}"),
    }
}

fn load_settings() -> anyhow::Result<Settings> {
    let config = ConfigSource::load()?;
    Settings::from_config(&config)
}

async fn list_keys(settings: &Settings) -> anyhow::Result<()> {
    for key in nazo_key_management::KeyManager::list_keys(&settings.key_settings()).await? {
        let status = key_record_status_label(key.status);
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}",
            key.kid,
            status,
            key.algorithm,
            key.backend,
            key.locator,
            key.retire_at.as_deref().unwrap_or("")
        );
    }
    Ok(())
}

fn key_record_status_label(status: nazo_key_management::KeyRecordStatus) -> &'static str {
    status.as_str()
}

#[derive(Debug)]
struct RegisterExternalKeyOptions {
    kid: String,
    alg: jsonwebtoken::Algorithm,
    key_ref: String,
    public_jwk_file: PathBuf,
}

async fn register_external_key(
    settings: &Settings,
    options: RegisterExternalKeyOptions,
) -> anyhow::Result<()> {
    nazo_key_management::KeyManager::register_external(
        &settings.key_settings(),
        nazo_key_management::ExternalKeyRegistration {
            kid: options.kid.clone(),
            algorithm: options.alg,
            key_ref: options.key_ref,
            public_jwk_file: options.public_jwk_file,
        },
    )
    .await?;
    println!("{}", options.kid);
    Ok(())
}

async fn validate_keyset(settings: &Settings) -> anyhow::Result<()> {
    nazo_key_management::KeyManager::validate(&settings.key_settings()).await?;
    println!("ok");
    Ok(())
}

fn parse_register_external_args(args: Vec<String>) -> anyhow::Result<RegisterExternalKeyOptions> {
    let mut kid = None;
    let mut alg = None;
    let mut key_ref = None;
    let mut public_jwk_file = None;
    let mut iter = args.into_iter();
    while let Some(flag) = iter.next() {
        let value = iter
            .next()
            .ok_or_else(|| anyhow::anyhow!("missing value for {flag}"))?;
        match flag.as_str() {
            "--kid" => kid = Some(value),
            "--alg" => {
                alg = Some(
                    signing_algorithm_from_name(&value)
                        .ok_or_else(|| anyhow::anyhow!("unsupported signing alg {value}"))?,
                );
            }
            "--key-ref" => key_ref = Some(value),
            "--public-jwk" => public_jwk_file = Some(PathBuf::from(value)),
            _ => bail!("unknown register-external option {flag}"),
        }
    }
    Ok(RegisterExternalKeyOptions {
        kid: kid.ok_or_else(|| anyhow::anyhow!("register-external requires --kid"))?,
        alg: alg.ok_or_else(|| anyhow::anyhow!("register-external requires --alg"))?,
        key_ref: key_ref.ok_or_else(|| anyhow::anyhow!("register-external requires --key-ref"))?,
        public_jwk_file: public_jwk_file
            .ok_or_else(|| anyhow::anyhow!("register-external requires --public-jwk"))?,
    })
}

#[cfg(test)]
#[path = "../tests/in_source/src/keyctl/tests/keyctl.rs"]
mod tests;
