mod backup;
mod cli;
mod filesystem;
mod install;
mod model;
mod operator;
mod process;
mod release;
mod runtime;
mod secret_provider;

#[cfg(all(test, unix))]
#[path = "../tests/unit/support.rs"]
mod test_support;

fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    if let Some(topic) = cli::help_topic(&args) {
        print_help(topic);
        return;
    }
    let cli = match cli::Cli::parse(args) {
        Ok(Some(cli)) => cli,
        Ok(None) => {
            print_help(cli::HelpTopic::TopLevel);
            return;
        }
        Err(error) => {
            eprintln!("nazoauthctl: {error:#}");
            std::process::exit(2);
        }
    };
    let result = controller::acquire_lock().and_then(|_lock| controller::run(cli));
    if let Err(error) = result {
        eprintln!("nazoauthctl: {error:#}");
        std::process::exit(1);
    }
}

fn print_help(topic: cli::HelpTopic) {
    println!("{}", help_text(topic));
}

fn help_text(topic: cli::HelpTopic) -> &'static str {
    match topic {
        cli::HelpTopic::TopLevel => {
            "nazoauthctl — install and safely operate NazoAuth

Usage:
  nazoauthctl [--config PATH] <command> [options]

Start here:
  nazoauthctl install --public-url https://auth.example
  nazoauthctl [--config PATH] bootstrap-admin
  nazoauthctl [--config PATH] status
  nazoauthctl [--config PATH] doctor
  nazoauthctl [--config PATH] update --plan
  nazoauthctl [--config PATH] update --yes

Commands:
  install       Fresh Podman, Docker, or host installation
  bootstrap-admin  Securely create the first administrator
  status        Machine-readable deployment and identity state
  doctor        Read-only health and security diagnostics
  check         Resolve and verify a candidate Release
  update        Plan or perform a signed transactional update
  rollback      Roll back the application artifact within the declared schema boundary
  recover       Resume or safely unwind an interrupted update
  migrate       Run the signed migration operation
  keys          List, validate, export OpenID4VC trust, generate, or register signing keys
  audit         Show or verify the management audit chain
  identity      Rotate controller and audit identities
  break-glass   Recover after controller-key loss or suspected theft

Run `nazoauthctl <command> --help` for exact options."
        }
        cli::HelpTopic::Install => {
            "Usage:
  nazoauthctl [--config PATH] install [options]

Options:
  --runtime auto|podman|docker|host   Default: auto (Podman, then Docker)
  --public-url URL                    Public issuer origin; default is local trial mode
  --profile baseline|standards-full   Default: baseline
  --profile-material PATH             Required only for standards-full
  --data-root PATH                    Default: /var/lib/nazoauth
  --port PORT                         Default: 8000
  --to VERSION                        Immutable vSemVer Release; default: latest
  --external-dependencies             Use operator-owned PostgreSQL and Valkey
  --secrets-stdin                     Read the three dependency URLs as strict JSON from stdin
  --secret-fd FD                      Read the same JSON from an already-open FD (Linux)
  --profile-secrets-stdin             Read standards-full profile bearer secrets as strict JSON from stdin
  --profile-secret-fd FD              Read the same profile JSON from an already-open FD (Linux)

With managed dependencies, identities and secrets are generated automatically.
External JSON keys: database_url, migration_database_url, valkey_url.
Profile JSON keys: dynamic_registration_initial_access_token,
ciba_automated_decision_token, openid4vci_management_token,
openid4vp_management_token. Profile secret input is accepted only for standards-full.
The two stdin modes are mutually exclusive; use separate inherited FDs when both inputs are needed.
Secret values are rejected in argv and ordinary environment variables."
        }
        cli::HelpTopic::BootstrapAdmin => {
            "Usage:
  nazoauthctl [--config PATH] bootstrap-admin [--yes]
  nazoauthctl [--config PATH] bootstrap-admin --credentials-stdin --yes

Interactive mode prompts for the administrator email and reads the password without
echo. Non-interactive mode accepts only strict JSON on stdin with keys `email` and
`password`. The private one-time bootstrap token is read from the exact managed
runtime-owned mount and sent only in the HTTPS request body; it never enters argv, environment,
configuration, logs, audit records, or command output."
        }
        cli::HelpTopic::Update => {
            "Usage:
  nazoauthctl [--config PATH] check [--to VERSION]
  nazoauthctl [--config PATH] update --plan [--to VERSION]
  nazoauthctl [--config PATH] update --yes [--to VERSION] [--accept-migration-barrier]
  nazoauthctl [--config PATH] rollback --yes
  nazoauthctl [--config PATH] recover --yes
  nazoauthctl [--config PATH] migrate --yes

`update --plan` is read-only and reports artifact rollback, schema-compatible
rollback, backup/PITR recovery, and any irreversible migration barrier separately.
`--yes` skips only the prompt; it never skips verification, backup, health, replay,
audit, or rollback protection."
        }
        cli::HelpTopic::Keys => {
            "Usage:
  nazoauthctl [--config PATH] keys list
  nazoauthctl [--config PATH] keys validate
  nazoauthctl [--config PATH] keys export-openid4vc-trust --output ABSOLUTE_PATH
  nazoauthctl [--config PATH] keys generate-local --alg ALG --purposes CSV --yes
  nazoauthctl [--config PATH] keys register-external --kid KID --alg ALG \
    --key-ref REF --public-jwk PATH --yes

`keys export-openid4vc-trust` is available only for standards-full managed installs.
It verifies the managed atomic OpenID4VC bundle and writes only its CA:TRUE trust
anchor(s) to a regular absolute destination using an fsync+rename transition. It
never exports a leaf certificate or private key."
        }
        cli::HelpTopic::Audit => {
            "Usage:
  nazoauthctl [--config PATH] audit verify
  nazoauthctl [--config PATH] audit show [--request-id ID]"
        }
        cli::HelpTopic::Identity => {
            "Usage:
  nazoauthctl [--config PATH] identity rotate --yes

Rotation is a signed, journaled transition. The old identity cannot authorize new work
after the transition commits."
        }
        cli::HelpTopic::BreakGlass => {
            "Usage:
  nazoauthctl [--config PATH] break-glass recover-controller --reason lost|stolen --yes
  nazoauthctl [--config PATH] break-glass controller-availability
  nazoauthctl [--config PATH] break-glass rehearse-controller-loss --yes

This requires the separately stored recovery private key and rotates controller,
audit, and break-glass identities in one audited transition. `controller-availability`
reports only whether this file provider can currently use the active controller key;
it does not claim to prove a key was not copied. `rehearse-controller-loss` performs
the real recovery transition while forbidding controller signing reads after its
in-memory probe key is prepared; it proves simulated provider unavailability, not
physical key loss or non-copy."
        }
    }
}

mod controller;

#[cfg(test)]
#[path = "../tests/unit/entrypoint.rs"]
mod tests;
