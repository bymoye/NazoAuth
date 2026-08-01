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
    let result = controller::acquire_lock(matches!(cli.command, cli::Command::Install(_)))
        .and_then(|_lock| controller::run(cli));
    if let Err(error) = result {
        eprintln!("nazoauthctl: {error:#}");
        std::process::exit(1);
    }
}

fn print_help(topic: cli::HelpTopic) {
    let help = match topic {
        cli::HelpTopic::TopLevel => {
            "nazoauthctl — install and safely operate NazoAuth

Usage:
  nazoauthctl [--config PATH] <command> [options]

Start here:
  nazoauthctl install --public-url https://auth.example
  nazoauthctl [--config PATH] status
  nazoauthctl [--config PATH] doctor
  nazoauthctl [--config PATH] update --plan
  nazoauthctl [--config PATH] update --yes

Commands:
  install       Fresh Podman, Docker, or host installation
  status        Machine-readable deployment and identity state
  doctor        Read-only health and security diagnostics
  check         Resolve and verify a candidate Release
  update        Plan or perform a signed transactional update
  rollback      Roll back the application artifact within the declared schema boundary
  recover       Resume or safely unwind an interrupted update
  migrate       Run the signed migration operation
  keys          List, validate, generate, or register signing keys
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

With managed dependencies, identities and secrets are generated automatically.
External JSON keys: database_url, migration_database_url, valkey_url.
Secret values are rejected in argv and ordinary environment variables."
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
  nazoauthctl [--config PATH] keys generate-local --alg ALG --purposes CSV --yes
  nazoauthctl [--config PATH] keys register-external --kid KID --alg ALG \
    --key-ref REF --public-jwk PATH --yes"
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

This requires the separately stored recovery private key and rotates controller,
audit, and break-glass identities in one audited transition."
        }
    };
    println!("{help}");
}

mod controller;
