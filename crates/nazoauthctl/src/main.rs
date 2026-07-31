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
    let cli = match cli::Cli::parse(std::env::args()) {
        Ok(Some(cli)) => cli,
        Ok(None) => {
            print_help();
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

fn print_help() {
    println!(
        "nazoauthctl

Usage:
  nazoauthctl [--config PATH] install [--runtime auto|podman|docker|host] [--public-url URL] [--profile baseline|standards-full] [--profile-material PATH] [options]
  nazoauthctl [--config PATH] status
  nazoauthctl [--config PATH] doctor
  nazoauthctl [--config PATH] check [--to VERSION]
  nazoauthctl [--config PATH] update --plan [--to VERSION]
  nazoauthctl [--config PATH] update --yes [--to VERSION] [--accept-migration-barrier]
  nazoauthctl [--config PATH] rollback --yes
  nazoauthctl [--config PATH] recover --yes
  nazoauthctl [--config PATH] migrate --yes
  nazoauthctl [--config PATH] keys <list|generate-local|register-external|validate> [options]
  nazoauthctl [--config PATH] audit verify
  nazoauthctl [--config PATH] audit show [--request-id ID]
  nazoauthctl [--config PATH] identity rotate --yes
  nazoauthctl [--config PATH] break-glass recover-controller --reason lost|stolen --yes"
    );
}

mod controller;
