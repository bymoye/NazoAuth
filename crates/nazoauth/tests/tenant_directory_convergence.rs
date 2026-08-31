//! Two real NazoAuth server processes sharing one PostgreSQL directory and
//! one Valkey cache must converge on tenant lifecycle mutations within a
//! bounded time, survive cache outages through the authoritative database
//! reconciliation, and repair a poisoned ahead-of-DB snapshot.
//!
//! Without `NAZO_TEST_DATABASE_URL`/`DATABASE_URL` and
//! `NAZO_TEST_VALKEY_URL`/`VALKEY_URL` the test skips so plain `cargo test`
//! stays hermetic; in CI their absence is a hard failure.

use std::{
    io::{Read as _, Write as _},
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use diesel_async::{AsyncConnection as _, AsyncPgConnection, SimpleAsyncConnection as _};
use nazo_identity::{OrganizationId, RealmId, TenantContext, TenantDirectoryBinding, TenantId};
use nazo_postgres::{
    TenantBoundaryDefinition, TenantDirectoryRepository, TenantProvisioningRequest,
    TenantRuntimeStatus, create_pool, run_pending_migrations,
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};
use uuid::Uuid;

const CONVERGENCE_WINDOW: Duration = Duration::from_secs(30);
const DISCOVERY_PATH: &str = "/.well-known/openid-configuration";
const DEPLOYMENT_ID: &str = "t1-convergence";
const STATE_EPOCH: &str = "0198f7d1-0000-7000-8000-000000000001";

fn test_databases() -> Option<(String, String)> {
    let database = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok()?;
    let valkey = std::env::var("NAZO_TEST_VALKEY_URL")
        .or_else(|_| std::env::var("VALKEY_URL"))
        .ok()?;
    Some((database, valkey))
}

/// Replaces the path component of a PostgreSQL URL with one database name.
fn with_database_name(database_url: &str, name: &str) -> String {
    let separator = database_url.rfind('/').expect("database URL has a path");
    format!("{}/{}", &database_url[..separator], name)
}

fn temporary_directory(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("nazoauth-t1-{tag}-{}", Uuid::now_v7().simple()));
    std::fs::create_dir_all(&root).expect("temp directory should create");
    root
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("probe listener should bind")
        .local_addr()
        .expect("probe listener address should resolve")
        .port()
}

fn server_config_yaml(port: u16, database_url: &str, valkey_url: &str, data_dir: &Path) -> String {
    format!(
        r#"BIND: "127.0.0.1:{port}"
DATA_DIR: "{}"
DEPLOYMENT_ID: "{DEPLOYMENT_ID}"
DATABASE_URL: "{database_url}"
VALKEY_URL: "{valkey_url}"
VALKEY_STATE_EPOCH: "{STATE_EPOCH}"
VALKEY_COMMAND_TIMEOUT_MS: 1000
ISSUER: "http://127.0.0.1:{port}"
TRANSPORT_MODE: "trusted-proxy"
TRUSTED_PROXY_CIDRS: "127.0.0.1/32"
MTLS_CERTIFICATE_SOURCE: "rfc9440"
CLIENT_IP_HEADER_MODE: "x-forwarded-for"
CLIENT_SECRET_PEPPER: "t1-convergence-client-secret-pepper-000000"
COOKIE_SECURE: true
SESSION_COOKIE_NAME: "t1_session"
CSRF_COOKIE_NAME: "t1_csrf"
DEFAULT_AUDIENCE: "resource://t1"
SUBJECT_TYPE: "public"
SECURITY_AUDIT_REQUIRE_LEAST_PRIVILEGE: false
RUST_LOG: "info"
"#,
        data_dir.display().to_string().replace('\\', "/")
    )
}

const MIGRATION_RUNTIME_ROLE: &str = "nazoauth_t1_convergence_runtime";

fn write_config(path: &Path, yaml: &str) {
    std::fs::write(path, yaml).expect("server config should write");
}

struct ServerProcess {
    child: Child,
    port: u16,
    log_path: PathBuf,
}

impl ServerProcess {
    fn wait_until_ready(&mut self, host: &str) -> Duration {
        let started = Instant::now();
        loop {
            let status = discovery_status(self.port, host);
            if status == 200 {
                return started.elapsed();
            }
            if let Some(exit) = self
                .child
                .try_wait()
                .expect("server process status should be readable")
            {
                let log = std::fs::read_to_string(&self.log_path).unwrap_or_default();
                panic!(
                    "server on port {} exited with {exit} before readiness (last status {status}):\n{log}",
                    self.port
                );
            }
            assert!(
                started.elapsed() < CONVERGENCE_WINDOW,
                "server on port {} did not become ready within the startup window (last status {status})",
                self.port
            );
            std::thread::sleep(Duration::from_millis(500));
        }
    }
}

/// Environment variables that would override the per-process `.env.yaml`:
/// inherited test-process variables must never leak into a child whose
/// configuration file is authoritative for it.
const OVERRIDING_ENV_KEYS: &[&str] = &[
    "DATABASE_URL",
    "VALKEY_URL",
    "VALKEY_STATE_EPOCH",
    "ISSUER",
    "PUBLIC_BASE_URL",
    "BIND",
    "DATA_DIR",
    "JWK_KEYS_DIR",
    "AVATAR_STORAGE_DIR",
    "TRANSPORT_MODE",
    "DEPLOYMENT_ID",
    "TRUSTED_PROXY_CIDRS",
    "CLIENT_IP_HEADER_MODE",
    "CLIENT_SECRET_PEPPER",
    "COOKIE_SECURE",
    "SESSION_COOKIE_NAME",
    "CSRF_COOKIE_NAME",
    "DEFAULT_AUDIENCE",
    "SUBJECT_TYPE",
];

fn child_command(subcommand: &str, config: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nazoauth"));
    command
        .arg(subcommand)
        .env("NAZOAUTH_SERVER_CONFIG_FILE", config);
    for key in OVERRIDING_ENV_KEYS {
        command.env_remove(key);
    }
    command
}

fn spawn_server(config: &Path, port: u16) -> ServerProcess {
    let log_path = config
        .parent()
        .expect("config has a parent")
        .join("server.log");
    let log = std::fs::File::create(&log_path).expect("server log file should create");
    let error_log = log.try_clone().expect("server error log file should clone");
    let child = child_command("server", config)
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(error_log))
        .spawn()
        .expect("server process should spawn");
    ServerProcess {
        child,
        port,
        log_path,
    }
}

fn run_cli(command: &str, config: &Path) {
    let output = child_command(command, config)
        .env("NAZOAUTH_MIGRATION_RUNTIME_ROLE", MIGRATION_RUNTIME_ROLE)
        .output()
        .expect("nazoauth CLI should run");
    assert!(
        output.status.success(),
        "{command} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// One HTTP probe of the discovery endpoint under a forced tenant Host.
fn discovery_status(port: u16, host: &str) -> u16 {
    let Ok(mut stream) = std::net::TcpStream::connect(("127.0.0.1", port)) else {
        return 0;
    };
    let request =
        format!("GET {DISCOVERY_PATH} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    if stream.write_all(request.as_bytes()).is_err() {
        return 0;
    }
    let mut response = Vec::new();
    if stream.read_to_end(&mut response).is_err() {
        return 0;
    }
    let head = String::from_utf8_lossy(&response);
    head.split_whitespace()
        .nth(1)
        .and_then(|status| status.parse::<u16>().ok())
        .unwrap_or(0)
}

fn wait_for_routing(port: u16, host: &str, expected: u16) -> Duration {
    let started = Instant::now();
    loop {
        let status = discovery_status(port, host);
        if status == expected {
            return started.elapsed();
        }
        assert!(
            started.elapsed() < CONVERGENCE_WINDOW,
            "host {host} did not reach status {expected} on port {port} within the convergence window (last status {status})"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn wait_for_away(port: u16, host: &str) {
    let started = Instant::now();
    loop {
        if discovery_status(port, host) == 404 {
            return;
        }
        assert!(
            started.elapsed() < CONVERGENCE_WINDOW,
            "host {host} still routes on port {port} after the convergence window"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Issues one RESP command and returns the raw reply, used to verify and then
/// poison the directory snapshot key without external tooling.
fn resp_command(address: SocketAddr, payload: String) -> String {
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("resp runtime should build");
        runtime.block_on(async move {
            let mut stream = TcpStream::connect(address)
                .await
                .expect("resp connection should open");
            stream
                .write_all(payload.as_bytes())
                .await
                .expect("resp write should succeed");
            let mut reply = vec![0u8; 4096];
            let read = stream
                .read(&mut reply)
                .await
                .expect("resp read should succeed");
            String::from_utf8_lossy(&reply[..read]).into_owned()
        })
    })
    .join()
    .expect("resp thread should join")
}

/// Resolves the host:port of a `redis://host:port/db` style URL.
fn valkey_socket_address(valkey_url: &str) -> SocketAddr {
    let rest = valkey_url
        .strip_prefix("redis://")
        .unwrap_or(valkey_url)
        .split('/')
        .next()
        .expect("valkey URL has a host portion");
    let (host, port) = rest
        .rsplit_once(':')
        .expect("valkey URL must include a port");
    let address = format!("{host}:{port}");
    address
        .parse()
        .expect("valkey URL must resolve to a socket address")
}

fn snapshot_key() -> String {
    format!("nazo:state:v1:{DEPLOYMENT_ID}:{STATE_EPOCH}:tenant-directory:snapshot")
}

/// Forwards a local port to the real Valkey so the test can cut and restore
/// the cache path without touching shared infrastructure.
struct ValkeyProxy {
    upstream: SocketAddr,
    port: u16,
    task: Option<JoinHandle<()>>,
    shutdown: tokio::sync::watch::Sender<bool>,
}

impl ValkeyProxy {
    async fn start(upstream: SocketAddr, port: u16) -> Self {
        let listener = Self::bind(port).await;
        let (shutdown, mut shutdown_rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => break,
                    accepted = listener.accept() => {
                        let (mut client, _) = match accepted {
                            Ok(pair) => pair,
                            Err(_) => break,
                        };
                        let Ok(mut server) = TcpStream::connect(upstream).await else {
                            continue;
                        };
                        tokio::spawn(async move {
                            let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
                        });
                    }
                }
            }
        });
        Self {
            upstream,
            port,
            task: Some(task),
            shutdown,
        }
    }

    async fn bind(port: u16) -> TcpListener {
        let started = Instant::now();
        loop {
            match TcpListener::bind(("127.0.0.1", port)).await {
                Ok(listener) => return listener,
                Err(_) => {
                    assert!(
                        started.elapsed() < CONVERGENCE_WINDOW,
                        "proxy port {port} never became bindable"
                    );
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        }
    }

    /// Stops forwarding so every server cache command fails open into the
    /// database reconciliation path.
    async fn stop(&mut self) {
        self.shutdown.send_replace(true);
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }

    async fn resume(&mut self) {
        assert!(self.task.is_none(), "proxy is still running");
        *self = Self::start(self.upstream, self.port).await;
    }

    fn address(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.port))
    }
}

fn provisioning_request(slug: &str, host: &str) -> TenantProvisioningRequest {
    let tenant_id = TenantId::new(Uuid::now_v7()).expect("tenant id is non-nil");
    let realm_id = RealmId::new(Uuid::now_v7()).expect("realm id is non-nil");
    let organization_id = OrganizationId::new(Uuid::now_v7()).expect("organization id is non-nil");
    fn boundary<Id>(id: Id, slug: &str, suffix: &str) -> TenantBoundaryDefinition<Id> {
        TenantBoundaryDefinition {
            id,
            slug: format!("{slug}-{suffix}"),
            display_name: format!("{slug} {suffix}"),
        }
    }
    TenantProvisioningRequest {
        tenant: boundary(tenant_id, slug, "tenant"),
        realm: boundary(realm_id, slug, "realm"),
        organization: boundary(organization_id, slug, "organization"),
        binding: TenantDirectoryBinding {
            tenant: TenantContext {
                tenant_id,
                realm_id,
                organization_id,
            },
            runtime_revision: 1,
            issuer: format!("https://{host}"),
            external_host: host.to_owned(),
        },
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_processes_converge_on_lifecycle_mutations_and_survive_cache_failures() {
    let Some((database_url, valkey_url)) = test_databases() else {
        return;
    };

    // Isolated authoritative directory.
    let database_name = format!("t1_convergence_{}", Uuid::now_v7().simple());
    let mut coordinator = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test database should connect");
    coordinator
        .batch_execute(&format!("CREATE DATABASE \"{database_name}\";"))
        .await
        .expect("isolated database should create");
    drop(coordinator);
    let isolated_url = with_database_name(&database_url, &database_name);
    run_pending_migrations(&isolated_url)
        .await
        .expect("isolated database migrations should apply");

    // Local Valkey proxy in front of the shared cache.
    let upstream = valkey_socket_address(&valkey_url);
    let proxy_port = free_port();
    let mut proxy = ValkeyProxy::start(upstream, proxy_port).await;
    let proxied_valkey = format!("redis://127.0.0.1:{proxy_port}");

    // Production install chain: migrate -> tenant-bootstrap -> servers.
    let bootstrap_dir = temporary_directory("bootstrap");
    let bootstrap_config = bootstrap_dir.join(".env.yaml");
    write_config(
        &bootstrap_config,
        &server_config_yaml(free_port(), &isolated_url, &proxied_valkey, &bootstrap_dir),
    );
    // The migration runtime role is cluster-wide: create it once, idempotently.
    {
        let mut role_coordinator = AsyncPgConnection::establish(&database_url)
            .await
            .expect("test database should connect for role preparation");
        role_coordinator
            .batch_execute(&format!(
                "SELECT pg_advisory_lock(564196923451771043);                 DO $$ BEGIN                    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{MIGRATION_RUNTIME_ROLE}') THEN                      CREATE ROLE {MIGRATION_RUNTIME_ROLE} NOSUPERUSER NOBYPASSRLS NOINHERIT;                    END IF;                  END $$;                 SELECT pg_advisory_unlock(564196923451771043);"
            ))
            .await
            .expect("migration runtime role fixture should exist");
        drop(role_coordinator);
    }
    run_cli("migrate", &bootstrap_config);
    run_cli("tenant-bootstrap", &bootstrap_config);

    // Two independent processes share the directory and the cache.
    let process_a_dir = temporary_directory("process-a");
    let process_b_dir = temporary_directory("process-b");
    let port_a = free_port();
    let port_b = free_port();
    let config_a = process_a_dir.join(".env.yaml");
    let config_b = process_b_dir.join(".env.yaml");
    write_config(
        &config_a,
        &server_config_yaml(port_a, &isolated_url, &proxied_valkey, &process_a_dir),
    );
    write_config(
        &config_b,
        &server_config_yaml(port_b, &isolated_url, &proxied_valkey, &process_b_dir),
    );
    let mut server_a = spawn_server(&config_a, port_a);
    let mut server_b = spawn_server(&config_b, port_b);
    let startup_a = server_a.wait_until_ready("127.0.0.1");
    let startup_b = server_b.wait_until_ready("127.0.0.1");
    println!("server startup: process A {startup_a:?}, process B {startup_b:?}");

    let outcome = exercise_lifecycle(&isolated_url, &mut proxy, port_a, port_b).await;

    let _ = server_a.child.kill();
    let _ = server_a.child.wait();
    let _ = server_b.child.kill();
    let _ = server_b.child.wait();
    proxy.stop().await;
    if outcome.is_err() {
        for (name, directory) in [("A", &process_a_dir), ("B", &process_b_dir)] {
            let log = directory.join("server.log");
            if let Ok(contents) = std::fs::read_to_string(&log) {
                println!(
                    "--- server {name} log ({}): ---
{}",
                    log.display(),
                    contents
                );
            }
        }
    }
    outcome.expect("two-process convergence lifecycle should hold");
}

async fn exercise_lifecycle(
    isolated_url: &str,
    proxy: &mut ValkeyProxy,
    port_a: u16,
    port_b: u16,
) -> anyhow::Result<()> {
    let pool = create_pool(isolated_url.to_owned(), 4)?;
    let repository = TenantDirectoryRepository::new(pool);
    let revision = repository.current_revision().await?;
    assert_eq!(revision, 1, "bootstrap leaves the directory at revision 1");

    // A long-lived baseline tenant proves other tenants stay untouched.
    let baseline = provisioning_request("baseline", "t1-baseline.example");
    let baseline_host = baseline.binding.external_host.clone();
    let revision = repository
        .provision_tenant_binding(revision, baseline)
        .await?;
    wait_for_routing(port_a, &baseline_host, 200);
    wait_for_routing(port_b, &baseline_host, 200);
    println!("baseline tenant routed by both processes at revision {revision}");

    // 1. create: both processes route the new tenant within the window.
    let tenant_a = provisioning_request("alpha", "t1-alpha.example");
    let tenant_id = tenant_a.binding.tenant.tenant_id;
    let alpha_host = tenant_a.binding.external_host.clone();
    let revision = repository
        .provision_tenant_binding(revision, tenant_a)
        .await?;
    let elapsed_a = wait_for_routing(port_a, &alpha_host, 200);
    let elapsed_b = wait_for_routing(port_b, &alpha_host, 200);
    println!("tenant create converged: process A {elapsed_a:?}, process B {elapsed_b:?}");

    // 2. update: the old host stops resolving everywhere, the new host serves.
    let renamed_host = "t1-alpha-renamed.example";
    let revision = repository
        .update_tenant_binding(
            revision,
            tenant_id,
            format!("https://{renamed_host}"),
            renamed_host.to_owned(),
        )
        .await?;
    wait_for_routing(port_a, renamed_host, 200);
    wait_for_routing(port_b, renamed_host, 200);
    assert_eq!(discovery_status(port_a, &alpha_host), 404);
    assert_eq!(discovery_status(port_b, &alpha_host), 404);
    println!("tenant host update converged at revision {revision}");

    // 3. Valkey outage: the cache path dies, DB reconciliation still delivers.
    proxy.stop().await;
    let outage_host = "t1-outage.example";
    let tenant_c = provisioning_request("outage", outage_host);
    let outage_tenant_id = tenant_c.binding.tenant.tenant_id;
    let revision = repository
        .provision_tenant_binding(revision, tenant_c)
        .await?;
    let elapsed_a = wait_for_routing(port_a, outage_host, 200);
    let elapsed_b = wait_for_routing(port_b, outage_host, 200);
    println!("mutation converged with the cache down: A {elapsed_a:?}, B {elapsed_b:?}");

    // 4. Poisoned ahead-of-DB snapshot: the DB authority repairs the cache.
    proxy.resume().await;
    let verify = resp_command(
        proxy.address(),
        format!(
            "*2\r\n$3\r\nGET\r\n${}\r\n{snapshot_key}\r\n",
            snapshot_key().len(),
            snapshot_key = snapshot_key()
        ),
    );
    assert!(
        verify.contains("nazo-tenant-directory-cache-v2"),
        "the directory snapshot key must be present before poisoning: {verify}"
    );
    let poison = r#"{"schema_version":2,"integrity":"nazo-tenant-directory-cache-v2","revision":"999999","tenants":[]}"#;
    resp_command(
        proxy.address(),
        format!(
            "*3\r\n$3\r\nSET\r\n${}\r\n{snapshot_key}\r\n${}\r\n{poison}\r\n",
            snapshot_key().len(),
            poison.len(),
            snapshot_key = snapshot_key()
        ),
    );
    let repaired_host = "t1-repaired.example";
    let tenant_d = provisioning_request("repaired", repaired_host);
    let revision = repository
        .provision_tenant_binding(revision, tenant_d)
        .await?;
    wait_for_routing(port_a, repaired_host, 200);
    wait_for_routing(port_b, repaired_host, 200);
    assert_eq!(
        repository.current_revision().await?,
        revision,
        "the directory revision must stay DB-authoritative"
    );
    println!("poisoned ahead cache repaired through the database at revision {revision}");

    // 5. disable: both processes stop routing the tenant; the baseline and the
    //    bootstrapped system tenant stay untouched.
    let revision = repository
        .set_tenant_runtime_status(revision, outage_tenant_id, TenantRuntimeStatus::Suspended)
        .await?;
    wait_for_away(port_a, outage_host);
    wait_for_away(port_b, outage_host);
    assert_eq!(discovery_status(port_a, &baseline_host), 200);
    assert_eq!(discovery_status(port_b, &baseline_host), 200);
    assert_eq!(discovery_status(port_a, "127.0.0.1"), 200);
    assert_eq!(discovery_status(port_b, "127.0.0.1"), 200);
    println!("tenant disable converged at revision {revision}; baseline tenants unaffected");

    Ok(())
}
