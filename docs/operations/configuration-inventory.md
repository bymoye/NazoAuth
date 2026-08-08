# Configuration inventory

This is the reviewed configuration contract for NazoAuth and NazoAuthCtl.
The server allowlist currently contains **157** names. The list below is
grouped only to make the decision readable; every name is an exact option.

Legend:

- **保留** — meaningful operator input; keep it.
- **保留（默认/派生）** — keep the override, but the normal path supplies a
  safe default or derives it from another value.
- **保留（自动生成）** — keep the import/file form for recovery, but a managed
  install or the server creates and persists it when absent.
- **保留（外部）** — NazoAuth cannot invent a credential that must also be
  accepted by another system; the external owner must provide it.
- **条件** — only needed when the corresponding capability is selected.

## NazoAuth server options

| Exact names | Importance / decision |
|---|---|
| `BIND`, `PUBLIC_BASE_URL`, `DATA_DIR`, `RUST_LOG` | **保留**。The process listener, public contract, durable state root, and diagnostics have no redundant owner. |
| `ISSUER`, `FRONTEND_BASE_URL`, `MTLS_ENDPOINT_BASE_URL`, `CORS_ALLOWED_ORIGINS`, `COOKIE_SECURE`, `SESSION_COOKIE_NAME`, `CSRF_COOKIE_NAME` | **保留（默认/派生）**。All default from the public issuer; explicit values remain for split-origin or reverse-proxy deployments. |
| `CLIENT_IP_HEADER_MODE`, `TRUSTED_PROXY_CIDRS`, `MTLS_CERTIFICATE_SOURCE` | **保留（外部）**。These describe a real proxy trust boundary and must not be guessed. |
| `TLS_BIND`, `TLS_CERTIFICATE_FILE`, `TLS_PRIVATE_KEY_FILE`, `TLS_CLIENT_CA_FILE` | **保留（外部）**。Certificate lifecycle belongs to the TLS owner; silently creating a production certificate would be unsafe. |
| `UI_CACHE_DIR`, `UI_STATIC_DIR`, `AVATAR_STORAGE_DIR`, `AVATAR_MAX_BYTES` | **保留（默认/派生）**。Paths and the upload bound are operational policy; storage paths default below `DATA_DIR`. |
| `DATABASE_URL`, `DATABASE_URL_FILE`, `DATABASE_MAX_CONNECTIONS`, `VALKEY_URL`, `VALKEY_URL_FILE`, `VALKEY_COMMAND_TIMEOUT_MS` | **保留（外部/默认）**。CTL generates local managed dependency URLs; an independent server cannot create a reachable external database or Valkey service. File aliases are transport forms, not second sources of truth. |
| `DEPLOYMENT_ID`, `RUNTIME_INSTANCE_ID`, `INSTANCE_IDENTITY_DIR`, `JWK_KEYS_DIR` | **保留（默认/自动生成）**。Identity IDs and signing-key paths are persisted; missing deployment/instance identity and signing material are generated atomically. |
| `AUTHORIZATION_SERVER_PROFILE`, `DEFAULT_AUDIENCE`, `PROTECTED_RESOURCE_IDENTIFIER`, `SUBJECT_TYPE` | **保留**。These change protocol semantics and issuer/client subject contracts. The protected-resource identifier defaults from the issuer. |
| `ACCESS_TOKEN_TTL_SECONDS`, `AUTH_CODE_TTL_SECONDS`, `ID_TOKEN_TTL_SECONDS`, `REFRESH_TOKEN_TTL_SECONDS`, `SESSION_TTL_SECONDS`, `PAR_TTL_SECONDS`, `DEVICE_AUTHORIZATION_TTL_SECONDS`, `DEVICE_AUTHORIZATION_POLL_INTERVAL_SECONDS`, `CIBA_AUTH_REQ_ID_TTL_SECONDS`, `CIBA_POLL_INTERVAL_SECONDS`, `CLIENT_DELIVERY_TTL_SECONDS` | **保留**。These are bounded lifetime/back-pressure policy, not feature toggles. |
| `DPOP_NONCE_POLICY`, `FAPI_RESOURCE_DPOP_NONCE_POLICY`, `REQUEST_OBJECT_JTI_POLICY`, `REQUIRE_PUSHED_AUTHORIZATION_REQUESTS`, `CIBA_SECURITY_PROFILE`, `FAPI_HTTP_SIGNATURE_MAX_AGE_SECONDS` | **保留**。They select protocol assurance and replay windows; invalid combinations fail closed. |
| `CIBA_AUTOMATED_DECISION_MODE` | **保留（默认关闭）**。`disabled` is the safe default; `header`/`query` are explicit isolated-test choices. |
| `CIBA_AUTOMATED_DECISION_TOKEN`, `CIBA_AUTOMATED_DECISION_TOKEN_FILE` | **保留（自动生成/条件）**。A token is generated only for explicit static header/query mode. Default lease-gated CIBA does not depend on this secret. |
| `CIBA_NOTIFICATION_PRIVATE_ORIGINS`, `CIBA_PING_TLS_TRUST_BUNDLE`, `BACKCHANNEL_LOGOUT_PRIVATE_ORIGINS`, `REMOTE_CLIENT_DOCUMENT_PRIVATE_ORIGINS` | **条件/外部**。These are exact-origin or trust-bundle boundaries; leave empty unless the integration is deliberately enabled. |
| `ENABLE_AUTHORIZATION_DETAILS`, `ENABLE_FAPI_HTTP_SIGNATURES`, `ENABLE_NATIVE_SSO`, `ENABLE_SCIM_SECURITY_EVENTS`, `ENABLE_OPENID4VCI_ISSUER`, `ENABLE_OPENID4VP_VERIFIER` | **条件**。These are the remaining capability prerequisites. Stable modules such as CIBA, Device Grant, Request Objects, PAR, Front-/Session-Logout are controlled by persisted runtime-module state, not environment flags. |
| `DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN`, `DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN_FILE` | **保留（自动生成）**。The initial-access bearer is generated and persisted when absent; its presence is the provisioning prerequisite, while the runtime-module database state remains authoritative. |
| `SCIM_EVENT_RETENTION_SECONDS` | **保留**。Retention is a data-minimization and delivery-retry policy. |
| `CLIENT_SECRET_PEPPER`, `CLIENT_SECRET_PEPPER_FILE`, `PAIRWISE_SUBJECT_SECRET`, `PAIRWISE_SUBJECT_SECRET_FILE` | **保留（自动生成/条件）**。The server creates durable random material; pairwise material is only needed for `SUBJECT_TYPE=pairwise`. File forms support controlled import/recovery. |
| `MFA_TOTP_ENCRYPTION_KEY`, `MFA_TOTP_ENCRYPTION_KEY_FILE`, `MFA_TOTP_ENCRYPTION_KEY_ID`, `MFA_TOTP_PREVIOUS_ENCRYPTION_KEY`, `MFA_TOTP_PREVIOUS_ENCRYPTION_KEY_FILE`, `MFA_TOTP_PREVIOUS_ENCRYPTION_KEY_ID` | **保留（自动生成）**。Current TOTP material and its ID are generated/derived; previous material is optional rotation input. |
| `TOKEN_ISSUANCE_RESPONSE_ENCRYPTION_KEY`, `TOKEN_ISSUANCE_RESPONSE_ENCRYPTION_KEY_FILE`, `TOKEN_ISSUANCE_RESPONSE_ENCRYPTION_KEY_ID`, `TOKEN_ISSUANCE_RESPONSE_PREVIOUS_ENCRYPTION_KEY`, `TOKEN_ISSUANCE_RESPONSE_PREVIOUS_ENCRYPTION_KEY_FILE`, `TOKEN_ISSUANCE_RESPONSE_PREVIOUS_ENCRYPTION_KEY_ID` | **保留（自动生成）**。Current response-envelope material and IDs are generated/derived; previous material is only for rotation overlap. |
| `OPENID4VC_DATA_ENCRYPTION_KEY`, `OPENID4VC_DATA_ENCRYPTION_KEY_FILE`, `OPENID4VCI_ISSUER_MANAGEMENT_TOKEN`, `OPENID4VCI_ISSUER_MANAGEMENT_TOKEN_FILE`, `OPENID4VP_VERIFIER_MANAGEMENT_TOKEN`, `OPENID4VP_VERIFIER_MANAGEMENT_TOKEN_FILE` | **条件/自动生成**。When the corresponding OpenID4VC module is enabled, service-owned encryption and management material is generated and persisted. |
| `OPENID4VC_CLIENT_ATTESTATION_JWKS_JSON`, `OPENID4VC_CLIENT_ATTESTATION_ISSUER`, `OPENID4VC_KEY_ATTESTATION_JWKS_JSON` | **条件/外部**。These are trust assertions for an external attestation ecosystem; NazoAuth must not mint trust for itself. |
| `OPENID4VC_SIGNING_CERTIFICATE_CHAIN_FILE`, `OPENID4VC_TRUST_ANCHORS_FILE`, `OPENID4VC_REVOCATION_POLICY`, `OPENID4VC_REVOCATION_SNAPSHOT_FILE`, `OPENID4VC_REVOCATION_RELOAD_INTERVAL_SECONDS`, `OPENID4VC_TRANSACTION_TTL_SECONDS`, `OPENID4VCI_CREDENTIAL_CONFIGURATIONS_JSON`, `OPENID4VCI_DEFERRED_CREDENTIAL_CONFIGURATIONS`, `OPENID4VP_WALLET_AUTHORIZATION_ORIGINS` | **条件**。Required only for the selected issuer/verifier profile; CTL can create the managed certificate bundle, while trust/revocation/configuration content remains operator policy. |
| `EMAIL_DELIVERY`, `EMAIL_FROM`, `EMAIL_CODE_TTL_SECONDS`, `EMAIL_CODE_SEND_COOLDOWN_SECONDS`, `EMAIL_CODE_PEER_COOLDOWN_SECONDS`, `EMAIL_CODE_DEV_RESPONSE_ENABLED` | **保留（默认/条件）**。Delivery and abuse controls are product policy; development responses are debug+loopback only. |
| `EMAIL_SMTP_HOST`, `EMAIL_SMTP_PORT`, `EMAIL_SMTP_TLS`, `EMAIL_SMTP_USERNAME`, `EMAIL_SMTP_PASSWORD` | **条件/外部**。SMTP credentials are owned by the provider and cannot be generated by NazoAuth. |
| `FEDERATION_PROVIDER_CONFIGS` | **条件/外部**。Provider metadata and client credentials belong to each federation owner. |
| `FEDERATION_SAML_GATEWAY_ENABLED`, `FEDERATION_SAML_GATEWAY_ISSUER`, `FEDERATION_SAML_GATEWAY_AUDIENCE`, `FEDERATION_SAML_GATEWAY_SECRET` | **条件/外部**. The gateway is a separate trust domain; its shared secret must match that gateway. |
| `PASSKEY_RP_ID`, `PASSKEY_RP_NAME`, `PASSKEY_ORIGIN`, `PASSKEY_REQUIRE_USER_VERIFICATION`, `PASSKEY_REQUIRE_USER_HANDLE`, `PASSKEY_STRICT_BASE64` | **保留（默认/条件）**。RP identity is derived from the issuer where possible; the remaining flags are WebAuthn compatibility/security policy. |
| `AUTH_RATE_LIMIT_MAX_REQUESTS`, `RATE_LIMIT_WINDOW_SECONDS`, `TOKEN_RATE_LIMIT_MAX_REQUESTS`, `TOKEN_MANAGEMENT_RATE_LIMIT_MAX_REQUESTS`, `LOGIN_FAILURE_IP_EMAIL_MAX_ATTEMPTS`, `LOGIN_FAILURE_WINDOW_SECONDS`, `PASSWORD_HASH_MAX_CONCURRENCY`, `PASSWORD_HASH_QUEUE_TIMEOUT_MS` | **保留**。These are resource and abuse controls; removing them would move safety policy into hidden constants. |
| `SIGNING_EXTERNAL_COMMAND`, `SIGNING_EXTERNAL_TIMEOUT_MS`, `SIGNING_KEY_ROTATION_INTERVAL_SECONDS`, `SIGNING_KEY_PREPUBLISH_SECONDS` | **保留（条件）**。External KMS/HSM and signing-key lifecycle are explicit operator choices; local keys are generated by the key manager when no external command is configured. |
| `OTEL_ENABLED`, `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_PROTOCOL`, `OTEL_EXPORTER_OTLP_TIMEOUT`, `PERF_METRICS_ENABLED`, `SECURITY_AUDIT_REQUIRE_LEAST_PRIVILEGE` | **保留（默认/外部）**。Observability and database privilege posture affect operations and auditability. |
| `AUDIT_ANCHOR_MODE`, `AUDIT_ANCHOR_STATUS_FILE`, `AUDIT_ANCHOR_FRESHNESS_SECONDS`, `AUDIT_ANCHOR_MAX_LAG_SECONDS` | **保留（条件）**。These are the server-side durable-audit preflight policy. |
| `AUDIT_ANCHOR_BATCH_SIZE`, `AUDIT_ANCHOR_DATABASE_MAX_CONNECTIONS`, `AUDIT_ANCHOR_DATABASE_URL`, `AUDIT_ANCHOR_DATABASE_URL_FILE`, `AUDIT_ANCHOR_LOCK_TIMEOUT_SECONDS`, `AUDIT_ANCHOR_POLL_INTERVAL_SECONDS`, `AUDIT_ANCHOR_REQUEST_TIMEOUT_SECONDS`, `AUDIT_ANCHOR_TOKEN`, `AUDIT_ANCHOR_TOKEN_FILE`, `AUDIT_ANCHOR_URL` | **保留（外部/worker-only）**。These are accepted only by the isolated audit-anchor worker loader. The endpoint and HMAC token must be provisioned consistently with the external anchor service; they cannot be invented by the server. |

### Removed server options

The following names were removed from the allowlist and from CTL-generated
profiles: `ENABLE_REQUEST_OBJECT`, `ENABLE_PAR_REQUEST_OBJECT`,
`ENABLE_DEVICE_AUTHORIZATION_GRANT`, `ENABLE_DYNAMIC_CLIENT_REGISTRATION`,
`ENABLE_CIBA`, `ENABLE_FRONTCHANNEL_LOGOUT`, and `ENABLE_SESSION_MANAGEMENT`.
Existing `.env.yaml` files containing them must be edited once before restart;
runtime-module desired state in the database is now the only authority.

## NazoAuthCtl options

### Durable `UpdateConfig` fields

The JSON document has these top-level fields:

`schema`, `trust`, `capabilities`, `install_profile`, `repository`,
`backup_root`, `deployment_root`, `operator`, `dependencies`, `runtime`,
`postgres`, `valkey`, `ui`.

Nested fields are deliberately explicit and are not user secrets on argv:

- `operator.*`: `deployment_id`, controller/receipt/audit/break-glass `*_key_id`,
  their `*_private_key`/`*_public_key` paths,
  `active_identity_file`, `identity_generations_directory`,
  `recovery_generations_directory`, `secret_revision_file`, `state_directory`,
  `audit_directory`, `trust_state_file`.
- `dependencies.*`: `mode`, `database_url_file`,
  `migration_database_url_file`, `valkey_url_file`.
- `runtime.*`: `backend`, `dependency_backend`, `container_name`,
  `runtime_instance_id`, `network`, `ip_address`, `publish_address`,
  `health_url`, `readiness_attempts`, `readiness_interval_seconds`,
  `public_discovery_url`, `expected_issuer`, `mounts`, `snapshot_paths`,
  `environment`, `service_name`, `service_user`, `binary_path`,
  `binary_releases`, `working_directory`.
- `mounts[*]`: `source`, `target`, `read_only`, `selinux_relabel`.
- `postgres.*`: `container_name`, `database`, `user`, `image`,
  `validation_image`.
- `valkey.*`: `container_name`, `data_volume`, `image`, `rdb_path`,
  `password_file`.
- `ui.*`: `releases_root`.
- `capabilities.*`: `runtime`, `artifact`, `server_config`, `database`,
  `valkey`, `operator_tasks`, `backups`, `proxy_tls`; each grant has
  `responsibility` and `scope`.

`updater_install_path` was removed: self-update already resolves the running
CTL executable and had no consumer for a configured path.

### CTL environment and transport names

| Names | Decision |
|---|---|
| `NAZOAUTHCTL_CONFIG_ROOT`, `NAZOAUTHCTL_STATE_ROOT`, `NAZOAUTHCTL_BREAK_GLASS_ROOT`, `NAZOAUTH_UPDATE_CONFIG`, `NAZOAUTH_BINARY_INSTALL_PATH`, `NAZOAUTH_BINARY_RELEASES`, `NAZOAUTH_SYSTEMD_UNIT_DIR` | **保留**. They locate durable state or the selected artifact/runtime boundary. |
| `NAZOAUTHCTL_LOCK`, `NAZOAUTHCTL_RECOVERY_OPERATION` | **保留（受限）**. Lock/recovery markers are process-safety transport, not application configuration. |
| `NAZOAUTH_OPERATOR_CONTEXT_FILE`, `NAZOAUTH_OPERATOR_CONTROLLER_PUBLIC_KEY_FILE`, `NAZOAUTH_OPERATOR_RECEIPT_PRIVATE_KEY_FILE`, `NAZOAUTH_OPERATOR_SECRET_REVISION_FILE`, `NAZOAUTH_OPERATOR_STATE_DIRECTORY`, `NAZOAUTH_OPERATOR_CONFIG_MANIFEST_FILE`, `NAZOAUTH_OPERATOR_PUBLIC_JWK_FILE`, `NAZOAUTH_SERVER_CONFIG_FILE` | **保留（内部传输）**. One-shot operator tasks receive short-lived file references; these are not user options. |
| `NAZOAUTHCTL_TESTING`, `NAZOAUTH_BUILD_*`, server-side `NAZOAUTH_OPERATOR_DEPLOYMENT_ID_FILE`, `NAZOAUTH_OPERATOR_TEST_FAILPOINT`, `NAZOAUTH_OPERATOR_TEST_FAILPOINT_MARKER` | **测试/构建专用**. Never enable them in a production environment. |

### Install and operation flags

Install retains only deployment boundaries and external dependency choices:
`--runtime`, `--public-url`, `--profile`, `--profile-material`, `--data-root`,
`--control-root`, `--recovery-root`, `--port`, `--network-subnet`,
`--runtime-ip`, `--to`, `--external-dependencies`, `--secrets-stdin`, and
`--secret-fd`. Standards-full profile secret input
(`--profile-secrets-stdin`/`--profile-secret-fd`) remains optional for
controlled import/recovery; absent values are generated by CTL. Conformance
lease token-file flags are runner/lease inputs, not server configuration.

The important design rule is therefore: configuration selects boundaries and
policy; service-owned key material is generated once and persisted; only
credentials whose peer is outside NazoAuth remain externally provisioned.

For completeness, the CTL parser currently exposes these **46** command-line
option names. They are command arguments rather than durable server settings;
secret-bearing values are accepted only through bounded files/FDs.

`--accept-migration-barrier`, `--alg`, `--alias`, `--candidate-build-id`,
`--candidate-oci-digest`, `--candidate-release`, `--candidate-revision`,
`--capability`, `--ciba-automated-decision-token-file`, `--config`,
`--control-root`, `--credentials-stdin`, `--data-root`, `--deployment`,
`--dynamic-registration-token-file`, `--external-dependencies`, `--file`,
`--help`, `--key-ref`, `--kid`, `--lease-id`, `--lifecycle`, `--material`,
`--network-subnet`, `--output`, `--plan`, `--port`, `--profile`,
`--profile-material`, `--profile-secret-fd`, `--profile-secrets-stdin`,
`--public-jwk`, `--public-url`, `--purposes`, `--reason`,
`--recovery-evidence`, `--recovery-root`, `--request-id`, `--runtime`,
`--runtime-ip`, `--secret-fd`, `--secrets-stdin`, `--target`, `--to`,
`--ttl-seconds`, `--yes`.
