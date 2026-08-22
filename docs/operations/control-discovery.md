# NazoAuth control discovery protocol

NazoAuth exposes a product-specific, read-only discovery endpoint at
`POST /.well-known/nazoauth-control`. The request contains schema version `1`
and a fresh 32-byte base64url nonce. The response contains an Ed25519 compact
JWS with type `nazoauth-control-discovery+jwt` plus the instance public key.

The signed statement binds the nonce, issuer, immutable deployment ID,
runtime-instance ID, embedded build identity, and supported control and
operator protocol versions. It contains no database or Valkey URL, credential,
administrator data, controller material, break-glass material, or privileged
operation.

The instance identity is separate from OAuth signing, controller, receipt,
audit, and break-glass identities. A single-instance deployment stores it at:

```text
DATA_DIR/instance/identity.key
DATA_DIR/instance/identity.pub
DATA_DIR/instance/deployment-statement.jws
```

For a replicated deployment, `DATA_DIR/instance/deployment-id` is the shared
logical deployment identity. Each replica must set `INSTANCE_IDENTITY_DIR` to
its own persistent mount; its `identity.key`, `identity.pub`, runtime ID and
signed statement live there and must never be shared with another replica.

`deployment-statement.jws` uses the distinct
`nazoauth-deployment-statement+jwt` type and has no freshness claim. It permits
offline identification when the server cannot start; it is not proof that the
current binary or OCI image is trusted. A recovery controller must separately
verify the mounted binary hash or local OCI digest against cached Release,
attestation, and signature evidence.

Replicas sharing a logical deployment must share the persisted deployment ID
but use separate instance identity directories and runtime-instance IDs. Set
`INSTANCE_IDENTITY_DIR` and `RUNTIME_INSTANCE_ID` per replica, and set the same
`DEPLOYMENT_ID` for the deployment. A persisted identity mismatch fails startup
closed.

The one-shot `operator-task` executor applies the same boundary before it
claims a request: `deployment_id` must equal the local deployment identity,
`iss` must be exactly `controller:<deployment_id>`, and `aud` must be exactly
`runtime:<deployment_id>`. When `DATA_DIR/instance/deployment-id` already
exists, it must agree with `DEPLOYMENT_ID` in the mounted server configuration.
The operator-state mount also persists the same identity for one-shot
containers that intentionally do not mount the full server data directory;
once present, that anchor is required for every subsequent task. During the
first migration, before either local anchor exists, the canonical mounted
`DEPLOYMENT_ID` is the explicit bootstrap source for `migrate-apply` only.
`NAZOAUTH_OPERATOR_DEPLOYMENT_ID_FILE` may be set to require a separate
read-only identity mount; a configured but unavailable file fails closed. This
check is local and does not make the recovery controller a runtime dependency.

The wire DTOs, JWS types, signing/verification policy, compatibility parsing,
and fixed vectors live only in `crates/operator-protocol`. Controllers consume
that crate at an exact version and source revision; they do not copy protocol
code.

The management OpenID4VP create request carries a caller-generated,
non-secret `create_request_jti` in canonical lowercase UUID form. The caller
must reuse that JTI for automatic retries. NazoAuth binds it to the tenant and
to canonical JSON of the fully default-expanded create request. An exact retry
during the transaction retention window returns the same transaction,
authorization URL, original `expires_in`, JTI, and create-request digest; the
same JTI with different normalized input returns `409`. Once bounded cleanup
removes the expired transaction, the JTI may be reused and creates a new
transaction. Controllers must therefore never deliberately recycle create
JTIs.

OpenID4VP verification intents and success receipts are also signed by the
current instance identity. Receipt issuance is available for at most 600
seconds after successful completion, and each public receipt is valid for at
most 600 seconds after issuance. This deployment has no historical instance
keyring for those receipts: before replacing or removing an instance identity,
operators must stop new evidence attachment/issuance and drain both bounded
windows. A receipt signed by any key other than the live discovery identity
fails closed; key rotation must not overlap an active receipt window.

Result and capability AEAD associated data binds tenant, transaction, evidence
context, presentation-request digest, exact trust-policy tuple, and signed
intent digest; capability ciphertext additionally binds the issuance JTI.
Legacy transaction-ID-only AEAD fallback is accepted only for an unexpired
pre-migration transaction with none of the create/evidence columns populated.
Such a row cannot be upgraded by attaching evidence or issuing a receipt.

The database cleanup function deletes at most 256 expired transactions per
call, uses the indexed effective expiry deadline, and is invoked before
management create, evidence attach, and receipt issuance repository work. No
new resident cleanup worker is introduced.

The database itself does not provide an external monotonic rollback anchor. A
whole-database rollback could therefore restore an older signed state. Normal
APIs prevent JTI reuse and receipts expire within 600 seconds, but protection
against storage-snapshot rollback requires an external monotonic deployment
or backup-generation control and is outside this protocol revision.
