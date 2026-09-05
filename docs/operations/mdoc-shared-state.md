# Managed OpenID4VC state

The tenant signing-key record owns the ES256 signing key, matching certificate
chain, historical trust anchors, IACA private material and local DS revocation
facts. The existing persistence adapter commits the complete encrypted record
with compare-and-swap. No new database table or object-storage adapter is used.
IACA private material is excluded from public keyset metadata.

A signing operation captures one key generation. Its x5c, mdoc leaf certificate,
OpenID4VP certificate-derived client_id and signature use that same generation.
A pending signed-post VP request bound to an old certificate hash is rejected
if explicit certificate rotation occurs before nonce retrieval; the wallet must
start a new request. No JWT is returned with mismatched outer/inner identity.
Rotation retains old IACA records and roots for previously issued credentials
and their CRL URLs. It does not delete historical authority material.

The existing key lifecycle refreshes managed OpenID4VC generations at most every
30 seconds. Local revocation facts are authoritative database state; a successful
read establishes a new observation window, without writing a new revision.
Verification rejects an observation older than 60 seconds. CRL requests read the
database directly and issue a CRL valid for 24 hours. A revoked active DS cannot
be selected for new signing; rotate it to resume issuance.

Client-scoped external trust continues to use tenant TrustPolicy resources.
Managed issuer state does not use external trust resources as a private-key
store. The former managed certificate/trust/revocation file settings and file
reload interval have been removed.

## Upgrade from file-backed certificates

Use the new binary with the deployment's normal configuration and the same
signing-key encryption root. This is a host-administrator operation. Ctl has no
arbitrary remote-command or directory-import interface, so migration is explicit
on the target host, not hidden in server startup.

1. Keep a backup of the existing database, encryption root and each tenant's
   `openid4vc` directory. Prevent old instances or management jobs from updating
   those files during migration.
2. Remove `OPENID4VC_SIGNING_CERTIFICATE_CHAIN_FILE`,
   `OPENID4VC_TRUST_ANCHORS_FILE`, `OPENID4VC_REVOCATION_SNAPSHOT_FILE` and
   `OPENID4VC_REVOCATION_RELOAD_INTERVAL_SECONDS` from deployment configuration.
3. Import each affected tenant before starting its new runtime:

   ```sh
   nazoauth mdoc-import --tenant <tenant-uuid> --from <tenant-openid4vc-directory>
   ```

   The directory contains `certificate-bundle.pem`, and for mdoc also
   `revocation-snapshot.json` plus `iaca-keys/<IACA-fingerprint>.pem`.
   Each IACA file contains its private key, DS certificate and IACA certificate.
   The selected signing key must already be in the tenant database keyset.
   Deployments predating database keysets must first perform the separate
   `nazoauth keys-import --tenant <tenant-uuid> --from <legacy-keys-directory>`.
4. Check the command's successful revision result, then start the new instances
   against the shared database. Verify credential issuance and old CRL URLs.
   Source files are not deleted by import; retain them with the migration backup.

### Upgrade from a pre-IACA bundle

NazoAuth v0.2.9 generated a local CA only while creating
`certificate-bundle.pem`; it did not retain the CA private key or create an
`iaca-keys/` directory. Its certificate also predates the managed mdoc
certificate profile. Those bytes cannot be treated as a current IACA record or
used to sign a CRL.

For that released format, keep the old service stopped and use two explicit
steps after `keys-import`:

1. Make a migration-only copy of the final configuration whose
   `OPENID4VCI_CREDENTIAL_CONFIGURATIONS_JSON` omits every `mso_mdoc`
   configuration. Run `mdoc-import` with that copy. This preserves the existing
   ES256 `kid`, certificate and public CA as historical verification material;
   it does not invent the unavailable CA private key.
2. Run `mdoc-rotate` with the final configuration, including the intended
   `mso_mdoc` configuration. The single database commit creates a new conformant
   DS/IACA generation and revocation state, retains the old CA trust anchor, and
   keeps the old ES256 key through the configured verification grace period.

Do not use this path for a source that already contains `iaca-keys/`, or when a
locally owned revocation record must remain serviceable under its old IACA.
Import those complete records with the ordinary procedure instead. Verify the
old `kid` remains in JWKS, the new active `kid` issues credentials, and the new
IACA CRL endpoint succeeds before starting the managed update.

Import checks certificate/key relationships and keeps the existing signing kid.
A legacy revoked entry without its own timestamp uses the old snapshot observation
time once during import; subsequent CRL refreshes and rotation preserve it.
It imports only locally owned DS revocation facts; mixed external status input
must not be promoted to authoritative local state. Missing IACA records, a
mismatched chain or an existing managed aggregate cause an error. No automatic
regeneration or file fallback occurs. A failed commit leaves the prior keyset
unchanged. A repeated import after success reports that material already exists.

Fresh installations initialize the complete aggregate through tenant bootstrap
or the existing tenant key-generation operation. Normal server startup reads
it and does not create certificate files.

## Rotation and revocation

With the deployment's normal configuration available to the administrator:

```sh
nazoauth mdoc-rotate --tenant <tenant-uuid>
nazoauth mdoc-revoke --tenant <tenant-uuid> --issuer-id <IACA-fingerprint>
```

The fingerprint is the 64-character SHA-256 IACA identifier already present in
that DS certificate's CRL URL. Each current IACA record owns one DS; revocation
marks that DS revoked, not every historical DS. Concurrent updates use the
record revision to prevent lost writes. A conflict fails explicitly and must be
reviewed before repeating the operation. Neither command modifies other tenants.

Back up the database and wrapping root together. Restarting an instance requires
no local mdoc directory. These storage properties do not by themselves prove
whole-system multi-instance acceptance or authorize closing issue #108.
