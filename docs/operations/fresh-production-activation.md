# Fresh production activation

This is the destructive acceptance runbook for a deliberately new NazoAuth
deployment. It is a single continuous task, not a phased delivery contract.
The normal first-install and upgrade interface remains
[`nazoauthctl`](one-click-update.md).

## Preconditions

- A reviewed commit has produced an immutable tagged Release containing the
  server binaries and versioned protocol package, exact-workflow schema-5
  GitHub attestations for its platform binaries, and a signed multi-platform
  OCI index. The bound NazoAuthWeb descriptor identifies a separately attested
  frontend Release.
- The operator has inventoried the exact NazoAuth containers, volumes, files,
  proxy references, ports, and local OIDF Suite state. Unrelated host resources
  are out of scope.
- The existing NazoAuth state has been backed up when retention is required.
  A destructive clean-install exercise intentionally does not reuse that state.
- The TLS ingress for the requested public issuer already exists; the installer
  must verify public Discovery through it.

## One continuous acceptance sequence

1. Record the commit, Release/build identity, signed manifest, artifact digest,
   current inventory, command, exit code, timestamp, and evidence path.
2. Remove only the inventoried NazoAuth application/dependency containers,
   volumes, configuration, deployment records, application state, controller,
   receipt, audit and break-glass identities, and audit chain. Re-inventory the
   host to prove unrelated services were unchanged.
3. During this same continuous acceptance run, create one-time material for the
   exact commit and host-local Suite, then install the verified `nazoauthctl`
   from the same immutable Release:

   ```sh
   sudo python3 /opt/nazoauth/source/scripts/prepare_host_local_oidf_install.py \
     --source-dir /opt/nazoauth/source \
     --source-commit "$DEPLOYED_SOURCE_SHA" \
     --suite-origin https://oauth-test.nazo.run \
     --output-dir /run/nazoauth-host-local-oidf-install
   sudo nazoauthctl install --runtime auto --public-url https://auth.example.com \
     --profile standards-full \
     --profile-material /run/nazoauth-host-local-oidf-install/standards-full-profile.json \
     --to vX.Y.Z
   secret-provider read nazoauth/initial-admin | \
     sudo nazoauthctl bootstrap-admin --credentials-stdin --yes
   sudo nazoauthctl status
   sudo nazoauthctl doctor
   ```

   The host-local Suite path must not pass through GitHub. The independent
   preparation entrypoint creates a `standards-full-profile.json` with no test
   trust keys, time-bounded public attestation trust, and matching private Suite
   run material, with a manifest binding the source commit, Suite origin, and
   every file SHA-256 value. None comes from
   the deleted deployment or a historical artifact. The GitHub public onboarding
   workflow is only for the official public Suite path run on GitHub. Installation
   reads only the baseline profile. The host-local runner uses
   `nazoauthctl conformance lease create` to grant attestation keys only to
   clients bound to that lease and bind the run-local credential CA only to
   verifier transactions for the same Suite origin, then consumes both the public
   trust file and private material once. Revocation or expiry stops using that
   trust immediately; periodic cleanup deletes the clients and bound verifier
   transactions and clears the stored public material.
   The initial administrator token is resolved from the new private runtime-owned
   mount and is never printed, copied from old state, or placed in argv or the
   ordinary environment.

4. Exercise `update --plan`, update, artifact rollback, explicit backup recovery,
   migration, key list/validation/mutation, audit show/verify, normal identity
   rotation, break-glass controller recovery, interruption retry, and restart
   recovery through public commands only. `--yes` skips prompts only; it never
   bypasses signatures, authorization, replay defense, audit, backups, health
   checks, rollback policy, or migration barriers.
5. Verify the application runs as a non-root UID with no capabilities and a
   read-only root filesystem; task mounts/networks match the operation; managed
   runtime PostgreSQL cannot perform DDL; no secret appears in argv, ordinary
   environment, inspect output, journal, logs, audit, or a persisted envelope;
   raw `nazoauth migrate`/`keyctl` paths are rejected; intent/receipt retries are
   idempotent and signed audit/trust chains verify.
6. Run the remote host-local OIDF Conformance Suite against this exact public
   instance for all `27 + 17 = 44` fixed plans and every declared variant. Sampling,
   capability reduction, verdict changes, and unsupported expected skips are
   forbidden.

Any error, timeout, manual repair, internal-state edit, privilege expansion,
security bypass, incomplete evidence, or OIDF failure invalidates the attempt.
Fix the code, publish a new immutable Release, delete the NazoAuth deployment
again, and restart this sequence at step 1.

## Completion record

The only successful conclusion is `PASSED`, with the commit, Release and
embedded build identity, actual OCI/binary digest, full commands and exit codes,
request IDs, remote evidence paths, OIDF Suite version, and every plan/variant
result. Otherwise report `FAILED` or `BLOCKED`; neither means completion.

The protocol invariants, recovery boundaries, fault windows, and detailed task
matrix are defined in the
[operator-task protocol plan](../security/operator-task-protocol-plan.zh-CN.md)
and its [implementation task book](../project/operator-task-protocol-implementation-task.zh-CN.md).
