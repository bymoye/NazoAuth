# GitHub Actions secrets

Repository Secrets are an execution boundary, not a configuration archive. A
secret stays only while a current workflow references it. Values are never
copied into documentation, logs, artifacts, repository variables, or pull
request descriptions.

## Current inventory

| Secret | Purpose | Rotation trigger |
|---|---|---|
| `CODECOV_TOKEN` | Authenticates coverage upload. | Codecov repository token rotation or suspected disclosure. |
## Audit procedure

1. Extract every `secrets.NAME` reference from `.github/workflows`.
2. Compare the resulting set with `gh secret list --repo <owner>/<repo>`.
3. Delete names not referenced by a current workflow.
4. Fail if a workflow reference has no repository or explicitly documented
   organization/environment Secret.
5. Rotate a retained value only from its authoritative provider. GitHub does
   not expose stored values, so an audit must never claim value freshness from
   a name or timestamp alone.

Organization Secrets require organization-administrator access and must be
audited separately. This repository does not use GitHub Environments.
