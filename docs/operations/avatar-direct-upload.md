# Avatar direct upload

When the configured avatar object store exposes direct upload, a browser uploads image bytes to the object store and NazoAuth never receives an upload-body relay.

An authenticated `GET /auth/me/avatar/uploads` reports the selected tenant's
`upload_mode`: `disabled`, `multipart`, or `direct`. Clients use this capability
to choose the upload flow and disable avatar controls when storage is unavailable.
It exposes no provider or credentials. A failed request never switches upload modes.

1. Send `POST /auth/me/avatar/uploads` with the normal authenticated session, CSRF token, and a JSON body containing the exact image byte count, for example `{"content_length": 18432}`. The value must be between one byte and the configured avatar limit.
2. Receive `upload_id`, `expires_at`, and `upload`. Forward `upload.url`, `upload.method`, every `upload.headers` entry verbatim in the one browser request. The image bytes are sent according to that opaque target; the current direct target uses `PUT` with the image as the raw request body. Let the browser supply the body length from the `File` or `Blob` and do not set `Content-Length` from script.
3. Before `expires_at`, send `POST /auth/me/avatar/uploads/{upload_id}/complete` with the same session and CSRF protection. The response is the normal `/auth/me` account projection.

For step 2, `file` is the original browser `File` whose `size` was declared:

```js
const uploaded = await fetch(upload.url, {
  method: upload.method,
  headers: upload.headers,
  body: file,
});
if (!uploaded.ok) throw new Error("Avatar upload failed");
```

`upload` is an opaque storage contract. Clients must not infer a provider, modify the request, reuse it for a different object, or send an avatar through `POST /auth/me/avatar` when the direct target is available. A completion retry is safe after a lost response.

The target accepts only its fixed staging object and its signed exact byte count. Completion reads the bounded staged snapshot, decodes PNG, JPEG, or WebP bytes, records the source version and content-derived immutable candidate, then asks the object store to publish that source version server-side. The database avatar reference CAS remains authoritative. Replaying a staging target later cannot overwrite the final object.

For the S3-compatible adapter, set `AVATAR_OBJECT_STORE: s3` plus `AVATAR_S3_ENDPOINT`, `AVATAR_S3_REGION`, `AVATAR_S3_BUCKET`, `AVATAR_S3_ACCESS_KEY`, `AVATAR_S3_SECRET_KEY`, and optional `AVATAR_S3_PATH_STYLE`. These keys are parsed only by the concrete adapter. The deployment must keep the `avatars/staging/` prefix unreadable to the public; a private bucket provides this directly. If a deployment serves final objects through a public domain, its access policy must still exclude staging objects. Configure CORS to allow the browser origin to perform the signed PUT and to expose no broader write capability. Configure an object-lifecycle rule that deletes the adapter's `avatars/staging/` prefix after the upload authorization window; final objects require a separate retention process because the server never deletes them after an ambiguous database outcome.

## Global default and tenant overrides

`AVATAR_OBJECT_STORE` and the corresponding settings optionally select the deployment default. An absent tenant entry inherits that default only when it is configured. `AVATAR_TENANT_STORAGE_JSON` supplies complete configurations keyed by tenant UUID; individual fields are never merged with the default. Only `local` and `s3` are supported. R2 is an S3 configuration of the Linux validation environment deployment, not another adapter.

The administrator chooses shared storage by setting `AVATAR_OBJECT_STORE`, or an allowlist by omitting it and configuring only selected tenant UUIDs in `AVATAR_TENANT_STORAGE_JSON`. No separate allowlist is maintained. If neither applies to a tenant, avatar storage is disabled; authenticated avatar requests return HTTP 403 `access_denied` with a storage-not-configured message. Authentication and authorization remain available. No local avatar directory is created for a disabled tenant.

Local storage requires an explicit `AVATAR_OBJECT_STORE: local` or tenant `type: local`. Setting `AVATAR_STORAGE_DIR` alone does not enable it. The generated configuration leaves global storage unset. Invalid configured storage fails configuration, and runtime S3 failures return storage errors without switching to local disk.

For example, a YAML configuration can inherit global local storage for most tenants and override two tenants:

```yaml
AVATAR_OBJECT_STORE: local
AVATAR_TENANT_STORAGE_JSON: >-
  {
    "00000000-0000-0000-0000-000000000011": {
      "type": "s3",
      "endpoint": "https://objects.example.com",
      "region": "auto",
      "bucket": "tenant-avatars",
      "access_key": "replace-with-access-key",
      "secret_key": "replace-with-secret-key",
      "path_style": true
    },
    "00000000-0000-0000-0000-000000000012": {
      "type": "local",
      "directory": "/srv/avatars"
    }
  }
```

All S3 fields shown are required except `path_style`, which defaults to `true`. A local override requires an absolute base `directory` (use an absolute Windows path on Windows). Remove the `AVATAR_OBJECT_STORE: local` line in this example to enable storage for only those two tenants. Removing a tenant entry restores inheritance when global storage exists, or disables storage for that tenant otherwise. Configurations are loaded at process startup; update every instance consistently and restart to apply changes. The launcher resolves the concrete tenant storage once and injects its capability into the tenant runtime. Tenant routing and identity business code do not parse S3 settings or credentials.

Resource layout remains isolated even when tenants share the same base directory or bucket:

- Default local: `DATA_DIR/tenants/{tenant_uuid}/avatars/{user_uuid}/`.
- Explicit global `AVATAR_STORAGE_DIR` or tenant local `directory`: `{base}/{tenant_uuid}/{user_uuid}/`.
- S3 staging: `avatars/staging/{tenant_namespace}/{upload_id}`.
- S3 final: `avatars/final/{tenant_namespace}/{object_id}`.

The existing S3 `tenant_namespace` is the lowercase hexadecimal SHA-256 of the tenant UUID's 16 raw bytes. Both S3 prefixes already isolate tenants; their layout is unchanged. Local disk storage still requires all serving instances to see the same files; a common path string on independent disks does not share data.

## Manual storage migration

Changing configuration does not move data. Avatar database references do not record the old backend, and the runtime does not search multiple backends.

Before removing the last applicable storage configuration for an existing tenant, migrate its avatars to a remaining configured store or clear its avatar references and retire the old objects while that store is still available. Disabling storage does not silently clear database references or delete files.

1. Pause avatar writes for the affected tenant on every instance, allow issued uploads and completion operations to finish or expire, and retain the old configuration and data until verification succeeds.
2. For a local directory change, copy the tenant's user directories, including `avatar.bin` and `meta.json`, into the new tenant root. For an S3 bucket or endpoint change, copy the tenant's final objects with exactly the same object keys, bytes and Content-Type metadata. Do not carry unfinished upload authorizations across stores.
3. Apply the new configuration consistently, restart the instances, and verify existing avatar reads plus a new upload/read/delete cycle before reopening writes or retiring the old data.

Upgrading from the previous single-tenant local layout requires moving `DATA_DIR/avatars/{user_uuid}/` to `DATA_DIR/tenants/{tenant_uuid}/avatars/{user_uuid}/`, or moving the user directories beneath `{AVATAR_STORAGE_DIR}/{tenant_uuid}/` when an explicit base was used. Existing directory-managed default paths and S3 object paths are unchanged.

Local and S3 layouts differ: local stores each user's bytes and version metadata, while S3 stores an object named by the version in the database avatar URL and carries Content-Type as object metadata. A cross-adapter migration must explicitly translate that layout and preserve the referenced version, or re-upload through the target adapter and update the reference. A recursive directory copy alone is not a cross-adapter migration. No automatic migration or dual write is performed.
