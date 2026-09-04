# Avatar direct upload

When the configured avatar object store exposes direct upload, a browser uploads image bytes to the object store and NazoAuth never receives an upload-body relay.

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
