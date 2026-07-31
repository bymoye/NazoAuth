# mTLS proxy presets

NazoAuth accepts certificate identity only from `TRUSTED_PROXY_CIDRS`.

- Prefer `MTLS_CERTIFICATE_SOURCE=rfc9440` when the TLS terminator emits the
  singleton RFC 9440 `Client-Cert` header and removes any inbound copy.
- Use `MTLS_CERTIFICATE_SOURCE=legacy-verified-headers` with the reviewed nginx
  preset in this directory. It requires `X-SSL-Client-Verify: SUCCESS`.
- Keep `MTLS_CERTIFICATE_SOURCE=disabled` when the deployment has no
  authenticated certificate-forwarding boundary.

The proxy-to-application hop must be private or mutually authenticated. A CIDR
allowlist does not protect traffic that can be injected by another workload on
the same network.
