# mTLS proxy preset

NazoAuth accepts forwarded certificate identity only from `TRUSTED_PROXY_CIDRS`.

- Use `MTLS_CERTIFICATE_SOURCE=rfc9440` only when the TLS terminator emits the
  singleton RFC 9440 `Client-Cert` header and removes every inbound copy.
- Use `MTLS_CERTIFICATE_SOURCE=disabled` when no authenticated forwarding
  boundary exists.
- Keep the proxy-to-application hop private or mutually authenticated; a CIDR
  allowlist alone does not prevent injection by another workload on that CIDR.

## HAProxy with RFC 9440

[`haproxy-rfc9440.cfg`](haproxy-rfc9440.cfg) is the reviewed HAProxy 3.2
starting point. It separates ordinary HTTPS from a dedicated listener that
requires a client certificate. `active-client-cas.pem` is deployment state and
contains only approved production client roots; never put a private key in it.

Apply trust-bundle changes recoverably:

1. Write the candidate bundle in a root-owned directory with mode `0600`.
2. Validate certificates and the complete candidate configuration.
3. Run `haproxy -c -f /path/to/candidate.cfg` with the serving HAProxy version.
4. Atomically replace the active files and perform a graceful reload.
5. Verify readiness, Discovery, anonymous rejection on the mTLS listener, a
   valid client handshake, and rejection of disallowed cipher suites.
6. Restore the previous files and reload immediately if any probe fails.

Do not use `ca-ignore-err all` or `crt-ignore-err all`. Prefer a dedicated
`verify required` listener; `verify optional` is valid only when deliberately
designed and still needs an exact active CA bundle.

```yaml
TRANSPORT_MODE: "trusted-proxy"
MTLS_CERTIFICATE_SOURCE: "rfc9440"
MTLS_ENDPOINT_BASE_URL: "https://auth.example.com:8443"
TRUSTED_PROXY_CIDRS: "127.0.0.1/32"
```

Use the address NazoAuth actually observes. The preset removes inbound
`Forwarded`, `X-Forwarded-*`, `Client-Cert`, `Client-Cert-Chain`, and `X-SSL-*`
headers, then adds only the RFC 9440 value derived from the verified TLS peer.
