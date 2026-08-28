# mTLS proxy presets

NazoAuth accepts certificate identity only from `TRUSTED_PROXY_CIDRS`.

- Prefer `MTLS_CERTIFICATE_SOURCE=rfc9440` when the TLS terminator emits the
  singleton RFC 9440 `Client-Cert` header and removes any inbound copy.
- Keep `MTLS_CERTIFICATE_SOURCE=disabled` when the deployment has no
  authenticated certificate-forwarding boundary.

The proxy-to-application hop must be private or mutually authenticated. A CIDR
allowlist does not protect traffic that can be injected by another workload on
the same network.

## HAProxy with RFC 9440

[`haproxy-rfc9440.cfg`](haproxy-rfc9440.cfg) is the reviewed starting point for
HAProxy 3.2. It deliberately separates the ordinary HTTPS listener from the
listener that requires a client certificate. Set `MTLS_ENDPOINT_BASE_URL` to
the dedicated mTLS origin and keep `PUBLIC_BASE_URL` on the public listener.

The file named `active-client-cas.pem` is deployment state, not a checked-in
certificate. For ordinary clients it contains the approved production roots.
For an isolated conformance run, construct a temporary bundle from the public
`mtls_trust_anchor_pem` values bound to that run's active lease. Never put a
client private key in this bundle.

Each client leaf must have an issuer DN matching its generated CA and a subject
DN distinct from that issuer. Validate the exact material with
`openssl verify -CAfile run-ca.pem client.pem` before activation. Reusing the
CA's subject DN for a different-key leaf can make OpenSSL and HAProxy classify
the leaf as self-signed and reject it even though the signature was produced by
the CA key.

Apply a new bundle and configuration as one recoverable operation:

1. Refuse the change while another proxy mutation or conformance run owns the
   shared listener.
2. Write the candidate bundle and configuration in the same root-owned
   directory with mode `0600`; record their SHA-256 digests and the lease id in
   a private journal.
3. Run `haproxy -c -f /path/to/candidate.cfg` with the same HAProxy version that
   serves traffic.
4. Atomically replace the active files and perform a graceful reload.
5. Prove that public readiness and Discovery still work, that the dedicated
   listener rejects a connection without a certificate, that the run's client
   certificate succeeds, and that CBC and CHACHA20 are rejected.
6. In normal completion and interruption cleanup, atomically restore the
   previous bundle/configuration, reload, repeat the probes, and only then
   retire the old worker and temporary CA.

`nazoauthctl oidf run` can own the bundle portion directly with the
paired options `--proxy-trust-bundle /run/nazoauth/active-client-cas.pem` and
`--proxy-reload-executable /usr/local/sbin/reload-nazoauth-proxy`. The reload
executable must be an absolute, root-owned regular file that is not
group/world-writable. It must validate the complete configuration, perform a
bounded graceful reload, and return non-zero unless the new worker is healthy.
The controller retains a private sibling recovery file, restores it during
normal or interrupted cleanup, and recovers stale bundle state before a later
run. The helper must not generate certificates, read client private keys, or
change unrelated proxy state.

Do not use `ca-ignore-err all` or `crt-ignore-err all`. Those options make a
client certificate available to the application even when HAProxy did not
establish the certificate chain required by the deployment. `verify optional`
is acceptable only on a deliberately shared public listener and still requires
an exact active CA bundle; prefer the dedicated `verify required` listener in
the supplied preset.

When RFC 9440 mode is selected, set:

```yaml
TRANSPORT_MODE: "trusted-proxy"
MTLS_CERTIFICATE_SOURCE: "rfc9440"
MTLS_ENDPOINT_BASE_URL: "https://auth.example.com:8443"
TRUSTED_PROXY_CIDRS: "127.0.0.1/32"
```

Use the address NazoAuth actually observes for the proxy instead of the sample
loopback CIDR. The preset deletes inbound `Forwarded`, `X-Forwarded-*`,
`Client-Cert`, `Client-Cert-Chain`, and `X-SSL-*` headers. Only the singleton
RFC 9440 `Client-Cert` value derived from the verified TLS peer is added on the
dedicated mTLS listener. The upstream must not be reachable by an untrusted
peer.
