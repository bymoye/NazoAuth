# NazoAuth Helm chart

Create the connection Secret, then install the chart:

```sh
kubectl create secret generic nazoauth-connections \
  --from-literal=database-url='postgresql://...' \
  --from-literal=valkey-url='redis://...'
helm upgrade --install nazoauth ./deploy/helm/nazoauth \
  --set image.repository=registry.example/nazoauth \
  --set image.tag=vX.Y.Z \
  --set publicBaseUrl=https://auth.example.com \
  --set mtls.trustedProxyCidrs=10.0.0.10/32
```

Replace `vX.Y.Z` with an immutable published Release tag. Production GitOps
should pin the verified platform image digest rather than follow a mutable tag.

The chart defaults to `transportMode=trusted-proxy` because the Service exposes
HTTP inside the cluster. Set `mtls.trustedProxyCidrs` to the exact ingress peer
addresses before installation; startup fails closed when that boundary is
missing. The current chart does not mount the server/client-CA identities needed
for `direct-tls`.

With one replica, NazoAuth generates application secrets and signing keys into
the persistent data volume. Multiple replicas are rejected unless
`appSecrets.existingSecret` is set and the generated-secret RWO volume is not
used. For an HSM/KMS, set `signing.externalCommand` and mount its executable and
credentials through `extraVolumes` and `extraVolumeMounts`.

TLS termination and DNS certificates are external deployment facts. Configure
an ingress/gateway separately and use the mTLS proxy contract under
`deploy/proxy` when certificate-bound clients are enabled.
