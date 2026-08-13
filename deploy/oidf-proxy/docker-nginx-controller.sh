#!/bin/sh
set -eu

container=${NAZOAUTH_OIDF_PROXY_CONTAINER:-nazo-oauth-mtls-proxy-1}
trust_file=${NAZOAUTH_OIDF_PROXY_TRUST_FILE:-/opt/nazoauth-conformance/proxy/oidf-mtls-ca.crt}

case "${1:-}" in
    -t)
        test -f "$trust_file"
        docker cp "$trust_file" "$container:/etc/nginx/pki/client-ca.pem"
        docker exec "$container" nginx -t
        ;;
    -s)
        test "${2:-}" = reload
        docker exec "$container" nginx -s reload
        ;;
    *)
        echo "usage: docker-nginx-controller.sh <-t|-s reload>" >&2
        exit 2
        ;;
esac
