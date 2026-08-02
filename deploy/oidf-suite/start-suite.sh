#!/bin/sh
set -eu

if [ -f /oidf-proxy-pki/server-ca.crt ]; then
    cp "$JAVA_HOME/lib/security/cacerts" /tmp/oidf-suite-cacerts
    chmod 0600 /tmp/oidf-suite-cacerts
    keytool -importcert -noprompt -alias nazoauth-host-local-oidf-proxy \
        -file /oidf-proxy-pki/server-ca.crt \
        -keystore /tmp/oidf-suite-cacerts -storepass changeit >/dev/null
    JAVA_EXTRA_ARGS="-Djavax.net.ssl.trustStore=/tmp/oidf-suite-cacerts -Djavax.net.ssl.trustStorePassword=changeit ${JAVA_EXTRA_ARGS:-}"
    export JAVA_EXTRA_ARGS
fi

exec java \
  -D"fintechlabs.base_url=${BASE_URL}" \
  -D"fintechlabs.base_mtls_url=${BASE_MTLS_URL}" \
  -D"spring.data.mongodb.uri=mongodb://${MONGODB_HOST}:27017/test_suite" \
  ${SIGNING_KEY:+-D"fintechlabs.signingKey=${SIGNING_KEY}"} \
  ${DEPRECATED_SIGNING_KEY:+-D"fintechlabs.deprecatedSigningKey=${DEPRECATED_SIGNING_KEY}"} \
  ${PRIVATE_LINK_SIGNING_KEY:+-D"fintechlabs.privateLinkSigningKey=${PRIVATE_LINK_SIGNING_KEY}"} \
  -D"oidc.google.clientid=${OIDC_GOOGLE_CLIENTID}" \
  -D"oidc.google.secret=${OIDC_GOOGLE_SECRET}" \
  -D"oidc.gitlab.clientid=${OIDC_GITLAB_CLIENTID}" \
  -D"oidc.gitlab.secret=${OIDC_GITLAB_SECRET}" \
  ${JAVA_EXTRA_ARGS:-} \
  -jar /server/fapi-test-suite.jar \
  -Djdk.tls.maxHandshakeMessageSize=65536
