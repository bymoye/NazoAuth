import http from 'k6/http';
import { check, fail } from 'k6';
import exec from 'k6/execution';
import { SharedArray } from 'k6/data';

const BASE_URL = (__ENV.BASE_URL || 'http://nazoauth:8000').replace(/\/$/, '');
const secrets = JSON.parse(open('/perf-state/secrets.json'));
const vectors = new SharedArray('signed-vectors', () => JSON.parse(open('/perf-state/vectors.json')));
const scenario = __ENV.PERF_SCENARIO || 'token_client_credentials';
const duration = __ENV.PERF_DURATION || '20s';
const executor = __ENV.PERF_EXECUTOR || '';
const rate = Number(__ENV.PERF_RATE || '0');
const timeUnit = __ENV.PERF_TIME_UNIT || '1s';
const vus = Number(__ENV.PERF_VUS || '8');
const flowVus = Number(__ENV.PERF_FLOW_VUS || __ENV.PERF_VUS || '8');
const preAllocatedVus = Number(__ENV.PERF_PRE_ALLOCATED_VUS || __ENV.PERF_FLOW_VUS || __ENV.PERF_VUS || '8');
const maxVus = Number(__ENV.PERF_MAX_VUS || Math.max(preAllocatedVus * 2, preAllocatedVus));
const iterations = Number(__ENV.PERF_ITERATIONS || '50');
const scenarioSteps = {
  token_client_credentials: ['token_client_credentials'],
  mtls_client_credentials: ['mtls_client_credentials'],
  par_signed_request_object: ['par_oidc'],
  token_only_client_credentials: ['token_client_credentials'],
  oidc_cold_login_refresh: [
    'par_oidc',
    'login',
    'authorize',
    'authorize_decision',
    'token_authorization_code',
    'token_refresh',
  ],
  oidc_logged_in_authorization_code: [
    'par_oidc',
    'authorize',
    'authorize_decision',
    'token_authorization_code',
  ],
  oidc_refresh_only: ['token_refresh'],
  fapi2_full_security: [
    'par_fapi',
    'login',
    'authorize',
    'authorize_decision',
    'fapi_token_authorization_code',
    'fapi_token_refresh',
  ],
  refresh_token_rotation: [
    'par_oidc',
    'login',
    'authorize',
    'authorize_decision',
    'token_authorization_code',
    'token_refresh',
  ],
  introspect_opaque_refresh_token: [
    'par_oidc',
    'login',
    'authorize',
    'authorize_decision',
    'token_authorization_code',
    'introspect',
  ],
  authorize_par_session: ['par_oidc', 'login', 'authorize'],
  same_user_refresh_token_rotation: [
    'par_oidc',
    'login',
    'authorize',
    'authorize_decision',
    'token_authorization_code',
    'token_refresh',
  ],
  same_user_introspect_opaque_refresh_token: [
    'par_oidc',
    'login',
    'authorize',
    'authorize_decision',
    'token_authorization_code',
    'introspect',
  ],
  same_user_authorize_par_session: ['par_oidc', 'login', 'authorize'],
  fapi2_par_jar_private_key_jwt_dpop: [
    'par_fapi',
    'login',
    'authorize',
    'authorize_decision',
    'fapi_token_authorization_code',
    'fapi_token_refresh',
  ],
};
const vectorStride = Math.max(iterations, 100);
const vectorOffsets = {
  par_signed_request_object: 0,
  refresh_token_rotation: vectorStride,
  introspect_opaque_refresh_token: vectorStride * 2,
  authorize_par_session: vectorStride * 3,
  fapi2_par_jar_private_key_jwt_dpop: vectorStride * 4,
  same_user_refresh_token_rotation: vectorStride * 5,
  same_user_introspect_opaque_refresh_token: vectorStride * 6,
  same_user_authorize_par_session: vectorStride * 7,
  oidc_cold_login_refresh: vectorStride * 8,
  oidc_logged_in_authorization_code: vectorStride * 9,
  oidc_refresh_only: vectorStride * 10,
  fapi2_full_security: vectorStride * 11,
};

export const options = {
  summaryTrendStats: ['min', 'avg', 'med', 'p(50)', 'p(90)', 'p(95)', 'p(99)', 'max'],
  scenarios: {
    [scenario]: scenarioOptions(scenario),
  },
  thresholds: thresholds(),
};

function thresholds() {
  const base = {
    checks: ['rate>0.99'],
    http_req_failed: ['rate<0.01'],
    http_req_duration: ['p(99)<5000'],
  };
  for (const step of scenarioSteps[scenario] || []) {
    base[`http_req_duration{step:${step}}`] = ['p(99)<5000'];
    base[`http_req_failed{step:${step}}`] = ['rate<0.01'];
    base[`http_reqs{step:${step}}`] = ['count>=0'];
  }
  return base;
}

function scenarioOptions(name) {
  if (executor === 'constant-arrival-rate') {
    if (rate <= 0) {
      throw new Error('PERF_RATE must be positive when PERF_EXECUTOR=constant-arrival-rate');
    }
    return {
      executor,
      rate,
      timeUnit,
      duration,
      preAllocatedVUs: preAllocatedVus,
      maxVUs: maxVus,
      exec: name,
    };
  }
  if (name === 'token_client_credentials' || name === 'mtls_client_credentials') {
    return {
      executor: 'constant-vus',
      vus,
      duration,
      exec: name,
    };
  }
  return {
    executor: 'shared-iterations',
    vus: flowVus,
    iterations,
    maxDuration: '10m',
    exec: name,
  };
}

function form(data) {
  return Object.entries(data)
    .filter(([, value]) => value !== undefined && value !== null)
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
    .join('&');
}

function requestTags(step, extra = {}) {
  return Object.assign({ flow: scenario, step }, extra);
}

function formHeaders(extra = {}, tags = {}) {
  return {
    headers: Object.assign({ 'Content-Type': 'application/x-www-form-urlencoded' }, extra),
    redirects: 0,
    tags,
  };
}

function jsonHeaders(tags = {}) {
  return {
    headers: {
      'Content-Type': 'application/json',
    },
    redirects: 0,
    tags,
  };
}

function cookieHeaderFromResponse(response) {
  const parts = [];
  for (const [name, values] of Object.entries(response.cookies || {})) {
    if (values && values.length > 0) {
      parts.push(`${name}=${values[0].value}`);
    }
  }
  return parts.join('; ');
}

function sessionHeaders() {
  return __VU_STATE.cookieHeader ? { Cookie: __VU_STATE.cookieHeader } : {};
}

function vector() {
  const offset = vectorOffsets[scenario] || 0;
  const index = offset + exec.scenario.iterationInTest;
  if (index >= vectors.length) {
    fail(`signed vector pool exhausted at index ${index}; raise PERF_VECTOR_COUNT`);
  }
  return vectors[index];
}

function locationHeader(response) {
  return response.headers.Location || response.headers.location || '';
}

function queryParamFromLocation(location, name) {
  const marker = `${name}=`;
  const query = location.split('?')[1] || location;
  for (const part of query.split('&')) {
    if (part.startsWith(marker)) {
      return decodeURIComponent(part.slice(marker.length));
    }
  }
  return '';
}

function selectedUser(sharedUser) {
  const users = secrets.users || [secrets.user];
  if (sharedUser || users.length === 1) {
    return users[0];
  }
  const vuIndex = Math.max((exec.vu && exec.vu.idInTest ? exec.vu.idInTest : 1) - 1, 0);
  return users[vuIndex % users.length];
}

function ensureUserSession(user, cacheSession = false) {
  if (cacheSession && __VU_STATE.csrf) {
    return;
  }
  const response = http.post(
    `${BASE_URL}/auth/login`,
    JSON.stringify({
      email: user.email,
      password: user.password,
    }),
    jsonHeaders(requestTags('login', {
      endpoint: '/auth/login',
      auth_context: 'password',
    })),
  );
  check(response, {
    'login status is 200': (r) => r.status === 200,
    'login csrf cookie returned': (r) => Boolean(r.cookies.nazo_oauth_csrf && r.cookies.nazo_oauth_csrf.length),
  });
  if (response.status !== 200) {
    fail(`login failed: ${response.status} ${response.body}`);
  }
  __VU_STATE.csrf = response.cookies.nazo_oauth_csrf[0].value;
  __VU_STATE.cookieHeader = cookieHeaderFromResponse(response);
}

const __VU_STATE = {};

function oidcPar(v) {
  const body = form({
    client_id: secrets.clients.oidc,
    client_secret: secrets.client_secret,
    request: v.oidc_request,
  });
  const response = http.post(
    `${BASE_URL}/par`,
    body,
    formHeaders({}, requestTags('par_oidc', {
      endpoint: '/par',
      client_profile: 'oidc',
      request_object: 'jar',
    })),
  );
  check(response, {
    'oidc PAR status is 201': (r) => r.status === 201,
    'oidc PAR request_uri returned': (r) => Boolean(r.json('request_uri')),
  });
  if (response.status !== 201) {
    fail(`oidc PAR failed: ${response.status} ${response.body}`);
  }
  return response.json('request_uri');
}

function fapiPar(v) {
  const body = form({
    client_id: secrets.clients.fapi,
    client_assertion_type: secrets.client_assertion_type,
    client_assertion: v.fapi_par_assertion,
    request: v.fapi_request,
  });
  const response = http.post(
    `${BASE_URL}/par`,
    body,
    formHeaders({ DPoP: v.dpop_par }, requestTags('par_fapi', {
      endpoint: '/par',
      client_profile: 'fapi2',
      request_object: 'jar',
      sender_constraint: 'dpop',
    })),
  );
  check(response, {
    'fapi PAR status is 201': (r) => r.status === 201,
    'fapi PAR request_uri returned': (r) => Boolean(r.json('request_uri')),
  });
  if (response.status !== 201) {
    fail(`fapi PAR failed: ${response.status} ${response.body}`);
  }
  return response.json('request_uri');
}

function authorizePar(clientId, requestUri, user, cacheSession = false) {
  ensureUserSession(user, cacheSession);
  const response = http.get(
    `${BASE_URL}/authorize?${form({ client_id: clientId, request_uri: requestUri })}`,
    {
      headers: sessionHeaders(),
      redirects: 0,
      tags: requestTags('authorize', {
        endpoint: '/authorize',
      }),
    },
  );
  check(response, {
    'authorize returns request id redirect': (r) => r.status === 302 && Boolean(queryParamFromLocation(locationHeader(r), 'request_id')),
  });
  const requestId = queryParamFromLocation(locationHeader(response), 'request_id');
  if (response.status !== 302 || !requestId) {
    fail(`authorize failed: ${response.status} ${locationHeader(response)} ${response.body}`);
  }
  return requestId;
}

function approveAuthorization(requestId, expectedState) {
  const response = http.post(
    `${BASE_URL}/authorize/decision`,
    form({
      request_id: requestId,
      decision: 'approve',
      csrf_token: __VU_STATE.csrf,
    }),
    formHeaders(sessionHeaders(), requestTags('authorize_decision', {
      endpoint: '/authorize/decision',
    })),
  );
  const location = locationHeader(response);
  check(response, {
    'authorization decision returns code redirect': (r) => r.status === 302 && location.includes('code='),
    'authorization state roundtrips': () => location.includes(`state=${encodeURIComponent(expectedState)}`),
  });
  if (response.status !== 302) {
    fail(`authorization decision failed: ${response.status} ${response.body}`);
  }
  return queryParamFromLocation(location, 'code');
}

function tokenAuthorizationCode(v, code) {
  const response = http.post(
    `${BASE_URL}/token`,
    form({
      grant_type: 'authorization_code',
      client_id: secrets.clients.oidc,
      client_secret: secrets.client_secret,
      code,
      redirect_uri: secrets.redirect_uri,
      code_verifier: v.pkce_verifier,
    }),
    formHeaders({}, requestTags('token_authorization_code', {
      endpoint: '/token',
      grant_type: 'authorization_code',
      client_profile: 'oidc',
    })),
  );
  check(response, {
    'authorization_code token status is 200': (r) => r.status === 200,
    'authorization_code refresh token returned': (r) => Boolean(r.json('refresh_token')),
  });
  if (response.status !== 200) {
    fail(`authorization_code token failed: ${response.status} ${response.body}`);
  }
  return response.json();
}

function fapiTokenAuthorizationCode(v, code) {
  const response = http.post(
    `${BASE_URL}/token`,
    form({
      grant_type: 'authorization_code',
      code,
      redirect_uri: secrets.redirect_uri,
      code_verifier: v.fapi_pkce_verifier,
      client_assertion_type: secrets.client_assertion_type,
      client_assertion: v.fapi_token_assertion,
    }),
    formHeaders({ DPoP: v.dpop_token }, requestTags('fapi_token_authorization_code', {
      endpoint: '/token',
      grant_type: 'authorization_code',
      client_profile: 'fapi2',
      client_auth: 'private_key_jwt',
      sender_constraint: 'dpop',
    })),
  );
  check(response, {
    'fapi authorization_code token status is 200': (r) => r.status === 200,
    'fapi token is DPoP-bound': (r) => r.json('token_type') === 'DPoP',
    'fapi refresh token returned': (r) => Boolean(r.json('refresh_token')),
  });
  if (response.status !== 200) {
    fail(`fapi authorization_code token failed: ${response.status} ${response.body}`);
  }
  return response.json();
}

export function token_client_credentials() {
  const response = http.post(
    `${BASE_URL}/token`,
    form({
      grant_type: 'client_credentials',
      client_id: secrets.clients.client_credentials,
      client_secret: secrets.client_secret,
      scope: 'profile',
    }),
    formHeaders({}, requestTags('token_client_credentials', {
      endpoint: '/token',
      grant_type: 'client_credentials',
      client_auth: 'client_secret_post',
    })),
  );
  check(response, {
    'client_credentials status is 200': (r) => r.status === 200,
    'client_credentials access token returned': (r) => Boolean(r.json('access_token')),
  });
}

export function token_only_client_credentials() {
  token_client_credentials();
}

export function mtls_client_credentials() {
  const response = http.post(
    `${BASE_URL}/token`,
    form({
      grant_type: 'client_credentials',
      client_id: secrets.clients.mtls,
      scope: 'profile',
    }),
    formHeaders({
      'x-ssl-client-verify': 'SUCCESS',
      'x-forwarded-tls-client-cert-sha256': secrets.mtls_thumbprint,
      'x-ssl-client-subject-dn': 'CN=perf-mtls',
    }, requestTags('mtls_client_credentials', {
      endpoint: '/token',
      grant_type: 'client_credentials',
      client_auth: 'tls_client_auth',
      sender_constraint: 'mtls',
    })),
  );
  check(response, {
    'mtls client_credentials status is 200': (r) => r.status === 200,
    'mtls client_credentials access token returned': (r) => Boolean(r.json('access_token')),
  });
}

export function introspect_opaque_refresh_token() {
  introspectOpaqueRefreshToken(false);
}

function introspectOpaqueRefreshToken(sharedUser) {
  const user = selectedUser(sharedUser);
  const v = vector();
  const requestUri = oidcPar(v);
  const requestId = authorizePar(secrets.clients.oidc, requestUri, user);
  const code = approveAuthorization(requestId, v.oidc_state);
  const tokens = tokenAuthorizationCode(v, code);
  const response = http.post(
    `${BASE_URL}/introspect`,
    form({
      token: tokens.refresh_token,
      client_id: secrets.clients.oidc,
      client_secret: secrets.client_secret,
    }),
    formHeaders({}, requestTags('introspect', {
      endpoint: '/introspect',
      token_type: 'opaque_refresh_token',
      client_profile: 'oidc',
    })),
  );
  check(response, {
    'refresh token introspection status is 200': (r) => r.status === 200,
    'refresh token introspection active': (r) => r.json('active') === true,
  });
}

export function refresh_token_rotation() {
  refreshTokenRotation(false);
}

function refreshTokenRotation(sharedUser) {
  const user = selectedUser(sharedUser);
  const v = vector();
  const requestUri = oidcPar(v);
  const requestId = authorizePar(secrets.clients.oidc, requestUri, user);
  const code = approveAuthorization(requestId, v.oidc_state);
  const tokens = tokenAuthorizationCode(v, code);
  const response = http.post(
    `${BASE_URL}/token`,
    form({
      grant_type: 'refresh_token',
      client_id: secrets.clients.oidc,
      client_secret: secrets.client_secret,
      refresh_token: tokens.refresh_token,
    }),
    formHeaders({}, requestTags('token_refresh', {
      endpoint: '/token',
      grant_type: 'refresh_token',
      client_profile: 'oidc',
    })),
  );
  check(response, {
    'refresh_token rotation status is 200': (r) => r.status === 200,
    'refresh_token rotation returns new refresh token': (r) => Boolean(r.json('refresh_token')),
  });
}

export function oidc_cold_login_refresh() {
  refreshTokenRotation(false);
}

export function oidc_logged_in_authorization_code() {
  const user = selectedUser(false);
  const v = vector();
  const requestUri = oidcPar(v);
  const requestId = authorizePar(secrets.clients.oidc, requestUri, user, true);
  const code = approveAuthorization(requestId, v.oidc_state);
  tokenAuthorizationCode(v, code);
}

function bootstrapRefreshToken() {
  const user = selectedUser(false);
  const v = vector();
  const requestUri = oidcPar(v);
  const requestId = authorizePar(secrets.clients.oidc, requestUri, user, true);
  const code = approveAuthorization(requestId, v.oidc_state);
  const tokens = tokenAuthorizationCode(v, code);
  __VU_STATE.refreshToken = tokens.refresh_token;
}

export function oidc_refresh_only() {
  if (!__VU_STATE.refreshToken) {
    bootstrapRefreshToken();
  }
  const response = http.post(
    `${BASE_URL}/token`,
    form({
      grant_type: 'refresh_token',
      client_id: secrets.clients.oidc,
      client_secret: secrets.client_secret,
      refresh_token: __VU_STATE.refreshToken,
    }),
    formHeaders({}, requestTags('token_refresh', {
      endpoint: '/token',
      grant_type: 'refresh_token',
      client_profile: 'oidc',
      load_model: 'refresh_only',
    })),
  );
  check(response, {
    'refresh-only rotation status is 200': (r) => r.status === 200,
    'refresh-only rotation returns new refresh token': (r) => Boolean(r.json('refresh_token')),
  });
  if (response.status !== 200) {
    fail(`refresh-only token failed: ${response.status} ${response.body}`);
  }
  __VU_STATE.refreshToken = response.json('refresh_token');
}

export function par_signed_request_object() {
  oidcPar(vector());
}

export function authorize_par_session() {
  authorizeParSession(false);
}

function authorizeParSession(sharedUser) {
  const user = selectedUser(sharedUser);
  const v = vector();
  const requestUri = oidcPar(v);
  const requestId = authorizePar(secrets.clients.oidc, requestUri, user);
  check({ requestId }, {
    'authorize PAR session request id returned': (value) => Boolean(value.requestId),
  });
}

export function fapi2_par_jar_private_key_jwt_dpop() {
  const user = selectedUser(false);
  const v = vector();
  const requestUri = fapiPar(v);
  const requestId = authorizePar(secrets.clients.fapi, requestUri, user);
  const code = approveAuthorization(requestId, v.fapi_state);
  const tokens = fapiTokenAuthorizationCode(v, code);
  const response = http.post(
    `${BASE_URL}/token`,
    form({
      grant_type: 'refresh_token',
      refresh_token: tokens.refresh_token,
      client_assertion_type: secrets.client_assertion_type,
      client_assertion: v.fapi_refresh_assertion,
    }),
    formHeaders({ DPoP: v.dpop_refresh }, requestTags('fapi_token_refresh', {
      endpoint: '/token',
      grant_type: 'refresh_token',
      client_profile: 'fapi2',
      client_auth: 'private_key_jwt',
      sender_constraint: 'dpop',
    })),
  );
  check(response, {
    'fapi DPoP refresh status is 200': (r) => r.status === 200,
    'fapi DPoP refresh returns DPoP token': (r) => r.json('token_type') === 'DPoP',
  });
  if (response.status !== 200) {
    fail(`fapi refresh failed: ${response.status} ${response.body}`);
  }
}

export function fapi2_full_security() {
  fapi2_par_jar_private_key_jwt_dpop();
}

export function same_user_refresh_token_rotation() {
  refreshTokenRotation(true);
}

export function same_user_introspect_opaque_refresh_token() {
  introspectOpaqueRefreshToken(true);
}

export function same_user_authorize_par_session() {
  authorizeParSession(true);
}

export default function () {
  fail('PERF_SCENARIO must select a named scenario exec function');
}
