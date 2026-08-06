# External audit-ledger anchoring

NazoAuth persists security events in the append-only `security_audit_events`
ledger and its durable outbox.  An independent `nazoauth audit-anchor-worker`
(or equivalent sidecar) claims that outbox in bounded batches and sends one
checkpoint per event to `AUDIT_ANCHOR_URL` over HTTPS.  The server process does
not run this exporter and does not receive its database role or sink secret.

Each request contains the checkpoint schema `nazo.audit.anchor.v1` and these
fields:

* `event_id` (also the `Idempotency-Key`);
* `deployment_id`, `sequence`, `previous_hash`, and `event_hash`;
* `event_type`, `event_category`, `payload`, and `occurred_at`.

The signed body is immutable for a given outbox row. The delivery timestamp is
carried separately in `X-Nazo-Audit-Sent-At`, so retries reuse the same body,
signature, and idempotency key. The empty ledger uses a stable
`genesis:<deployment_id>` idempotency key and an explicit `checkpoint_kind` of
`genesis`.

The receiver must recompute the BLAKE3 event hash before accepting a
checkpoint. The hash input is `nazo.audit.v1\0`, big-endian sequence, previous
hash, UUID bytes, length-prefixed UTF-8 event type and category, big-endian
microsecond timestamp, and length-prefixed PostgreSQL `jsonb::text` payload.
This makes the independent receiver, rather than the database writer alone,
the final authority for hash-chain validity.

The worker authenticates the exact JSON body with HMAC-SHA-256 in
`X-Nazo-Audit-Signature: sha256=<base64url>`. Only a 2xx response acknowledges
the outbox row; an idempotent receiver must return 2xx for a replay rather than
an ambiguous conflict response.
Transport and non-success responses are rescheduled with bounded exponential
backoff.  The response body is never logged, and the HMAC secret is never
included in logs or the checkpoint.

The worker atomically writes `AUDIT_ANCHOR_STATUS_FILE` with schema
`nazo.audit.anchor.health.v1`.  It records the observed ledger head, pending
outbox count, oldest pending event, last anchored sequence/hash, observation
time, and delivery lag.  In `AUDIT_ANCHOR_MODE=required`, high-impact
management preflight fails closed unless the status is recent, has no pending
outbox entries, and the recorded last anchor equals the observed ledger head.
The server also reads the current head through its writer-only database API and
requires an exact match, so a stale-but-recent status file cannot hide a newer
pending event. An empty ledger is represented by a signed, externally accepted
genesis checkpoint before required mode becomes ready.
`optional` records health without blocking; `disabled` is an explicit
development setting and provides no protection against a privileged local
attacker.

Delivery is deliberately strict and ordered: a permanently rejected earliest
checkpoint blocks later checkpoints. Operators must alert on `audit.anchor`
retries and repair the receiver contract or credentials. There is no skip/DLQ
operation because skipping would make a later external chain look complete
when it is not.

Recommended production separation:

* give the server writer role only ledger append/check-availability rights;
* give the worker exporter role only outbox claim/ack/health rights;
* provide the worker `AUDIT_ANCHOR_DATABASE_URL` and `AUDIT_ANCHOR_TOKEN` (or
  its secret-file form), while the server receives only the preflight status
  path and deployment identity;
* protect the HTTPS receiver with append-only/WORM retention and verify its
  idempotency behavior independently.

This repository contains the worker protocol and local health/preflight logic;
it does not prove a deployed receiver's WORM guarantees, cross-host
availability, or real external acceptance.  Those require a deployment-level
probe and an independent receiver audit.

Worker configuration also includes `AUDIT_ANCHOR_MODE`, `DEPLOYMENT_ID`,
`AUDIT_ANCHOR_URL`, `AUDIT_ANCHOR_STATUS_FILE`, polling/request/freshness/lag
durations, bounded batch size, a positive lock timeout, and an optional
`AUDIT_ANCHOR_DATABASE_MAX_CONNECTIONS`. The server must never receive the
worker database URL or sink token.
