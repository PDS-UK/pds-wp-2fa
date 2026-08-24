# Persistence and migration boundaries for security records

**Decision ticket:** [#8 — Define persistence and migration boundaries for security records](https://github.com/PDS-UK/pds-wp-2fa/issues/8)

**Parent:** [#1 — PDS WP 2FA Wayfinder Map](00-wayfinder-map.md)

**Decision date:** 2026-08-24

This is the implementation contract for the single-site phase-one persistence
layer. It is aligned with [#5 role policy](05-role-policy.md), [#11 method
lifecycle](11-method-lifecycle.md), [#12 installation identity](12-installation-identity.md),
and the closed [#6 cryptographic primitive decision](https://github.com/PDS-UK/pds-wp-2fa/issues/6).

## Decisions and resolved boundaries

1. Security state uses dedicated, prefixed InnoDB tables. It is never stored in
   user meta, transients, the object cache, or `wp_options`.
2. Every security row carries the current `installation_identity_hash` and
   `installation_epoch` from #12. Repositories must include both values in
   every read, update, and delete predicate.
3. The physical `challenges` table is the persistence form of #11’s
   `auth_interaction`. It stores the one-time interaction reference, generic
   server challenge, provider state, and WebAuthn allow-list snapshot in one
   row; a second WebAuthn-only challenge table would create two consumption
   authorities.
4. #5’s `site_id` remains on role-policy records for exact alignment, but the
   phase-one resolver accepts only the current single site. It is not a second
   installation identity.
5. SQL foreign keys are not used in phase one. WordPress tables can use a
   caller-selected prefix and are not plugin-owned lifecycle tables; `dbDelta()`
   is also a schema-diff helper rather than a relational migration framework.
   The repository layer therefore enforces foreign-key-like invariants inside
   transactions, with binding columns repeated on every reference.
6. `dbDelta()` is used for additive, idempotent DDL only. Security transitions
   use explicit InnoDB transactions and conditional updates. A schema migration
   is never treated as part of an authentication transaction.

## Storage conventions

- The physical name of each table is `$wpdb->prefix . 'pds_wp_2fa_' . $suffix`.
  The prefix is read from `$wpdb->prefix`; no table name is accepted from a
  request. Every table uses `$wpdb->get_charset_collate()` and `ENGINE=InnoDB`.
- All timestamps are UTC server timestamps stored as `datetime`. The injected
  clock is the authority; database time is not used to resolve policy deadlines.
- `installation_identity_hash` is `binary(32)` and `installation_epoch` is
  `bigint(20) unsigned`. The raw installation identity is never a column.
- Opaque IDs are 16 random bytes (`binary(16)`). WordPress session-token
  digests are 32 raw HMAC-SHA-256 bytes using the configured WordPress auth
  salt; interaction-reference and rate-bucket digests are 32 raw SHA-256
  bytes. None is user-visible.
- WordPress user IDs use `bigint(20) unsigned`. Role keys and labels use
  bounded `varchar(191)` fields. Provider payloads use typed provider tables or
  a versioned provider-owned payload; the core never interprets an unversioned
  provider blob.
- SQL values go through `$wpdb->prepare()` or the typed `$wpdb` write helpers.
  Identifiers are selected from the fixed table map. A failed query is an error,
  not a successful zero-row state.

## Table contract

The following names are suffixes after the required `pds_wp_2fa_` prefix.
`PK` means the listed columns form the primary key; all keys shown are required.

### Installation and migration metadata

#### `installations`

| Columns | Keys and rules |
| --- | --- |
| `installation_id tinyint(3) unsigned` (always `1`); `identity_hash binary(32)`; `identity_epoch bigint(20) unsigned`; `environment_type varchar(16)`; `global_enforcement tinyint(1)`; `audit_retention_days smallint(5) unsigned`; `bound_at datetime`; `updated_at datetime`; `schema_version int(10) unsigned` | `PK (installation_id)`; `KEY identity_epoch (identity_hash, identity_epoch)`; `KEY environment_type (environment_type)`. There is exactly one row. `identity_epoch` starts at 1 and increases on init, rebind, and rotation. `global_enforcement` defaults on and `audit_retention_days` defaults to 400, with a permitted range of 400–2555. The row is the recorded binding and configuration authority, never the deployment-secret authority. |

`installations.identity_hash` is the same fingerprint `F` that every other
security table names `installation_identity_hash`; the two names are not two
different identities. The singleton `installation_id` is only a row key and is
never used as an authenticator or WebAuthn binding.

#### `schema_versions`

This is migration metadata, not security state, so it intentionally has no
installation binding columns and may exist before `identity init`. It contains
one row with `migration_key varchar(64)`, `schema_version int(10) unsigned`,
`state varchar(16)` (`ready` or `failed`), `updated_at datetime`, and a safe
`last_error_code varchar(64) NULL`.

`PK (migration_key)` is required. A failed or incomplete migration leaves
`state = failed`; the plugin does not read or write security records until the
ledger is `ready` at the code’s required version.

#### `maintenance_leases`

Retention and cleanup jobs use one binding-scoped lease rather than relying on
cron's at-most-once behavior. The row contains `lease_key varchar(64)`, binding
columns, `owner_token_hash binary(32)`, `cursor_created_at datetime NULL`,
`cursor_event_id binary(16) NULL`, `acquired_at datetime`, `expires_at
datetime`, and `updated_at datetime`.

`PK (installation_identity_hash, installation_epoch, lease_key)` and `KEY
lease_expiry (installation_identity_hash, installation_epoch, expires_at)` are
required. Acquisition is a conditional update/insert; an expired lease may be
reclaimed. The cursor is advisory progress only: every deletion still checks
retention, binding, and row status. A failed job leaves the cursor safe to
retry.

### Role policy and deadlines

#### `role_policies`

Columns: `role_policy_id binary(16)`, binding columns, `site_id bigint(20)
unsigned`, `role_key varchar(191)`, `current_role_label varchar(191)`,
`status varchar(16)`, `enabled_configuration tinyint(1)`,
`grace_period_seconds bigint(20) unsigned`, nullable `activated_at`,
`discovered_at`, nullable `last_seen_at`, `created_at`, and `updated_at`.

Keys: `PK (installation_identity_hash, installation_epoch, role_policy_id)`;
`UNIQUE KEY role_identity (installation_identity_hash, installation_epoch,
site_id, role_key)`; `KEY role_status (installation_identity_hash,
installation_epoch, site_id, status)`.

`role_key`, not the label or capabilities, is the policy identity. Discovery
creates a disabled row. Orphaning, reappearance, enable/disable, immutable
`activated_at`, and label snapshots follow #5 exactly.

#### `user_role_policies`

Columns: `user_role_policy_id binary(16)`, binding columns, `site_id`, `user_id`,
`role_policy_id binary(16)`, `role_key varchar(191)`, `first_observed_at`,
immutable `affected_since`, `created_at`, and `updated_at`.

Keys: `PK (installation_identity_hash, installation_epoch,
user_role_policy_id)`; `UNIQUE KEY user_role_policy (installation_identity_hash,
installation_epoch, site_id, user_id, role_policy_id)`; `KEY user_roles
(installation_identity_hash, installation_epoch, site_id, user_id)`.

The repository may insert the anchor once, but must never update
`affected_since` during role churn, policy toggles, label changes, or repeated
discovery. The referenced role policy and duplicated `role_key` must match in
the same binding and site.

#### `enrollment_cycles`

Columns: `cycle_id binary(16)`, binding columns, `user_id`, `status varchar(16)`
(`open`, `completed`, or `reset`), nullable `current_marker char(1)`,
`started_at`, nullable `completed_at`, nullable `reset_at`, `created_at`, and
`updated_at`.

Keys: `PK (installation_identity_hash, installation_epoch, cycle_id)`;
`UNIQUE KEY current_cycle (installation_identity_hash, installation_epoch,
user_id, current_marker)`; `KEY user_cycles (installation_identity_hash,
installation_epoch, user_id, status)`.

Only the open cycle has `current_marker = 'Y'`; historical rows have `NULL`,
which permits history while enforcing one current cycle under InnoDB. Enrollment
success closes the cycle. An explicit reset creates a new cycle and never
inherits an old extension.

#### `deadline_extensions`

Columns: `extension_id binary(16)`, binding columns, `cycle_id`, `user_id`,
absolute `granted_until`, `granted_at`, `granted_by bigint(20) unsigned NULL`,
`granted_source varchar(16)`, `reason varchar(255)`,
`previous_effective_deadline datetime`, `new_effective_deadline datetime`,
nullable `revoked_at`, nullable `revoked_by`, nullable `revocation_reason`, and
`created_at`.

Keys: `PK (installation_identity_hash, installation_epoch, extension_id)`;
`KEY current_extensions (installation_identity_hash, installation_epoch,
user_id, cycle_id, granted_until)`.

Rows are append-only except explicit revocation metadata. A grant is valid only
for its current cycle, is never a duration to be recalculated, and cannot move
the current effective deadline earlier.

### Authenticators and provider data

#### `methods` (the `auth_method` record from #11)

Columns: `method_id binary(16)`, binding columns, `user_id`,
`provider_key varchar(32)`, `provider_schema_version int(10) unsigned`,
`label varchar(191)`, `status varchar(16)` (`active`, `exhausted`, or
`revoked`), `created_at`, `updated_at`, nullable `last_used_at`, nullable
`revoked_at`, nullable `revoked_by`, nullable `revoked_reason`, and
`revision bigint(20) unsigned`.

Keys: `PK (installation_identity_hash, installation_epoch, method_id)`;
`KEY user_methods (installation_identity_hash, installation_epoch, user_id,
status, provider_key)`.

Labels are not unique and never affect verification. `revision` increases on
provider-state or lifecycle changes. A revoked or exhausted method is terminal.

#### `method_totp`

Columns: binding columns, `method_id`, nullable `secret_envelope varbinary(255)`,
`envelope_version int(10) unsigned`, `encryption_key_version varchar(64)`,
`algorithm varchar(16)`, `digits smallint(5) unsigned`,
`period_seconds int(10) unsigned`, `t0 bigint(20)`, nullable
`last_accepted_step bigint(20)`, `created_at`, and `updated_at`.

`PK (installation_identity_hash, installation_epoch, method_id)` and
`KEY method_totp_lookup (installation_identity_hash, installation_epoch,
method_id)` are required. The phase-one #6 profile is recorded per method:
20-byte secret, HMAC-SHA-1, six digits, `T0 = 0`, 30 seconds, and an acceptance
window of at most ±1. The secret envelope is authenticated and deployment-key
versioned; plaintext never reaches this table.

#### `method_webauthn`

Columns: binding columns, `method_id`, `user_id`, `credential_id varbinary(1024)`,
`user_handle varbinary(64)`, `public_key longblob`, `rp_id varchar(255)`,
`transports varchar(255) NULL`, `aaguid binary(16) NULL`,
`signature_counter bigint(20) unsigned`, `backup_eligible tinyint(1) NULL`,
`backup_state tinyint(1) NULL`, `credential_revision bigint(20) unsigned`,
`created_at`, and `updated_at`.

Keys: `PK (installation_identity_hash, installation_epoch, method_id)`;
`UNIQUE KEY credential_identity (installation_identity_hash,
installation_epoch, credential_id)`; `KEY user_credentials
(installation_identity_hash, installation_epoch, user_id)`.

The credential is public data; private keys never enter the database. The RP ID
and origin remain domain policy, not installation identity. Counter changes use
the method/credential revision as a compare-and-swap guard.

#### `recovery_generations`

Columns: `generation_id binary(16)`, binding columns, `user_id`, `method_id`,
`status varchar(16)` (`active`, `exhausted`, or `revoked`), nullable
`active_marker char(1)`, `created_at`, nullable `exhausted_at`, nullable
`revoked_at`, and `updated_at`.

Keys: `PK (installation_identity_hash, installation_epoch, generation_id)`;
`UNIQUE KEY active_generation (installation_identity_hash,
installation_epoch, user_id, active_marker)`; `KEY user_generations
(installation_identity_hash, installation_epoch, user_id, status)`.

Only the active row has `active_marker = 'Y'`; old generations have `NULL`.
There is at most one active recovery generation per user and binding. Its method
must be the matching `recovery` row in `methods`.

#### `recovery_codes`

Columns: `code_id binary(16)`, binding columns, `generation_id`, `user_id`,
`code_verifier varchar(255) NULL`, `created_at`, nullable `used_at`, and
nullable `revoked_at`.

Keys: `PK (installation_identity_hash, installation_epoch, code_id)`;
`KEY generation_codes (installation_identity_hash, installation_epoch,
generation_id, used_at, revoked_at)`.

There are exactly ten independent rows per newly generated generation. Each
active row contains one `password_hash()` result for one 128-bit code. Plaintext,
the displayed bundle, and the candidate code are never stored. A successful use
is `UPDATE ... WHERE code_id = ? AND used_at IS NULL AND revoked_at IS NULL`
inside the verification transaction; exactly one affected row is required.

### Challenges, sessions, and abuse controls

#### `challenges` (the physical `auth_interaction` table)

Columns: `interaction_id_hash binary(32)`, binding columns, `user_id`,
`session_token_hash binary(32)`, `purpose varchar(32)`,
`provider_key varchar(32)`, nullable `method_id`, nullable
`allowed_method_ids longtext`, `server_challenge varbinary(64)`, nullable
`provider_state longblob`, `provider_state_version int(10) unsigned`,
`created_at`, `expires_at`, nullable `consumed_at`, nullable `revoked_at`, and
`attempt_count int(10) unsigned`.

Keys: `PK (installation_identity_hash, installation_epoch,
interaction_id_hash)`; `UNIQUE KEY server_challenge (installation_identity_hash,
installation_epoch, server_challenge)`; `KEY session_challenges
(installation_identity_hash, installation_epoch, user_id,
session_token_hash, expires_at)`; `KEY challenge_expiry
(installation_identity_hash, installation_epoch, expires_at)`.

`interaction_id_hash` is the hash of a fresh opaque browser reference. The
server creates at least 32 random challenge bytes. `allowed_method_ids` is a
versioned, canonical snapshot of method IDs, not a client-selected list.
`provider_state` is provider-owned and versioned; a pending TOTP secret is an
authenticated encrypted envelope, not plaintext. Authentication interactions
expire in five minutes; enrollment, rotation, and recovery-regeneration
interactions expire in ten minutes. A row is consumed only after provider
verification and provider-state CAS updates succeed.

#### `sessions`

Columns: binding columns, `user_id`, `session_token_hash binary(32)`,
`state varchar(32)` (`pending`, `satisfied`, or `invalidated`), `created_at`,
`updated_at`, `wordpress_expires_at`, nullable
`satisfied_at`, and nullable `invalidated_at`.

Keys: `PK (installation_identity_hash, installation_epoch, user_id,
session_token_hash)`; `KEY token_lookup (installation_identity_hash,
installation_epoch, session_token_hash)`; `KEY user_session_state
(installation_identity_hash, installation_epoch, user_id, state)`.

The token is only represented by its hash. A new WordPress login always inserts
or reconciles a new pending row. No user-level “completed” flag can satisfy a
new token. `enrollment_required` is a derived enforcement mode, not a
persisted session state; resolve it from current role policy, enrollment cycle,
and clock while the session remains `pending`.

#### `admin_reauth_grants`

Columns: `grant_id_hash binary(32)`, binding columns, `user_id`,
`session_token_hash binary(32)`, `scope varchar(32)`, `issued_at`,
`expires_at`, nullable `consumed_at`, and `created_at`.

`PK (installation_identity_hash, installation_epoch, grant_id_hash)`;
`KEY grant_session (installation_identity_hash, installation_epoch, user_id,
session_token_hash, scope, expires_at)`; and `KEY grant_expiry
(installation_identity_hash, installation_epoch, expires_at)` are required.
The grant is issued only after fresh WordPress password re-authentication,
expires within ten minutes, is scoped to one operation family, and is never
accepted for another user, session, binding, or scope. Emergency grants are
single-use; ordinary scopes may be reused only until expiry as defined by #10.

#### `rate_limits`

Columns: `bucket_key_hash binary(32)`, binding columns, `bucket_type varchar(32)`,
nullable `user_id`, nullable `provider_key varchar(32)`, nullable `method_id`,
nullable `network_key_hash binary(32)`, `window_started_at`, `window_ends_at`,
`failure_count int(10) unsigned`, nullable `blocked_until`, and `updated_at`.

Keys: `PK (installation_identity_hash, installation_epoch,
bucket_key_hash)`; `KEY rate_user (installation_identity_hash,
installation_epoch, user_id, provider_key, method_id)`; `KEY rate_expiry
(installation_identity_hash, installation_epoch, window_ends_at)`.

`bucket_key_hash` is derived from canonical rate dimensions. It must not contain
the session token, raw IP address, code, challenge, or credential input. At
minimum, user/provider and installation-wide buckets survive across browser
sessions so a new session cannot reset a failure budget. The phase-one limiter
has these normative buckets and thresholds:

| Bucket | Failures counted | Window and response |
| --- | --- | --- |
| user + provider | Invalid factor, replay, unknown/revoked method, or stale provider proof | Five-minute window; 5 failures blocks 30 seconds, 10 blocks 5 minutes, 20 blocks 1 hour (one-hour cap). |
| user + provider + network | The same failures, using a keyed network digest | Five-minute window; 10 failures blocks 30 seconds, 20 blocks 5 minutes, 40 blocks 1 hour. |
| installation + provider | The same failures across users | Five-minute window; 100 failures blocks that provider for 60 seconds as a circuit breaker. |

The most restrictive active bucket wins. A valid factor, WebAuthn user
cancellation, invalid nonce, expired interaction, and primary-password failure
do not increment these buckets. Invalid proof outcomes increment the relevant
buckets with an atomic conditional upsert; a rate-limited response is HTTP 429
for HTML/REST and uses the fixed route error code. Counters expire after the
window and blocked-until time; a new browser session never resets them.

### Audit

#### `audit_events`

Columns: `event_id binary(16)`, binding columns, `event_type varchar(64)`,
`severity varchar(16)`, `actor_kind varchar(16)`, nullable `actor_user_id`,
nullable `subject_user_id`, nullable `role_key varchar(191)`, nullable
`method_id`, `source varchar(16)`, `outcome varchar(16)`, nullable
`reason_code varchar(32)`, `safe_metadata longtext`, `schema_version int(10)
unsigned`, nullable `correlation_id_hash binary(32)`, `created_at datetime`,
and `retained_until`.

Keys: `PK (installation_identity_hash, installation_epoch, event_id)`;
`KEY audit_time (installation_identity_hash, installation_epoch, created_at)`;
`KEY audit_subject (installation_identity_hash, installation_epoch,
subject_user_id, created_at)`; `KEY audit_type (installation_identity_hash,
installation_epoch, event_type, created_at)`; `KEY audit_actor
(installation_identity_hash, installation_epoch, actor_kind, actor_user_id,
created_at)`.

The stream is append-only except retention purge. `safe_metadata` is a bounded,
validated allow-list of diagnostic fields. It must not contain passwords,
secrets, recovery verifiers, submitted codes, raw challenges, WebAuthn response
data, private keys, decryption keys, or session tokens.

## Durability and retention boundary

| Data | Authority and default retention |
| --- | --- |
| Installation binding; role policies; user-role anchors; enrollment cycles and extension history | Durable authority. Never automatically purge. Rebind/rotation changes the binding and epoch; it does not rewrite imported rows. |
| Active methods and provider records; revoked method tombstones | Durable authority and race/audit history. Retain tombstones indefinitely; set revoked TOTP ciphertext to `NULL` when policy permits. |
| Recovery generations and code rows | Generation/tombstone rows are durable. Erase `code_verifier` from used/revoked rows after 30 days, while retaining status/timestamps; active verifiers remain until use or revocation. |
| Challenges/interactions | Operationally ephemeral. Reject by status/expiry even before cleanup; erase provider state and delete expired rows 24 hours after `expires_at`. |
| Session state | Operationally ephemeral. Invalidate on logout, WordPress session destruction, rebind, and rotation; delete 24 hours after invalidation or `wordpress_expires_at`. |
| Rate-limit buckets | Operationally ephemeral. Delete 24 hours after `window_ends_at` and `blocked_until`, whichever is later. Failures remain represented only by the audit policy where appropriate. |
| Audit events | Durable append-only audit for at least 400 days by default. `retained_until` is set at insertion; deployments may increase, but not shorten, this minimum. |

Cleanup is background work (cron or CLI), never the security decision. It uses
the same binding predicate and only deletes rows proven expired. A copied row
that has a foreign binding is never revived by cleanup or rebind.

## Foreign-key-like invariants

Repositories must enforce these before any provider or session success:

1. Every parent and child reference has equal binding hash and epoch; a matching
   user ID, method ID, credential ID, role key, or challenge alone is invalid.
2. A role-policy reference matches the same `site_id` and exact `role_key`.
   Only currently discovered active policies contribute to enforcement.
3. A cycle belongs to the same user and binding as every extension. Only its
   current open row can receive a new grant.
4. A provider row has exactly one matching active `methods` row and its
   `provider_key`; a recovery generation has one matching recovery method.
5. A WebAuthn credential ID is unique within `(identity_hash, epoch)` and its
   user and method agree. RP ID/origin checks remain separate protocol policy.
6. A challenge’s user, session-token hash, purpose, provider, method, method
   snapshot, expiry, and binding must match the server context. A challenge
   cannot reference a revoked/exhausted method.
7. A session state is valid only for its exact token hash and current binding.
   `satisfied` is never copied to another row.
8. A rate bucket is independent of the session token and has no raw network or
   credential material.
9. Audit references are informational and may outlive purged operational rows;
   audit insertion must not make a security transition succeed if it fails.

## Transaction and atomic-consumption rules

All security tables must be InnoDB. The transaction manager uses
`START TRANSACTION`, `COMMIT`, and `ROLLBACK` through `$wpdb->query()` and
checks every return value. It locks the current binding row and relevant parent
rows with `SELECT ... FOR UPDATE` where a decision depends on a count or status.

- **Login/session creation:** insert the pending session with the current
  binding and exact session-token hash. Duplicate insertion reconciles only the
  same user/token row; it never reuses another session’s state.
- **Challenge verification:** perform cheap binding and rate checks first. After
  provider verification, start a transaction, re-read/lock the challenge,
  session, method, and provider row, re-check expiry/status/revision, then
  conditionally update provider state, mark the challenge consumed, update
  `last_used_at`/revision, set only that session to `satisfied`, and insert the
  redacted audit event. Any conflict rolls back and leaves the session pending.
- **TOTP:** require `matched_step > last_accepted_step` in the same transaction;
  the conditional update must affect exactly one row.
- **WebAuthn:** update the credential record and counter only when its stored
  `credential_revision` still matches. A stale CAS is a failed verification,
  not a second success.
- **Recovery:** conditionally mark exactly one `recovery_codes` row used; if it
  was the last unused row, mark its generation exhausted in the same transaction.
  The current session may remain satisfied, but future sessions cannot use that
  generation.
- **Enrollment/rotation:** create provider rows, consume the interaction, and
  append the audit event in one transaction. Replacement activates the new
  method before revoking the old final method. Recovery regeneration revokes
  every old code before the new plaintext bundle is returned after commit.
- **Policy changes/extensions:** lock the role/cycle rows, calculate the old and
  new deadline from immutable anchors, write the new state and audit event in
  one transaction. Extensions are absolute timestamps.
- **Identity init/rebind/rotation:** run only through the explicit CLI boundary.
  Lock `installations`, verify the current configuration/environment, change the
  binding and increment the epoch, revoke/expire challenges and sessions, and
  invalidate recovery credentials as required by #12. Existing authenticator
  rows keep their old binding and remain foreign; no row is rewritten to the new
  fingerprint.

No provider may mark success before this commit. A commit failure, failed audit
insert, stale revision, or affected-row count other than the expected value is
an error and cannot return a successful authentication response.

## Schema-version migrations and `dbDelta()` constraints

1. Derive all table names from `$wpdb->prefix`, load
   `wp-admin/includes/upgrade.php`, and run canonical `CREATE TABLE` statements
   through `dbDelta()`. Each field is on its own line; types are lowercase;
   SQL keywords are uppercase; `KEY` (not `INDEX`) is used; key names and
   lengths are explicit; and `PRIMARY KEY  (...)` has the spacing expected by
   `dbDelta()`. Do not quote field names with apostrophes or backticks in the
   canonical DDL.
2. The migration runner compares the code schema version with
   `schema_versions`, runs additive `dbDelta()` changes, then performs explicit
   idempotent data backfills in bounded batches. It verifies `DESCRIBE` and
   `SHOW INDEX` results before setting the ledger to `ready`.
3. `dbDelta()` does not provide a safe destructive migration plan. Never depend
   on it to drop columns, rename data, remove obsolete indexes, or add a unique
   constraint to dirty data. Use expand → backfill → verify → switch; retain
   old columns until a later, explicit maintenance migration proves they are
   unused.
4. Schema DDL and security DML are separate boundaries. MySQL DDL can implicitly
   commit, so `dbDelta()` is never called inside a login, enrollment, recovery,
   rebind, or rotation transaction. If a migration fails, leave the ledger
   failed and keep all plugin security operations fail-closed until it is
   rerun successfully.
5. A new database may receive empty tables without creating an identity row.
   `identity init` inserts the binding only after the schema is ready and only
   when no security rows exist. A web request never generates, adopts, or
   rebinds an identity.
6. A legacy table without binding columns is quarantined, not backfilled with
   the current fingerprint. A migration must either prove a matched explicit
   migration source or leave those records unavailable and require operator
   recovery.
7. Migration SQL uses `$wpdb->prepare()` for values and checks errors. DDL
   identifiers come only from the fixed table map; request input never reaches
   schema SQL.

These rules follow WordPress’s documented table-creation and upgrade guidance:
`dbDelta()` compares the desired and current structure, is deliberately picky
about SQL formatting, uses the caller’s table prefix and charset/collation, and
is normally paired with a plugin schema-version check. They also preserve the
database transaction boundary exposed by `$wpdb` and InnoDB.

## Clone and identity mismatch handling

At runtime, an absent/invalid configuration, constant/environment conflict,
missing binding, environment mismatch, or hash/epoch mismatch is respectively
`unconfigured`, `configuration_error`, `uninitialized`, or `identity_mismatch`
as defined in #12. In all such states:

- no authenticator, recovery code, challenge, or satisfied session is accepted;
- no enrollment or authentication transition is committed;
- protected interactive requests remain blocked; and
- diagnostics contain only redacted state and fingerprints, never raw identity
  values or credential material.

An explicit clone rebind increments the epoch and changes only the singleton
binding plus the required ephemeral/recovery invalidation. Imported methods and
provider rows retain the source fingerprint/epoch and remain foreign. A matched
production database/configuration restore is the only automatic credential
preservation path. A production identity rotation or lost-secret recovery
provisions a new identity, invalidates old credentials, and requires fresh
enrollment.

## Acceptance tests

- [ ] Activation/migration creates every listed table with the configured
  prefix, `ENGINE=InnoDB`, charset/collation, required columns, composite
  binding keys, unique keys, and lookup indexes; rerunning it is a no-op.
- [ ] `schema_versions` resumes an interrupted additive migration, rejects an
  unknown/failed version for security operations, and never drops or silently
  renames data through `dbDelta()`.
- [ ] Every security repository includes the current `(identity_hash, epoch)`
  predicate; a cloned row with the same user, method, credential, or role key
  is not returned under a new binding.
- [ ] Role discovery creates disabled policies, preserves immutable activation
  and affected-since anchors, resolves the earliest multi-role deadline, and
  stores extensions as absolute current-cycle grants.
- [ ] A user can have multiple TOTP/WebAuthn methods, labels can duplicate, and
  revoked/exhausted methods cannot be selected or verified.
- [ ] The TOTP row stores the fixed #6 profile and authenticated ciphertext;
  tampering, missing key material, or a wrong envelope binding fails closed.
- [ ] A WebAuthn credential ID is unique only within its installation binding;
  public-key data and counter updates use the method revision CAS, while RP ID
  and origin remain separate from installation identity.
- [ ] Recovery generation creates exactly ten independent 128-bit verifier
  rows, allows only one active generation, returns plaintext once after commit,
  and never logs or stores plaintext.
- [ ] Two concurrent submissions of one recovery code yield at most one
  affected-row success; consuming the last code exhausts the generation and
  satisfies only the bound current session.
- [ ] A challenge is bound to user, installation, session token hash, purpose,
  provider, method snapshot, and expiry; replay, expiry, mismatch, and method
  revocation fail before provider verification.
- [ ] Two concurrent valid challenge submissions yield at most one consumed
  interaction and one satisfied session; any provider/CAS/audit failure leaves
  the session pending.
- [ ] Logout, WordPress session destruction, rebind, and rotation invalidate
  matching session/challenge state; a new token never inherits satisfaction.
- [ ] Rate-limit buckets survive a session change, contain no raw IP/token/code,
  and expire independently of the audit stream.
- [ ] Audit events are appended in the same successful state transaction,
  redact all sensitive values, remain queryable by binding/user/type/time, and
  retention cleanup cannot make an invalid transition valid.
- [ ] A database clone with a new identity enters mismatch, rejects every
  imported factor/session/challenge, increments epoch only through confirmed
  CLI rebind, and does not rewrite source fingerprints.
- [ ] A matched production restore preserves eligible credentials; an
  environment mismatch or interrupted rotation fails closed and requires the
  explicit recovery path from #12.

## Primary sources

- [Issue #8](https://github.com/PDS-UK/pds-wp-2fa/issues/8) — persistence and migration question.
- [Issue #6](https://github.com/PDS-UK/pds-wp-2fa/issues/6) — closed TOTP, recovery, and secret-protection decision.
- [WordPress: Creating Tables with Plugins](https://developer.wordpress.org/plugins/creating-tables-with-plugins/) — `$wpdb->prefix`, charset/collation, `dbDelta()`, schema versions, and upgrade checks.
- [`dbDelta()` reference and source](https://developer.wordpress.org/reference/functions/dbdelta/) — structure/index comparison behavior.
- [`wpdb::query()`](https://developer.wordpress.org/reference/classes/wpdb/query/) — query execution and affected-row/error results.
- [`wpdb::prepare()`](https://developer.wordpress.org/reference/classes/wpdb/prepare/) — parameterized SQL values and identifiers.
- [`wpdb` class](https://developer.wordpress.org/reference/classes/wpdb/) — WordPress database abstraction.
- [MySQL InnoDB transaction model](https://dev.mysql.com/doc/refman/8.4/en/innodb-transaction-model.html) — transaction and locking model.
- [MySQL statements that cause an implicit commit](https://dev.mysql.com/doc/refman/8.4/en/implicit-commit.html) — DDL boundary used by the migration decision.
- [W3C WebAuthn RP identifier](https://www.w3.org/TR/webauthn-3/#relying-party-identifier) — domain-scoped RP identity kept separate from installation binding.
- [PHP `password_hash()`](https://www.php.net/manual/en/function.password-hash.php) and [`password_verify()`](https://www.php.net/manual/en/function.password-verify.php) — recovery-code verifiers.
