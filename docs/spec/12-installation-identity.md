# Installation identity and environment transition rules

Status: implementation-ready decision for [issue #12](https://github.com/PDS-UK/pds-wp-2fa/issues/12)

Parent: [issue #1](https://github.com/PDS-UK/pds-wp-2fa/issues/1)

Decision date: 2026-08-24

This document specifies the installation binding used by PDS WP 2FA. It is
intentionally separate from the WebAuthn relying-party identity. It applies to
the phase-one single-site plugin described by [the parent specification](00-wayfinder-map.md).

## Decision summary

1. Every logical deployment environment has its own 256-bit installation
   identity. The identity is stable across releases, replicas, blue/green
   slots, and failover instances of that same environment.
2. The active identity is provisioned outside the database as
   `PDS_WP_2FA_INSTALLATION_ID`, preferably by a deployment secret manager and
   otherwise by `wp-config.php`. It is exactly 64 lowercase hexadecimal
   characters, generated from 32 bytes of cryptographically secure randomness.
3. The database stores only a SHA-256 fingerprint of the identity, together
   with an installation epoch and the classified environment. The raw value is
   never stored in `wp_options`, user meta, plugin tables, logs, or source
   control.
4. Every authenticator, recovery credential, challenge, session-state record,
   and identity-relevant audit event is scoped to the current fingerprint and
   epoch. A record copied from another installation is therefore foreign even
   when its WordPress user ID, TOTP secret, or WebAuthn credential ID is the
   same.
5. A configuration/database mismatch is fail-closed for PDS WP 2FA. The plugin
   never adopts the database value, silently rewrites the binding, or treats a
   clone as a new installation during a web request.
6. Binding, rebind, and rotation are explicit WP-CLI operations. A database
   clone gets a new identity before its first request and must be explicitly
   rebound; imported authentication records are not made valid by that rebind.
7. Production recovery uses a matched database plus deployment-configuration
   backup whenever possible. If the raw production identity is lost, recovery
   provisions a new identity and invalidates all existing plugin credentials;
   it does not attempt to recover the raw value from its database fingerprint.

## Terms and invariants

Let:

```text
I = the canonical 32-byte installation identity from deployment configuration
F = SHA-256(I), stored as 32 raw bytes in the database
E = the current WordPress environment type
N = the monotonically increasing installation epoch
R = the WebAuthn relying-party ID, if WebAuthn is enabled
```

The installation is active only when the following are all true:

```text
configured identity is valid
database.identity_hash == F
database.environment_type == E
the runtime identity state is active
```

Every security-record lookup must include both `F` and `N`. Comparing only the
WordPress user ID, credential ID, database name, site URL, or environment label
is insufficient. A WordPress session-token digest is the raw 32-byte
HMAC-SHA-256 value defined by the route/persistence contract; the installation
fingerprint remains a separate binding column.

The identity is an installation binding, not a password, encryption key, or
WebAuthn RP ID. Treat the deployment value as sensitive configuration because
it controls which database records are eligible, but do not use it as the key
for TOTP encryption or any other secret-envelope operation.

## Environment classification

Use WordPress's `wp_get_environment_type()` as the only environment classifier.
WordPress defines `local`, `development`, `staging`, and `production`; when no
valid value is configured, it returns `production`. Its documented source reads
the `WP_ENVIRONMENT_TYPE` system variable and then lets the
`WP_ENVIRONMENT_TYPE` constant override it. [WordPress environment type reference](https://developer.wordpress.org/reference/functions/wp_get_environment_type/)

Do not infer the environment from the request host, `home`, `siteurl`, database
name, filesystem path, Git branch, or a value copied from the database. The
environment is policy metadata and is not a substitute for the random
installation identity.

| Environment | Identity | WebAuthn | Enforcement policy |
| --- | --- | --- | --- |
| `local` | Unique to the local installation | Disabled in phase one | TOTP/recovery may be used; any enforcement bypass must be explicitly configured for non-production. |
| `development` | Unique to the development installation | Disabled in phase one | Same non-production rule; never inherit production enforcement state implicitly. |
| `staging` | Unique to staging | Disabled in phase one | Prefer production-like policy for rehearsal; a non-production bypass is explicit and cannot affect production. |
| `production` | Unique and stable for the live logical installation | Enabled subject to the WebAuthn policy | Role policy and global enforcement apply; non-production bypass settings are ignored. |

The non-production bypass is a deployment setting, not a database setting. Its
exact enforcement behavior belongs to the role/session policy implementation,
but the invariant is fixed here: no setting classified as a non-production
bypass can weaken a runtime classified as `production`.

Because WordPress defaults an absent or invalid environment to `production`, a
missing `WP_ENVIRONMENT_TYPE` is a production-safety condition. Local,
development, and staging deployments must set it explicitly before importing a
database. The plugin should expose a configuration warning, but must not
silently downgrade the environment.

Changing `E` for an existing database is an identity transition. It requires the
same explicit rebind and credential invalidation as changing `I`, even if the
operator accidentally reuses the same identity value.

## Provisioning and configuration authority

### Configuration contract

The runtime reads `PDS_WP_2FA_INSTALLATION_ID` as follows:

1. If the PHP constant is defined, use it.
2. If an environment variable is also defined, it must be byte-for-byte equal
   to the constant; otherwise enter `configuration_error`.
3. If the constant is not defined, use the environment variable.
4. If neither source provides a value, enter `unconfigured`.

The value must match `^[0-9a-f]{64}$`. Whitespace, uppercase hexadecimal,
short values, values derived from hostnames, and values copied from an existing
database are invalid. Canonicalization must happen before hashing; an invalid
value must never be normalized into an accepted value.

Provision a value with the equivalent of:

```php
bin2hex(random_bytes(32))
```

PHP documents `random_bytes()` as producing cryptographically secure random
bytes suitable for long-term secrets. [PHP `random_bytes()`](https://www.php.net/random-bytes)

The deployment process stores the resulting string in its secret manager or in
the environment-specific `wp-config.php`. It must not commit the value to the
repository, put it in a database export, or print it from a web endpoint. A
WP-CLI generator may print a newly generated value to an operator's terminal,
but status and diagnostic commands must never print the raw value.

WordPress's `AUTH_*`, `LOGGED_IN_*`, and `NONCE_*` keys/salts have a different
responsibility: WordPress documents that changing them invalidates existing
cookies. They remain WordPress authentication configuration and must not be
reused or derived as the PDS WP 2FA installation identity; otherwise a routine
cookie/salt rotation would unexpectedly change the installation binding.
[WordPress security keys and salts](https://developer.wordpress.org/apis/wp-config-php/)

The initial implementation must provide these command-level operations:

| Operation | Effect |
| --- | --- |
| `wp pds-wp-2fa identity generate` | Generate and print one new canonical value; does not change configuration or the database. |
| `wp pds-wp-2fa identity status` | Report environment, binding state, epoch, and redacted fingerprints; never report raw identities or credentials. Read-only. |
| `wp pds-wp-2fa identity init --confirm` | On a new plugin database with no security records, create the binding from the active configuration. Refuse if a binding or security records already exist. |
| `wp pds-wp-2fa identity rebind --from-clone --confirm` | Bind the active configuration to an intentionally cloned database, increment the epoch, and quarantine the imported security records. Production requires an additional explicit production confirmation. |
| `wp pds-wp-2fa identity rotate --confirm-production` | Use the pre-provisioned next identity, increment the epoch, and invalidate the old installation's credentials. This is never a web-admin operation. |

`PDS_WP_2FA_INSTALLATION_ID_NEXT` may be exposed only to the WP-CLI rotation
operation. It is not a runtime fallback and must not be accepted by web
requests. The rotation operation must require that the active identity matches
the database before it changes anything, and must reject a next identity equal
to the active identity.

### Database binding row

The persistence layer must have one installation row per single-site plugin
installation. The row contains at least:

| Field | Required meaning |
| --- | --- |
| `installation_id` | Fixed singleton key, for example `1`. |
| `identity_hash` | `hash('sha256', I, true)`; 32 binary bytes. |
| `identity_epoch` | Unsigned integer, starting at `1`, incremented for every init/rebind/rotation. |
| `environment_type` | The exact `E` value at binding time. |
| `bound_at`, `updated_at` | Audit timestamps. |
| `schema_version` | Version for future binding-format changes. |

The row is a recorded binding, not a source of authority. The source of
authority is the deployment configuration plus the current WordPress
environment classification. Store only the fingerprint to reduce accidental
exposure in database dumps; a fingerprint is not a replacement for access
control or encryption.

Every security table must include:

```text
installation_identity_hash BINARY(32) NOT NULL
installation_epoch        BIGINT UNSIGNED NOT NULL
```

This applies at minimum to authenticators, recovery credentials, WebAuthn
challenges, pending/satisfied session state, and audit events that describe
identity-bound operations. Repositories must scope reads and writes to the
current `(F, N)` pair. Add indexes that make `(installation_identity_hash,
installation_epoch, user_id)` and credential-ID lookups selective. The
credential ID remains unique within an installation binding, not globally
across all database copies.

Use a fixed-length binary comparison in the identity service; where two
fingerprints are compared in PHP, use `hash_equals()` rather than an ordinary
early-exit comparison. [PHP `hash_equals()`](https://www.php.net/manual/en/function.hash-equals.php)

Schema creation must not auto-generate or auto-bind an identity during a web
request. A fresh deployment is `unconfigured` until the operator has injected
the value and run the explicit initialization operation. If an installation
row is absent but security records are present, initialization must refuse and
require an explicit quarantine/recovery procedure.

## Database cloning and override behavior

WordPress treats its database and files/configuration as separate backup
artifacts: a database backup does not include `wp-config.php`, while a full
site backup needs both. [WordPress database backup guidance](https://developer.wordpress.org/advanced-administration/security/backup/database/), [WordPress file backup guidance](https://developer.wordpress.org/advanced-administration/security/backup/files/)

Therefore, a database export/import is never itself a valid installation
provisioning event. The destination operator must do the following before the
first normal request:

1. Classify the destination explicitly with `WP_ENVIRONMENT_TYPE`.
2. Generate and store a destination-specific `PDS_WP_2FA_INSTALLATION_ID`.
3. Import the database and files only as a maintenance operation.
4. Observe the expected `identity_mismatch` state. The plugin must not accept
   any imported TOTP, WebAuthn, recovery, challenge, or session record.
5. Run the explicit `identity rebind --from-clone --confirm` command.
6. Verify that the new binding is active, that the epoch increased, and that
   users can only proceed after fresh enrollment or an approved recovery path.

The configuration value is a runtime override of the database's recorded
expectation, but it is not an automatic database rewrite. In particular:

- Do not add an installation identity to `wp_options` and expect it to be
  overridden after cloning; options are part of the cloned database.
- Do not choose an identity from `siteurl`, a domain, a database name, or
  WordPress salts.
- Do not use a URL search-and-replace operation to change identity data. URL
  migration is a separate concern; WordPress documents that serialized values
  require a serialization-aware procedure, and WP-CLI provides a dedicated
  search-replace command for that job. [WordPress migration guidance](https://developer.wordpress.org/advanced-administration/upgrade/migrating/), [WP-CLI `search-replace`](https://developer.wordpress.org/cli/commands/search-replace/)
- Do not let plugin activation, an admin screen, or the first request adopt the
  destination value silently.

The rebind transaction changes only the singleton binding row and the current
epoch. It does not rewrite imported authenticator fingerprints into the new
fingerprint. Existing rows remain foreign/quarantined and are excluded by
repository queries. Pending challenges, session state, and recovery credentials
must additionally be revoked or expired as part of the transaction. Imported
authenticator rows may be retained for audit or purged by a separate,
environment-appropriate data-retention operation; they must never become valid
merely because the binding row changed.

## Request behavior while the binding is unavailable

`unconfigured`, `uninitialized`, `configuration_error`, `environment_mismatch`,
and `identity_mismatch` are fail-closed runtime states. The plugin must not
create, read, or accept security records in these states.

- Ordinary authenticated admin, AJAX, and admin-post browser requests return
  HTTP 503 with the fixed, non-secret code `pds_wp_2fa_unavailable`; no target
  callback or screen handler runs.
- Cookie-authenticated REST requests return a JSON `WP_Error` with the same
  code and HTTP 503; they are never redirected to an HTML enrollment route.
- A password login may complete in WordPress, but the plugin does not create a
  pending row; any subsequent protected browser request remains blocked with
  the same 503 until the operator repairs the binding. This avoids both a
  fail-open login and an attempt to bind state to an unknown installation.
- Application Passwords, XML-RPC, WP-CLI, and cron retain their existing
  non-interactive authentication boundaries. PDS WP 2FA does not perform
  credential writes through them while the binding is unavailable; only the
  explicitly permitted identity status/recovery commands may inspect or repair
  the state.

The response never includes the raw configured identity, database fingerprint,
credential material, or migration error text. Once `identity init`, rebind, or
repair completes and the binding is active, ordinary route behavior resumes;
foreign rows remain unusable.

## Authenticator comparison across environments

The following matrix is normative. “New identity” means a new random value and
therefore a new `(F, N)` binding, not merely a new label.

| Transition | Destination binding | Imported records | Required outcome |
| --- | --- | --- | --- |
| Local → development | New identity, `E=development` | Foreign | No imported factor is accepted; test users enroll again. |
| Development → staging | New identity, `E=staging` | Foreign | No copied TOTP, WebAuthn, recovery, challenge, or session state is accepted. |
| Staging → production | New production identity, `E=production` | Foreign | Explicit production rebind; users enroll production authenticators. Production WebAuthn is enabled only after the production binding is active. |
| Production → local/development/staging | New non-production identity and explicit non-production `E` | Foreign | No production factor is accepted. A non-production bypass, if used, is explicit. |
| Production backup → production failover/restore | Same production identity and `E=production` | Valid only when the database and configuration are a matched backup set | Preserve authenticators and session policy according to the restored database. |
| Same logical environment → replica/blue-green slot | Same identity and same `E` | Valid | Treat the slots as one installation; distribute the same protected configuration securely. |
| Any environment → new logical installation | New identity | Foreign | Rebind explicitly; require fresh enrollment. |
| In-place identity rotation | New identity and incremented epoch | Old | All old authenticators and recovery credentials are invalidated; users enroll again. |

For every authenticator lookup, require the current `(F, N)` before checking
the user, credential status, TOTP counter, WebAuthn credential ID, or recovery
code verifier. A matching user ID or matching WebAuthn credential ID is not an
exception. The same applies to a copied TOTP secret: it is data from the source
installation and is not portable to the destination.

The WebAuthn relying-party identity is a separate comparison. An RP ID is a
domain-scoped value, not a database identifier, and the browser ceremony also
validates origin. The installation fingerprint must be used to select and bind
the credential record, never inserted into `rp.id` or used as a domain. [WebAuthn RP ID definition](https://www.w3.org/TR/webauthn-3/#relying-party-identifier)

Changing `I` does not migrate WebAuthn credentials between RP IDs. Changing
`R`, changing the production host, or introducing a new origin is a separate
WebAuthn policy/migration decision. In phase one, WebAuthn is disabled in local,
development, and staging as required by the existing WebAuthn boundary.

## Mismatch, rotation, and recovery handling

### Runtime states

The identity service exposes these states to the rest of the plugin:

| State | Meaning | Web behavior |
| --- | --- | --- |
| `unconfigured` | No valid deployment identity is available | Do not create or read plugin security state. Protected 2FA cannot be satisfied. |
| `uninitialized` | Configuration is valid but no binding row exists | Permit only explicit CLI initialization; do not auto-bind from a web request. |
| `active` | Configuration, database binding, epoch, and environment agree | Normal plugin behavior. |
| `configuration_error` | Constant/env conflict or invalid format | Fail closed; expose only a redacted status and operator-facing audit/log event. |
| `identity_mismatch` | Configuration fingerprint or environment differs from the binding row | Fail closed for plugin credential/session operations; require explicit CLI rebind, rotation, or matched restore. |

On `unconfigured`, `configuration_error`, or `identity_mismatch`:

- no authenticator, recovery credential, challenge, or satisfied-session record
  may be accepted;
- no new enrollment may be completed;
- no current login may be marked 2FA-satisfied;
- protected interactive requests must remain blocked by the existing pending
  session gate; and
- error pages, REST responses, and logs must not disclose the raw identity,
  database fingerprint, TOTP secret, recovery verifier, or WebAuthn data.

WP-CLI status and recovery commands may run because they are operator-controlled
non-interactive paths, but they must still require the appropriate OS/database
access and write an audit event. No production web setting may bypass an
identity mismatch.

### Rotation

Rotation is destructive to plugin authentication state by design:

1. Take and verify a matched database plus deployment-configuration backup.
2. Provision `PDS_WP_2FA_INSTALLATION_ID_NEXT` in the production secret store.
3. Put the site in a maintenance/change window and confirm the current active
   configuration still matches the database.
4. Run the explicit rotation command. In one database transaction, verify the
   next value, replace the binding fingerprint, increment `identity_epoch`,
   revoke pending challenges/session state/recovery credentials, and emit a
   redacted audit event. Existing authenticator rows retain the old fingerprint
   and epoch and are therefore foreign.
5. Promote the next value to `PDS_WP_2FA_INSTALLATION_ID`, remove the next-value
   configuration, and verify `identity status` is `active`.
6. Require fresh enrollment for every user, including administrators. Do not
   roll back by changing only the configuration value; use the matched backup
   or another explicit rebind that invalidates state again.

If the deployment update is interrupted after the database transaction, the
site remains intentionally unavailable to protected plugin operations until the
new configuration is restored. If the raw old identity is lost, the database
fingerprint cannot reconstruct it; provision a new value and perform an
explicit, audited rebind/rotation that invalidates old credentials.

### Production recovery

The preferred recovery is to restore the database and the exact deployment
configuration from the same backup set, then verify that the environment is
`production` and the binding is `active`. WordPress recommends regular database
backups and notes that the database backup does not include `wp-config.php`,
so the identity secret must be backed up under the deployment's secret-storage
controls as part of the full recovery set. [WordPress backup guidance](https://developer.wordpress.org/advanced-administration/security/backup/)

If the database is known-good but the identity secret is unavailable:

1. Keep the plugin in mismatch state; do not guess or copy a value from the
   database.
2. Create a new 32-byte identity in the production secret store.
3. Run the production-confirmed CLI rebind/rotation under maintenance.
4. Increment the epoch and invalidate all plugin authentication state.
5. Deploy the new identity and require administrator re-enrollment.

If a production database is restored with a staging/local configuration, or a
staging database is restored with the production configuration, the expected
result is `identity_mismatch`, not a best-effort migration. A full restore of a
matched production database/configuration pair is the only automatic recovery
path.

## Acceptance tests

The following tests are required before this decision is considered implemented.
They should use injected configuration, environment, clock, random source,
database, and CLI collaborators so no test depends on a real deployment secret.

### Provisioning and storage

- Generate an identity from a deterministic fake random source and verify it is
  exactly 32 bytes represented as 64 lowercase hexadecimal characters.
- Reject empty, short, long, uppercase, whitespace-containing, non-hex, host-
  derived, and database-derived values.
- Accept a matching constant and environment variable; reject a conflict
  between them without selecting either value.
- Treat a missing value as `unconfigured`; prove that a web request does not
  generate, persist, or adopt an identity.
- Initialize a clean database once; reject a second initialization.
- Reject initialization when plugin security rows already exist without an
  installation row.
- Verify that only the fingerprint, epoch, environment, and timestamps are
  stored; the raw identity never appears in SQL rows, logs, HTML, REST, or
  normal CLI status output.
- Verify all security repositories add the current `(F, N)` predicate and that
  a record with a matching user ID but a foreign binding is not returned.

### Environment classification

- Exercise `local`, `development`, `staging`, and `production` and verify the
  expected WebAuthn/enforcement policy matrix.
- Verify that an absent or invalid WordPress environment resolves to the
  production-safe policy, not a non-production bypass.
- Verify that a host, `siteurl`, database name, or cloned environment label
  cannot choose an installation identity.
- Verify that changing the environment type without an explicit rebind creates
  `identity_mismatch`, even when the configured identity string is unchanged.
- Verify that a non-production bypass setting has no effect in `production`.

### Cloning and transitions

- Clone a source database, inject a fresh destination identity, and verify the
  first request enters `identity_mismatch` and accepts no source credential.
- Run an explicit non-production rebind and verify the epoch increases, the
  binding becomes active, and every source authenticator, recovery credential,
  challenge, and session record remains foreign.
- Verify rebind never rewrites source fingerprints to the destination
  fingerprint.
- Exercise every matrix transition above, including production backup restore,
  same-environment replica, staging-to-production, and production-to-local.
- Verify that identical WordPress user IDs, TOTP secrets, recovery codes, and
  WebAuthn credential IDs do not cross an identity boundary.
- Verify that a matched production database/configuration restore preserves
  eligible credentials and that a mismatched restore does not.

### Mismatch, rotation, and recovery

- Verify `configuration_error`, `unconfigured`, and `identity_mismatch` all
  block plugin credential/session operations and return redacted errors.
- Verify a web administrator cannot invoke init, rebind, or rotate through an
  admin page, AJAX route, REST route, or ordinary plugin request.
- Verify `identity status` is read-only and redacts both raw identity sources
  and credential material.
- Rotate using a configured next identity and verify an atomic fingerprint
  change, epoch increment, revocation of ephemeral/recovery state, and fresh
  enrollment requirements.
- Verify an interrupted rotation leaves a mismatch rather than accepting the
  old or next value as a fallback.
- Verify changing only the configuration after rotation cannot roll back the
  binding or revive old authenticator rows.
- Verify lost-secret recovery requires a new identity and invalidates old
  credentials; no database-only operation recovers the old raw identity.

### WebAuthn separation

- Verify the installation fingerprint is present in challenge/credential lookup
  context but never supplied as the WebAuthn RP ID.
- Verify a valid installation binding still fails WebAuthn when the configured
  RP ID/origin policy is wrong, and a valid RP ID does not bypass an installation
  mismatch.
- Verify non-production environments cannot enable WebAuthn merely by copying
  a production database or changing the database's stored metadata.

## Implementation handoff

Implement in this order:

1. Add the injected configuration/environment identity service and redacted
   state model.
2. Add the singleton binding migration and `(identity_hash, identity_epoch)`
   columns/indexes to every security table.
3. Make all repositories scope reads and writes to the active binding before
   implementing provider or session transitions.
4. Add WP-CLI generate/status/init/rebind/rotate operations with transactions,
   capability-by-CLI/OS boundaries, and audit events.
5. Add clone, rotation, restore, and mismatch tests before enabling the web
   authentication flows.

The later persistence/migration and administration tickets may choose concrete
table names and SQL types, but they must preserve the binding fields,
single-site singleton semantics, explicit-operator transitions, and acceptance
invariants in this document.

## Primary sources

- [WordPress `wp_get_environment_type()` reference](https://developer.wordpress.org/reference/functions/wp_get_environment_type/)
- [WordPress `wp-config.php` security keys and salts](https://developer.wordpress.org/apis/wp-config-php/)
- [WordPress database backup guidance](https://developer.wordpress.org/advanced-administration/security/backup/database/)
- [WordPress file backup guidance](https://developer.wordpress.org/advanced-administration/security/backup/files/)
- [WordPress migration guidance](https://developer.wordpress.org/advanced-administration/upgrade/migrating/)
- [WP-CLI `search-replace` reference](https://developer.wordpress.org/cli/commands/search-replace/)
- [PHP `random_bytes()` manual](https://www.php.net/random-bytes)
- [PHP `hash_equals()` manual](https://www.php.net/manual/en/function.hash-equals.php)
- [W3C WebAuthn relying-party identifier](https://www.w3.org/TR/webauthn-3/#relying-party-identifier)
