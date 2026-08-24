# Administrative recovery, audit, and CLI boundaries

**Issue:** [#10 — Define administrative recovery, audit, and CLI boundaries](https://github.com/PDS-UK/pds-wp-2fa/issues/10)
**Parent:** [#1 — PDS WP 2FA Wayfinder Map](https://github.com/PDS-UK/pds-wp-2fa/issues/1)
**Status:** implementation-ready decision
**Date:** 2026-08-24

This document defines the privileged administration surface. It complements
the interactive route contract in [`07-route-contract.md`](07-route-contract.md),
the role-policy rules in [`05-role-policy.md`](05-role-policy.md), the method
lifecycle in [`11-method-lifecycle.md`](11-method-lifecycle.md), and the
installation binding in [`12-installation-identity.md`](12-installation-identity.md).
It does not choose concrete tables or SQL types; those belong to issue #8.

## Decisions and assumptions

- Administrative pages are separate from the end-user `pds-2fa` challenge,
  enrollment, and recovery routes. They are never added to the pending-session
  allowlist.
- WordPress capabilities, not role names, authorize web actions. A target
  user is additionally checked with the `edit_user` meta capability.
- Every state-changing web action requires a satisfied (or
  `not_required`) current session, an action-specific nonce, and fresh
  password re-authentication. A nonce is CSRF protection, not authentication.
- Administrative recovery never silently authenticates a browser session. It
  either invalidates state, changes a deadline, or starts a new enrollment
  operation; the affected user must complete the normal route contract.
- Non-production bypass is deployment configuration, not an editable database
  setting. It is effective only for `local`, `development`, or `staging`, and
  is ignored when WordPress reports `production`.
- Logical records below are persistence-neutral. Issue #8 must provide atomic
  writes, uniqueness, indexes, schema versions, and retention cleanup without
  changing their security meaning.
- Assumption for reconciliation with #8: the initial audit retention is 400
  days; administrators may select 400–2555 days. Identity-bound and emergency
  events have a 2555-day minimum. If legal or operational policy changes these
  values, #8 must change the validation and acceptance tests together.

## 1. Capability and page boundary

The plugin registers these capabilities. Runtime checks use these exact names;
they must not check `administrator`, `editor`, or another role label directly.

| Capability | Permitted surface |
| --- | --- |
| `manage_pds_wp_2fa` | Global enforcement, discovered role-policy enable/disable, role grace-period settings, and read-only deployment diagnostics. |
| `view_pds_wp_2fa_status` | User-status list and detail views; no credential material. |
| `manage_pds_wp_2fa_users` | Target-user session reset, grace extension, method revoke, and recovery-generation actions. Requires `edit_user` for the target. |
| `view_pds_wp_2fa_audit` | Filtered audit list and event detail with redacted metadata. |
| `manage_pds_wp_2fa_retention` | Audit-retention configuration and scheduling of eligible cleanup. |
| `manage_pds_wp_2fa_emergency` | Force re-enrollment that revokes every method. This is not granted by default to a new role and is CLI-preferred for production. |

On activation, the implementation may grant the ordinary five capabilities to
the existing `administrator` role key as a bootstrap assumption; it must not
use that role key as an authorization check or auto-enable that role’s 2FA
policy. The emergency capability requires an explicit operator decision. Site
owners may delegate capabilities to other roles through normal WordPress role
management.

The administrative pages and their read permissions are:

```text
admin.php?page=pds-wp-2fa-settings  -> manage_pds_wp_2fa
admin.php?page=pds-wp-2fa-users     -> view_pds_wp_2fa_status
admin.php?page=pds-wp-2fa-audit    -> view_pds_wp_2fa_audit
```

`add_menu_page()`/`add_submenu_page()` registration is presentation only;
every page callback repeats its capability check. `GET` requests render
only. No secret is placed in a URL, form value, page title, HTML comment, or
JavaScript payload.

### Settings and role-policy controls

The settings page exposes exactly these mutable fields:

| Field | Authorization and validation | Effect |
| --- | --- | --- |
| `global_enforcement` | `manage_pds_wp_2fa`; boolean; production `off` is CLI-only emergency behavior | Enables or disables enforcement while retaining policy anchors and history. Re-enabling never creates a new grace period. |
| `role_policy[role_key].enabled` | `manage_pds_wp_2fa`; `role_key` must be currently discovered by `wp_roles()->get_names()` | Explicitly enables or disables one role policy. New roles remain disabled; orphaned keys are read-only until they reappear. |
| `role_policy[role_key].grace_period_seconds` | `manage_pds_wp_2fa`; integer `0..31536000` | Changes the configured duration without changing `activated_at` or `affected_since`. The role-policy resolver applies the unchanged anchor. |
| `audit_retention_days` | `manage_pds_wp_2fa` and `manage_pds_wp_2fa_retention`; integer `400..2555` | Changes future cleanup eligibility; it never deletes records in the settings request. |

The page displays, but cannot edit, environment type, installation binding
state/epoch, WebAuthn availability, and non-production bypass state. RP ID,
allowed origins, installation identity, encryption keys, and deployment
environment are deployment-controlled and have no web-admin setter.

Each settings save validates the complete submitted desired state, rejects
unknown fields and role keys, and writes one audit event per changed logical
field. A partial save is not reported as successful. Role-policy events retain
the immutable timestamps defined by #5.

## 2. User-status views and actions

The users page is a diagnostic view, not a credential-management dump. Its
allowlisted filters are `q` (user ID or login), `role_key`, `policy_state`
(`unprotected|grace|enrollment_required|enrolled`), `deadline_before`,
`deadline_after`, `method_type` (`totp|webauthn|recovery`), and `method_state`
(`active|exhausted|revoked`). Results are paginated, default 50 and maximum
100, ordered by user ID. Search and filters are escaped and never become SQL
fragments.

Each row/detail view may show:

```text
user_id, user_login, current role keys and labels
protected/policy state, contributing role keys, base and effective deadline
enrollment-cycle state, active method counts by provider, recovery unused count
method labels, method status, created_at, last_used_at, and revoked_at
```

It must not show TOTP secrets or provisioning URIs, recovery plaintext or
hashes, WebAuthn responses/private keys, raw credential IDs, challenges,
session tokens or hashes, installation values/fingerprints, encryption keys,
request bodies, or provider exception text. A status page must not claim that
all of a user’s browser sessions are satisfied; satisfaction is token-bound.

The exact state-changing `admin-post.php` actions are:

| Action | Required capability | Semantics |
| --- | --- | --- |
| `pds_wp_2fa_extend_grace` | `manage_pds_wp_2fa_users` + target `edit_user` | Positive `extension_seconds` `1..31536000`; apply #5’s absolute, current-cycle formula; require a non-secret `reason_code`. |
| `pds_wp_2fa_reset_sessions` | `manage_pds_wp_2fa_users` + target `edit_user` | Destroy the target’s WordPress sessions and matching plugin session/interaction state. Preserve authenticators and start the next login pending. |
| `pds_wp_2fa_revoke_method` | `manage_pds_wp_2fa_users` + target `edit_user` | Terminally revoke one method by server-issued opaque method reference. Enforce #11’s final-method rule under transaction/lock. |
| `pds_wp_2fa_revoke_recovery` | `manage_pds_wp_2fa_users` + target `edit_user` | Revoke the active recovery generation, subject to the final-method rule. |
| `pds_wp_2fa_reset_enrollment` | `manage_pds_wp_2fa_emergency` + target `edit_user` | Emergency operation: invalidate all target sessions, revoke all methods and recovery rows, start a new enrollment cycle, and force `enrollment_required`. It never logs the user in. Production use is CLI-preferred and requires the production confirmation below. |

An administrator cannot revoke the only active/non-exhausted method through a
normal action. A valid replacement must be active before the old method is
revoked. Emergency reset is the explicit exception and must record a high-
severity event containing the actor, target, reason code, old method count, and
new enrollment-required state.

Administrators never generate or receive another user’s plaintext recovery
codes. A target user regenerates their own codes through the satisfied,
re-authenticated `route=recovery` flow in #7; an administrator may revoke the
old generation or force full re-enrollment. This keeps every recovery bundle
bound to the user’s own session and one-time display.

## 3. Re-authentication, nonce, and request rules

The current actor must pass all checks in this order:

1. classify the request and reject CLI/XML-RPC/cron from the browser handler;
2. require a logged-in current user whose plugin session is `satisfied` or
   `not_required`;
3. check the exact capability and, for a target, `current_user_can('edit_user',
   $target_user_id)`;
4. verify the action-specific nonce with `check_admin_referer()`;
5. require fresh password re-authentication; and
6. load and lock the target records, re-check the installation `(hash, epoch)`,
   policy state, method revision/final-method count, and transaction inputs.

Nonce action names are exactly the `admin-post` action names above plus:
`pds_wp_2fa_save_settings`, `pds_wp_2fa_save_role_policy`,
`pds_wp_2fa_save_retention`, and `pds_wp_2fa_reauthenticate`. A nonce is
created with `wp_nonce_field()` and checked before any state change. Failed
nonce or capability checks do not disclose whether a target user, method, or
recovery generation exists.

Fresh re-authentication is a current WordPress password check against the
current user’s stored password using `wp_check_password()`. The submitted
password exists only for that request. It is never passed to an audit event,
stored in a re-auth record, included in an exception, or placed in a redirect.
External-auth users without a usable WordPress password cannot use these web
administrative actions; the CLI/operator path is the recovery boundary.

On success, the server creates an `admin_reauth_grant` logical record:

```text
grant_id_hash, user_id, session_token_hash, installation_hash, installation_epoch
scope, issued_at, expires_at (10 minutes maximum), consumed_at
```

The grant is scoped to one operation family (`settings`, `user_management`,
`retention`, or `emergency`) and the current WordPress session. It is consumed
once for emergency reset and may be reused only within its ten-minute lifetime
for ordinary actions in the same scope. A changed/expired/logout-destroyed
session invalidates it. Raw password, nonce, session token, and grant values
never appear in output.

Admin POSTs use PRG and `wp_safe_redirect()`. Submitted passwords, recovery
codes, TOTP values, and WebAuthn payloads are cleared before rendering an
error. Administrative endpoints are not part of the five pending-session
actions in #7; a pending session receives the normal 403/redirect gate before
the callback runs.

## 4. Audit event contract

Audit is append-only logical security history, not the source of truth for
current enforcement. Every state-changing operation writes its event in the
same transaction as the state change. A failed transaction writes no success
event; a separately committed failure event may record only a safe failure
category.

Each event contains at least:

```text
event_id, event_type, severity, occurred_at
actor_kind (user|cli|system|cron), actor_user_id (nullable), source
target_user_id (nullable), role_key (nullable), method_id (opaque, nullable)
installation_hash, installation_epoch, outcome, reason_code
safe_metadata, schema_version, correlation_id_hash (nullable)
```

`safe_metadata` is an event-type allowlist, not a copy of request data. Values
are scalar/enumerated or bounded integers/timestamps. A free-form operator
note is not stored; `reason_code` is one of `support`, `lost_authenticator`,
`policy_change`, `clone_rebind`, `incident`, `rotation`, `user_request`, or
`other`.

### Taxonomy

| Family | Event types |
| --- | --- |
| Authentication/session | `primary_login_succeeded`, `primary_login_failed`, `session_pending`, `session_satisfied`, `session_invalidated`, `logout`, `challenge_started`, `challenge_succeeded`, `challenge_failed`, `challenge_replayed`, `challenge_expired`, `rate_limited`. |
| Method/recovery | `method_enrollment_started`, `method_enrollment_completed`, `method_enrollment_failed`, `method_revoked`, `method_rotation_completed`, `recovery_generation_created`, `recovery_generation_revoked`, `recovery_code_consumed`, `recovery_attempt_failed`. |
| Role/policy | `role_policy_discovered`, `role_policy_enabled`, `role_policy_disabled`, `role_policy_reenabled`, `role_policy_grace_changed`, `role_policy_orphaned`, `role_policy_reappeared`, `role_label_changed`, `user_role_policy_affected`, `enrollment_cycle_started`, `enrollment_cycle_completed`, `grace_extension_granted`, `grace_extension_revoked`, `enrollment_deadline_reached`, `global_enforcement_changed`. |
| Administration/identity | `admin_reauth_succeeded`, `admin_reauth_failed`, `admin_authorization_denied`, `admin_sessions_reset`, `admin_enrollment_reset`, `identity_status_mismatch`, `identity_initialized`, `identity_rebound`, `identity_rotated`, `foreign_records_quarantined`, `retention_policy_changed`, `audit_retention_run`. |

Ordinary page views do not create an event per row. The implementation may
record `admin_status_viewed` or `audit_viewed` for high-assurance deployments,
but those reads must be rate-limited and redacted in the same way.

### Redaction and output

The following keys and values are never accepted in `safe_metadata`:
`password`, `password_confirmation`, `totp`, `secret`, `seed`, `otpauth`,
`recovery_code`, `code_hash`, `webauthn_response`, `client_data_json`,
`authenticator_data`, `signature`, `challenge`, `session_token`, `cookie`,
`nonce`, `private_key`, `encryption_key`, raw identity, request body, headers,
or provider exception text. The logger/audit writer must use an allowlist
before serialization, not a best-effort blacklist after serialization.

Human, JSON, CSV, and YAML status/audit output contains only the safe fields
listed in the view/command contracts. It never returns secrets, password
material, raw credential IDs, raw hashes, session material, or challenge data.

### Retention and filtering

The audit page filters only on `event_type`, `severity`, `actor_kind`,
`actor_user_id`, `target_user_id`, `source`, `outcome`, `role_key`, provider,
installation epoch, and an inclusive UTC `since`/`until` range. Results are
ordered by `(occurred_at DESC, event_id DESC)`, with a maximum page size of 100.
There is no arbitrary metadata or request-body search.

The configured retention applies as follows:

- ordinary authentication, policy, and user-management events: the configured
  400–2555 day period, default 400;
- identity-bound and emergency events: at least 2555 days; and
- ephemeral interaction/session cleanup records: the shorter persistence
  window selected by #8, never used as an audit source of truth.

WordPress cron may run eligible cleanup. `audit prune` is a dry-run by default
and can delete only rows older than both the configured period and the
identity/emergency floor. It requires explicit confirmation, records an
`audit_retention_run` summary before deletion, and never accepts a raw
“delete these IDs” request from a browser form.

## 5. Exact WP-CLI contract

The command namespace is `wp pds-wp-2fa`. Commands call domain services
directly; they do not create a browser cookie, fake a session token, or rely on
`admin_init`. `WP_CLI` is an explicit non-interactive boundary. Unless stated
otherwise, safe output supports `--format=table|csv|json|yaml`; structured
output uses stable field names and never contains secrets.

### Read and policy commands

```text
wp pds-wp-2fa status [--user=<id|login>] [--format=<table|csv|json|yaml>]
wp pds-wp-2fa settings get [--format=<table|csv|json|yaml>]
wp pds-wp-2fa role list [--format=<table|csv|json|yaml>]
wp pds-wp-2fa user status --user=<id|login> [--format=<table|csv|json|yaml>]
wp pds-wp-2fa recovery status --user=<id|login> [--format=<table|csv|json|yaml>]
wp pds-wp-2fa audit list [--event=<type>] [--severity=<level>]
  [--actor=<id|cli|system|cron>] [--user=<id>] [--role=<role-key>]
  [--source=<web|cli|system|cron>] [--outcome=<success|failure>]
  [--since=<UTC>] [--until=<UTC>] [--per-page=<1..100>]
  [--format=<table|csv|json|yaml>]
```

`status` without `--user` reports only environment, binding state, epoch,
enforcement state, WebAuthn availability, policy counts, and redacted audit
retention. With `--user`, it returns the same safe fields as the user-status
view. `recovery status` returns generation state and unused-count only.

### Identity commands

```text
wp pds-wp-2fa identity generate
wp pds-wp-2fa identity status [--format=<table|json|yaml>]
wp pds-wp-2fa identity init --confirm
wp pds-wp-2fa identity rebind --from-clone --confirm [--confirm-production]
wp pds-wp-2fa identity rotate --confirm-production
```

`identity generate` changes neither configuration nor the database. It is the
one intentionally secret-bearing provisioning operation inherited from #12:
it prints one newly generated canonical value only to a direct TTY, never in
structured output, audit, logs, web responses, or redirected/non-TTY output.
All other identity commands print only environment, state, epoch, and
redacted fingerprint/presence information. This is the only exception to the
no-secrets output rule.

`identity init` requires a clean database and valid active configuration.
`rebind` requires `--from-clone --confirm`; production additionally requires
`--confirm-production`, increments the epoch, binds the active configuration,
and quarantines imported records without rewriting their fingerprints.
`rotate` requires a distinct pre-provisioned next identity, an active current
binding, and production confirmation; it increments the epoch and invalidates
old plugin credentials, recovery records, challenges, and session state.
Neither rebind nor rotation recovers or prints a lost old identity.

### Mutating commands

```text
wp pds-wp-2fa settings set --enforcement=<on|off> --reason=<reason-code>
  [--confirm|--confirm-production]
wp pds-wp-2fa role set <role-key> --enabled=<on|off>
  [--grace-seconds=<0..31536000>] --reason=<reason-code> --confirm
wp pds-wp-2fa user extend-grace --user=<id|login>
  --seconds=<1..31536000> --reason=<reason-code> --confirm
wp pds-wp-2fa user reset-sessions --user=<id|login> --reason=<reason-code> --confirm
wp pds-wp-2fa user reset-enrollment --user=<id|login>
  --reason=<reason-code> --confirm --confirm-production
wp pds-wp-2fa method revoke --user=<id|login> --method=<opaque-id>
  --reason=<reason-code> --confirm
wp pds-wp-2fa recovery revoke --user=<id|login>
  --reason=<reason-code> --confirm
wp pds-wp-2fa audit prune [--before=<UTC>] [--dry-run] --confirm
```

All mutating commands require an active installation binding, except
`identity` recovery commands and read-only status. `--user` accepts only a
numeric user ID or exact `user_login`; email, password, recovery codes, method
labels, and credential material are never command arguments. Recovery-code
generation is deliberately a user-session web operation; WP-CLI may revoke a
generation but never generates or delivers plaintext codes.

Exit status is stable: `0` success, `1` usage/validation error, `2`
confirmation or policy refusal, `3` unconfigured/mismatched identity, `4`
transaction/persistence conflict, and `5` target not found. Errors are short,
generic, and secret-free; `WP_CLI::error()` must not receive provider
exception text or serialized request data.

### Non-production and emergency behavior

- `local`, `development`, and `staging` may use the explicit deployment
  non-production bypass. It is reported by status, does not delete state, and
  does not suppress audit events. It has no effect in `production`.
- Web admin cannot change the deployment bypass or identity binding.
- In production, `settings set --enforcement=off` is CLI-only, requires
  `--confirm-production` and `--reason=incident`, and creates a high-severity
  `global_enforcement_changed` event. Re-enabling does not rebaseline role
  anchors or grace extensions.
- `user reset-enrollment` is the emergency user recovery operation. It is
  destructive, production-confirmed, invalidates all current sessions, revokes
  all methods, and forces fresh enrollment. It does not reveal a credential or
  grant a satisfied session.
- When binding state is `unconfigured`, `configuration_error`, or
  `identity_mismatch`, only status and the explicitly applicable identity
  command may run. User/method/recovery writes fail with exit code 3.
- A failed or interrupted identity transition leaves the plugin mismatched;
  changing only configuration cannot revive foreign records.

Every successful CLI mutation writes the same audit event as the web operation
with `actor_kind=cli`, `source=cli`, no browser session identifiers, and no
copy of command-line arguments. CLI execution itself is not a 2FA bypass for
web users; it is an operator boundary whose OS/database access must be
protected by deployment controls.

## 6. Persistence handoff to #8

Issue #8 must represent, at minimum, the following logical records or
equivalents:

- `admin_reauth_grant`, bound to user/session/installation/scope and expiry;
- `audit_event`, append-only with a schema version, safe metadata allowlist,
  installation epoch, and retention eligibility;
- an atomic user-management operation boundary that can update methods,
  recovery rows, session state, enrollment cycle, and its audit event together;
- retention configuration with the 400–2555-day validation and high-severity
  floor; and
- a cleanup cursor/lease or equivalent that prevents concurrent retention jobs
  from deleting the same logical batch twice.

Concrete table names, JSON vs normalized safe metadata, indexes, migration
steps, and transaction primitives remain #8 decisions. Regardless of those
choices, repositories must scope every security lookup to the current
installation hash and epoch, use compare-and-set/locking for final-method and
recovery races, and never store raw tokens, passwords, codes, challenges,
private keys, or raw installation identity.

## Acceptance checklist

- [ ] Every listed page, field, and action enforces its exact capability,
      target-user check, nonce, current-session state, and fresh re-auth rule.
- [ ] Role settings use current role keys, preserve #5 anchors, and cannot
      edit deployment identity, environment, RP ID, or encryption keys.
- [ ] Status views and every CLI format omit credential material and session
      identifiers; recovery regeneration never prints plaintext codes.
- [ ] Normal revoke obeys the final-method rule; emergency reset is explicit,
      destructive, audited, and never authenticates a session.
- [ ] Audit events are allowlisted, redacted, transactionally paired with
      mutations, filterable by the stated fields, and retained by the stated
      floors.
- [ ] Identity mismatch, non-production bypass, production confirmation,
      CLI exit codes, and command output behavior match this contract.
- [ ] #8 tests re-auth grants, atomic races, retention cleanup, audit schema
      migration, installation scoping, and secret-free serialization.

## Primary sources

### WordPress

- [`current_user_can()`](https://developer.wordpress.org/reference/functions/current_user_can/) — capability and meta-capability checks.
- [`add_menu_page()`](https://developer.wordpress.org/reference/functions/add_menu_page/) — admin page registration.
- [`register_setting()`](https://developer.wordpress.org/reference/functions/register_setting/) and [`settings_fields()`](https://developer.wordpress.org/reference/functions/settings_fields/) — Settings API registration and form fields.
- [`check_admin_referer()`](https://developer.wordpress.org/reference/functions/check_admin_referer/), [`wp_verify_nonce()`](https://developer.wordpress.org/reference/functions/wp_verify_nonce/), and [`wp_nonce_field()`](https://developer.wordpress.org/reference/functions/wp_nonce_field/) — nonce intent verification.
- [`wp_check_password()`](https://developer.wordpress.org/reference/functions/wp_check_password/) — current WordPress password verification.
- [`wp_get_session_token()`](https://developer.wordpress.org/reference/functions/wp_get_session_token/) and [`WP_Session_Tokens`](https://developer.wordpress.org/reference/classes/wp_session_tokens/) — session-bound state and invalidation.
- [`WP_Session_Tokens::destroy_all()`](https://developer.wordpress.org/reference/classes/wp_session_tokens/destroy_all/) — invalidating a user’s sessions.
- [`wp_safe_redirect()`](https://developer.wordpress.org/reference/functions/wp_safe_redirect/) — safe PRG redirects.
- [`wp_roles()`](https://developer.wordpress.org/reference/functions/wp_roles/) and [`WP_Roles::get_names()`](https://developer.wordpress.org/reference/classes/wp_roles/get_names/) — current role-key discovery.
- [`wp_get_environment_type()`](https://developer.wordpress.org/reference/functions/wp_get_environment_type/) — environment classification.
- [`admin_init`](https://developer.wordpress.org/reference/hooks/admin_init/), [`admin-post.php`](https://developer.wordpress.org/reference/files/wp-admin/admin-post.php), [`wp_doing_cron()`](https://developer.wordpress.org/reference/functions/wp_doing_cron/), and [`wp_logout()`](https://developer.wordpress.org/reference/functions/wp_logout/) — request and session boundaries.

### WP-CLI

- [Commands Cookbook](https://make.wordpress.org/cli/handbook/guides/commands-cookbook/) — command registration and synopsis conventions.
- [`WP_CLI::add_command()`](https://make.wordpress.org/cli/handbook/references/internal-api/wp-cli-add-command/) — command registration.
- [`WP_CLI::error()`](https://make.wordpress.org/cli/handbook/references/internal-api/wp-cli-error/) — non-secret error termination.
- [WP-CLI implementation details](https://make.wordpress.org/cli/handbook/contributions/implementation-details/) — `WP_CLI` bootstrap boundary.

### PHP

- [`password_verify()`](https://www.php.net/manual/en/function.password-verify.php) — password-style verification used by recovery credentials.
- [`hash_equals()`](https://www.php.net/manual/en/function.hash-equals.php) — timing-safe comparison for fixed-length digests.
- [`random_bytes()`](https://www.php.net/manual/en/function.random-bytes.php) — cryptographically secure random values.
