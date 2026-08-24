# PDS WP 2FA implementation map

Status: implementation-ready planning baseline

This document turns [issue #1](https://github.com/PDS-UK/pds-wp-2fa/issues/1)
into a staged handoff for a Composer-installable, single-site WordPress plugin.
It is a security specification and delivery map, not an implementation of the
plugin runtime.

## Product boundary

PDS WP 2FA protects interactive, cookie-authenticated WordPress administration
for users affected by an enabled role policy. The primary WordPress password
check creates a pending login session; a successful TOTP, production WebAuthn,
or single-use recovery challenge satisfies that session. Enrollment state is
durable user state and is never treated as proof that a new login has passed
2FA.

The phase-one product is single-site only. It excludes WordPress Multisite,
SMS/email/voice/push factors, remembered devices, trusted networks, risk-based
rules, mandatory multiple factors, and interactive challenges for Application
Passwords, XML-RPC, WP-CLI, or cron.

The technical identity is fixed as:

```text
Composer:   pds/wp-2fa
Namespace:  PDS\\WP2FA
WP prefix:  pds_wp_2fa_
CLI:        wp pds-wp-2fa
```

## Security invariants

These rules are acceptance criteria for every implementation stage:

1. A protected user with only a valid password cannot reach an unrestricted
   administrative handler.
2. The 2FA state is bound to the exact WordPress session token. Satisfying one
   login does not satisfy another login for the same user.
3. Durable enrollment, authenticator availability, and current-session
   satisfaction are separate facts. Completing enrollment activates a method
   but leaves the current session pending until a separate challenge succeeds.
4. Every challenge is server-created, short-lived, single-use, and bound to
   the user, operation, pending session, and installation identity.
5. TOTP secrets are encrypted with an authenticated envelope; recovery codes
   are stored only as password verifiers; WebAuthn private keys never reach the
   server.
6. A credential or challenge copied from a different installation or cloned
   environment is rejected unless an explicit, audited migration says
   otherwise.
7. WebAuthn RP ID/origin validation remains domain-scoped and distinct from
   installation identity. Production WebAuthn cannot be enabled by changing a
   database value alone.
8. Challenge failures and replay attempts are throttled and audited without
   logging secrets, submitted codes, raw challenges, or library exception
   details.
9. Pending browser sessions are gated before ordinary admin, AJAX, admin-post,
   and cookie-authenticated REST handlers run. Non-interactive mechanisms keep
   their existing authentication boundary.
10. All state-changing enrollment, recovery, reset, extension, and policy
    operations require capability, nonce, session, and re-authentication checks
    appropriate to the operation.

## Settled inputs

The parent issue already records these decisions:

- Composer package and support baseline: [issue #4](https://github.com/PDS-UK/pds-wp-2fa/issues/4)
  and `docs/research/composer-runtime-baseline.md` on the corresponding
  research branch.
- WebAuthn: `web-auth/webauthn-lib`; the library verifies protocol ceremony
  details while the plugin owns challenge/session/environment binding,
  persistence, rate limits, audit, and session transitions. See
  `docs/research/webauthn-library-verification.md`.
- WordPress enforcement: bind state to the session token, gate at `admin_init`
  and cookie-authenticated `rest_authentication_errors`, and bypass
  Application Passwords, XML-RPC, WP-CLI, and cron. See
  `docs/research/wordpress-auth-hooks.md`.
- TOTP and recovery primitives: RFC 6238-compatible TOTP, local QR generation,
  single-use hashed recovery codes, and authenticated encryption with a
  deployment-specific key. See
  `docs/research/totp-recovery-crypto.md` on the corresponding research branch.

The detailed decisions from the remaining child tickets live in these focused
documents:

| Ticket | Decision document | Dependency role |
| --- | --- | --- |
| #5 role policy | `docs/spec/05-role-policy.md` | independent input |
| #7 route contract | `docs/spec/07-route-contract.md` | depends on #3 |
| #11 method lifecycle | `docs/spec/11-method-lifecycle.md` | depends on #2 and #6 |
| #12 installation identity | `docs/spec/12-installation-identity.md` | independent input |
| #8 persistence/migrations | `docs/spec/08-persistence.md` | depends on #5, #11, #12 |
| #10 administration/audit/CLI | `docs/spec/10-administration.md` | depends on #5, #7, #8 |
| #9 acceptance/compatibility | `docs/spec/09-acceptance-matrix.md` | depends on #7, #8, #10, #11, #12 |

Each child document must state decisions, invariants, and acceptance tests;
questions are not implementation requirements until resolved in the document.

## Delivery stages

The work is intentionally staged so implementation never has to guess across a
security boundary:

### Stage 0 — package and bootstrap

Create the Composer package, plugin header/bootstrap, namespace, dependency
loading, environment classifier, installation identity provider, clock, and
test harness. The bootstrap must fail clearly if required dependencies are not
available; it must not start a partially initialized authentication system.

### Stage 1 — persistence and domain services

Implement migrations and repositories for installation metadata, role policy
state, authenticators, recovery-code generations, challenge records,
session-state records, rate-limit buckets, and audit events. Keep durable rows
separate from ephemeral challenge/session records. Add transaction and
uniqueness guarantees before adding HTTP handlers.

### Stage 2 — provider and credential lifecycle

Implement the method-provider contract from #11. Add TOTP enrollment and
verification first, then recovery, then production-only WebAuthn behind the
same session transition. The provider must receive injected repositories,
clock, randomness, and environment policy so protocol verification and plugin
policy can be tested independently.

### Stage 3 — interactive routes and session gate

Implement the route/state contract from #7 and the hook boundary from the
WordPress research. Capture the issued session token, create pending state,
redirect only as a user-experience aid, and enforce the decision centrally
before handlers. Challenge and enrollment endpoints must be the only allowlisted
paths while a session is pending.

### Stage 4 — role policy and administration

Implement role discovery, activation timestamps, effective deadlines, and
audited user-specific grace extensions from #5. Add capability-protected
settings, user status, reset/revoke/extension actions, audit views, retention,
and CLI recovery according to #10. Administrative actions must never reveal
credential material.

### Stage 5 — compatibility, hardening, and release

Run the complete acceptance matrix from #9, including direct routes, AJAX,
admin-post, REST, grace expiry, bypass controls, rate limits, revocation,
session invalidation, and non-interactive authentication. Add WooCommerce
compatibility coverage without creating a WooCommerce-specific enforcement
path. Finish deployment, upgrade, rollback, and QA documentation from the
Composer baseline.

## Cross-stage test contract

The implementation should use deterministic fakes for the clock, random source,
session-token lookup, repositories, and WebAuthn validator. The test suite must
cover at least:

- session-specific pending/satisfied transitions and logout/revocation;
- role-policy changes, multiple roles, grace deadlines, and extensions;
- challenge expiry, replay, wrong user/session/installation, and atomic use;
- TOTP vectors, adjacent-step policy, replay counters, secret-envelope tamper,
  missing key, and recovery-code race/regeneration;
- WebAuthn origin/RP ID, user-handle, credential ownership, counter, production
  environment, and library-boundary failures;
- every route in the pending-session allowlist and direct access to each
  protected admin/AJAX/admin-post/REST path;
- Application Passwords, XML-RPC, WP-CLI, cron, and ordinary frontend sessions;
- capability/nonce/re-authentication checks for administrative and CLI actions;
- audit redaction, retention, migration idempotence, and cloned-database
  installation mismatch; and
- Composer install/deploy behavior on the supported PHP/WordPress baseline.

## Handoff checklist

Before coding begins, the repository should contain all seven linked child
decision documents, each with a clear owner boundary and no unresolved choice
that another stage must infer. Before release, the implementation branch must
link its tests and deployment notes back to this map, and the final review must
check both standards and fidelity to issue #1.
