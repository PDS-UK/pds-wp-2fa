# Security acceptance matrix

**Decision ticket:** [#9 — Define the security acceptance matrix for bypasses,
rate limits, and compatibility](https://github.com/PDS-UK/pds-wp-2fa/issues/9)

**Parent:** [#1 — PDS WP 2FA Wayfinder Map](00-wayfinder-map.md)

**Status:** implementation-ready release gate

This matrix is the minimum security and compatibility contract for the
single-site phase-one implementation. The test harness should use deterministic
clock, randomness, session-token, repository, and WebAuthn-validator fakes.
HTTP status and response shape are part of the contract; user-facing strings
must remain translated fixed messages from [the route contract](07-route-contract.md).

## Test fixtures and common rules

Create fixtures for:

- a protected user with an enrolled TOTP method and a valid pending cookie
  session;
- a protected unenrolled user with an active grace deadline, and the same user
  at/after the deadline;
- a protected user with TOTP, WebAuthn, and recovery credentials in separate
  test cases;
- two independent WordPress session tokens for the same user;
- an Application Password request, XML-RPC request, WP-CLI process, cron
  process, public `admin_post_nopriv_*` action, and ordinary frontend request;
- a current installation `(identity_hash, identity_epoch)` and a foreign pair;
- a fake WooCommerce plugin that uses ordinary admin, AJAX, REST, and frontend
  requests; and
- a rate-limit clock that can advance windows without sleeping.

The security gate must run before the target handler. A test that sees the
handler's side effect has failed even if the eventual response is a denial.
Audit assertions must check event type, subject, outcome, and safe metadata,
but must also assert that raw credentials and request secrets are absent.

## Authentication and route matrix

| ID | Setup and request | Expected result | Audit/rate-limit expectation |
| --- | --- | --- | --- |
| AUTH-01 | Protected user completes WordPress password login and receives token T1. | A session row for `(user,T1)` is `pending`; enrollment status is unchanged. | Record successful primary login/session creation without storing T1. |
| AUTH-02 | T1 requests ordinary `/wp-admin/` while an authenticator exists. | `302` to the challenge view; target is validated same-site admin navigation. Target handler does not run. | Record pending-admin block; no factor failure bucket consumed. |
| AUTH-03 | T1 posts a valid TOTP/WebAuthn proof through the exact challenge action. | Transaction consumes the interaction, updates provider state, and changes only T1 to `satisfied`; `303` to the safe target. | Record factor success; update `last_used_at`; no submitted proof or raw challenge is logged. |
| AUTH-04 | T1 submits an invalid proof, expired interaction, wrong user, wrong session, wrong provider, or foreign installation. | `422` for invalid proof or the documented expired/session response; T1 remains pending; no handler-side success. | Record one categorized failure where applicable; apply the central limiter; generic message only. |
| AUTH-05 | T1 and T2 for the same user each submit the same valid factor. | The successful transaction satisfies only the winning token; the other remains pending and must verify separately. | Rate limits and audit are per intended security dimensions, never reset by creating T2. |
| AUTH-06 | A valid proof is submitted twice concurrently, or a recovery code is submitted twice concurrently. | Exactly one transaction succeeds; the other fails on interaction/code CAS and leaves no second success. | One success and one replay/concurrency event; no duplicate session transition. |
| AUTH-07 | An enrolled user logs out or WordPress destroys the session, then reuses a challenge. | Matching plugin session/interactions are invalidated; reuse is rejected. A new login starts pending. | Record logout/session invalidation; do not expose whether a stale proof was otherwise valid. |
| ROUTE-01 | Pending T1 requests `admin.php?page=pds-2fa&route=challenge`, `enroll`, or `recovery` in the permitted mode. | Only the documented view renders. Unknown route/mode redirects to the correct safe view. | No privileged non-plugin screen is rendered. |
| ROUTE-02 | Pending T1 requests a protected admin screen directly, including `index.php`, `edit.php`, `profile.php`, and `admin.php?page=other`. | Challenge/enrollment redirect according to current mode; target handler does not run. | Record the boundary decision without query strings or credential data. |
| ROUTE-03 | Pending T1 calls any unrelated authenticated `wp_ajax_*` action. | `admin_init` stops dispatch before the callback and returns the documented JSON `403`. | No callback side effect; classify as a blocked route, not a factor failure. |
| ROUTE-04 | Pending T1 calls an unrelated authenticated `admin_post_*` action. | `admin_init` stops dispatch before the callback and returns the documented HTML `403`. | No callback side effect. Public `admin_post_nopriv_*` remains unchanged. |
| ROUTE-05 | Pending T1 calls a PDS POST action without its action-specific nonce, with a stale nonce, or with a different token. | `403` and no state change. | No credential attempt is recorded; safe CSRF/session failure audit only. |
| ROUTE-06 | Pending T1 submits an external, malformed, or non-admin `pds_return_to`. | Redirect falls back to `admin_url()`; no external redirect occurs. | No security state change. |
| ROUTE-07 | Pending T1 makes cookie-authenticated REST request with a valid REST nonce. | PDS returns `WP_Error` `pds_wp_2fa_pending`, HTTP `403`, JSON response, and no redirect. | No REST endpoint callback runs. |
| ROUTE-08 | REST request uses an Application Password or an existing non-null authentication result. | PDS returns the existing result unchanged; no interactive challenge is attempted. | Preserve the upstream authentication audit/provider behavior. |
| ROUTE-09 | REST request has no valid cookie authentication or has a missing/invalid REST nonce. | Core REST authentication behavior remains authoritative; PDS does not infer browser identity from a raw Cookie header or user ID. | No PDS factor failure. |

The boundary relies on WordPress's documented `admin_init` lifecycle for
`admin.php`, `admin-ajax.php`, and `admin-post.php`, and on
`rest_authentication_errors` for REST. See [`admin_init`](https://developer.wordpress.org/reference/hooks/admin_init/),
[admin source](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-admin/admin.php),
[AJAX source](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-admin/admin-ajax.php),
[admin-post source](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-admin/admin-post.php),
and [REST authentication](https://developer.wordpress.org/rest-api/using-the-rest-api/authentication/).

## Policy, environment, and bypass matrix

| ID | Setup and request | Expected result | Audit/rate-limit expectation |
| --- | --- | --- | --- |
| POLICY-01 | Protected unenrolled user is before the effective deadline. | Admin access is allowed only under grace, with a visible setup notice; session remains pending. | Record/refresh policy resolution; no satisfied session state. |
| POLICY-02 | Same user reaches `now == effective_deadline` or later. | Admin is routed to enrollment; grace no longer permits access. | Record deadline enforcement; no automatic extension. |
| POLICY-03 | Global enforcement is disabled. | No interactive admin gate is applied, but role/deadline state continues to reconcile and audit. | Record setting change; do not erase enrollment or session state. |
| POLICY-04 | Non-production bypass is explicitly enabled in local/development/staging. | The documented bypass applies only in that classified environment; WebAuthn remains disabled in phase one. | Record environment and bypass state; never treat bypass as enrollment or session satisfaction. |
| POLICY-05 | The same bypass setting is present while environment resolves to production. | Production enforcement remains active and production WebAuthn policy is unchanged. | Record configuration warning/error; no silent downgrade. |
| POLICY-06 | Database binding has a foreign identity hash/epoch or runtime identity is absent/malformed. | PDS fails closed with configuration/binding error; copied credentials, challenges, sessions, and recovery codes are unusable. | High-severity identity mismatch event without raw identity. |
| POLICY-07 | WebAuthn is attempted in local/development/staging or before the production binding is active. | Method is rejected before protocol verification; TOTP/recovery policy remains available where configured. | Record environment-policy failure; do not count as a malformed browser proof. |
| POLICY-08 | A protected user has multiple active role policies and one stricter deadline. | The earliest role deadline wins; an extension can only move the user deadline later for the current cycle. | Record contributing roles and policy changes, not just the minimum. |

Environment classification follows [`wp_get_environment_type()`](https://developer.wordpress.org/reference/functions/wp_get_environment_type/);
the installation binding and transitions are specified in
[12-installation-identity.md](12-installation-identity.md).

## Abuse, replay, and lifecycle matrix

| ID | Setup and request | Expected result | Audit/rate-limit expectation |
| --- | --- | --- | --- |
| ABUSE-01 | Submit invalid TOTP/recovery/WebAuthn proofs repeatedly from one session. | After the normative #8 bucket threshold, return HTTP `429` with the generic rate-limited response and do not invoke expensive verification beyond the policy boundary. | Bucket survives logout/new-session creation and is bounded by user/provider/install dimensions. |
| ABUSE-02 | Submit failures from several sessions for the same user. | A new session cannot reset the user/provider failure budget; legitimate separate sessions remain distinguishable. | Audit each categorized failure without raw input; test window expiry with the fake clock. |
| ABUSE-03 | Replay a successful TOTP time step for the same method. | Second use is rejected even from another session; accepted step update is conditional. | Record replay/failure; no second satisfied transition. |
| ABUSE-04 | WebAuthn counter is zero/zero, increasing, stale, or concurrently updated. | Zero/zero is valid; increasing update succeeds; non-zero rollback or stale CAS fails and preserves the latest record. | Record safe counter category only; never log browser response bytes. |
| ABUSE-05 | Recovery generation is regenerated while an old code is being submitted. | Old generation is revoked atomically; only the new generation can be used after commit. | Record generation replacement; plaintext codes never enter audit/storage. |
| ABUSE-06 | Last active method is manually revoked or disabled. | Operation is rejected by the final-method rule unless an explicit emergency policy is used. | Record rejection; emergency reset requires high-severity audit and session invalidation. |
| ABUSE-07 | A challenge, method, or recovery row is copied from another installation or epoch. | Repository binding predicate rejects it before provider success. | Record identity mismatch; cleanup/rebind never revives foreign rows. |
| ABUSE-08 | Expired challenge/session/rate-limit rows are present before cleanup. | Security decision rejects them based on status/time; cleanup timing cannot grant access. | Cleanup is operational and safe to rerun; expired secrets/provider state are removed per retention policy. |

Rate-limit behavior follows the project’s TOTP/recovery research and the
provider lifecycle contract in [11-method-lifecycle.md](11-method-lifecycle.md);
all state transitions and compare-and-swap rules are in
[08-persistence.md](08-persistence.md).

## Compatibility matrix

| ID | Setup and request | Expected result | Audit/rate-limit expectation |
| --- | --- | --- | --- |
| COMPAT-01 | Application Password authenticates a REST request to a protected user's endpoint. | Request is not routed to browser 2FA; normal Application Password and capability checks remain. | No interactive factor failure or pending-session row is created. |
| COMPAT-02 | XML-RPC request is made by a valid existing client. | Broad `authenticate`/user filters do not impose an interactive challenge; existing XML-RPC authorization remains. | Preserve existing audit behavior; no browser redirect. |
| COMPAT-03 | WP-CLI invokes ordinary commands and explicit PDS recovery/identity commands. | Browser gate is bypassed; each PDS command applies its own capability/confirmation/production checks and audit. | Commands never print raw secrets except the explicitly confirmed one-time identity generator output. |
| COMPAT-04 | Cron runs cleanup and scheduled maintenance. | Browser gate is bypassed; cleanup remains binding-scoped, idempotent, and unable to revive rows. | Record maintenance outcome without user credential material. |
| COMPAT-05 | Unauthenticated frontend page/form and public `admin_post_nopriv_*` action run. | Existing public behavior remains; PDS does not apply an authenticated pending-session redirect. | No PDS factor failure. |
| COMPAT-06 | WooCommerce uses ordinary frontend, admin, AJAX, or REST requests with a satisfied session. | Requests continue normally subject to ordinary WordPress/WooCommerce capability and nonce checks. | No WooCommerce-specific bypass or duplicated gate is introduced. |
| COMPAT-07 | WooCommerce or another plugin calls an authenticated admin/AJAX/admin-post/REST path with a pending protected session. | PDS blocks the same as any other protected handler before dispatch; documented integration must use the PDS allowlist if it needs a setup route. | One central boundary event; no plugin-specific exemption. |
| COMPAT-08 | Existing third-party REST authentication returns a non-null result before PDS's filter. | PDS preserves that result exactly. | Do not overwrite provider audit or turn it into a browser challenge. |

The non-interactive boundary is based on the existing authentication-hook
research and [WordPress Application Password documentation](https://developer.wordpress.org/advanced-administration/security/application-passwords/).
WooCommerce compatibility is deliberately a normal WordPress compatibility
test, not a mandatory WooCommerce workflow.

## Release QA checklist

- [ ] Every matrix row has an automated test or a documented manual test with
      its fixture and expected response.
- [ ] Direct admin, AJAX, admin-post, and cookie REST tests prove the target
      handler/callback did not run on a pending session.
- [ ] Two-session, logout, WordPress session revocation, challenge replay,
      TOTP replay, recovery race, and WebAuthn counter tests are deterministic.
- [ ] Rate-limit budgets survive session changes and reset only according to
      the configured clock/window policy.
- [ ] Production cannot be weakened by a non-production setting, a cloned
      database, an invalid environment value, or a foreign installation row.
- [ ] Application Passwords, XML-RPC, WP-CLI, cron, frontend, and public
      `admin_post_nopriv_*` regression tests pass.
- [ ] Capability, nonce, re-authentication, and explicit CLI confirmation
      tests cover every administrative state-changing operation.
- [ ] Audit assertions prove no TOTP secret, recovery code/verifier, WebAuthn
      response, private key, raw challenge, session token, or encryption key
      reaches logs, responses, or query strings.
- [ ] The supported Composer/PHP/WordPress matrix installs from a clean build,
      runs migrations idempotently, and passes the full test suite.
- [ ] Manual accessibility and browser checks cover keyboard-only enrollment,
      no-JavaScript recovery, error focus, translated messages, QR alternative
      text, and expired-transaction recovery.
