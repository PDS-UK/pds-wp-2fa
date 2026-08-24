# PDS WP 2FA route contract

Status: implementation decision for parent issue #1
Scope: issue #7, enrollment, challenge, and recovery routes
Decision date: 2026-08-24

This is the normative MVP contract for interactive WordPress cookie
authentication. It follows the session-boundary decision in
[issue #3](https://github.com/PDS-UK/pds-wp-2fa/issues/3) and
[the authentication-hook research](../research/wordpress-auth-hooks.md).

## Decisions

- WordPress owns username/password login at wp-login.php. The plugin observes
  success, captures the exact session token from
  [set_logged_in_cookie](https://developer.wordpress.org/reference/hooks/set_logged_in_cookie/),
  and records a protected login as pending. wp_login is audit/orchestration
  only because it does not provide the token.
- The browser UI is the registered admin page
  admin.php?page=pds-2fa. challenge, enroll, and recovery are the only route
  values. State-changing forms POST to allowlisted
  admin-post.php?action=pds_wp_2fa_* actions.
- The MVP has no PDS AJAX or REST authentication routes. Pending sessions are
  blocked before unrelated AJAX/admin-post callbacks and receive a REST 403.
- A factor satisfies only the current WordPress session. It never sets a
  user-level “2FA complete” flag and never satisfies another browser session.
- Grace is an explicit policy exception for an unenrolled protected user. It
  permits admin access until the deadline but leaves the session pending.
- Valid TOTP, WebAuthn, or one unused recovery code marks the same session
  satisfied. Factor success does not rotate the WordPress session token.
- GET renders only. Enrollment start/completion/cancel, challenge verification,
  and recovery consumption are POST-only, nonce-protected, and token-bound.

## 1. State machine

The plugin session state is one of:

| State | Meaning | Admin access |
| --- | --- | --- |
| not_required | No active role policy or enforcement disabled. | Allowed. |
| pending | WordPress primary authentication passed, required factor not yet completed. | Blocked except for allowlisted routes. |
| satisfied | This session completed a permitted factor or recovery code. | Allowed. |

For a pending session, policy resolves one mode on every protected request:

| Mode | Condition | Behavior |
| --- | --- | --- |
| challenge | At least one active authenticator exists. | Require TOTP/WebAuthn; show recovery only when codes exist. |
| grace | No active authenticator and enrollment deadline is in the future. | Allow admin with a visible notice; allow enrollment. |
| enrollment_required | No active authenticator and deadline is absent/expired. | Allow only enrollment and logout. |

Transitions:

1. Successful protected password login plus set_logged_in_cookie creates
   pending(user, token).
2. Valid TOTP or WebAuthn proof changes only that token to satisfied.
3. Valid recovery proof atomically consumes one code and changes only that
   token to satisfied.
4. A grace request remains pending; once its deadline is reached, the next
   protected request resolves to enrollment_required.
5. Enrollment start creates a short-lived transaction, not an auth state.
   Valid completion atomically activates the authenticator but leaves the
   current session pending. The response shows the one-time recovery bundle
   when applicable and then routes to a separate challenge interaction; only
   that challenge can satisfy the session.
6. Invalid proof, cancel, expiry, browser close, or abandonment revokes the
   transaction and leaves the session pending; grace is re-evaluated.
7. Logout/session destruction invalidates matching plugin state and
   transactions. A new login gets a new pending record.

Partial TOTP/WebAuthn enrollment never grants access. An active authenticator
exists only after method verification and repository commit succeed.

## 2. Routes and redirects

### Views

All views use:

    GET {admin_url}/admin.php?page=pds-2fa&route={challenge|enroll|recovery}[&pds_return_to={url}]

| View | Allowed mode | Purpose |
| --- | --- | --- |
| route=challenge | pending/challenge | TOTP or WebAuthn assertion; link to recovery if available. |
| route=enroll | pending/grace or pending/enrollment_required | Start/continue TOTP or WebAuthn enrollment. |
| route=recovery | pending/challenge with recovery codes | Enter a recovery code instead of the authenticator. |
| route=recovery | satisfied/recovery-management | Re-authenticate and regenerate the current user’s recovery generation; display the new bundle once. |

Unknown route values, stale views, and mismatched modes redirect to the correct
view or safe target; they never load a privileged fallback screen.

### POST actions

| Action | Required state | Success |
| --- | --- | --- |
| pds_wp_2fa_challenge | pending/challenge | Consume proof, set satisfied, 303 to safe target or wp-admin/. |
| pds_wp_2fa_recovery | pending/challenge with codes | Atomically consume one code, set satisfied, 303 to safe target or wp-admin/. |
| pds_wp_2fa_enrollment_begin | pending/grace or pending/enrollment_required | Create short-lived transaction, 303 to route=enroll. |
| pds_wp_2fa_enrollment_complete | Matching active transaction | Commit authenticator, keep the session pending, and render the one-time recovery bundle with a continue control to the challenge view. |
| pds_wp_2fa_enrollment_cancel | Matching active transaction | Revoke transaction, 303 to route=enroll. |
| pds_wp_2fa_recovery_regenerate | satisfied/recovery-management | Require fresh password re-authentication, atomically replace the current user’s generation, show plaintext codes once with `no-store`, and keep the session satisfied. |

WordPress's [admin-post.php source](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-admin/admin-post.php)
and [admin.php source](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-admin/admin.php)
confirm that admin_init fires before authenticated admin_post_* callbacks.
Successful POSTs use PRG except the two one-time recovery-bundle operations,
which render a non-cacheable success page with an explicit continue control.
Proof failures render the same view with HTTP 422 and clear submitted OTP,
recovery code, and raw WebAuthn data.

### Login and target handling

The [login_redirect hook](https://developer.wordpress.org/reference/hooks/login_redirect/)
uses its user argument; the global current user may not yet exist:

- unprotected login: retain WordPress's normal safe target;
- protected admin/default-admin login with an authenticator: route to
  challenge;
- protected admin/default-admin login with grace active: retain the admin
  target and show the grace notice;
- protected admin/default-admin login with expired/absent grace: route to
  enroll; and
- non-admin target: retain the validated target; this document does not gate
  frontend requests.

pds_return_to is navigation data only. It MUST be same-site, an allowed admin
path, and validated with wp_validate_redirect before every use; invalid,
missing, or external values become admin_url(). Use
[wp_safe_redirect](https://developer.wordpress.org/reference/functions/wp_safe_redirect/).
Never put a token, challenge, secret, recovery code, or credential response in
the target.

The logout link uses
[wp_logout_url](https://developer.wordpress.org/reference/functions/wp_logout_url/)
and WordPress's own logout nonce. Before wp_logout clears identity/cookies,
capture the user and token digest, invalidate matching plugin state, and then
allow core logout to finish.

## 3. Request boundaries

The central gate runs early on
[admin_init](https://developer.wordpress.org/reference/hooks/admin_init/).
WordPress documents that it runs for ordinary admin screens, admin-ajax.php,
and admin-post.php.

### Ordinary admin

For a protected cookie session:

| State/mode | Result |
| --- | --- |
| pending/challenge | 302 to route=challenge |
| pending/grace | Continue and render the grace notice |
| pending/enrollment_required | 302 to route=enroll |
| satisfied/not_required | Continue |

The gate fails closed for a protected user with missing/corrupt plugin state.
It MUST NOT trust user meta as proof.

### AJAX

The [admin-ajax.php source](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-admin/admin-ajax.php)
sets DOING_AJAX, fires admin_init, then dispatches wp_ajax_{action}. PDS
registers no AJAX auth action. A pending authenticated request to any AJAX
action is stopped before dispatch with HTTP 403 JSON:

    {"success":false,"data":{"code":"pds_wp_2fa_pending","message":"Complete two-factor authentication before continuing."}}

Unauthenticated wp_ajax_nopriv_* behavior is unchanged. A future PDS AJAX
action requires an explicit allowlist entry, check_ajax_referer, and the same
state/token checks.

### admin-post

The early pending-session gate allows only the five factor/enrollment actions
above in their listed pending states. The sixth recovery-regeneration action is
available only to a satisfied current user and is still capability/nonce/
re-authentication protected.
Pending requests to unrelated admin_post_{action} callbacks receive HTML HTTP
403 with “Complete two-factor authentication before continuing.” and the
callback does not run. Public admin_post_nopriv_* flows remain unchanged.

### REST

PDS registers on rest_authentication_errors after WordPress's Application
Password and cookie handlers. Core registers those at priorities 90 and 100;
see [default-filters.php](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/default-filters.php#L304-L316)
and [rest_cookie_check_errors](https://developer.wordpress.org/reference/functions/rest_cookie_check_errors/).

The filter MUST:

1. return an existing non-null result unchanged;
2. return null when
   [rest_get_authenticated_app_password](https://developer.wordpress.org/reference/functions/rest_get_authenticated_app_password/)
   reports an Application Password;
3. return null when the request was not authenticated by a valid WordPress
   login cookie; do not infer this from an arbitrary Cookie header or user ID;
4. return WP_Error code pds_wp_2fa_pending, message “Complete two-factor
   authentication before using this REST API.”, status 403 for a pending
   cookie session; and
5. return null for satisfied/non-protected cookie sessions.

WordPress's [REST authentication documentation](https://developer.wordpress.org/rest-api/using-the-rest-api/authentication/)
states that cookie REST requests require a wp_rest nonce and that missing nonce
makes the request unauthenticated. Invalid/missing REST nonces retain core
behavior; PDS MUST NOT redirect JSON requests. Application Passwords and other
non-cookie providers never enter the interactive challenge.

### Non-interactive channels

The browser gate classifies these before applying the admin/REST policy:

| Channel | Signal | Decision |
| --- | --- | --- |
| Application Password | REST Application Password result | Preserve; no browser challenge. |
| XML-RPC | XMLRPC_REQUEST | Bypass this browser-only gate; do not reject in broad auth filters. See [core XML-RPC source](https://github.com/WordPress/wordpress-develop/blob/trunk/src/xmlrpc.php). |
| WP-CLI | defined('WP_CLI') && WP_CLI | Bypass browser routes; use explicit CLI authorization/audit. See [WP-CLI implementation details](https://make.wordpress.org/cli/handbook/contributions/implementation-details/). |
| Cron | wp_doing_cron()/DOING_CRON | Bypass browser routes; scheduled cleanup runs normally. See [wp_doing_cron](https://developer.wordpress.org/reference/functions/wp_doing_cron/) and the [Cron Handbook](https://developer.wordpress.org/plugins/cron/). |
| Frontend browser | Not admin, REST, XML-RPC, CLI, or cron | No gate in this document. |

These are scope boundaries, not blanket authorization: existing capability,
API, XML-RPC, CLI, and cron checks remain in force.

## 4. Nonces, tokens, and transactions

Each POST has its own nonce action equal to its action name:
pds_wp_2fa_challenge, pds_wp_2fa_recovery, pds_wp_2fa_enrollment_begin,
pds_wp_2fa_enrollment_complete, pds_wp_2fa_enrollment_cancel, and
pds_wp_2fa_recovery_regenerate. Templates emit
wp_nonce_field; handlers verify with check_admin_referer/wp_verify_nonce.
WordPress documents nonces as request-intent protection, not authentication;
see [wp_create_nonce](https://developer.wordpress.org/reference/functions/wp_create_nonce/)
and [check_admin_referer](https://developer.wordpress.org/reference/functions/check_admin_referer/).

Every POST also requires the current logged-in user, current token from
[wp_get_session_token](https://developer.wordpress.org/reference/functions/wp_get_session_token/),
matching token digest, installation, state, and route transaction. Store only:

    session_key = HMAC-SHA-256(token, wp_salt('auth'))

Never store raw tokens in records, URLs, HTML, logs, or error messages. A
method transaction is server-created, short-lived (MVP maximum: 10 minutes),
bound to user/token/installation/operation, and atomically consumed or
revoked. The client never supplies the expected WebAuthn challenge.

Challenge/enrollment/recovery pages MUST send Cache-Control: no-store. Do not
log request bodies, TOTP secrets, recovery codes, WebAuthn responses, or
challenge values. The factor transition keeps the existing WordPress cookie;
if it expires or changes before POST, reject and return through WordPress login.

## 5. Failure messages

Messages are translatable fixed source strings; never expose library
exceptions, credential IDs, or account-enumeration details.

| Code | Behavior and message |
| --- | --- |
| pds_wp_2fa_invalid_totp | 422: “That verification code was not accepted. Check the code and try again.” |
| pds_wp_2fa_invalid_webauthn | 422: “That security-key response was not accepted. Try again or use another method.” |
| pds_wp_2fa_webauthn_cancelled | 422/info, not counted: “No security-key response was received. Try again or use another method.” |
| pds_wp_2fa_invalid_recovery | 422: “That recovery code was not accepted. Check the code and try again.” |
| pds_wp_2fa_enrollment_invalid | 422: “We could not verify that setup. Check the code or security-key response and try again.” |
| pds_wp_2fa_enrollment_expired | Discard transaction, render enroll: “Your setup session expired. Start enrollment again.” |
| pds_wp_2fa_nonce_invalid | 403, no state change: “This form has expired or cannot be verified. Refresh the page and try again.” |
| pds_wp_2fa_session_expired | 401/login redirect: “Your sign-in session expired. Sign in again to continue.” |
| pds_wp_2fa_rate_limited | HTTP 429 from the central limiter: “Too many verification attempts. Wait and try again, or use another recovery option.” |
| pds_wp_2fa_pending | Admin block: “Complete two-factor authentication before continuing.”; REST: “Complete two-factor authentication before using this REST API.” |
| pds_wp_2fa_grace_notice | Continue admin: “Two-factor authentication setup is required. You can continue until {localized deadline}; set it up now.” |

Primary password failures remain WordPress failures. The plugin may audit
wp_login_failed but MUST NOT replace its errors. Numeric attempt limits belong
to the central security limiter; routes consume its typed result.

## 6. Abandoned enrollment and recovery

The MVP enrollment transaction expires after 10 minutes. Closing the browser,
losing connectivity, cancelling, or expiry leaves the session pending, revokes
uncommitted secret/challenge material, activates no credential, and re-evaluates
grace/enrollment_required on the next request. Logout invalidates it immediately.

Recovery is an alternate factor for an enrolled user who cannot use an
authenticator. The handler normalizes the documented presentation, verifies the
stored verifier, and consumes exactly one matching code in the same transaction
that sets the current session satisfied. A satisfied user can regenerate their
own generation through the separate re-authenticated management action above;
it replaces the old generation atomically and displays plaintext only once.
Reused, revoked, expired,
user-mismatched, installation-mismatched, or already-consumed codes fail.
Recovery does not create an authenticator; if none remains, the next new login
is enrollment_required, while the current session may reach supported recovery
or enrollment work. Cryptographic format follows [issue #6](https://github.com/PDS-UK/pds-wp-2fa/issues/6).

## 7. Accessibility

Meet the [WordPress accessibility coding standards](https://make.wordpress.org/accessibility/2015/12/15/accessibility-code-standards-for-wordpress-core/)
and text error identification in [WCAG 2.2 SC 3.3.1](https://www.w3.org/WAI/WCAG22/Understanding/error-identification):

- one meaningful h1, logical headings, semantic forms, explicit label/input
  associations, fieldset/legend for method choices, keyboard operation, and
  visible focus;
- text errors linked with aria-describedby and aria-invalid, an error
  summary/live region, and focus moved to the summary or first invalid field;
- notices/statuses exposed as text, not color-only;
- TOTP input with inputmode=numeric and autocomplete=one-time-code, a label,
  and acceptance of documented separators;
- recovery flow usable without JavaScript;
- WebAuthn controls with accessible name, progress/status announcement,
  keyboard path, and TOTP/recovery alternative;
- QR enrollment never the only path: expose selectable TOTP secret text;
- no silent timeout while typing; expired transactions explain how to restart;
- no submitted OTP/recovery value echoed after failure; recovery codes shown
  once are selectable and do not require copying to continue; and
- localized, RTL-safe, responsive, sufficient-contrast UI.

## Acceptance checklist

- [ ] Protected password login creates token-bound pending state and routes
      admin/default-admin login to challenge or enrollment; grace continues
      with a notice.
- [ ] Only the three exact views and six exact POST actions are allowed; the
      recovery-regeneration action is available only to an already satisfied,
      re-authenticated current user.
- [ ] TOTP, WebAuthn, and single-use recovery success satisfy only the current
      token; enrollment is atomic and abandoned enrollment grants nothing.
- [ ] Forced/grace deadlines, stale sessions, logout, and separate sessions
      behave as specified.
- [ ] Early admin_init blocks direct admin, arbitrary AJAX, and arbitrary
      admin-post before callbacks; REST returns JSON 403 without redirects.
- [ ] Application Passwords, non-cookie REST, XML-RPC, WP-CLI, cron, and public
      admin_post_nopriv_* flows are not sent to browser routes.
- [ ] Nonces, token digests, transaction expiry/consumption, no-store/no-log,
      safe redirects, exact messages, and accessibility have tests.

## Primary sources

- [REST authentication](https://developer.wordpress.org/rest-api/using-the-rest-api/authentication/)
- [set_logged_in_cookie](https://developer.wordpress.org/reference/hooks/set_logged_in_cookie/)
- [login_redirect](https://developer.wordpress.org/reference/hooks/login_redirect/)
- [admin_init](https://developer.wordpress.org/reference/hooks/admin_init/)
- [wp_get_session_token](https://developer.wordpress.org/reference/functions/wp_get_session_token/)
- [WP_Session_Tokens](https://developer.wordpress.org/reference/classes/wp_session_tokens/)
- [wp_create_nonce](https://developer.wordpress.org/reference/functions/wp_create_nonce/)
- [check_admin_referer](https://developer.wordpress.org/reference/functions/check_admin_referer/)
- [wp_safe_redirect](https://developer.wordpress.org/reference/functions/wp_safe_redirect/)
- [wp_logout](https://developer.wordpress.org/reference/functions/wp_logout/)
- [wp_logout_url](https://developer.wordpress.org/reference/functions/wp_logout_url/)
- [rest_authentication_errors](https://developer.wordpress.org/reference/hooks/rest_authentication_errors/)
- [rest_cookie_check_errors](https://developer.wordpress.org/reference/functions/rest_cookie_check_errors/)
- [rest_get_authenticated_app_password](https://developer.wordpress.org/reference/functions/rest_get_authenticated_app_password/)
- [Application Passwords](https://developer.wordpress.org/advanced-administration/security/application-passwords/)
- [admin.php source](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-admin/admin.php)
- [admin-ajax.php source](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-admin/admin-ajax.php)
- [admin-post.php source](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-admin/admin-post.php)
- [REST core source](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/rest-api.php)
- [default REST filters](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/default-filters.php)
- [XML-RPC source](https://github.com/WordPress/wordpress-develop/blob/trunk/src/xmlrpc.php)
- [WP-CLI implementation details](https://make.wordpress.org/cli/handbook/contributions/implementation-details/)
- [wp_doing_cron](https://developer.wordpress.org/reference/functions/wp_doing_cron/)
- [Cron Handbook](https://developer.wordpress.org/plugins/cron/)
- [WordPress accessibility coding standards](https://make.wordpress.org/accessibility/2015/12/15/accessibility-code-standards-for-wordpress-core/)
- [WCAG 2.2 SC 3.3.1](https://www.w3.org/WAI/WCAG22/Understanding/error-identification)
