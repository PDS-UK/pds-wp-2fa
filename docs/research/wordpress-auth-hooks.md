# WordPress authentication hook map for pending 2FA sessions

- Context: [Map WordPress authentication hooks for explicit pending-session admin gating](https://github.com/PDS-UK/pds-wp-2fa/issues/3)
- Repository: [PDS-UK/pds-wp-2fa](https://github.com/PDS-UK/pds-wp-2fa)
- Research date: 24 August 2026
- Scope: WordPress core source and official WordPress developer documentation only. WP-CLI references are from the official WP-CLI handbook.

## Decision summary

The plugin should treat 2FA as a per-login-session state, not as a user-level boolean:

```text
primary password accepted
        ↓
session token issued by WordPress
        ↓
plugin state for (user, session token) = pending
        ↓
TOTP/WebAuthn/recovery challenge succeeds
        ↓
plugin state for (user, session token) = satisfied
```

The session-token binding and the request gate are separate responsibilities:

1. Observe successful interactive login and capture the exact token that WordPress places in the authentication cookie. The most useful core hook for this is [`set_logged_in_cookie`](https://developer.wordpress.org/reference/hooks/set_logged_in_cookie/), whose arguments include the user ID and session token. [`wp_login`](https://developer.wordpress.org/reference/hooks/wp_login/) is useful for login auditing and orchestration, but does not receive the token.
2. Use [`login_redirect`](https://developer.wordpress.org/reference/hooks/login_redirect/) to send a protected login to the challenge or enrolment screen. This is user experience, not the security boundary.
3. Enforce the state centrally at [`admin_init`](https://developer.wordpress.org/reference/hooks/admin_init/). Core runs this hook for ordinary administration screens as well as [`admin-ajax.php`](https://developer.wordpress.org/reference/files/wp-admin/admin-ajax.php) and [`admin-post.php`](https://developer.wordpress.org/reference/files/wp-admin/admin-post.php), before their action handlers or normal admin screen handlers run.
4. Add a separate [`rest_authentication_errors`](https://developer.wordpress.org/reference/hooks/rest_authentication_errors/) policy for REST requests authenticated by the normal WordPress cookie and REST nonce. Preserve non-cookie mechanisms, including Application Passwords and third-party authentication, by respecting the filter's existing result and excluding Application Passwords.
5. Do not turn the generic password filters into a 2FA rejection point. [`authenticate`](https://developer.wordpress.org/reference/hooks/authenticate/) and [`wp_authenticate_user`](https://developer.wordpress.org/reference/hooks/wp_authenticate_user/) are used by more than the interactive browser login path. Rejecting there would risk breaking XML-RPC, REST, Application Passwords, and other programmatic authentication.
6. Explicitly classify and bypass browser 2FA enforcement for [`WP_CLI`](https://make.wordpress.org/cli/handbook/contributions/implementation-details/), [`XMLRPC_REQUEST`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/xmlrpc.php), and [`wp_doing_cron()`](https://developer.wordpress.org/reference/functions/wp_doing_cron/). These mechanisms do not have an interactive browser session to complete a TOTP/WebAuthn challenge.

This gives one central admin gate without assuming that every authenticated WordPress request is an interactive browser login.

## 1. Password authentication and login completion

### Credential validation

[`wp_signon()`](https://developer.wordpress.org/reference/functions/wp_signon/) is the normal high-level login function. In current core it:

1. calls [`wp_authenticate()`](https://developer.wordpress.org/reference/functions/wp_authenticate/) with the submitted username and password;
2. calls [`wp_set_auth_cookie()`](https://developer.wordpress.org/reference/functions/wp_set_auth_cookie/) after a successful `WP_User` result; and
3. fires [`wp_login`](https://developer.wordpress.org/reference/hooks/wp_login/) after the cookie has been set.

The current implementation is in [`src/wp-includes/user.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/user.php). The developer reference also notes that `wp_signon()` does not set the current user; the current user may not be available until the normal WordPress initialization sequence.

[`wp_authenticate()`](https://developer.wordpress.org/reference/functions/wp_authenticate/) applies the [`authenticate`](https://developer.wordpress.org/reference/hooks/authenticate/) filter. Core uses that filter for the ordinary username/password path and for additional authentication providers. The [`wp_authenticate_user`](https://developer.wordpress.org/reference/hooks/wp_authenticate_user/) filter runs after the user has been found and before the login is completed; its arguments include the plaintext password, so it is also a particularly unsuitable place for plugin-level 2FA state management.

The failure hook [`wp_login_failed`](https://developer.wordpress.org/reference/hooks/wp_login_failed/) is appropriate for audit or rate-limit signals, but not for establishing a pending session because no successful WordPress session exists at that point.

### Login completion

The [`wp_login`](https://developer.wordpress.org/reference/hooks/wp_login/) action fires after [`wp_set_auth_cookie()`](https://developer.wordpress.org/reference/functions/wp_set_auth_cookie/). It receives the username and `WP_User`, but not the newly created session token. Therefore, it is not sufficient by itself to bind plugin state to one login session.

`wp_set_auth_cookie()` creates a token through [`WP_Session_Tokens::create()`](https://developer.wordpress.org/reference/classes/wp_session_tokens/) when a token is not supplied. Immediately before setting the cookies, it fires both [`set_auth_cookie`](https://developer.wordpress.org/reference/hooks/set_auth_cookie/) and [`set_logged_in_cookie`](https://developer.wordpress.org/reference/hooks/set_logged_in_cookie/). Both hooks include the token as an argument. The `logged_in` cookie is the practical session identity for subsequent WordPress requests, and `set_logged_in_cookie` is the clearest point at which to capture the outgoing token for a newly created browser session.

The [`login_redirect`](https://developer.wordpress.org/reference/hooks/login_redirect/) filter is applied by [`wp-login.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-login.php) after `wp_signon()` succeeds. It is a good place to route a protected login to a challenge or enrolment page. It cannot be the only enforcement point because direct requests to `/wp-admin/`, programmatic login callers, AJAX, admin-post, and REST do not all pass through that redirect.

### Recommended login boundary

Use the following division of responsibility:

| Responsibility | Recommended core signal | Reason |
| --- | --- | --- |
| Observe completed normal login | `wp_login` | Confirms that WordPress accepted the primary credentials. |
| Capture the session identity | `set_logged_in_cookie` (or `set_auth_cookie`) | Supplies user ID and the exact token being issued. |
| Route the browser | `login_redirect` | Gives the user a challenge/enrolment path after login. |
| Record failed primary authentication | `wp_login_failed` | Useful for audit and rate limiting only. |
| Reject or accept primary credentials | `authenticate`, `wp_authenticate_user` | Leave these to primary authentication; they are too broad for interactive-only 2FA. |

The implementation should not expect `wp_get_session_token()` to return the new token during the response that creates the cookie. [`wp_get_session_token()`](https://developer.wordpress.org/reference/functions/wp_get_session_token/) reads the incoming `logged_in` cookie, so it becomes useful for binding the next request, while the token argument on `set_logged_in_cookie` is needed during the initial response.

## 2. Session tokens and explicit state

[`WP_Session_Tokens`](https://developer.wordpress.org/reference/classes/wp_session_tokens/) manages a user's sessions. The default manager is [`WP_User_Meta_Session_Tokens`](https://developer.wordpress.org/reference/classes/wp_user_meta_session_tokens/), and core stores session information such as expiration, login time, IP address, and user agent. The manager can be replaced through [`session_token_manager`](https://developer.wordpress.org/reference/hooks/session_token_manager/), and session information can be extended through [`attach_session_information`](https://developer.wordpress.org/reference/hooks/attach_session_information/).

For this plugin, the safest conceptual model is a plugin-owned record keyed by the user ID and a one-way hash of the WordPress session token:

```text
user_id
session_token_hash
state: pending | enrollment_required | satisfied
created_at
updated_at
```

The plaintext WordPress token should not be stored in the plugin table. The record must be session-specific; an enrolled user still starts each new interactive login in `pending`, and a completed 2FA challenge changes only the current session to `satisfied`.

Using a user-meta flag such as `user_has_completed_2fa = true` would incorrectly authenticate every future session. Likewise, changing WordPress's global session-token manager merely to attach the plugin state would create a broad integration surface. A dedicated plugin record, with cleanup when the WordPress session is destroyed, keeps the security state explicit and testable.

[`determine_current_user`](https://developer.wordpress.org/reference/hooks/determine_current_user/) and [`wp_validate_auth_cookie()`](https://developer.wordpress.org/reference/functions/wp_validate_auth_cookie/) are useful for understanding how WordPress establishes the current user, but they are not recommended as the plugin's redirect gate. Returning a different user or returning no user from `determine_current_user` changes WordPress's authentication result and can break API or non-interactive callers. `wp_validate_auth_cookie()` also participates in REST cookie authentication.

The [`auth_cookie_valid`](https://developer.wordpress.org/reference/hooks/auth_cookie_valid/) action exposes the validated cookie elements, including the token. It is useful for audit and observability, but it occurs during cookie validation rather than at a central response-routing boundary. Use it to observe or reconcile state if needed; do not depend on it as the only admin gate.

## 3. Normal administration request lifecycle

The current [`wp-admin/admin.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-admin/admin.php) entry point defines `WP_ADMIN`, loads WordPress and the admin APIs, calls [`auth_redirect()`](https://developer.wordpress.org/reference/functions/auth_redirect/), and then fires [`admin_init`](https://developer.wordpress.org/reference/hooks/admin_init/). The `admin_init` action runs before the screen-specific handlers and admin page hooks.

This is the central browser-admin boundary. A user who has passed the WordPress password check has already satisfied `auth_redirect()` from WordPress's point of view, so a pending 2FA state must be checked after WordPress identifies the user and before the requested admin handler runs.

The gate should be registered at an early `admin_init` priority and should:

1. classify the request;
2. bypass non-interactive execution contexts;
3. identify the current user and the incoming session token;
4. resolve the user's strongest role policy and current enrolment/grace state;
5. allow a satisfied session or an eligible grace-period session; and
6. for a pending or enrolment-required session, allow only the plugin's challenge/enrolment resources and deny or safely redirect every other admin request.

`admin_init` is preferable to adding checks to individual screens. It covers direct requests such as `/wp-admin/`, `index.php`, `edit.php`, `profile.php`, and `admin.php?page=...` through the same central path.

[`is_admin()`](https://developer.wordpress.org/reference/functions/is_admin/) is not an authorization check. It identifies an administration context, and `admin-ajax.php` and `admin-post.php` also run with admin context. Use it with request classification signals rather than treating it as proof that a request is an ordinary admin screen.

## 4. AJAX and admin-post requests

### `admin-ajax.php`

The current [`wp-admin/admin-ajax.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-admin/admin-ajax.php) defines `DOING_AJAX` and `WP_ADMIN`, loads WordPress, fires `admin_init`, and then dispatches to either [`wp_ajax_{$action}`](https://developer.wordpress.org/reference/hooks/wp_ajax_action/) or `wp_ajax_nopriv_{$action}`.

This means the same early `admin_init` gate runs before the AJAX callback. A pending protected user must not be able to call an arbitrary authenticated AJAX action and reach privileged code without 2FA. The plugin should allow only a strict, namespaced allowlist of its own challenge/enrolment actions while the session is pending. It should not allow all AJAX merely because the action is sent to `admin-ajax.php`; frontend code also uses that endpoint, and authenticated AJAX can perform meaningful state changes.

Use [`wp_doing_ajax()`](https://developer.wordpress.org/reference/functions/wp_doing_ajax/) as the primary AJAX classification signal. The action value can be used to identify the plugin's routes only after treating it as untrusted input and applying a strict allowlist.

### `admin-post.php`

The current [`wp-admin/admin-post.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-admin/admin-post.php) also defines `WP_ADMIN`, loads WordPress and admin APIs, fires `admin_init`, and dispatches to [`admin_post_{$action}`](https://developer.wordpress.org/reference/hooks/admin_post_action/) or its unauthenticated counterpart.

`admin-post.php` is a generic form/action endpoint and can be used by frontend forms as well as the admin. The central gate should therefore apply to authenticated protected users but must not globally block unauthenticated `admin_post_nopriv_*` flows. While a protected session is pending, allow only the plugin's own challenge/enrolment actions and block the rest before dispatch.

The practical result is one admin hook with three request classes:

```text
admin.php       → ordinary admin screen gate
admin-ajax.php  → gate before wp_ajax_* dispatch
admin-post.php  → gate before admin_post_* dispatch
```

## 5. REST authentication

REST is a separate request lifecycle. [`rest_api_loaded()`](https://developer.wordpress.org/reference/functions/rest_api_loaded/) defines `REST_REQUEST`, creates the REST server, serves the request, and exits; it does not pass through `admin_init`.

The official [REST API authentication documentation](https://developer.wordpress.org/rest-api/using-the-rest-api/authentication/) distinguishes cookie authentication from Application Passwords. Cookie-authenticated REST requests require a valid `wp_rest` nonce. If the nonce is absent, core clears the current user for that request and treats it as unauthenticated. Application Passwords use HTTP Basic authentication over HTTPS and are intended for API use.

The central REST authentication filter is [`rest_authentication_errors`](https://developer.wordpress.org/reference/hooks/rest_authentication_errors/). Its contract is important:

- return an existing non-`null` result unchanged;
- return `null` when the authentication method does not apply; and
- return a `WP_Error` for an authentication failure.

Current core's [`rest_cookie_check_errors()`](https://developer.wordpress.org/reference/functions/rest_cookie_check_errors/) is attached to this filter at priority 100. Application Password validation is attached earlier, at priority 90. The plugin should therefore use a later filter priority, for example 110, so core has classified the request, while still preserving an existing result.

The REST gate should only apply when all of the following are true:

1. the request is a REST request;
2. the request is authenticated through the WordPress cookie/session path;
3. the current user is protected and the plugin's token-bound state is not `satisfied`; and
4. the request is not authenticated by an Application Password or another non-cookie mechanism.

Core exposes the Application Password result through [`rest_get_authenticated_app_password()`](https://developer.wordpress.org/reference/functions/rest_get_authenticated_app_password/), and the current REST implementation tracks cookie authentication status internally. The plugin should use those core signals together with the incoming session token, rather than assuming that every REST request made by a logged-in user is browser-cookie authentication.

The filter must not turn Application Password requests into interactive 2FA challenges. It must also preserve a non-`null` result supplied by another authentication provider. This is the key rule for avoiding breakage of API clients while still protecting REST calls initiated by a pending browser session.

[`rest_pre_dispatch`](https://developer.wordpress.org/reference/hooks/rest_pre_dispatch/) is a useful defence-in-depth or route-allowlist hook because it runs before endpoint dispatch, but it is not the primary authentication boundary. [`rest_request_after_callbacks`](https://developer.wordpress.org/reference/hooks/rest_request_after_callbacks/) is too late and is not called for authentication failures, so it must not be the only enforcement point.

For a pending cookie-authenticated browser session, the recommended policy is to allow only the plugin's own REST challenge/enrolment routes, if REST is used for that UI, and return a normal REST authentication error for other routes. A browser redirect from a REST request is likely to be mishandled by callers and should not be the default response.

## 6. Logout and session destruction

[`wp_logout()`](https://developer.wordpress.org/reference/functions/wp_logout/) destroys the current WordPress session, clears the authentication cookies, sets the current user to zero, and fires the `wp_logout` action. [`clear_auth_cookie`](https://developer.wordpress.org/reference/hooks/clear_auth_cookie/) fires immediately before the cookies are cleared.

The plugin should use `clear_auth_cookie` or the session-destruction path to remove or invalidate the matching pending/satisfied plugin state, and use `wp_logout` for an audit event if the user ID is still needed. The timing matters: by the time `wp_logout` runs, the current user has been reset, so code that needs the incoming token or user should capture it earlier.

Administrative reset should destroy the user's WordPress sessions using the core session APIs, then invalidate all matching plugin state and recovery/authenticator records as required by the product policy. This prevents an old satisfied session from surviving a reset.

## 7. Application Passwords

Application Passwords are explicitly a non-interactive API mechanism. The official [Application Passwords documentation](https://developer.wordpress.org/advanced-administration/security/application-passwords/) describes them as credentials for API authentication, and core's [`wp_authenticate_application_password()`](https://developer.wordpress.org/reference/functions/wp_authenticate_application_password/) identifies REST and XML-RPC API requests through `REST_REQUEST` and `XMLRPC_REQUEST` (with the [`application_password_is_api_request`](https://developer.wordpress.org/reference/hooks/application_password_is_api_request/) filter available for extensions).

The success and failure hooks are [`application_password_did_authenticate`](https://developer.wordpress.org/reference/hooks/application_password_did_authenticate/) and [`application_password_failed_authentication`](https://developer.wordpress.org/reference/hooks/application_password_failed_authentication/). The [`wp_authenticate_application_password_errors`](https://developer.wordpress.org/reference/hooks/wp_authenticate_application_password_errors/) action can add validation errors after a candidate has been checked.

None of these should be used as a blanket 2FA rejection point in phase one. The plugin may audit their use, but must not require a browser TOTP/WebAuthn challenge for Application Password requests. The same principle applies if an API client uses an Application Password for a user whose interactive browser sessions require 2FA.

## 8. XML-RPC

The current [`xmlrpc.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/xmlrpc.php) defines `XMLRPC_REQUEST`, clears `$_COOKIE`, loads WordPress, creates the XML-RPC server, and serves the request. It intentionally does not use the browser's authentication cookie.

The XML-RPC server's [`login()`](https://developer.wordpress.org/reference/classes/wp_xmlrpc_server/login/) method calls `wp_authenticate()` with the credentials supplied for that XML-RPC call, sets the current user, and returns the user to the method. It does not create the normal browser login session. [`xmlrpc_login_error`](https://developer.wordpress.org/reference/hooks/xmlrpc_login_error/) is an error filter, and [`xmlrpc_call`](https://developer.wordpress.org/reference/hooks/xmlrpc_call/) fires after an XML-RPC user has authenticated and before the method runs.

Because XML-RPC has no interactive browser challenge in phase one, the admin gate must bypass requests classified by `XMLRPC_REQUEST`. Do not add the pending-session redirect to `authenticate`, `wp_authenticate_user`, or `xmlrpc_call`; doing so would turn a browser-only requirement into a protocol-wide requirement and would break the stated non-interactive compatibility boundary.

## 9. WP-CLI

The official [WP-CLI implementation details](https://make.wordpress.org/cli/handbook/contributions/implementation-details/) document that WP-CLI defines `WP_CLI` before loading WordPress and bootstraps WordPress through the CLI runner. The official [command cookbook](https://make.wordpress.org/cli/handbook/guides/commands-cookbook/) describes the normal `after_wp_load` command lifecycle, and the [configuration reference](https://make.wordpress.org/cli/handbook/references/config/) documents CLI contexts such as `auto`, `admin`, and `cli`.

The plugin's browser gate must bail when `defined('WP_CLI') && WP_CLI` is true. It should register its own commands through [`WP_CLI::add_command()`](https://make.wordpress.org/cli/handbook/references/internal-api/wp-cli-add-command/) and call domain services directly rather than trying to simulate a browser cookie/session or passing through `admin_init` as an authorization shortcut.

The plugin's WP-CLI administrative commands can still perform capability-equivalent checks appropriate to CLI operation and should write audit events with an explicit source such as `WP-CLI`. They should not require an interactive TOTP/WebAuthn challenge, and they should not assume `is_admin()` means a browser admin screen.

## 10. Cron and background execution

WordPress cron is a background execution context, not an interactive session. [`wp_doing_cron()`](https://developer.wordpress.org/reference/functions/wp_doing_cron/) reports the `DOING_CRON` state. The official [Cron Handbook](https://developer.wordpress.org/plugins/cron/) describes scheduled callbacks, and the current [`wp-cron.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-cron.php) entry point defines `DOING_CRON` before loading WordPress for scheduled work.

The browser 2FA gate must bypass `wp_doing_cron()`/`DOING_CRON`. Scheduled audit retention cleanup is a suitable cron task, but it must not be forced through a browser challenge. The same classification should be applied before any generic admin gate is considered; URL matching against `/wp-cron.php` alone is not a sufficient request classifier.

## 11. Request classification for the central policy

The following classification is the recommended policy model. The signals are classification inputs, not authorization by themselves.

| Request class | Core signals | Authentication model | Pending-session policy |
| --- | --- | --- | --- |
| Ordinary admin screen | `WP_ADMIN`, not AJAX, not REST, not CLI/XML-RPC/cron; normally enters `admin.php` | WordPress auth cookie | Enforce at early `admin_init`. Allow only satisfied sessions, eligible grace-period sessions, or the plugin's challenge/enrolment routes. |
| Authenticated admin AJAX | `wp_doing_ajax()` / `DOING_AJAX` | Usually WordPress auth cookie | Enforce at `admin_init` before `wp_ajax_*`. Strictly allowlist plugin challenge/enrolment actions; do not allow arbitrary actions. |
| Admin-post | `WP_ADMIN` and `admin-post.php`, not AJAX | Cookie or unauthenticated action | Enforce authenticated protected users at `admin_init`; leave `admin_post_nopriv_*` behavior untouched; allow only plugin actions while pending. |
| REST with browser cookie | `REST_REQUEST`, valid cookie and REST nonce, current user protected | WordPress auth cookie | Enforce through `rest_authentication_errors` after core cookie processing. Allow plugin routes only while pending. |
| REST with Application Password | `REST_REQUEST`, Application Password status/UUID available | Application Password | Bypass interactive 2FA. Preserve core's non-`null` authentication result. |
| REST with another provider | `REST_REQUEST`, non-cookie provider result | Provider-specific | Preserve the existing `rest_authentication_errors` result; do not assume it is an interactive cookie session. |
| XML-RPC | `XMLRPC_REQUEST` | Per-call username/password or Application Password | Bypass interactive 2FA in phase one. |
| WP-CLI | `WP_CLI` true | CLI bootstrap and command arguments | Bypass browser gate. Use explicit CLI command services and audit source. |
| Cron | `wp_doing_cron()` / `DOING_CRON` | Background callback | Bypass browser gate. Run scheduled cleanup normally. |
| Ordinary frontend browser request | Not an admin, REST, XML-RPC, CLI, or cron request | Cookie or anonymous | Do not apply the `/wp-admin` gate. Optional frontend/WooCommerce integration can be layered separately. |

The classifier should be evaluated before redirecting or returning an error. In particular, a pending user must not be treated as a normal admin user merely because the request is an authenticated AJAX request, and an Application Password request must not be mistaken for a pending browser cookie session.

## 12. Proposed state transition and enforcement model

The core-facing behavior should be modelled as follows:

```text
Login response:
  wp_login + set_logged_in_cookie(token)
    → resolve role policy
    → create pending session record for hash(token)
    → login_redirect to challenge or enrolment when required

Subsequent request:
  classify request
    → CLI/XML-RPC/cron: bypass browser 2FA gate
    → ordinary frontend: no admin gate
    → admin/AJAX/admin-post: enforce at admin_init
    → REST: enforce cookie-auth state at rest_authentication_errors

Protected interactive request:
  no required policy       → continue
  grace period active      → continue and show enrolment notice where appropriate
  state = satisfied        → continue
  state = pending           → permit only challenge resources
  state = enrollment_required → permit only enrolment resources

Successful second factor:
  verify challenge, expiry, replay/session binding, and rate limit
    → state(hash(token)) = satisfied
    → continue to intended admin destination

Logout/reset/session destruction:
  invalidate matching plugin state
    → old satisfied state cannot be replayed on a new session
```

The challenge itself must remain bound to the user and session token, with a short expiry and replay protection. That is separate from the WordPress hook map, but it is essential: a correct request gate cannot compensate for a challenge that can be moved between accounts or sessions.

## 13. Hook recommendations and non-recommendations

### Use as central controls

- `set_logged_in_cookie` (or `set_auth_cookie`) for the token-bearing login boundary.
- `login_redirect` for post-password browser routing.
- `admin_init` for ordinary admin, `admin-ajax.php`, and `admin-post.php` enforcement before dispatch.
- `rest_authentication_errors` for cookie-authenticated REST enforcement, preserving non-cookie mechanisms.
- `clear_auth_cookie` plus `wp_logout`/session-destruction handling for state cleanup and audit.

### Use for observation, not as the only gate

- `wp_login` for successful primary-login observation and audit.
- `auth_cookie_valid` for cookie/session observation.
- `wp_login_failed` for failed primary-login audit and rate limiting.
- `application_password_did_authenticate` and `application_password_failed_authentication` for API audit signals.
- `xmlrpc_call` for optional XML-RPC audit, not interactive 2FA enforcement.

### Do not use as a blanket interactive 2FA gate

- `authenticate` and `wp_authenticate_user`, because they are broader than browser login.
- `determine_current_user`, because changing its result changes WordPress identity resolution.
- `is_admin()`, because it is context detection rather than authorization and also covers AJAX/admin-post.
- `rest_request_after_callbacks`, because it is too late and does not cover authentication failures.
- Individual screen hooks, because direct admin, AJAX, and admin-post routes would create bypass gaps.

## 14. Security and bypass checks for implementation later

The eventual implementation should have tests for at least these routes and transitions:

1. Direct requests to `/wp-admin/`, `/wp-admin/index.php`, `/wp-admin/edit.php`, `/wp-admin/profile.php`, and `/wp-admin/admin.php?page=...` while the session is pending.
2. Authenticated `admin-ajax.php` calls to both the plugin's allowed challenge action and unrelated privileged actions.
3. Authenticated and unauthenticated `admin-post.php` actions, including `admin_post_nopriv_*`.
4. REST with a valid cookie and `wp_rest` nonce while pending, with the plugin route allowed and unrelated privileged routes rejected.
5. REST without a nonce, which core must continue to treat as unauthenticated.
6. REST with an Application Password, which must remain usable without an interactive challenge.
7. XML-RPC password and Application Password authentication, which must remain outside the browser gate.
8. WP-CLI plugin commands with no browser cookies and with `WP_ADMIN`-like CLI contexts.
9. Cron callbacks and audit cleanup with `DOING_CRON`.
10. Logout, session destruction, administrative reset, and a new login using the same user but a new token.
11. A user with multiple roles, verifying that the strongest policy is attached to the session before the first admin request.
12. A session that copies a user-meta “completed” value but has no matching token-bound plugin state; it must remain pending.

The most important negative test is that a user who has passed the password check cannot reach an arbitrary admin, AJAX, admin-post, or cookie-authenticated REST handler until the token-bound state is satisfied.

## 15. Final recommendation

Implement the MVP around one explicit policy service and two request gates:

```text
session state service
  ├── token-bound pending/satisfied state
  ├── role policy and grace-period resolution
  └── challenge/enrolment transitions

admin_init gate
  ├── ordinary admin screens
  ├── admin-ajax.php before wp_ajax_* dispatch
  └── admin-post.php before admin_post_* dispatch

rest_authentication_errors gate
  └── cookie-authenticated REST only
```

The non-interactive classifier must run before those gates and must leave Application Passwords, XML-RPC, WP-CLI, and cron alone. This is the smallest central design that satisfies the phase-one requirement that a WordPress password alone must not be sufficient for protected interactive `/wp-admin` access, without accidentally turning browser 2FA into a protocol-wide requirement.

## Official sources

### WordPress developer documentation

- [`wp_signon()`](https://developer.wordpress.org/reference/functions/wp_signon/)
- [`wp_authenticate()`](https://developer.wordpress.org/reference/functions/wp_authenticate/)
- [`authenticate`](https://developer.wordpress.org/reference/hooks/authenticate/)
- [`wp_authenticate_user`](https://developer.wordpress.org/reference/hooks/wp_authenticate_user/)
- [`wp_login`](https://developer.wordpress.org/reference/hooks/wp_login/)
- [`wp_login_failed`](https://developer.wordpress.org/reference/hooks/wp_login_failed/)
- [`login_redirect`](https://developer.wordpress.org/reference/hooks/login_redirect/)
- [`wp_set_auth_cookie()`](https://developer.wordpress.org/reference/functions/wp_set_auth_cookie/)
- [`set_auth_cookie`](https://developer.wordpress.org/reference/hooks/set_auth_cookie/)
- [`set_logged_in_cookie`](https://developer.wordpress.org/reference/hooks/set_logged_in_cookie/)
- [`wp_get_session_token()`](https://developer.wordpress.org/reference/functions/wp_get_session_token/)
- [`WP_Session_Tokens`](https://developer.wordpress.org/reference/classes/wp_session_tokens/)
- [`session_token_manager`](https://developer.wordpress.org/reference/hooks/session_token_manager/)
- [`attach_session_information`](https://developer.wordpress.org/reference/hooks/attach_session_information/)
- [`determine_current_user`](https://developer.wordpress.org/reference/hooks/determine_current_user/)
- [`wp_validate_auth_cookie()`](https://developer.wordpress.org/reference/functions/wp_validate_auth_cookie/)
- [`auth_cookie_valid`](https://developer.wordpress.org/reference/hooks/auth_cookie_valid/)
- [`wp_logout()`](https://developer.wordpress.org/reference/functions/wp_logout/)
- [`clear_auth_cookie`](https://developer.wordpress.org/reference/hooks/clear_auth_cookie/)
- [`admin_init`](https://developer.wordpress.org/reference/hooks/admin_init/)
- [`is_admin()`](https://developer.wordpress.org/reference/functions/is_admin/)
- [`wp_doing_ajax()`](https://developer.wordpress.org/reference/functions/wp_doing_ajax/)
- [`admin-ajax.php`](https://developer.wordpress.org/reference/files/wp-admin/admin-ajax.php)
- [`wp_ajax_{$action}`](https://developer.wordpress.org/reference/hooks/wp_ajax_action/)
- [`admin-post.php`](https://developer.wordpress.org/reference/files/wp-admin/admin-post.php)
- [`admin_post_{$action}`](https://developer.wordpress.org/reference/hooks/admin_post_action/)
- [`rest_api_loaded()`](https://developer.wordpress.org/reference/functions/rest_api_loaded/)
- [`rest_authentication_errors`](https://developer.wordpress.org/reference/hooks/rest_authentication_errors/)
- [`rest_cookie_check_errors()`](https://developer.wordpress.org/reference/functions/rest_cookie_check_errors/)
- [`rest_get_authenticated_app_password()`](https://developer.wordpress.org/reference/functions/rest_get_authenticated_app_password/)
- [`rest_pre_dispatch`](https://developer.wordpress.org/reference/hooks/rest_pre_dispatch/)
- [`rest_request_after_callbacks`](https://developer.wordpress.org/reference/hooks/rest_request_after_callbacks/)
- [REST API authentication](https://developer.wordpress.org/rest-api/using-the-rest-api/authentication/)
- [`wp_authenticate_application_password()`](https://developer.wordpress.org/reference/functions/wp_authenticate_application_password/)
- [`application_password_is_api_request`](https://developer.wordpress.org/reference/hooks/application_password_is_api_request/)
- [`application_password_did_authenticate`](https://developer.wordpress.org/reference/hooks/application_password_did_authenticate/)
- [`application_password_failed_authentication`](https://developer.wordpress.org/reference/hooks/application_password_failed_authentication/)
- [`wp_authenticate_application_password_errors`](https://developer.wordpress.org/reference/hooks/wp_authenticate_application_password_errors/)
- [Application Passwords](https://developer.wordpress.org/advanced-administration/security/application-passwords/)
- [`wp_xmlrpc_server::login()`](https://developer.wordpress.org/reference/classes/wp_xmlrpc_server/login/)
- [`xmlrpc_login_error`](https://developer.wordpress.org/reference/hooks/xmlrpc_login_error/)
- [`xmlrpc_call`](https://developer.wordpress.org/reference/hooks/xmlrpc_call/)
- [`wp_doing_cron()`](https://developer.wordpress.org/reference/functions/wp_doing_cron/)
- [Cron Handbook](https://developer.wordpress.org/plugins/cron/)

### WordPress core source

- [`wp-includes/user.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/user.php)
- [`wp-includes/pluggable.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/pluggable.php)
- [`wp-includes/class-wp-session-tokens.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/class-wp-session-tokens.php)
- [`wp-includes/rest-api.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/rest-api.php)
- [`wp-includes/rest-api/class-wp-rest-server.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/rest-api/class-wp-rest-server.php)
- [`wp-includes/default-filters.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/default-filters.php)
- [`wp-login.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-login.php)
- [`wp-admin/admin.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-admin/admin.php)
- [`wp-admin/admin-ajax.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-admin/admin-ajax.php)
- [`wp-admin/admin-post.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-admin/admin-post.php)
- [`xmlrpc.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/xmlrpc.php)
- [`wp-cron.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-cron.php)

### Official WP-CLI documentation

- [Implementation details](https://make.wordpress.org/cli/handbook/contributions/implementation-details/)
- [Commands cookbook](https://make.wordpress.org/cli/handbook/guides/commands-cookbook/)
- [Configuration reference](https://make.wordpress.org/cli/handbook/references/config/)
- [`WP_CLI::add_command()`](https://make.wordpress.org/cli/handbook/references/internal-api/wp-cli-add-command/)
