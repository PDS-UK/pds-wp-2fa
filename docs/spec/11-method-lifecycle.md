# Decision: authentication-method abstraction and credential lifecycle

**Issue:** [#11 — Choose the authentication-method abstraction and credential lifecycle](https://github.com/PDS-UK/pds-wp-2fa/issues/11)
**Parent:** [#1 — Build the role-based WordPress 2FA plugin](https://github.com/PDS-UK/pds-wp-2fa/issues/1)
**Status:** implementation-ready decision
**Date:** 2026-08-24

## Decision summary

Use one plugin-owned, provider-neutral **authentication method** model for every credential that can satisfy a protected WordPress login. A method is one registered authenticator instance:

- one TOTP secret is one method;
- one WebAuthn credential is one method; and
- one recovery-code generation is one method containing multiple single-use code credentials.

The core owns method identity, user and installation binding, friendly names, lifecycle state, challenge/interaction records, WordPress session state, revocation policy, final-method protection, audit events, and rate limits. A provider owns only the protocol or secret-specific work needed to enroll and verify its method.

The provider boundary is a small adapter interface. Provider implementations receive a server-created, immutable context and untrusted browser input; they return typed proposals and verification decisions. They cannot mark a session as satisfied, consume a generic interaction, or write audit events. The core commits those effects in one transaction.

Adopt these providers for phase one:

| Provider key | Method instance | Verification owner | Core commit performed after verification |
| --- | --- | --- | --- |
| `totp` | One encrypted TOTP secret and recorded profile | TOTP adapter using the issue #6 profile | Atomically reject a previously accepted time-step, update the accepted step, consume the interaction, update metadata, satisfy the current session |
| `webauthn` | One WebAuthn credential/public-key record | `web-auth/webauthn-lib` through the plugin adapter | Atomically persist the library-returned credential record/counter, consume the interaction, update metadata, satisfy the current session |
| `recovery` | One active recovery-code generation with child code rows | Recovery adapter using password-style hash verification | Atomically mark exactly one matching code used, exhaust the generation when its last code is consumed, consume the interaction, update metadata, satisfy the current session |

This document does not choose the WordPress request hooks, role-policy rules, dependency versions, or database migration tooling. It defines the method and credential seam those pieces consume.

## Inputs and boundary

This decision depends on the closed research issues:

- [Issue #2](https://github.com/PDS-UK/pds-wp-2fa/issues/2) selects `web-auth/webauthn-lib` and assigns WebAuthn protocol verification to that library. The plugin remains responsible for challenge storage/consumption, WordPress user and session binding, installation/environment policy, credential persistence, rate limiting, audit, and the explicit 2FA-satisfied transition. The detailed report is [`docs/research/webauthn-library-verification.md`](../research/webauthn-library-verification.md).
- [Issue #6](https://github.com/PDS-UK/pds-wp-2fa/issues/6) selects the phase-one TOTP and recovery profiles: RFC 6238 with 20-byte secrets, SHA-1, six digits, 30 seconds, and a bounded ±1 step window; ten independent 128-bit recovery codes stored individually with `password_hash()`; and encrypted TOTP secrets using the documented sodium envelope. Its research report is on the [`research/totp-recovery-crypto`](https://github.com/PDS-UK/pds-wp-2fa/tree/research/totp-recovery-crypto) branch because it is not present in this checkout.
- [`CONTEXT.md`](../../CONTEXT.md) defines the installation identity, authenticator, challenge, recovery credential, and explicit per-session authentication state terms.
- [`docs/research/wordpress-auth-hooks.md`](../research/wordpress-auth-hooks.md) establishes that 2FA satisfaction is bound to the current WordPress session token, not to a user-level “completed” flag.

The external facts used here are cited directly in [Primary sources](#primary-sources). Project choices are marked as decisions; a standards citation does not transfer ownership of the surrounding application policy to an external library.

## Terminology

### Provider, method, and credential

- **Provider** is a registered implementation identified by a stable key such as `totp`. It knows how to start and finish its protocol-specific enrollment and verification.
- **Method** is the core record shown to the user and used by lifecycle policy. It has an opaque `method_id`, a provider key, a user, an installation, a friendly name, status, and metadata.
- **Credential** is provider-specific proof material. A TOTP secret and a WebAuthn public-key credential are one credential per method. A recovery method contains multiple child recovery-code credentials.
- **Interaction** is a short-lived, one-use server record for one enrollment, authentication, rotation, or recovery-generation operation. It is the common challenge-binding mechanism even when the provider has no browser challenge of its own.

The word “method” is used in the core API. Provider-specific code must not make callers depend on `Webauthn\\*` DTOs, OTPHP objects, sodium envelopes, or recovery hash rows.

### Method states

The core method state machine is deliberately small:

```text
             successful enrollment
       pending ----------------------> active
                                      /   |
                          last code  /    | explicit revoke,
                         consumed   /     | replacement, reset
                                    v      v
                                exhausted revoked
```

- `pending` exists only in an interaction and is not a usable method.
- `active` can be selected for authentication, subject to environment and provider policy.
- `exhausted` is only expected for a recovery generation with no unused child codes. It cannot authenticate and cannot be reactivated.
- `revoked` is terminal. Keep a tombstone and safe metadata for audit and race detection; never reactivate it. Re-enrollment creates a new `method_id`.

Provider-specific invalid, disabled, or unavailable data is an authentication failure, not a new core lifecycle state. A provider may expose a capability or a safe health result to the UI, but the core must fail closed when an active record cannot be verified.

## Core data model

The exact SQL types belong to the persistence implementation, but the following fields are required domain data. Binary values must use a binary-safe column or canonical base64url encoding; no raw secret or raw session token is put in logs or URLs.

### `auth_method` core record

| Field | Requirement |
| --- | --- |
| `method_id` | Opaque, immutable, cryptographically unpredictable identifier. Never reuse it. |
| `user_id` | WordPress user ID. Every lookup is scoped by this value and the current installation binding. |
| `installation_identity_hash`, `installation_epoch` | The current deployment binding tuple `(F,N)` from #12. The raw installation identity is never part of this record; the tuple is not a WebAuthn RP ID. |
| `provider_key` | Registry key (`totp`, `webauthn`, `recovery`, or a future provider). Never select a class from untrusted input. |
| `provider_schema_version` | Version for provider payload migrations. Unknown versions fail closed. |
| `label` | User-facing friendly name, separate from credential data. Enforce a bounded length, store safely, escape on output, and never use it for lookup or authorization. |
| `status` | `active`, `exhausted`, or `revoked`. |
| `created_at`, `updated_at` | UTC timestamps. |
| `last_used_at` | Nullable UTC timestamp. Update only after a successful, committed authentication; enrollment does not set it. |
| `revoked_at`, `revoked_by`, `revoked_reason` | Nullable immutable revocation metadata. The actor is a user/admin/system identifier, not a secret. |
| `revision` | Monotonic optimistic-concurrency value. Increment on provider state or lifecycle changes. |

Recommended defaults are `Authenticator app` for TOTP, `Security key` for WebAuthn, and `Recovery codes` for recovery. Users may rename methods; duplicate labels are allowed. A label is presentation metadata, not a credential name.

### Provider data

Provider data should use provider-owned tables or a strictly validated versioned payload. It must not be an untyped blob that the core interprets with provider-specific branches.

- **TOTP:** encrypted secret envelope, recorded algorithm/digits/period/T0 profile, encryption/key version, and the last accepted time-step counter. Use a fresh nonce and authenticated additional data binding the envelope to `installation_identity_hash`, `installation_epoch`, `user_id`, `method_id`, provider, and envelope version. The secret is never stored in plaintext.
- **WebAuthn:** credential ID with a uniqueness constraint scoped to the installation binding, public credential record, user handle, RP ID, transports, AAGUID/attestation metadata where retained, backup/UV metadata where available, signature counter, and a provider record revision. The private key never reaches the server; WebAuthn stores public credential material. The RP ID remains a domain value and is separate from the installation binding.
- **Recovery:** one active generation per user/binding, represented by the recovery method, with child rows containing a code ID, password-style verifier, `used_at`, and `revoked_at`. Never store plaintext codes or the displayed bundle. A generation with no unused rows is `exhausted`.

### `auth_interaction` record

Every provider operation is bound to a core interaction. Store at least:

| Field | Requirement |
| --- | --- |
| `interaction_id_hash` | Hash of an opaque, one-time browser reference. The reference is not a user ID or method ID. |
| `user_id`, `installation_identity_hash`, `installation_epoch` | Exact binding expected at submission. |
| `session_token_hash` | HMAC-SHA-256 digest of the WordPress session token for interactive flows. Never store the plaintext token. |
| `purpose` | `enrollment`, `authentication`, `rotation`, or `recovery_regeneration`. |
| `provider_key` | Provider selected by the server. A submitted provider key must match it. |
| `method_id` | Required for a selected TOTP/recovery method; nullable for WebAuthn discovery across an allow-list. |
| `allowed_method_ids` or an equivalent snapshot | For WebAuthn, the active credential set used to build `allowCredentials`. A response cannot choose a credential outside this snapshot. |
| `server_challenge` | Fresh random server value for the interaction. The core creates it and passes it to the provider; for WebAuthn it is the expected ceremony challenge, while for TOTP/recovery it binds the generic interaction. Keep it server-side; never use the browser response as the expected value. |
| `provider_state` | Provider-owned state such as serialized WebAuthn options, a pending TOTP secret, or recovery-generation hashes. Persist according to its sensitivity and schema version; never expose server-only state. |
| `created_at`, `expires_at` | Short lifetime enforced by the injected clock. Recommended maximums: five minutes for authentication and ten minutes for enrollment/rotation. |
| `consumed_at`, `revoked_at` | Nullable one-use state. Consumption is an atomic compare-and-set. |
| `attempt_count` | Bounded attempt accounting for rate limiting and audit correlation. |
| `provider_state_version` | Version for decoding provider state; unknown versions fail closed. |

An interaction is consumed only after provider verification succeeds and all provider-specific state changes have committed. Failed, expired, mismatched, revoked, and already-consumed interactions do not call the provider verifier. Starting another authentication interaction for the same pending session revokes the previous unconsumed authentication interaction, so a method switch cannot leave multiple bearer references live.

## Stable provider interface

The following is the contract, expressed in PHP-like pseudocode. Names may be adapted to the repository's eventual namespace, but the responsibilities and transaction boundaries are binding.

```php
interface AuthenticationMethodProvider
{
    public function key(): ProviderKey;

    public function capabilities(): ProviderCapabilities;

    public function startEnrollment(
        ProviderContext $context,
    ): ProviderStart;

    public function completeEnrollment(
        ProviderContext $context,
        ProviderStart $start,
        UntrustedInput $input,
    ): EnrollmentResult;

    public function startVerification(
        ProviderContext $context,
    ): ProviderStart;

    public function verify(
        ProviderContext $context,
        ProviderStart $start,
        UntrustedInput $input,
    ): VerificationResult;

    /** Called inside the core's transaction after generic checks pass. */
    public function commitVerification(
        ProviderContext $context,
        VerificationResult $result,
    ): VerificationCommit;

    /** Called inside the core's transaction; terminal and idempotent. */
    public function revoke(
        ProviderContext $context,
        MethodRecord $method,
        RevocationReason $reason,
    ): void;
}
```

### Contract rules

`ProviderContext` is server-created and contains the user ID, installation identity, operation, interaction ID, session binding hash, trusted policy snapshot, clock, and the selected method snapshot. It may contain the server-created WebAuthn challenge, but never a client-supplied expected value. The provider cannot change user, installation, session, or purpose.

`ProviderStart` contains:

- an opaque interaction reference for the browser;
- a provider-specific `public_payload` such as WebAuthn request options, a TOTP provisioning response, or a recovery-code display bundle; and
- provider-owned `server_state` that the core persists in the interaction record and never sends to the browser.

The public payload is not necessarily harmless. A TOTP provisioning payload and recovery-code bundle are credential material while displayed. Return them only over HTTPS with `Cache-Control: no-store`, do not log them, and do not put them in URLs. A provider must label sensitive output so controllers and audit code cannot accidentally serialize it.

`UntrustedInput` is the original request payload after basic transport decoding. It is not allowed to select the expected challenge, user, installation, method, or policy. Each provider parses only its own input format and returns a typed failure for malformed input.

`EnrollmentResult` contains a provider-owned `MethodDraft` plus safe metadata. The draft is not active until the core transaction validates the interaction and inserts it. A provider may return a one-time display receipt for recovery codes, but it must never return plaintext credential material as a persisted method field.

`VerificationResult` is a pure, pre-commit decision. It identifies the matched method (when a provider can discover it), safe audit metadata, and the provider-specific mutation needed by `commitVerification`, for example an accepted TOTP counter, an updated WebAuthn credential record, or a recovery child-code ID. It does not change persistent state.

`commitVerification` must be safe to call only while the core transaction holds the interaction and relevant method/child-row locks. It must fail on a stale method revision, revoked method, already-used recovery code, counter conflict, or any other concurrent state change. It must not emit external side effects. The core then marks the interaction consumed, updates `last_used_at`, and transitions the current session to `satisfied` in the same transaction.

`revoke` must zeroize or retire provider-specific material as appropriate, be idempotent, and leave a terminal method tombstone. Revocation does not mean deletion from audit history, and a revoked interaction can never be revived.

### Registry and future providers

Providers are registered in a server-side allow-listed registry keyed by a stable lowercase string. The core resolves `provider_key` only through that registry. A future provider must implement the same contract, define a versioned provider state format, and supply provider-specific tests; it does not require changes to the core method table, interaction binding, session transition, audit schema, or final-method rule.

The core must treat `public_payload`, `server_state`, provider metadata, and input as opaque. It should use capability flags only for presentation and workflow decisions, not `if ($providerKey === ...)` security branches. Adding a provider must not weaken the default policy: unknown providers, unknown schema versions, missing provider implementations, and malformed provider results fail closed.

## Common lifecycle

### 1. Primary authentication and pending session

WordPress first performs primary authentication. The plugin creates or reconciles a session-specific record keyed by an HMAC-SHA-256 digest of the WordPress session token, with persisted state `pending`, `satisfied`, or `invalidated`; `enrollment_required` is a derived enforcement mode. An enrolled method on the user does not satisfy a new session. This follows the WordPress session model: a user can have multiple sessions and the plugin's 2FA state must be attached to the current one, not to user meta.

Only a pending session for the expected user may start an authentication interaction. Enrollment and management also require the current user, a valid session binding, CSRF protection, and the project’s required primary-authentication/re-authentication check.

### 2. Start an enrollment

1. The core resolves the registered provider from a server-side allow-list and checks environment policy.
2. It creates a new interaction with a fresh opaque reference, a fresh server challenge, purpose, user, installation, session hash, provider, and expiry. The core passes the server challenge to the provider; the provider may add provider-owned state such as a TOTP enrollment secret or serialized WebAuthn options.
3. The provider returns public options and opaque server state.
4. The core persists the interaction before returning the response. A response containing TOTP or recovery material is non-cacheable and never includes third-party resources.

Enrollment is not authentication. Completing enrollment never marks a later login as satisfied. If the current session needs access after enrollment, the caller starts a separate authentication interaction. This prevents registration of a new method from becoming an implicit second-factor success.

### 3. Complete an enrollment

1. The controller loads the opaque interaction by reference and rejects missing, expired, revoked, consumed, user-mismatched, session-mismatched, installation-mismatched, purpose-mismatched, or provider-mismatched submissions before provider verification.
2. The core applies the enrollment rate limit and CSRF/re-authentication checks.
3. The provider validates its input and returns a `MethodDraft`. For WebAuthn, this is where the adapter passes the browser response to `web-auth/webauthn-lib`; for TOTP it validates the newly provisioned code; for recovery it confirms the same enrollment interaction/acknowledgement after the hashes have been prepared.
4. In one transaction, the core re-checks the interaction and session, creates the method as `active`, persists provider data, atomically consumes the interaction, and writes a safe audit event. A duplicate WebAuthn credential ID, stale interaction, or provider conflict aborts the transaction.
5. The response contains only safe method metadata. Secrets and recovery plaintext are never available through a later “view” operation.

For initial enrollment, recovery-code generation can be coordinated with the first selected authenticator, but each provider still produces its own draft and the core commits all methods atomically. If the transaction fails, no recovery plaintext is returned as if it were active.

### 4. Start an authentication

1. The pending session asks for one method/provider. The method selection is a hint only; the server loads the method and verifies that it belongs to the current user and installation and is `active`.
2. For TOTP or recovery, the interaction records that exact method. For WebAuthn, it records a snapshot of every active WebAuthn method for the current user and builds the allow-list from that snapshot. A discoverable future flow may leave `method_id` unset, but it must still bind the returned user handle to the expected user and installation.
3. The provider returns a public request payload and server state. The core returns only the opaque interaction reference plus that payload.

### 5. Verify and commit an authentication

1. The core loads and locks the interaction and re-checks every common binding: user, installation, session token hash, purpose, provider, method snapshot, expiry, status, and one-use state.
2. The core applies rate limits before expensive or repeated verification. Failure responses are generic; provider exception text is not returned to the user.
3. The provider verifies its input and returns a pure `VerificationResult`. A WebAuthn result must identify a credential in the interaction’s allow-list; it cannot choose an arbitrary database record.
4. In one transaction, the core re-checks method status/revision and calls `commitVerification`. The provider-specific state change must be conditional: TOTP step not previously accepted, WebAuthn counter update not stale, or recovery child row still unused.
5. The core atomically marks the interaction consumed, updates the matched method’s `last_used_at` and `updated_at`, increments its revision, and changes only the current session record to `satisfied`.
6. The audit event is written with provider, method ID, user, outcome, timestamp, and safe diagnostic metadata. No submitted code, TOTP secret, recovery plaintext, WebAuthn response, raw challenge, session token, private key, or decryption key is logged.

If any commit step fails, the transaction rolls back and the session remains pending. A provider must not mark success before the core transaction commits.

### 6. Logout, expiration, and reset

Logout/session destruction invalidates the matching pending or satisfied plugin session state and all unconsumed interactions for that session. Interaction expiration and cleanup are safe background work; an expired row must still be rejected if it is presented before cleanup.

Administrative reset/revocation uses the same terminal method state and final-method checks unless a separately specified emergency-reset policy explicitly changes the user’s enrollment requirement. A new WordPress login always begins with a new pending plugin session, even when the user has active methods.

## Provider decisions

### TOTP

Use the issue #6 phase-one profile: 20 random bytes per secret; HMAC-SHA-1; six decimal digits; `T0 = 0`; 30-second period; and at most one adjacent time step in either direction. RFC 6238 defines TOTP as HOTP with a time-derived counter, recommends a 30-second default, and warns that larger acceptance windows increase the attack window ([RFC 6238 §§3–5.2](https://www.rfc-editor.org/rfc/rfc6238.html#section-5.2)).

Enrollment:

- Generate the secret with a cryptographically secure random source and construct the local `otpauth://` payload from trusted issuer/account fields.
- Encrypt the secret with the selected sodium envelope before durable persistence. The secret and provisioning URI exist only in the short-lived enrollment response/server state; they are never placed in a URL, cache, log, audit record, user meta, or option.
- Require a valid code from the new secret to complete enrollment. This proves the user copied the secret into the authenticator application, but it still does not satisfy a separate login session.
- Persist the profile alongside the encrypted secret so a future profile change cannot silently reinterpret old methods.

Authentication:

- Accept only the exact ASCII six-digit input for the recorded profile.
- Verify against the current step and one adjacent step on either side using an injected clock.
- Return the matched step as the provider mutation. In the core transaction, reject `matched_step <= last_accepted_step` and update the counter conditionally. This enforces one successful use per method/time-step even when the user submits the same code in multiple sessions.
- Never expose the decrypted secret to the core controller; the adapter decrypts immediately before calculation and returns only the safe mutation/result.

Rotation creates a new pending TOTP method and verifies it before changing the old method. The new method is activated and the old method revoked in one transaction. If verification is abandoned, the old method remains active and the pending method expires.

### WebAuthn

Use `web-auth/webauthn-lib`, the pure-PHP component selected by issue #2, behind the provider adapter. The library owns WebAuthn protocol parsing and ceremony verification: response structure, client-data type and challenge comparison, origin/RP ID checks, user handle, user presence/user verification, signature, attestation, credential record construction, and protocol counter handling. The plugin owns the surrounding application boundary.

The adapter must:

- build trusted creation/request options from environment and RP policy rather than from browser input;
- generate and store a fresh server challenge with the interaction, bound to the expected user, session, installation, operation, and expiry;
- use `attestation: none`, `residentKey: preferred`, and `userVerification: preferred` for phase-one registration, with no forced authenticator attachment;
- include every active WebAuthn credential for the user in the authentication allow-list, retaining transport hints;
- pass the original browser response and server-created options to the library rather than reimplementing cryptographic checks;
- reject a response whose matched credential is not in the interaction snapshot or does not belong to the expected user/installation;
- persist the library-returned updated credential record and counter with a transaction/CAS guard; zero/zero counters remain valid, while a non-zero rollback is a failed challenge under the issue #2 decision; and
- reject WebAuthn before protocol verification when environment policy, installation binding, session binding, method status, challenge binding, or rate limits fail.

WebAuthn enrollment creates one method per credential. Registering another key or platform credential adds another active method; it does not overwrite an existing public-key record. Revoking a key is terminal and does not alter other keys.

The WebAuthn library does not know the WordPress login session, installation identity, request classifier, database transaction, audit policy, or rate limiter. Those remain plugin responsibilities. The plugin must not treat successful registration as a satisfied login state.

### Recovery codes

Use one recovery method per active generation and ten independent 128-bit code rows. Generate each with `random_bytes(16)`, display as uppercase hexadecimal grouped for readability, and normalize only ASCII spaces/hyphens and case on input. Store one `password_hash()` result per normalized code and verify with `password_verify()`; PHP documents these APIs for password-style hashing and verification ([`password_hash()`](https://www.php.net/manual/en/function.password-hash.php), [`password_verify()`](https://www.php.net/manual/en/function.password-verify.php)).

Enrollment/generation:

- Require the appropriate primary-authentication/re-authentication and CSRF checks.
- Prepare hashes and the one-time plaintext display bundle in a pending interaction. Do not store the plaintext bundle.
- Commit the generation and child rows before returning the bundle, or commit them with the enclosing initial-enrollment transaction. The bundle is displayed once with `no-store`; there is no later reveal endpoint.
- Regeneration revokes every row in the old generation and activates the new generation atomically before returning the new plaintext bundle. A failed transaction returns no active new generation.

Authentication:

- Bind the submitted code to a recovery interaction and current pending WordPress session.
- Normalize and validate the exact 32-character hexadecimal form. Verify only unused rows for the expected user/generation; never log the candidate or hash-matching details.
- In the core transaction, mark the matching child row used with a conditional update such as `WHERE code_id = ? AND used_at IS NULL`. Zero affected rows are a replay/concurrency failure.
- If the last unused code is consumed, mark the recovery method `exhausted`. The current session that successfully used it remains `satisfied` so the user can immediately enroll a replacement; no later session can authenticate with the exhausted generation.

A recovery-code success records the method and child row identifier, not the code. Recovery is a fallback method, not a bulk bypass: rate limits and final-method management rules still apply.

## Multiple methods, names, and metadata

- A user may have multiple active TOTP methods and multiple active WebAuthn methods. The core list is provider-neutral; the WebAuthn provider builds its allow-list from all active WebAuthn records.
- There is at most one active recovery generation per user/installation. Regeneration is replacement, not an additional parallel recovery set.
- `label` is user-editable metadata with a bounded length and safe output escaping. It may be renamed without changing `method_id` or provider data. It never participates in verification, method selection authority, uniqueness, or final-method counting.
- `created_at` is set once. `last_used_at` is null until the first successful committed authentication and is updated in the same transaction as provider state. It is an informational UI field and never an authorization input.
- List/detail views may show provider type, label, creation time, last-used time, and status. They must not show TOTP secrets, provisioning URIs, recovery plaintext, WebAuthn private material (which is never stored), raw session/challenge values, or password hashes.
- Audit events use method ID/provider/status and safe metadata. Failed attempts may include a normalized failure category and rate-limit bucket, but never raw credential input.

## Revocation, rotation, and final-method protection

### Revocation

Revocation is a terminal, transactional transition from `active` to `revoked`:

1. Require a currently satisfied session, CSRF protection, and fresh re-authentication for a user-initiated revoke/regenerate operation.
2. Lock/recheck all active methods for the user and installation.
3. Apply the final-method rule below.
4. Revoke the method and provider data through `provider->revoke()`; invalidate interactions that reference it.
5. Write safe audit metadata in the same transaction.

Retain the tombstone for audit and race checks. TOTP ciphertext may be destroyed/zeroized on revoke; recovery hashes may be marked revoked; WebAuthn public data may be retained as a revoked record. In all cases, the method can never verify again.

### Rotation and replacement

There is no in-place credential replacement:

- TOTP rotation creates and verifies a new method, then atomically activates the new method and revokes the old one.
- WebAuthn “rotation” means enrolling an additional credential, then optionally revoking the old credential after the new one is active.
- Recovery regeneration creates a new generation and revokes the complete old generation atomically.

Any operation that replaces the final active method must activate the replacement before revoking the old method in the same transaction. If the replacement is not successfully prepared, the old method remains active.

### Final-method rule

For a protected user, a destructive management operation must not leave zero active, non-exhausted methods. The count is computed from locked core records, not from user-submitted labels or a stale UI list. A method counts as retained if it is `active`; provider environment availability may prevent use, but must not be used as a reason to silently remove the only credential.

Therefore:

- reject manual revoke/disable/delete of the only active method;
- allow a replacement transaction only when the new method is valid and active before the old method becomes revoked;
- reject concurrent revoke/rotation races by rechecking the count under lock;
- do not count `pending`, `revoked`, or `exhausted` methods; and
- permit consumption of the last recovery code as a special authentication transition, because refusing it would strand the user. After that success, the current session is satisfied and enrollment is required; the exhausted recovery method cannot authenticate another session.

If a separate emergency administrative reset is later required to remove every method, it must be a separately specified operation that also destroys/revokes current WordPress sessions, marks the account enrollment-required, and creates a high-severity audit event. It is not an implicit escape hatch in this interface.

## Security invariants

The implementation is correct only if all of these remain true:

1. **Session binding:** A method success can satisfy only the current WordPress session whose token hash is in the interaction; an enrolled user-level flag can never satisfy a new session.
2. **User/install binding:** Every method, interaction, provider state, and credential lookup is scoped to both the expected WordPress user and installation identity.
3. **Server challenge authority:** Expected challenges, provider policy, method allow-lists, and user identity come from server state. Client payloads are never used to select those values.
4. **One-use interaction:** An interaction is single-use, expires, is revocable, and is consumed atomically only after successful provider verification.
5. **Provider separation:** Provider verification is provider-specific; the core never reimplements WebAuthn cryptography or applies TOTP/recovery rules to another provider.
6. **No premature success:** No provider, enrollment completion, or controller can mark the session `satisfied`; only the core commit transaction can do so after provider state commits.
7. **Replay resistance:** TOTP accepted steps, WebAuthn credential revisions/counters, and recovery child rows are updated conditionally so successful proof cannot be replayed or overwritten by a stale concurrent request.
8. **Credential confidentiality:** TOTP secrets are encrypted at rest; recovery codes are stored only as password-style verifiers; WebAuthn private keys never reach the server; sensitive material is absent from URLs, logs, caches, audit events, and session state.
9. **Final-method safety:** A protected user cannot manually end with zero active/non-exhausted methods; replacement is activate-before-revoke and concurrency-safe.
10. **Terminal revocation:** A revoked/exhausted method and all interactions referring to it can never become valid again.
11. **Safe metadata:** Friendly names and `last_used_at` are informational only and cannot influence authentication or authorization.
12. **Fail closed:** Unknown providers, malformed provider state/results, unsupported schema versions, missing key material, invalid policy, and persistence conflicts result in no session success.
13. **Abuse control:** Failed verification is rate-limited across sessions and provider/method boundaries as appropriate; a new browser session cannot reset the user’s failure budget.
14. **Audit redaction:** Audit records identify the event and safe method metadata without recording secrets, submitted codes, raw WebAuthn responses, raw challenges, session tokens, or provider exception text.

## Acceptance tests

These are the minimum tests for issue #11. They should be implemented at the provider/core boundary with fake clock, repositories, rate limiter, session state service, and transaction manager. WebAuthn protocol fixtures should additionally exercise the upstream library’s testable ceremony steps; browser tests are supplementary.

### Interface and registry

- [ ] The registry resolves `totp`, `webauthn`, and `recovery` by stable keys and rejects an unknown key without dynamic class loading.
- [ ] A provider receives server context and untrusted input separately; changing user, installation, session, purpose, or expected challenge in input cannot change the context.
- [ ] A provider verification result alone cannot change method state, `last_used_at`, interaction state, or session state outside the core transaction.
- [ ] A malformed provider state/version or provider result aborts the transaction and leaves the session pending.
- [ ] A minimal fake future provider can enroll and verify through the same core lifecycle without a new core provider branch.

### Common lifecycle and challenge binding

- [ ] A new WordPress login for an enrolled user starts `pending`; a prior session’s `satisfied` state is not reused.
- [ ] An interaction is bound to the expected user, installation, session-token hash, purpose, provider, and method/snapshot; changing any one causes a generic failure.
- [ ] Expired, revoked, consumed, replayed, or wrong-provider interactions are rejected before provider verification.
- [ ] Starting a replacement authentication interaction revokes the previous pending interaction for that session.
- [ ] Concurrent submissions of one valid interaction produce at most one success and one `satisfied` transition.
- [ ] Enrollment success creates a method but does not mark the current or a future login session satisfied.
- [ ] Logout/session destruction invalidates plugin session state and pending interactions; a later request cannot reuse the old satisfied state.

### TOTP

- [ ] Enrollment uses the fixed 20-byte/RFC 6238 profile, requires a valid code from the new secret, encrypts the secret before durable storage, and never logs or URL-encodes the secret/URI.
- [ ] Verification accepts current, previous, or next step according to the configured ±1 policy, and rejects a code outside the window.
- [ ] A successful TOTP step is accepted once; a second submission of that same step, including from another session, fails through the conditional replay update.
- [ ] TOTP profile parameters are read from the method record, not silently changed by a global configuration change.
- [ ] TOTP rotation leaves the old method active when new enrollment is abandoned or invalid, and atomically activates the new method before revoking the old one when valid.
- [ ] Missing/malformed encryption key, tampered ciphertext, or wrong authenticated additional data fails closed without exposing plaintext.

### WebAuthn

- [ ] Registration and authentication use `web-auth/webauthn-lib`; the plugin does not reimplement response parsing, signature, RP ID/origin, user-presence/user-verification, attestation, user-handle, or counter protocol checks.
- [ ] A challenge is fresh, server-created, stored with the user/session/installation/operation, expires, and is atomically consumed only after library verification.
- [ ] A response with a changed challenge, origin/scheme/host/port, RP ID hash, user handle, credential ID, signature, required flag, or algorithm fails without satisfying the session.
- [ ] A credential belonging to another user/installation, a revoked credential, or a credential not in the interaction allow-list fails even when the library can cryptographically verify the response.
- [ ] Multiple platform and cross-platform credentials can be enrolled; authentication options contain all current user credentials and recorded transports.
- [ ] A valid assertion persists the library-returned updated record and counter with a CAS/version guard; a concurrent stale update fails and does not overwrite the newer record.
- [ ] Zero/zero counters are accepted according to the issue #2 decision; a non-zero rollback is rejected and audited without updating the counter.
- [ ] WebAuthn is rejected by environment policy where it is disabled, while TOTP/recovery remain governed by their own provider policy.

### Recovery

- [ ] A generation creates ten independent 128-bit codes, stores only individual password-style verifiers, and shows plaintext once with no-store handling.
- [ ] Input accepts only the documented normalization (ASCII spaces/hyphens and case) and exactly 32 hexadecimal characters; Unicode lookalikes and arbitrary punctuation fail.
- [ ] A valid recovery code marks exactly one child row used with a conditional update; two concurrent uses yield at most one success.
- [ ] A used, revoked, wrong-user, wrong-generation, malformed, or exhausted code fails and leaves the session pending.
- [ ] Consuming the last code marks the generation exhausted, satisfies only the current bound session, and requires replacement enrollment for future sessions.
- [ ] Regeneration revokes every old child row before the new plaintext bundle is returned; old codes fail even if a stale interaction is replayed.
- [ ] Recovery audit events contain method/child IDs and outcome but never the plaintext code or its hash.

### Methods, metadata, and management

- [ ] A user can enroll multiple TOTP and WebAuthn methods; each has a distinct immutable `method_id` and independently tracked `last_used_at`.
- [ ] Friendly names can be changed and safely displayed; equal names do not merge methods and names never affect verification.
- [ ] `last_used_at` changes only after a successful committed authentication and not after enrollment, failed verification, or a stale transaction.
- [ ] Manual revoke of the sole active/non-exhausted method is rejected and audited.
- [ ] A valid replacement can activate before revoking the old final method in one transaction; a failed/concurrent replacement leaves the old method active.
- [ ] Revoked methods, exhausted recovery generations, and interactions referring to them never become valid again.
- [ ] Management responses and logs redact secrets, codes, hashes, raw challenges, WebAuthn response data, and session tokens.

## Primary sources

These sources support external protocol/API facts. Project-specific decisions are recorded above and in the linked issue/research documents.

- [W3C Web Authentication: An API for accessing Public Key Credentials, Level 3](https://www.w3.org/TR/webauthn-3/) — registration/assertion ceremonies, RP ID/origin, user handles, credential records, discoverable credentials, authenticator flags, and signature counters.
- [IETF RFC 6238 — TOTP](https://www.rfc-editor.org/rfc/rfc6238.html) — TOTP construction, 30-second default, key protection, bounded validation windows, and one-time acceptance.
- [IETF RFC 4226 — HOTP](https://www.rfc-editor.org/rfc/rfc4226.html) — HOTP construction, digit profile guidance, random secret guidance, and throttling considerations.
- [`web-auth/webauthn-framework` source](https://github.com/web-auth/webauthn-framework) and [`AuthenticatorAssertionResponseValidator`](https://github.com/web-auth/webauthn-framework/blob/5.4.x/src/webauthn/src/AuthenticatorAssertionResponseValidator.php) — selected pure-PHP WebAuthn validator boundary.
- [PHP `random_bytes()`](https://www.php.net/manual/en/function.random-bytes.php) — cryptographically secure random bytes for secrets and identifiers.
- [PHP `password_hash()`](https://www.php.net/manual/en/function.password-hash.php) and [`password_verify()`](https://www.php.net/manual/en/function.password-verify.php) — password-style recovery-code verifiers and verification.
- [PHP XChaCha20-Poly1305-IETF AEAD](https://www.php.net/manual/en/function.sodium-crypto-aead-xchacha20poly1305-ietf-encrypt.php) — authenticated encryption and additional data for TOTP secret envelopes.
- [WordPress `WP_Session_Tokens`](https://developer.wordpress.org/reference/classes/wp_session_tokens/) and [`wp_get_session_token()`](https://developer.wordpress.org/reference/functions/wp_get_session_token/) — WordPress session-token model used for per-login 2FA state binding.
