# WebAuthn library and verification boundary

**Decision ticket:** [Choose the maintained PHP WebAuthn implementation and verification boundary](https://github.com/PDS-UK/pds-wp-2fa/issues/2)  
**Research date:** 2026-08-24  
**Scope:** server-side PHP implementation for registration and authentication of WebAuthn/FIDO2 authenticators in PDS WP 2FA. This report does not implement the plugin.

## Decision

Use **`web-auth/webauthn-lib`**, the pure-PHP library component of the maintained [Webauthn Framework](https://github.com/web-auth/webauthn-framework), pinned to the current supported 5.x line and locked in the plugin’s Composer lock file. At the time of this research, the upstream project’s latest stable release is 5.3.5, while the active development branch is 5.4.x; the final dependency constraint must be selected alongside the project’s PHP support-baseline decision.

The WordPress plugin should require the library package, not the Symfony bundle. The upstream documentation identifies `web-auth/webauthn-lib` as the package for pure PHP integrations, and the framework source contains a separate package definition for that library component. [Installation documentation](https://webauthn-doc.spomky-labs.com/v5.2/the-project/installation), [library package definition](https://github.com/web-auth/webauthn-framework/blob/5.3.5/src/webauthn/composer.json), [latest release](https://github.com/web-auth/webauthn-framework/releases/tag/5.3.5)

The library owns WebAuthn protocol parsing and cryptographic ceremony verification. PDS WP 2FA owns the application security protocol around it: challenge lifecycle, WordPress user/session binding, environment and origin policy, credential lookup and persistence, rate limiting, audit events, and the transition to the plugin’s explicit 2FA-satisfied session state.

## Why this library

WebAuthn is not a hardware-specific protocol. The browser’s Web Authentication API selects and communicates with either a platform authenticator (for example Touch ID or Windows Hello) or a cross-platform authenticator (for example a USB/NFC/Bluetooth security key). The server receives the same registration/assertion structures and verifies them against the RP policy and stored public key. The WebAuthn specification defines these attachment modalities and explicitly leaves the choice to the client when no attachment is forced. [W3C authenticator attachment](https://www.w3.org/TR/webauthn-3/#enumdef-authenticatorattachment), [W3C registration model](https://www.w3.org/TR/webauthn-3/#sctn-registration)

`web-auth/webauthn-lib` is the best fit because it provides:

- pure-PHP DTOs and validators rather than a WordPress- or Symfony-specific authentication flow;
- separate attestation and assertion validators;
- a configurable `CeremonyStepManager`, with individual steps for allowed credentials, challenge, origin, RP ID hash, user handle, user presence, user verification, signature, and counters;
- a credential record containing the credential ID, public key, user handle, transports, AAGUID/attestation metadata, counter, and backup-related state;
- an assertion validator that returns the updated credential record, making counter persistence explicit; and
- upstream unit tests around ceremony steps and credential records.

The validator and factory source shows this separation directly: [assertion validator](https://github.com/web-auth/webauthn-framework/blob/5.4.x/src/webauthn/src/AuthenticatorAssertionResponseValidator.php), [attestation validator](https://github.com/web-auth/webauthn-framework/blob/5.4.x/src/webauthn/src/AuthenticatorAttestationResponseValidator.php), [ceremony factory](https://github.com/web-auth/webauthn-framework/blob/5.4.x/src/webauthn/src/CeremonyStep/CeremonyStepManagerFactory.php), and [library tests](https://github.com/web-auth/webauthn-framework/tree/5.4.x/tests/library/Unit).

The library has had a security advisory for origin comparison in versions 5.2.0 through 5.2.3. The fixed version is 5.2.4; the plugin must use a supported release at or above that fix and must add regression tests for exact scheme, host, and port matching. [Upstream security advisory](https://github.com/web-auth/webauthn-framework/security/advisories/GHSA-f7pm-6hr8-7ggm)

## Candidate comparison

The comparison is limited to PHP libraries with a public upstream source and observable maintenance at the research date.

| Candidate | RP ID/origin | Challenge and user binding | Credentials, counters, discoverable credentials | Testability and concerns | Decision |
| --- | --- | --- | --- | --- | --- |
| [`web-auth/webauthn-lib`](https://github.com/web-auth/webauthn-framework) | Configurable allowed-origin ceremony step plus RP ID hash verification. The application supplies the expected host/origin policy. | Validator compares the response challenge with the creation/request options. The application must create, persist, expire, consume, and bind those options. User handle checking is a dedicated ceremony step. | `CredentialRecord` models credential ID, public key, user handle, transports, AAGUID/attestation data, counter, backup flags, and UV state. The request options can include an allow-list or omit it for discoverable credentials. | Strongest separation of concerns and explicit injectable ceremony steps. Requires PHP 8.2 on the current 5.3/5.4 library line and brings a larger dependency graph. Must avoid vulnerable 5.2.x releases. | **Recommended** |
| [`firehed/webauthn`](https://github.com/Firehed/webauthn-php) | Provides single-, multi-, and wildcard-origin relying-party implementations and documents RP ID/origin rules. | Provides expiring challenges and a challenge manager, but the application still binds the challenge and user context. | Supports multiple credentials and returns an updated credential after authentication; supports user handles and discoverable/authenticator flows. | Clear API, small dependency footprint, and strong examples. However, the upstream README currently lists unfinished verification/security work including trust anchoring, algorithm matching, counter handling, and malformed-input tests. That makes the verification boundary less complete for a security-critical plugin. [Open verification TODOs](https://github.com/Firehed/webauthn-php/blob/main/README.md#securityrisk) | Do not select for MVP |
| [`lbuchs/webauthn`](https://github.com/lbuchs/WebAuthn) | Constructor binds one RP ID and checks origin/RP ID hash. It supports platform and cross-platform selection. | Generates an internal challenge and exposes it for later checking; application code must still persist and bind it correctly. | Supports multiple credential IDs, transports, signature counters, and several attestation formats. However, its authentication method explicitly leaves allow-list verification, user-handle ownership, and credential lookup to the implementation. [Source comments and verification boundary](https://github.com/lbuchs/WebAuthn/blob/master/src/WebAuthn.php#L396-L412) | Lightweight and understandable, but the explicit `TO BE VERIFIED BY IMPLEMENTATION` steps are inside the central authentication path. It also has a more stateful, monolithic API and a slower release cadence than the recommended library. | Do not select for MVP |

The alternatives remain useful reference implementations and possible future options, but the plugin should not make its first production verification boundary depend on application code filling gaps that the selected library can model as testable ceremony steps.

## Protocol facts the plugin must preserve

The library choice does not change the WebAuthn protocol requirements.

### RP ID and origin are separate checks

An RP ID is a valid domain string, has no scheme or port, and scopes a credential. It must be equal to or a registrable suffix of the caller’s effective domain. The client data origin is a full origin and must be validated separately. An HTTPS origin is required except for the browser’s permitted `http://localhost` case. [W3C RP ID definition](https://www.w3.org/TR/webauthn-3/#relying-party-identifier), [W3C origin validation](https://www.w3.org/TR/webauthn-3/#sctn-validating-origin-of-a-credential)

For this plugin:

1. The WebAuthn RP ID is derived from the configured production site host according to the environment decision; it is never a database identifier.
2. The installation identity remains a separate application-level binding used to isolate cloned databases and credential records. It cannot replace the browser-enforced domain RP ID.
3. The allowed origin is derived from a trusted WordPress URL/configuration and an explicit deployment policy, not from an arbitrary request `Host` header.
4. Exact origin comparison includes scheme, host, and non-default port. Do not configure broad subdomain matching for MVP.
5. The plugin fails closed if the current environment is non-production, WebAuthn is disabled by deployment policy, the installation identity does not match the credential record, or the request origin is not explicitly allowed.

The browser page that invokes `navigator.credentials.create()` or `navigator.credentials.get()` must run on the same configured origin. A physical key or platform authenticator can be reused by registering separate credentials in separate environments, but a credential cannot be made portable across unrelated RP IDs by changing database metadata.

### Challenge handling

The server creates a fresh random challenge for every registration and authentication ceremony. Use at least 32 bytes from `random_bytes()` and pass that value to the library’s creation/request options. The browser response’s client-data challenge is an input to verification, not an authority for selecting the expected challenge. The W3C registration and assertion procedures both require comparison with the server-created options challenge. [W3C registration steps](https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential), [W3C assertion steps](https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion)

The plugin must store a challenge record containing at least:

- a cryptographically random challenge;
- the WordPress user ID, or a narrowly scoped pending-user identifier;
- the operation (`registration` or `authentication`);
- the pending 2FA session identifier and installation identity;
- creation and expiry timestamps;
- a consumed/revoked state; and
- an optional hash of the serialized ceremony options for diagnostics and integrity checks.

Consume it atomically only after successful verification. Reject expired, already-consumed, revoked, user-mismatched, operation-mismatched, installation-mismatched, and session-mismatched challenges. Do not put challenges in audit metadata or debug logs. The challenge record may be stored as short-lived server-side data; it is not a credential secret, but it must not be accepted from the client as the expected value.

### User handles and credential discovery

The user handle is an opaque, RP-specific byte sequence, not a username or email address. It is at most 64 bytes; the W3C recommends 64 random bytes. It must be stable for all credentials belonging to the same WordPress user within one installation and must not contain personally identifying information. [W3C user handle definition](https://www.w3.org/TR/webauthn-3/#user-handle), [W3C privacy guidance](https://www.w3.org/TR/webauthn-3/#sctn-user-handle-contents)

The MVP flow knows the user after successful WordPress password authentication. Therefore:

- create a random per-user WebAuthn user handle on first WebAuthn enrollment;
- use that handle as the `PublicKeyCredentialUserEntity.id` for every credential registered for that user;
- store it as binary data, separately from the display name, and never display it;
- when the user is known, load the credential by the submitted `rawId` and verify that it belongs to the current WordPress user and installation;
- if a response includes `userHandle`, require it to match the stored user handle; and
- retain the ability to support a future usernameless flow by requiring a non-empty returned user handle and looking up the user by that opaque value.

For authentication, include all of the current user’s credential descriptors in `allowCredentials`, including transport hints recorded at registration. This supports multiple authenticators while avoiding unauthenticated credential enumeration. Discoverable credentials are still supported when an authenticator creates them, because WebAuthn allows a discoverable credential to be used with a non-empty `allowCredentials` list. A future passwordless flow may omit the list, in which case the response’s user handle becomes necessary to identify the user. [W3C discoverable credentials](https://www.w3.org/TR/webauthn-3/#discoverable-credential), [W3C assertion user identification](https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion)

### Platform authenticators and security keys

Do not force `authenticatorAttachment` in the MVP registration options. Let the browser offer both platform and cross-platform authenticators. Use the native Web Authentication API; the PHP library should only process the returned response. The same server-side path then supports Touch ID, Windows Hello, Android platform authenticators, YubiKeys, Titan keys, and other compatible FIDO2 devices. [W3C attachment modalities](https://www.w3.org/TR/webauthn-3/#enumdef-authenticatorattachment), [FIDO Security Reference](https://fidoalliance.org/specs/common-specs/fido-security-ref-v2.1-ps-20220523.html)

Recommended MVP options:

- registration: `attestation: none`, `residentKey: preferred`, `userVerification: preferred`, and an `excludeCredentials` list for the current user;
- authentication: `userVerification: preferred`, all known credential descriptors in `allowCredentials`, and the stored transport hints; and
- require user presence through the normal assertion ceremony, while accepting either a physical-key touch or platform user verification. Do not require UV for every credential, because that would exclude security keys that provide user presence but do not have a configured PIN/biometric user-verification capability.

`attestation: none` is deliberate: the MVP needs a valid public-key credential, not manufacturer proof. It avoids making ordinary YubiKey, platform authenticator, or synced-passkey support depend on attestation roots and metadata policy. The W3C permits a relying party to accept a credential as having no attestation when its policy does not require proof of a particular authenticator model. [W3C attestation policy](https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential)

### Signature counters

At registration, persist the returned initial counter. At every successful assertion, compare the returned counter with the stored counter and persist the updated record atomically. If either value is non-zero and the new value is less than or equal to the stored value, WebAuthn treats it as a clone/malfunction/race signal; it is not proof of cloning, so the application must choose its response. [W3C signature counter guidance](https://www.w3.org/TR/webauthn-3/#sctn-signature-counter-considerations), [W3C assertion counter step](https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion)

For MVP, use the library’s default strict counter checker and treat a non-zero rollback as a failed WebAuthn challenge, retaining the last known counter and writing an audit event. Treat zero/zero as valid because some authenticators do not implement counters. Persist the library-returned updated credential record in a transaction with an optimistic version or equivalent compare-and-swap guard so concurrent assertions cannot silently overwrite a newer counter.

## Verification boundary

### The selected library must verify

The plugin must pass the original browser response through the library’s loader and validator and must not reimplement these checks:

1. response type and structure (`AuthenticatorAttestationResponse` or `AuthenticatorAssertionResponse`);
2. client-data JSON parsing and `webauthn.create`/`webauthn.get` type;
3. comparison of the client-data challenge with the challenge in the server-created options;
4. exact allowed-origin validation, including scheme and port, using a patched supported library version;
5. SHA-256 RP ID hash validation from authenticator data;
6. user-presence and configured user-verification flags;
7. user-handle consistency;
8. allowed credential ID and credential-record consistency;
9. credential public-key algorithm and signature verification;
10. attestation-object/CBOR parsing, supported attestation-format validation, and credential-public-key extraction;
11. credential ID size and duplicate-credential checks; and
12. signature-counter checks and updated credential-record construction.

These are represented as explicit upstream ceremony steps, including [challenge](https://github.com/web-auth/webauthn-framework/blob/5.4.x/src/webauthn/src/CeremonyStep/CheckChallenge.php), [origin](https://github.com/web-auth/webauthn-framework/blob/5.4.x/src/webauthn/src/CeremonyStep/CheckAllowedOrigins.php), [RP ID hash](https://github.com/web-auth/webauthn-framework/blob/5.4.x/src/webauthn/src/CeremonyStep/CheckRelyingPartyIdIdHash.php), [user handle](https://github.com/web-auth/webauthn-framework/blob/5.4.x/src/webauthn/src/CeremonyStep/CheckUserHandle.php), [signature](https://github.com/web-auth/webauthn-framework/blob/5.4.x/src/webauthn/src/CeremonyStep/CheckSignature.php), and [counter](https://github.com/web-auth/webauthn-framework/blob/5.4.x/src/webauthn/src/CeremonyStep/CheckCounter.php).

### The plugin must verify or enforce

The library cannot know WordPress’s authentication state or deployment policy. The plugin must implement and test:

1. **Trusted ceremony configuration.** Build creation/request options from server-side policy. Do not accept RP ID, allowed origins, user ID, credential allow-lists, or expected challenge from the browser response.
2. **Environment policy.** Enable WebAuthn only where `wp_get_environment_type()` and deployment configuration permit it. In staging/local/development, disable the WebAuthn method as decided by the project; do not reinterpret a database ID as an RP ID.
3. **Installation binding.** Store the installation identity with the challenge and credential. A database clone must not automatically make production WebAuthn records valid in another environment.
4. **Challenge lifecycle.** Generate, store, expire, revoke, atomically consume, and bind each challenge to the pending session, operation, user, and installation.
5. **Primary-authentication binding.** Start enrollment only after the current user has satisfied the required WordPress password/re-authentication step. Start a login challenge only for the user represented by the pending primary-authentication session.
6. **Credential lookup.** Load the credential record by raw credential ID from the plugin’s table, require that it belongs to the expected user and installation, and reject unknown, revoked, or disabled records before treating verification as successful.
7. **State transition.** Only after the library succeeds and the challenge is atomically consumed may the plugin mark the current login session as WebAuthn-satisfied. Enrollment must not itself be treated as proof for a later login.
8. **Persistence integrity.** Insert new credential IDs uniquely; update counters with a transaction/CAS guard; preserve the library’s updated credential record; and handle duplicate or stale updates as failures.
9. **MVP policy.** Decide and enforce `attestation: none`, user-verification preference, accepted algorithms, discoverable-credential preference, and the production-only environment rule in one policy object rather than scattered request handlers.
10. **Abuse controls and audit.** Rate-limit failed assertions, audit success/failure and authenticator metadata without storing private key material or raw challenge data, and return generic user-facing errors.

## Proposed adapter contract

The plugin should wrap the selected library behind a narrow adapter so WordPress code is not coupled to `Webauthn\*` DTOs:

```text
WebAuthnProvider
  begin_registration(user, pending_session) -> browser options + challenge reference
  complete_registration(user, pending_session, browser response) -> credential metadata
  begin_authentication(user, pending_session) -> browser options + challenge reference
  complete_authentication(user, pending_session, browser response) -> updated credential
```

The adapter should accept an injected credential repository, challenge repository, installation/environment policy, clock, and library validator. The browser response is untrusted input. The adapter should return a small internal result or a typed failure; WordPress controllers should not catch and expose library exception messages directly.

The adapter boundary makes the security-critical business logic independently testable:

- feed deterministic registration/assertion fixtures to the library validator;
- test each plugin-owned rejection before invoking the library;
- test challenge expiry, replay, user/session mismatch, installation mismatch, and atomic consumption separately;
- test credential ownership and counter persistence with a fake repository; and
- test the final session-state transition only after both repository and library verification succeed.

## Storage implications

The existing conceptual authenticator table should retain binary-safe or canonical base64url values for:

- credential ID, with a unique index;
- user ID and installation identity;
- opaque user handle;
- credential public key/credential record data;
- RP ID;
- transport hints;
- initial/current signature counter;
- AAGUID and optional attestation metadata;
- backup eligibility/status and UV-initialized state where available;
- friendly name, creation time, last-used time, and revocation state.

The private key never reaches the server. Only the public credential record is stored. The W3C recommends retaining the credential ID, public key, signature counter, transports, and related credential-record fields needed for later ceremonies. [W3C credential record](https://www.w3.org/TR/webauthn-3/#credential-record)

Challenge records should be separate, short-lived rows rather than user meta. They need indexes supporting lookup by pending session, user, operation, and expiry. Credential ID lookup should be indexed and unique within the installation.

## Testing requirements added by this decision

The implementation plan should include tests for:

- valid registration with `attestation: none`;
- valid assertion from a cross-platform/security-key response;
- valid assertion from a platform-authenticator response with UV set;
- unexpected origin, scheme, host, and port;
- RP ID hash mismatch;
- challenge mismatch, expiry, replay, operation mismatch, user mismatch, and session mismatch;
- user-handle mismatch and usernameless response without a user handle;
- unknown credential ID, credential belonging to another user, revoked credential, and duplicate registration;
- invalid signature, unsupported algorithm, invalid CBOR/attestation data, and missing UP/required UV;
- counter zero/zero, increasing counter, non-zero rollback, and concurrent stale updates;
- multiple credentials and transport descriptor generation; and
- production-only WebAuthn and staging/local disablement.

Use the upstream library’s unit-testable ceremony steps for protocol fixtures, and keep plugin tests focused on the adapter’s policy, persistence, and session-state boundary. Where browser-level coverage is added, use WebDriver virtual-authenticator support or real security keys/platform authenticators in CI/manual QA; do not replace server-side verification tests with browser-only tests.

## Consequences

Positive:

- The plugin can support YubiKeys, other FIDO2 security keys, Touch ID, Windows Hello, and compatible platform/passkey authenticators through one native browser API and one server validator.
- The protocol implementation is delegated to a maintained library with explicit, replaceable verification steps and test fixtures.
- WordPress-specific session gating, environment transitions, recovery, and audit behaviour remain under plugin control.

Costs and constraints:

- The selected 5.x library line requires PHP 8.2; the compatibility-baseline ticket must either adopt that baseline or identify a different supported line.
- The library has a larger dependency graph than the smaller alternatives, so Composer conflict testing is required for WordPress deployments.
- RP ID remains domain-scoped. A database-specific installation identity is an additional isolation control, not a way to share WebAuthn credentials across unrelated domains.
- WebAuthn is production-only under the project’s environment policy; staging/local users must use TOTP/recovery or an explicitly configured non-WebAuthn path.

## Final implementation decision

Adopt `web-auth/webauthn-lib` as the WebAuthn protocol dependency. Build a PDS WP 2FA adapter around its pure-PHP attestation/assertion validators and configurable ceremony steps. Keep all challenge storage and consumption, WordPress identity/session binding, environment/install binding, credential repository integrity, rate limiting, audit logging, and “2FA satisfied for this login” state transitions in the plugin.
