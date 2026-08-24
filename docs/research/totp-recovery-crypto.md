# Research: TOTP, QR, recovery-code, and secret-protection primitives

Context: [Choose TOTP, QR, recovery-code, and secret-protection primitives](https://github.com/PDS-UK/pds-wp-2fa/issues/6)

Status: recommendation for the phase-one implementation. No plugin code is implemented by this report.

## Decision summary

| Area | Recommendation |
| --- | --- |
| TOTP profile | RFC 6238 with `T0 = 0`, 30-second period, 6 decimal digits, and HMAC-SHA-1 for phase-one interoperability. |
| TOTP secret | Generate 20 random bytes (160 bits) with PHP `random_bytes()`. Encode as unpadded uppercase Base32 only when provisioning; never store the provisioning URI in plaintext. |
| TOTP library | Prefer a maintained, tagged release of [OTPHP](https://github.com/Spomky-Labs/otphp), constrained to the fixed parameters above and used through a narrow adapter. Do not parse attacker-controlled provisioning URIs. |
| QR generation | Generate the `otpauth://` URI locally and render it with [endroid/qr-code](https://github.com/endroid/qr-code), preferably its SVG writer. Do not call an external QR service. Resolve the compatible package major in the compatibility-baseline decision. |
| Recovery codes | Ten independent 128-bit values from `random_bytes(16)`, displayed as uppercase hexadecimal in groups of four characters. Normalize case, ASCII spaces, and hyphens before verification. |
| Recovery storage | One `password_hash()` result per code, preferring `PASSWORD_ARGON2ID` when available and otherwise using `PASSWORD_DEFAULT`; verify with `password_verify()`. Never use a fast unsalted digest as the stored verifier. |
| TOTP encryption | Use PHP ext-sodium XChaCha20-Poly1305-IETF AEAD with a fresh 24-byte nonce per record and a 32-byte derived key. Bind the ciphertext to its user/authenticator record with authenticated additional data. |
| Key derivation | Prefer an externally supplied, deployment-specific 32-byte master secret. Derive the encryption key with HKDF-SHA-256 and a fixed context string. WordPress salts are an explicitly documented fallback, not the preferred production secret source. |

## Standards profile

### Parameters

RFC 6238 defines TOTP as HOTP with a time-derived counter, using Unix time, a configured time step, and the Unix epoch as the default starting point. It specifies a 30-second default step and permits HMAC-SHA-256 or HMAC-SHA-512 as alternatives to the HOTP HMAC-SHA-1 construction. The same secret and time-step parameters must be used by the prover and verifier, and each prover must have a unique secret. [RFC 6238 §§3–4](https://www.rfc-editor.org/rfc/rfc6238.html#section-3)

Use this fixed phase-one profile:

```text
algorithm: SHA1
digits:    6
period:    30 seconds
T0:        0 (Unix epoch)
secret:    20 random bytes (160 bits)
```

This is an interoperability decision, not a claim that SHA-1 is suitable for new general-purpose hashing. RFC 4226 defines the HOTP construction around HMAC-SHA-1, requires at least a 128-bit shared secret, and recommends 160 bits. RFC 6238 says keys should be the HMAC output length to aid interoperability. [RFC 4226 §§4–5](https://www.rfc-editor.org/rfc/rfc4226.html#section-4), [RFC 6238 §5.1](https://www.rfc-editor.org/rfc/rfc6238.html#section-5.1)

Six digits is the default usability choice for common authenticator applications. RFC 4226 requires at least six digits and describes numeric output as easier to enter. [RFC 4226 §4](https://www.rfc-editor.org/rfc/rfc4226.html#section-4)

Persist the parameters alongside the encrypted secret, even though phase one uses one global profile. This prevents a future policy change from silently making existing registrations unverifiable. Existing authenticators should continue using their recorded parameters until the user re-enrols or an explicit migration changes them.

### Verification window and replay

The verifier should accept at most one adjacent time step on either side of the current step (`T-1`, `T`, `T+1`) as a deliberately bounded clock/network-skew policy. The window must be configurable in code, but should not be widened casually: RFC 6238 warns that larger windows increase the attack window and recommends at most one time step for network delay. [RFC 6238 §5.2](https://www.rfc-editor.org/rfc/rfc6238.html#section-5.2)

Record the accepted time-step counter for each TOTP authenticator and update it atomically. Reject a counter that has already been accepted for that authenticator, including a second submission in the same time step. RFC 6238 explicitly says a verifier must not accept the same OTP again after successful validation. [RFC 6238 §5.2](https://www.rfc-editor.org/rfc/rfc6238.html#section-5.2)

Rate-limit failures across login sessions, not only within one browser session. RFC 4226 recommends throttling and says a delay/lockout scheme must work across sessions to prevent parallel guessing. The plugin should use bounded exponential delay or a small rolling failure budget, audit failures, and avoid permanent account lockout. [RFC 4226 §§7.1–7.3](https://www.rfc-editor.org/rfc/rfc4226.html#section-7.3)

The verifier must use an injected UTC/Unix clock and support counters beyond a 32-bit integer. RFC 6238 requires support beyond 2038. [RFC 6238 §4.2](https://www.rfc-editor.org/rfc/rfc6238.html#section-4.2)

## Provisioning URI and local QR generation

Construct the provisioning URI from trusted, internally selected fields. The interoperable shape is:

```text
otpauth://totp/{url-encoded-issuer}:{url-encoded-account}?secret={BASE32_SECRET}&issuer={url-encoded-issuer}&algorithm=SHA1&digits=6&period=30
```

The Google Authenticator project documents the `otpauth://` format, the `totp` type, an unpadded Base32 secret, the issuer label and parameter, and the `algorithm`, `digits`, and `period` fields. Include the issuer both in the label prefix and as the `issuer` parameter, as recommended by that documentation. [Google Authenticator Key URI Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)

The URI contains the TOTP secret and must be treated as credential material. Generate it only after the user has passed the required primary-authentication and re-authentication checks, and only for the short-lived enrollment transaction. Use HTTPS, `Cache-Control: no-store`, an appropriate no-referrer policy, and a session-bound CSRF-protected POST. Do not put the URI or secret in a query string, redirect location, browser history, analytics payload, exception, audit entry, or debug log. Do not include third-party assets on the page that could receive a referrer containing enrollment context.

Use a local Composer library rather than a hosted QR endpoint. `endroid/qr-code` documents Composer installation and writers for PNG and SVG, including `SvgWriter`; SVG is preferable here because it avoids requiring a raster extension just to display the enrollment code. [endroid/qr-code README](https://github.com/endroid/qr-code#qr-code)

The QR image is only an encoding of the secret, not a protection mechanism. Render it from the locally constructed URI, keep the response non-cacheable, and display the same secret as text with copy instructions so enrollment remains accessible without a camera. Escape the textual secret and any label. Do not expose a persistent QR image URL that could be fetched after enrollment.

For TOTP calculation and URI construction, prefer a maintained tagged release of [OTPHP](https://github.com/Spomky-Labs/otphp), which identifies itself as an RFC 4226/RFC 6238 implementation compatible with Google Authenticator and other applications. Wrap it behind the plugin's method interface and pin the selected release in `composer.lock`. The implementation should construct OTP objects from the plugin's own validated fields. It must not pass arbitrary user-supplied `otpauth://` query keys into a dynamic object or accept a provisioning URI from an untrusted request.

The exact library versions and minimum PHP version belong to the separate compatibility-baseline decision. Do not use a development branch or an unbounded Composer constraint in production.

## Recovery-code format and hashing

Generate ten independent recovery codes during initial enrollment and on regeneration:

1. Call `random_bytes(16)` for each code. PHP documents `random_bytes()` as uniformly random, cryptographically secure, and suitable for long-term secrets such as encryption keys. [PHP `random_bytes()`](https://www.php.net/manual/en/function.random-bytes.php)
2. Encode the 16 bytes as 32 uppercase hexadecimal characters.
3. Display each code as eight groups of four characters, for example `AB12-CD34-EF56-7890-1234-5678-9ABC-DEF0`. The example is illustrative only; never use fixed example values as credentials.
4. On input, trim and normalize only ASCII whitespace and hyphens, convert `a-f` to uppercase, and require exactly 32 hexadecimal characters. Do not silently accept arbitrary punctuation or Unicode lookalikes.

Hex is intentionally chosen over a custom alphabet: it has exactly 128 bits of entropy, uses a small unambiguous character set (`0-9`, `A-F`), and remains easy to copy, print, and enter. The grouping is presentation only and must not reduce the entropy or create a second accepted spelling.

Store one row per code with a password-style verifier, generation identifier, timestamps, and a nullable `used_at`/`revoked_at` state. Hash the normalized 32-character value with `password_hash()`; prefer `PASSWORD_ARGON2ID` when the runtime provides it and otherwise use `PASSWORD_DEFAULT`. Do not provide a manual salt: PHP generates and embeds a random salt and the algorithm parameters in the returned hash. [PHP `password_hash()`](https://www.php.net/manual/en/function.password-hash.php)

Verify candidates with `password_verify()`, which is timing-attack safe and does not require separate salt or algorithm storage. Never compare by re-hashing with a fixed salt, and never store plaintext, reversible encryption, a fast SHA-256 digest, or the generated display bundle. [PHP `password_verify()`](https://www.php.net/manual/en/function.password-verify.php)

Single-use handling must be race-safe:

1. Load only unused hashes for the user/generation.
2. Verify the submitted normalized code against those hashes without logging the candidate.
3. Mark the matching row used with a conditional update such as `WHERE id = ? AND used_at IS NULL`.
4. Treat an update affecting zero rows as a failed/replayed use.

Regeneration must invalidate the complete previous generation before the new plaintext bundle is returned. The plaintext codes should exist only in the one enrollment/regeneration response and the user's local copy. Never show them to administrators or include them in the audit log. A recovery-code success should record only the code row identifier or generation metadata, not the code itself.

## TOTP encryption at rest

TOTP secrets must be recoverable by the verifier, so they require authenticated encryption rather than one-way hashing. RFC 6238 recommends protecting validator-side keys and exposing them only for the short period needed to verify an OTP. [RFC 6238 §5.1](https://www.rfc-editor.org/rfc/rfc6238.html#section-5.1)

### Recommended primitive and envelope

Use PHP ext-sodium's XChaCha20-Poly1305-IETF AEAD:

```text
key:             32-byte derived key
nonce:           24 fresh random bytes per encryption
additional_data: version || type || user_id || authenticator_id
plaintext:       TOTP secret and immutable parameter record
ciphertext:      ciphertext plus authentication tag
```

PHP documents XChaCha20-Poly1305-IETF as the preferred provided AEAD mode, with 256-bit keys, 24-byte nonces, and authenticated additional data that is not encrypted or stored in the ciphertext. Generate each nonce with `random_bytes()` and never reuse a nonce with the same key. [PHP XChaCha20-Poly1305 encryption](https://www.php.net/manual/en/function.sodium-crypto-aead-xchacha20poly1305-ietf-encrypt.php), [PHP XChaCha20-Poly1305 key generation](https://www.php.net/manual/en/function.sodium-crypto-aead-xchacha20poly1305-ietf-keygen.php)

Create the authenticator's immutable identifier before encryption so it can be included in the additional data. On decryption, reconstruct the exact additional data from the current row and reject the record if authentication fails. This prevents a valid ciphertext from being silently reassigned to a different user, authenticator type, or record. Store the nonce, ciphertext, envelope version, key version, and nonsecret parameter columns; do not store the effective encryption key in the row.

If the runtime cannot provide ext-sodium, fail closed for TOTP enrollment and verification rather than silently falling back to bespoke cryptography. OpenSSL AES-GCM could be a separately reviewed fallback, but phase one should have one sodium-based envelope and one migration path.

### Key derivation inputs

The preferred deployment contract is a secret configured outside the database, for example:

```text
PDS_WP_2FA_ENCRYPTION_KEY = base64 encoding of 32 random bytes
```

The plugin should decode it strictly, reject weak or malformed values, and never copy it into an option, user meta, table row, audit record, or generated source file. A deployment-specific secret should be used for production, staging, local, and cloned environments separately. A database identifier may be used as a public context value, but it is not a secret and must not be the sole protection boundary.

Derive the AEAD key with HKDF-SHA-256:

```text
IKM:  external 32-byte deployment secret
salt: 32-byte random installation KDF salt stored as nonsecret metadata
info: "pds-wp-2fa/totp-secret/v1"
L:    32 bytes
```

PHP's `hash_hkdf()` accepts raw input keying material, an application-specific `info` string, an optional salt, and a requested output length, returning raw output keying material. [PHP `hash_hkdf()`](https://www.php.net/manual/en/function.hash-hkdf.php)

The installation KDF salt is not confidential; it provides stable domain separation for this installation. If a database is cloned, the clone must receive a different deployment master secret when it must be cryptographically isolated. Do not assume that a database-stored installation identifier alone prevents a cloned database from decrypting copied TOTP rows.

### WordPress salt fallback and limitations

WordPress's [`wp_salt()`](https://developer.wordpress.org/reference/functions/wp_salt/) exposes scheme-specific values derived from WordPress key/salt configuration. The official documentation says the keys may be defined in `wp-config.php`, but if they are not defined WordPress can generate and store corresponding values as site options. The API is also filterable.

Therefore:

- Prefer `PDS_WP_2FA_ENCRYPTION_KEY` from server/deployment configuration for production.
- If a fallback is retained for easier installation, derive HKDF input from the four scheme values (`auth`, `secure_auth`, `logged_in`, and `nonce`) with a fixed plugin context, and clearly warn that WordPress may have placed missing salt material in the database.
- Do not treat `wp_salt()` as an independent key-management system, and do not allow a missing or default WordPress salt configuration to silently reduce the security boundary.
- In a high-security or production configuration, fail closed or require explicit administrator acknowledgement when the external plugin key is absent.

This distinction matters for database backups: an encrypted TOTP column plus a server-side key is a materially different boundary from an encrypted column plus a key derivable entirely from the same database backup.

Add an envelope/key version now. A future key rotation should retain the old external key only during a controlled decrypt-and-re-encrypt migration, then remove it from deployment configuration. If a key is unavailable or authentication fails, return a generic configuration error and log only non-secret diagnostic metadata.

## Safe handling boundaries

The implementation should enforce these boundaries:

- **Enrollment**: The secret and provisioning URI are created only after primary authentication, the explicit enrollment session is established, and required nonce/re-authentication checks pass. Expire and invalidate the enrollment transaction on success, cancel, logout, timeout, or user change.
- **Presentation**: Show the secret manually and in the local QR only during enrollment. Use `no-store`; do not place the URI in URLs or third-party requests. Never provide a later “reveal secret” action.
- **Persistence**: Store only encrypted TOTP material and immutable nonsecret parameters. Store only recovery-code hashes. Keep secrets out of user meta, options, audit metadata, exceptions, SQL errors, and debug logs.
- **Verification**: Decrypt just before TOTP calculation, use the secret immediately, and release/overwrite temporary buffers where PHP permits. Do not cache plaintext secrets in object properties, persistent caches, transients, or session data.
- **Sessions**: A successful enrollment or challenge must update the explicit per-login 2FA state; the presence of an enrolled row must never imply that the current session has passed 2FA.
- **Replay**: Atomically record the accepted TOTP time-step counter and reject a previously accepted counter. Recovery-code consumption must likewise be an atomic single-use transition.
- **Logging**: Audit event type, user, authenticator identifier/type, timestamps, IP, and safe metadata only. Never record TOTP secrets, submitted codes, recovery plaintext, provisioning URIs, AEAD keys, nonces together with plaintext, or decrypted credential data.
- **Transport**: Require HTTPS for enrollment and challenge pages. RFC 4226 also recommends a secure channel to protect privacy and avoid replay. [RFC 4226 §7.1](https://www.rfc-editor.org/rfc/rfc4226.html#section-7.1)
- **Administration**: Administrative status may expose method type and timestamps, but not secrets or recovery plaintext. Reset/revoke operations should invalidate the encrypted credential and recovery generation without attempting to recover their contents.
- **Testing**: Test RFC 4226/RFC 6238 vectors, the exact URI fields, ±1-step boundaries, counter replay, malformed/tampered ciphertext, wrong-user additional data, concurrent recovery-code use, regeneration invalidation, key-missing failure, and log redaction.

## Sources consulted

All sources used for the recommendations above are primary specifications, first-party WordPress documentation/source, PHP's official manual, or the official source/documentation for the named libraries:

- [RFC 4226 — HOTP](https://www.rfc-editor.org/rfc/rfc4226.html)
- [RFC 6238 — TOTP](https://www.rfc-editor.org/rfc/rfc6238.html)
- [PHP `random_bytes()`](https://www.php.net/manual/en/function.random-bytes.php)
- [PHP `hash_hkdf()`](https://www.php.net/manual/en/function.hash-hkdf.php)
- [PHP XChaCha20-Poly1305-IETF](https://www.php.net/manual/en/function.sodium-crypto-aead-xchacha20poly1305-ietf-encrypt.php)
- [PHP `password_hash()`](https://www.php.net/manual/en/function.password-hash.php)
- [PHP `password_verify()`](https://www.php.net/manual/en/function.password-verify.php)
- [WordPress `wp_salt()`](https://developer.wordpress.org/reference/functions/wp_salt/)
- [Google Authenticator Key URI Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)
- [Spomky-Labs OTPHP source](https://github.com/Spomky-Labs/otphp)
- [endroid/qr-code source and documentation](https://github.com/endroid/qr-code)

