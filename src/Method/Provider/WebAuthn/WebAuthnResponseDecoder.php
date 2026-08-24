<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method\Provider\WebAuthn;

use Webauthn\PublicKeyCredential;

interface WebAuthnResponseDecoder
{
    /** @param array<string, mixed> $input */
    public function decode(array $input): PublicKeyCredential;
}
