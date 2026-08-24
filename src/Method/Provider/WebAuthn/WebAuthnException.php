<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method\Provider\WebAuthn;

use PDS\WP2FA\Method\MethodException;

final class WebAuthnException extends MethodException
{
    public static function invalidInput(?\Throwable $previous = null): self
    {
        return new self('The security-key response was not accepted.', 0, $previous);
    }

    public static function unavailable(?\Throwable $previous = null): self
    {
        return new self('The security-key provider is unavailable.', 0, $previous);
    }
}
