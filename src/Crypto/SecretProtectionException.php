<?php

declare(strict_types=1);

namespace PDS\WP2FA\Crypto;

final class SecretProtectionException extends CryptoException
{
    public function __construct()
    {
        parent::__construct('Secret protection failed.');
    }
}
