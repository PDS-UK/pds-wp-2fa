<?php

declare(strict_types=1);

namespace PDS\WP2FA\Identity;

final class IdentityGenerator
{
    private RandomBytesSource $random;

    public function __construct(?RandomBytesSource $random = null)
    {
        $this->random = $random ?? new SecureRandomBytes();
    }

    /**
     * Generate the one-time provisioning value for an operator/CLI boundary.
     *
     * The caller must not persist this value in the plugin domain or include it
     * in status/diagnostic output.
     */
    public function generateCanonicalHex(): string
    {
        $bytes = $this->random->bytes(32);

        if (strlen($bytes) !== 32) {
            throw new \UnexpectedValueException('The random source did not return 32 bytes.');
        }

        return bin2hex($bytes);
    }

    public function generateIdentity(): InstallationIdentity
    {
        return InstallationIdentity::fromCanonicalHex($this->generateCanonicalHex());
    }
}
