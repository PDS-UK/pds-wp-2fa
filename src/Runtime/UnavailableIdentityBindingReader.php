<?php

declare(strict_types=1);

namespace PDS\WP2FA\Runtime;

use PDS\WP2FA\Identity\IdentityBindingReader;
use PDS\WP2FA\Identity\InstallationBinding;
use RuntimeException;

/** Prevents an absent database from being interpreted as a fresh binding. */
final class UnavailableIdentityBindingReader implements IdentityBindingReader
{
    public function read(): ?InstallationBinding
    {
        throw new RuntimeException('The WordPress database is unavailable.');
    }
}
