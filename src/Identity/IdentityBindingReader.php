<?php

declare(strict_types=1);

namespace PDS\WP2FA\Identity;

/**
 * Read-only persistence seam used by runtime inspection.
 */
interface IdentityBindingReader
{
    public function read(): ?InstallationBinding;
}
