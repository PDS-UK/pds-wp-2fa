<?php

declare(strict_types=1);

namespace PDS\WP2FA\Identity;

/**
 * Mutation seam for the later persistence and WP-CLI layers.
 *
 * This slice deliberately provides no implementation. Implementations must
 * perform the corresponding operation transactionally and invalidate foreign
 * security state according to the installation-identity contract.
 */
interface IdentityBindingWriter
{
    public function initialize(InstallationBinding $binding): void;

    public function rebind(InstallationBinding $binding): void;

    public function rotate(InstallationBinding $binding): void;
}
