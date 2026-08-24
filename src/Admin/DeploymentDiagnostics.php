<?php

declare(strict_types=1);

namespace PDS\WP2FA\Admin;

interface DeploymentDiagnostics
{
    /** @return array<string, mixed> */
    public function safeDiagnostics(): array;
}
