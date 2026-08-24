<?php

declare(strict_types=1);

namespace PDS\WP2FA\Admin;

interface AuditWriter
{
    public function append(AuditEvent $event): void;
}
