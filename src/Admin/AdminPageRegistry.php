<?php

declare(strict_types=1);

namespace PDS\WP2FA\Admin;

interface AdminPageRegistry
{
    public function addMenuPage(string $slug, string $capability, callable $render): void;

    public function addPostAction(string $action, callable $handler): void;
}
