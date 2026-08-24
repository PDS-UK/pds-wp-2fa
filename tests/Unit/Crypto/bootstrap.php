<?php

declare(strict_types=1);

spl_autoload_register(static function (string $class): void {
    $prefix = 'PDS\\WP2FA\\Crypto\\';

    if (!str_starts_with($class, $prefix)) {
        return;
    }

    $relative = substr($class, strlen($prefix));
    $path = dirname(__DIR__, 3) . '/src/Crypto/' . str_replace('\\', '/', $relative) . '.php';

    if (is_file($path)) {
        require_once $path;
    }
});
