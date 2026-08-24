<?php

declare(strict_types=1);

namespace PDS\WP2FA\Persistence;

use RuntimeException;

final class PersistenceException extends RuntimeException
{
    public static function queryFailed(string $operation, string $error = ''): self
    {
        $suffix = $error === '' ? '' : ': ' . $error;

        return new self('Persistence query failed during ' . $operation . $suffix);
    }

    public static function bindingMismatch(): self
    {
        return new self('The persisted record does not belong to the current installation binding.');
    }

    public static function compareAndSwapFailed(string $operation): self
    {
        return new self('The persistence compare-and-swap failed during ' . $operation . '.');
    }
}
