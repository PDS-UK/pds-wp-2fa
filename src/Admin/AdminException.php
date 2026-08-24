<?php

declare(strict_types=1);

namespace PDS\WP2FA\Admin;

final class AdminException extends \RuntimeException
{
    public function __construct(string $message, private readonly string $reason = 'invalid_request')
    {
        parent::__construct($message);
    }

    public function reason(): string
    {
        return $this->reason;
    }
}
