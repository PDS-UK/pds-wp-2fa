<?php

declare(strict_types=1);

namespace PDS\WP2FA\Persistence;

/**
 * The small part of WordPress' wpdb contract used by the plugin.
 *
 * Keeping this seam local makes repositories testable without loading all of
 * WordPress, while WordPressWpdb delegates to the real global implementation.
 */
interface Wpdb
{
    public function prefix(): string;

    public function prepare(string $query, mixed ...$args): string;

    public function query(string $query): int|false;

    public function get_var(string $query): mixed;

    public function get_row(string $query): mixed;

    /** @return list<mixed> */
    public function get_results(string $query): array;

    public function get_charset_collate(): string;

    public function get_error(): string;
}
