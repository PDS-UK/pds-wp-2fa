<?php

declare(strict_types=1);

namespace PDS\WP2FA\Persistence;

use RuntimeException;

/** Adapter around the global WordPress wpdb object. */
final class WordPressWpdb implements Wpdb
{
    public function __construct(private object $wpdb)
    {
        foreach (['prefix', 'prepare', 'query', 'get_var', 'get_row', 'get_results', 'get_charset_collate'] as $method) {
            if (!method_exists($wpdb, $method)) {
                throw new RuntimeException('The supplied object is not a compatible wpdb instance.');
            }
        }
    }

    public function prefix(): string
    {
        $prefix = $this->wpdb->prefix ?? null;
        if (!is_string($prefix) || $prefix === '' || preg_match('/\A[A-Za-z0-9_$-]+\z/', $prefix) !== 1) {
            throw new RuntimeException('The WordPress table prefix is invalid.');
        }

        return $prefix;
    }

    public function prepare(string $query, mixed ...$args): string
    {
        return $this->wpdb->prepare($query, ...$args);
    }

    public function query(string $query): int|false
    {
        return $this->wpdb->query($query);
    }

    public function get_var(string $query): mixed
    {
        return $this->wpdb->get_var($query);
    }

    public function get_row(string $query): mixed
    {
        $mode = defined('ARRAY_A') ? constant('ARRAY_A') : 'ARRAY_A';

        return $this->wpdb->get_row($query, $mode);
    }

    public function get_results(string $query): array
    {
        $mode = defined('ARRAY_A') ? constant('ARRAY_A') : 'ARRAY_A';
        $rows = $this->wpdb->get_results($query, $mode);

        return is_array($rows) ? $rows : [];
    }

    public function get_charset_collate(): string
    {
        return (string) $this->wpdb->get_charset_collate();
    }

    public function get_error(): string
    {
        return isset($this->wpdb->last_error) ? (string) $this->wpdb->last_error : '';
    }
}
