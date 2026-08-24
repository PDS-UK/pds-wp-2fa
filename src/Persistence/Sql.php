<?php

declare(strict_types=1);

namespace PDS\WP2FA\Persistence;

/** Shared checked query and binary/JSON encoding helpers. */
final class Sql
{
    public function __construct(private Wpdb $db) {}

    public function execute(string $sql, string $operation): int
    {
        $result = $this->db->query($sql);
        if ($result === false) {
            throw PersistenceException::queryFailed($operation, $this->db->get_error());
        }

        return $result;
    }

    /** @return array<string,mixed>|null */
    public function row(string $sql, string $operation): ?array
    {
        $row = $this->db->get_row($sql);
        if ($row === null || $row === false) {
            $error = $this->db->get_error();
            if ($error !== '') {
                throw PersistenceException::queryFailed($operation, $error);
            }
            return null;
        }
        if (is_object($row)) {
            $row = get_object_vars($row);
        }
        if (!is_array($row)) {
            throw PersistenceException::queryFailed($operation, 'Unexpected row shape.');
        }

        return $row;
    }

    /** @return list<array<string,mixed>> */
    public function rows(string $sql, string $operation): array
    {
        $rows = $this->db->get_results($sql);
        $error = $this->db->get_error();
        if ($error !== '') {
            throw PersistenceException::queryFailed($operation, $error);
        }
        $out = [];
        foreach ($rows as $row) {
            if (is_object($row)) {
                $row = get_object_vars($row);
            }
            if (!is_array($row)) {
                throw PersistenceException::queryFailed($operation, 'Unexpected row shape.');
            }
            $out[] = $row;
        }

        return $out;
    }

    public static function json(mixed $value): string
    {
        try {
            return json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        } catch (\JsonException $e) {
            throw new PersistenceException('Could not encode provider state safely.', 0, $e);
        }
    }

    public static function decodeJson(?string $value): array
    {
        if ($value === null || $value === '') {
            return [];
        }
        try {
            $decoded = json_decode($value, true, 32, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new PersistenceException('Persisted provider state is invalid.', 0, $e);
        }
        if (!is_array($decoded)) {
            throw new PersistenceException('Persisted provider state is not an object.');
        }

        return $decoded;
    }

    public static function utc(\DateTimeImmutable $date): string
    {
        return $date->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d H:i:s');
    }

    public static function date(?string $date): ?\DateTimeImmutable
    {
        return $date === null || $date === '' ? null : new \DateTimeImmutable($date, new \DateTimeZone('UTC'));
    }

    public static function opaque16(string $value): string
    {
        if (preg_match('/\A[0-9a-f]{32}\z/D', $value) === 1) {
            return hex2bin($value);
        }
        $decoded = base64_decode(strtr($value, '-_', '+/') . str_repeat('=', (4 - strlen($value) % 4) % 4), true);
        if (is_string($decoded) && strlen($decoded) === 16) {
            return $decoded;
        }

        return substr(hash('sha256', $value, true), 0, 16);
    }

    public static function opaque32(string $value): string
    {
        if (preg_match('/\A[0-9a-f]{64}\z/D', $value) === 1) {
            return hex2bin($value);
        }
        $decoded = base64_decode(strtr($value, '-_', '+/') . str_repeat('=', (4 - strlen($value) % 4) % 4), true);
        return is_string($decoded) && strlen($decoded) === 32 ? $decoded : hash('sha256', $value, true);
    }

    public static function externalId(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
