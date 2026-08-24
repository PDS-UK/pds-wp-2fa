<?php

declare(strict_types=1);

namespace PDS\WP2FA\Console;

enum OutputFormat: string
{
    case TABLE = 'table';
    case CSV = 'csv';
    case JSON = 'json';
    case YAML = 'yaml';

    public static function fromOption(mixed $value): self
    {
        if ($value === null || $value === '') {
            return self::TABLE;
        }
        $format = self::tryFrom(strtolower((string) $value));
        if ($format === null) {
            throw new CliException('Format must be table, csv, json, or yaml.', CliExitCode::USAGE);
        }

        return $format;
    }
}
