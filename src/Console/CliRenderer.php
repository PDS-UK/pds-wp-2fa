<?php

declare(strict_types=1);

namespace PDS\WP2FA\Console;

final class CliRenderer
{
    /** @param array<string, mixed>|list<array<string, mixed>> $data */
    public function render(array $data, OutputFormat $format): string
    {
        SafeCliData::assertSafe($data);
        $rows = self::rows($data);

        return match ($format) {
            OutputFormat::JSON => self::json($data),
            OutputFormat::CSV => self::csv($rows),
            OutputFormat::YAML => self::yaml($data),
            OutputFormat::TABLE => self::table($rows),
        };
    }

    /** @param array<string, mixed>|list<array<string, mixed>> $data @return list<array<string, mixed>> */
    private static function rows(array $data): array
    {
        if (array_is_list($data)) {
            return array_values(array_filter($data, static fn (mixed $row): bool => is_array($row)));
        }

        return [array_map(static fn (mixed $value): mixed => is_array($value) ? json_encode($value, JSON_THROW_ON_ERROR) : $value, $data)];
    }

    /** @param array<string, mixed>|list<array<string, mixed>> $data */
    private static function json(array $data): string
    {
        return json_encode($data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . PHP_EOL;
    }

    /** @param list<array<string, mixed>> $rows */
    private static function csv(array $rows): string
    {
        if ($rows === []) {
            return '';
        }
        $keys = array_keys($rows[0]);
        $lines = [implode(',', array_map([self::class, 'csvCell'], $keys))];
        foreach ($rows as $row) {
            $lines[] = implode(',', array_map(static fn (string $key): string => self::csvCell((string) ($row[$key] ?? '')), $keys));
        }

        return implode(PHP_EOL, $lines) . PHP_EOL;
    }

    /** @param list<array<string, mixed>> $rows */
    private static function table(array $rows): string
    {
        if ($rows === []) {
            return PHP_EOL;
        }
        $keys = array_keys($rows[0]);
        $widths = array_fill_keys($keys, 0);
        foreach ($keys as $key) {
            $widths[$key] = strlen($key);
        }
        foreach ($rows as $row) {
            foreach ($keys as $key) {
                $widths[$key] = max($widths[$key], strlen((string) ($row[$key] ?? '')));
            }
        }
        $line = static function (array $row) use ($keys, $widths): string {
            return implode('  ', array_map(static fn (string $key): string => str_pad((string) ($row[$key] ?? ''), $widths[$key]), $keys));
        };

        return $line(array_combine($keys, $keys)) . PHP_EOL
            . $line($rows[0]) . (count($rows) > 1 ? PHP_EOL . implode(PHP_EOL, array_map($line, array_slice($rows, 1))) : '') . PHP_EOL;
    }

    private static function csvCell(string $value): string
    {
        return '"' . str_replace('"', '""', $value) . '"';
    }

    /** @param array<string, mixed>|list<array<string, mixed>> $data */
    private static function yaml(array $data): string
    {
        return self::yamlValue($data) . PHP_EOL;
    }

    private static function yamlValue(mixed $value, int $indent = 0): string
    {
        $prefix = str_repeat('  ', $indent);
        if (!is_array($value)) {
            return is_bool($value) ? ($value ? 'true' : 'false') : ($value === null ? 'null' : (string) $value);
        }
        $lines = [];
        foreach ($value as $key => $nested) {
            $encodedKey = (string) $key;
            if (is_array($nested)) {
                $lines[] = $prefix . $encodedKey . ':';
                $lines[] = self::yamlValue($nested, $indent + 1);
            } else {
                $lines[] = $prefix . $encodedKey . ': ' . self::yamlValue($nested);
            }
        }

        return implode(PHP_EOL, $lines);
    }
}
