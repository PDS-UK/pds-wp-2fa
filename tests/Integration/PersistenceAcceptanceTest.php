<?php

declare(strict_types=1);

namespace PDS\WP2FA\Tests\Integration;

require_once __DIR__ . '/Fixtures.php';

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use PDS\WP2FA\Admin\SettingsSnapshot;
use PDS\WP2FA\Persistence\MigrationRunner;
use PDS\WP2FA\Persistence\SchemaDefinition;
use PDS\WP2FA\Persistence\TableNames;

final class PersistenceAcceptanceTest extends TestCase
{
    public function testMigrationIsAdditiveBoundedAndExecutableWithAwpdbFake(): void
    {
        $tables = new TableNames('wp_');
        $schema = new SchemaDefinition($tables, 'DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci');
        $statements = $schema->statements();

        self::assertCount(count(TableNames::SUFFIXES), $statements);
        foreach (TableNames::SUFFIXES as $suffix) {
            self::assertTrue(
                count(array_filter($statements, static fn (string $statement): bool => str_contains($statement, $tables->get($suffix)))) === 1,
                'Every fixed table must have exactly one canonical DDL statement: ' . $suffix,
            );
        }
        self::assertStringContainsString('audit_retention_days', $statements[1]);
        self::assertStringContainsString('installation_identity_hash', implode("\n", $statements));
        self::assertStringContainsString('installation_epoch', implode("\n", $statements));

        $db = new FixtureWpdb();
        $deltaCalls = [];
        $runner = new MigrationRunner(
            $db,
            $tables,
            $schema,
            static function (string $statement) use (&$deltaCalls): void {
                $deltaCalls[] = $statement;
            },
        );

        $runner->migrate(new DateTimeImmutable('2026-08-24T12:00:00+00:00'));

        self::assertCount(count($statements), $deltaCalls);
        self::assertTrue($runner->isReady());
        self::assertGreaterThanOrEqual(2, count($db->queries));
    }

    public function testRetentionPolicyAcceptsDocumentedBoundsAndRejectsOutsideThem(): void
    {
        self::assertSame(400, (new SettingsSnapshot(true, [], 400))->auditRetentionDays());
        self::assertSame(2555, (new SettingsSnapshot(true, [], 2555))->auditRetentionDays());

        $this->expectException(\InvalidArgumentException::class);
        new SettingsSnapshot(true, [], 399);
    }

    public function testRetentionPolicyRejectsValuesAboveMaximum(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new SettingsSnapshot(true, [], 2556);
    }
}
