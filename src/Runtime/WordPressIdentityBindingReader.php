<?php

declare(strict_types=1);

namespace PDS\WP2FA\Runtime;

use PDS\WP2FA\Identity\IdentityBindingReader;
use PDS\WP2FA\Identity\InstallationBinding;
use PDS\WP2FA\Persistence\Sql;
use PDS\WP2FA\Persistence\TableNames;
use PDS\WP2FA\Persistence\Wpdb;
use RuntimeException;

/** Read-only installation binding adapter for the WordPress database. */
final class WordPressIdentityBindingReader implements IdentityBindingReader
{
    public function __construct(
        private readonly Wpdb $db,
        private readonly TableNames $tables,
    ) {
    }

    public function read(): ?InstallationBinding
    {
        $sql = $this->db->prepare(
            'SELECT identity_hash, identity_epoch, environment_type FROM '
            . $this->tables->get('installations')
            . ' WHERE installation_id = %d',
            InstallationBinding::SINGLETON_ID,
        );
        $row = (new Sql($this->db))->row($sql, 'read installation binding');
        if ($row === null) {
            return null;
        }

        try {
            return InstallationBinding::fromPersistenceRecord($row);
        } catch (\Throwable $exception) {
            throw new RuntimeException('The installation binding is invalid.', 0, $exception);
        }
    }
}
