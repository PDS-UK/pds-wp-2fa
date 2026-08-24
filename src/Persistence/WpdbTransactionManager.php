<?php

declare(strict_types=1);

namespace PDS\WP2FA\Persistence;

use PDS\WP2FA\Method\TransactionManager;

final class WpdbTransactionManager implements TransactionManager
{
    public function __construct(private Wpdb $db) {}

    public function transaction(callable $operation): mixed
    {
        $this->checked('START TRANSACTION', 'start transaction');

        try {
            $result = $operation();
            $this->checked('COMMIT', 'commit transaction');

            return $result;
        } catch (\Throwable $e) {
            try {
                $this->checked('ROLLBACK', 'rollback transaction');
            } catch (\Throwable $rollback) {
                throw new PersistenceException('Transaction failed and rollback also failed.', 0, $e);
            }

            throw $e;
        }
    }

    private function checked(string $query, string $operation): void
    {
        if ($this->db->query($query) === false) {
            throw PersistenceException::queryFailed($operation, $this->db->get_error());
        }
    }
}
