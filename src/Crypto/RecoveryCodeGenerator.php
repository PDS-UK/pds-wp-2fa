<?php

declare(strict_types=1);

namespace PDS\WP2FA\Crypto;

final class RecoveryCodeGenerator
{
    /** @var callable(int): string */
    private $randomBytes;

    /** @param null|callable(int): string $randomBytes */
    public function __construct(?callable $randomBytes = null)
    {
        $this->randomBytes = $randomBytes ?? static fn (int $length): string => random_bytes($length);
    }

    public function generate(): RecoveryCodeBundle
    {
        $codes = [];

        for ($index = 0; $index < 10; ++$index) {
            try {
                $bytes = ($this->randomBytes)(16);
            } catch (\Throwable) {
                throw new CryptoException('Recovery-code generation failed.');
            }

            if (!is_string($bytes) || strlen($bytes) !== 16) {
                throw new CryptoException('Recovery-code generation failed.');
            }

            $code = strtoupper(bin2hex($bytes));

            if (isset($codes[$code])) {
                throw new CryptoException('Recovery-code generation failed.');
            }

            $codes[] = $code;
        }

        return new RecoveryCodeBundle($codes);
    }
}
