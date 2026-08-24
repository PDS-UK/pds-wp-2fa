<?php

declare(strict_types=1);

namespace PDS\WP2FA\Crypto;

final class TotpProfile
{
    public function __construct(
        public readonly string $algorithm = 'SHA1',
        public readonly int $digits = 6,
        public readonly int $period = 30,
        public readonly int $t0 = 0,
        public readonly int $window = 1,
    ) {
        if ($this->algorithm !== 'SHA1' || $this->digits !== 6 || $this->period !== 30 || $this->t0 !== 0) {
            throw new \InvalidArgumentException('Unsupported TOTP profile.');
        }

        if ($this->window < 0 || $this->window > 1) {
            throw new \InvalidArgumentException('Invalid TOTP verification window.');
        }
    }
}
