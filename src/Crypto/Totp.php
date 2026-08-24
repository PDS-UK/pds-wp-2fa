<?php

declare(strict_types=1);

namespace PDS\WP2FA\Crypto;

/**
 * Native RFC 6238 implementation for the fixed phase-one profile.
 *
 * An OTPHP adapter can implement the same public behavior later without
 * making the rest of the plugin depend on OTPHP types.
 */
final class Totp
{
    private const SECRET_LENGTH = 20;
    private const COUNTER_DIVISOR = 4294967296;

    public function __construct(
        private readonly UnixClock $clock,
        private readonly TotpProfile $profile = new TotpProfile(),
    ) {
    }

    public function generate(string $secret, ?int $unixTime = null): string
    {
        $this->assertSecret($secret);
        $step = $this->stepForTime($unixTime ?? $this->clock->now());

        return $this->generateForStep($secret, $step);
    }

    public function verify(
        string $code,
        string $secret,
        ?int $unixTime = null,
        ?int $lastAcceptedStep = null,
    ): TotpVerificationResult {
        $this->assertSecret($secret);

        if (preg_match('/\A[0-9]{6}\z/D', $code) !== 1) {
            return TotpVerificationResult::rejected('invalid_code');
        }

        if ($lastAcceptedStep !== null && $lastAcceptedStep < 0) {
            throw new \InvalidArgumentException('Invalid accepted TOTP step.');
        }

        $currentStep = $this->stepForTime($unixTime ?? $this->clock->now());
        $steps = [0];

        if ($this->profile->window === 1) {
            $steps[] = -1;
            $steps[] = 1;
        }

        foreach ($steps as $offset) {
            $candidateStep = $currentStep + $offset;

            if ($candidateStep < 0 || !hash_equals($this->generateForStep($secret, $candidateStep), $code)) {
                continue;
            }

            if ($lastAcceptedStep !== null && $candidateStep <= $lastAcceptedStep) {
                return TotpVerificationResult::rejected('already_accepted', $candidateStep);
            }

            return TotpVerificationResult::accepted($candidateStep);
        }

        return TotpVerificationResult::rejected('invalid_code');
    }

    public function stepForTime(int $unixTime): int
    {
        if ($unixTime < $this->profile->t0) {
            throw new \InvalidArgumentException('Invalid Unix time.');
        }

        return intdiv($unixTime - $this->profile->t0, $this->profile->period);
    }

    private function generateForStep(string $secret, int $step): string
    {
        $counter = pack(
            'N2',
            intdiv($step, self::COUNTER_DIVISOR),
            $step % self::COUNTER_DIVISOR,
        );
        $hash = hash_hmac('sha1', $counter, $secret, true);
        $offset = ord($hash[19]) & 0x0f;
        $binary = unpack('N', substr($hash, $offset, 4));

        if (!is_array($binary) || !isset($binary[1])) {
            throw new CryptoException('TOTP calculation failed.');
        }

        $value = ($binary[1] & 0x7fffffff) % 1000000;

        return str_pad((string) $value, 6, '0', STR_PAD_LEFT);
    }

    private function assertSecret(string $secret): void
    {
        if (strlen($secret) !== self::SECRET_LENGTH) {
            throw new \InvalidArgumentException('Invalid TOTP secret.');
        }
    }
}
