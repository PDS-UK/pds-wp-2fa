<?php

declare(strict_types=1);

namespace PDS\WP2FA\Crypto;

final class ProvisioningUri
{
    public static function build(
        string $issuer,
        string $account,
        string $secret,
        ?TotpProfile $profile = null,
    ): string {
        $profile ??= new TotpProfile();
        self::assertTrustedLabel($issuer);
        self::assertTrustedLabel($account);

        if (strlen($secret) !== 20) {
            throw new \InvalidArgumentException('Invalid TOTP secret.');
        }

        $label = rawurlencode($issuer) . ':' . rawurlencode($account);
        $query = http_build_query([
            'secret' => Base32::encode($secret),
            'issuer' => $issuer,
            'algorithm' => $profile->algorithm,
            'digits' => $profile->digits,
            'period' => $profile->period,
        ], '', '&', PHP_QUERY_RFC3986);

        return 'otpauth://totp/' . $label . '?' . $query;
    }

    private static function assertTrustedLabel(string $value): void
    {
        if ($value === '' || strlen($value) > 128 || preg_match('/[\x00-\x1F\x7F]/', $value) === 1) {
            throw new \InvalidArgumentException('Invalid provisioning label.');
        }
    }
}
