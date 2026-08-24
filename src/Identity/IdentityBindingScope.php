<?php

declare(strict_types=1);

namespace PDS\WP2FA\Identity;

/**
 * The mandatory pair every identity-bound security repository must carry.
 */
final class IdentityBindingScope
{
    private IdentityFingerprint $fingerprint;

    private int $epoch;

    public function __construct(IdentityFingerprint $fingerprint, int $epoch)
    {
        if ($epoch < 1) {
            throw new \InvalidArgumentException('Identity scope epoch must be positive.');
        }

        $this->fingerprint = $fingerprint;
        $this->epoch = $epoch;
    }

    public function fingerprint(): IdentityFingerprint
    {
        return $this->fingerprint;
    }

    public function epoch(): int
    {
        return $this->epoch;
    }

    /**
     * @return array{installation_identity_hash: string, installation_epoch: int}
     */
    public function toPersistenceCriteria(): array
    {
        return [
            'installation_identity_hash' => $this->fingerprint->binary(),
            'installation_epoch' => $this->epoch,
        ];
    }
}
