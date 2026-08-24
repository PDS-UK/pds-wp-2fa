<?php

declare(strict_types=1);

namespace PDS\WP2FA\Identity;

final class InstallationBinding
{
    public const SINGLETON_ID = 1;
    public const SCHEMA_VERSION = 1;

    private IdentityFingerprint $identityFingerprint;

    private int $identityEpoch;

    private EnvironmentType $environment;

    public function __construct(
        IdentityFingerprint $identityFingerprint,
        int $identityEpoch,
        EnvironmentType $environment
    ) {
        if ($identityEpoch < 1) {
            throw new \InvalidArgumentException('Installation identity epoch must start at 1.');
        }

        $this->identityFingerprint = $identityFingerprint;
        $this->identityEpoch = $identityEpoch;
        $this->environment = $environment;
    }

    /**
     * Hydrate only the non-secret binding columns supplied by persistence.
     *
     * @param array<string, mixed> $record
     */
    public static function fromPersistenceRecord(array $record): self
    {
        $identityHash = $record['identity_hash'] ?? null;
        $epoch = $record['identity_epoch'] ?? null;
        $environment = $record['environment_type'] ?? null;

        if (!is_string($identityHash) || strlen($identityHash) !== 32) {
            throw new \InvalidArgumentException('The persisted identity fingerprint is invalid.');
        }

        if (is_string($epoch) && ctype_digit($epoch)) {
            $epoch = (int) $epoch;
        }

        if (!is_int($epoch) || $epoch < 1) {
            throw new \InvalidArgumentException('The persisted identity epoch is invalid.');
        }

        if (!is_string($environment)) {
            throw new \InvalidArgumentException('The persisted environment type is invalid.');
        }

        return new self(
            IdentityFingerprint::fromBytes($identityHash),
            $epoch,
            EnvironmentType::fromStoredValue($environment)
        );
    }

    public function identityFingerprint(): IdentityFingerprint
    {
        return $this->identityFingerprint;
    }

    public function identityHash(): string
    {
        return $this->identityFingerprint->binary();
    }

    public function epoch(): int
    {
        return $this->identityEpoch;
    }

    public function environment(): EnvironmentType
    {
        return $this->environment;
    }

    public function matches(IdentityFingerprint $fingerprint, EnvironmentType $environment): bool
    {
        return $this->identityFingerprint->equals($fingerprint)
            && $this->environment->equals($environment);
    }

    /**
     * The persistence adapter may add timestamps and transactional metadata.
     * This domain record contains no raw identity value.
     *
     * @return array<string, mixed>
     */
    public function toPersistenceRecord(): array
    {
        return [
            'installation_id' => self::SINGLETON_ID,
            'identity_hash' => $this->identityHash(),
            'identity_epoch' => $this->identityEpoch,
            'environment_type' => $this->environment->value(),
            'schema_version' => self::SCHEMA_VERSION,
        ];
    }
}
