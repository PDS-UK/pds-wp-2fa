<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method;

final class MethodDraft
{
    public function __construct(
        private UserId $userId,
        private InstallationBinding $installation,
        private ProviderKey $providerKey,
        private int $schemaVersion,
        private FriendlyLabel $label,
        private ProviderData $providerData,
    ) {
        if ($schemaVersion < 1) {
            throw new \InvalidArgumentException('Provider schema versions must be positive.');
        }
        if ($schemaVersion !== $providerData->schemaVersion()) {
            throw new \InvalidArgumentException('Method draft and provider data versions must match.');
        }
    }

    public function userId(): UserId { return $this->userId; }
    public function installation(): InstallationBinding { return $this->installation; }
    public function providerKey(): ProviderKey { return $this->providerKey; }
    public function schemaVersion(): int { return $this->schemaVersion; }
    public function label(): FriendlyLabel { return $this->label; }
    public function providerData(): ProviderData { return $this->providerData; }
}
