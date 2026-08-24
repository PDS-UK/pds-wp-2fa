<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method\Provider\WebAuthn;

use PDS\WP2FA\Method\FriendlyLabel;
use PDS\WP2FA\Method\InstallationBinding;
use PDS\WP2FA\Method\MethodId;
use PDS\WP2FA\Method\UserId;
use Webauthn\CredentialRecord;

final class WebAuthnCredential
{
    public function __construct(
        private MethodId $methodId,
        private UserId $userId,
        private InstallationBinding $installation,
        private CredentialRecord $record,
        private FriendlyLabel $label,
        private int $revision = 1,
    ) {
        if ($revision < 1 || $record->publicKeyCredentialId === '' || $record->userHandle === '') {
            throw new \InvalidArgumentException('The WebAuthn credential record is invalid.');
        }
        if (strlen($record->userHandle) > 64) {
            throw new \InvalidArgumentException('The WebAuthn user handle is too long.');
        }
    }

    public function methodId(): MethodId { return $this->methodId; }
    public function userId(): UserId { return $this->userId; }
    public function installation(): InstallationBinding { return $this->installation; }
    public function record(): CredentialRecord { return $this->record; }
    public function label(): FriendlyLabel { return $this->label; }
    public function revision(): int { return $this->revision; }
}
