<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method;

final class ProviderContext
{
    private MethodSnapshotCollection $methodSnapshot;

    /** @param MethodSnapshotCollection|list<MethodSnapshot> $methodSnapshot */
    public function __construct(
        private UserId $userId,
        private InstallationBinding $installation,
        private SessionDigest $session,
        private InteractionId $interactionId,
        private InteractionPurpose $purpose,
        private ProviderKey $providerKey,
        private ServerChallenge $challenge,
        private PolicySnapshot $policy,
        MethodSnapshotCollection|array $methodSnapshot,
        private Clock $clock,
    ) {
        $this->methodSnapshot = $methodSnapshot instanceof MethodSnapshotCollection
            ? $methodSnapshot
            : new MethodSnapshotCollection($methodSnapshot);
    }

    public function userId(): UserId { return $this->userId; }
    public function installation(): InstallationBinding { return $this->installation; }
    public function session(): SessionDigest { return $this->session; }
    public function interactionId(): InteractionId { return $this->interactionId; }
    public function purpose(): InteractionPurpose { return $this->purpose; }
    public function providerKey(): ProviderKey { return $this->providerKey; }
    public function challenge(): ServerChallenge { return $this->challenge; }
    public function policy(): PolicySnapshot { return $this->policy; }
    public function methodSnapshot(): MethodSnapshotCollection { return $this->methodSnapshot; }
    public function clock(): Clock { return $this->clock; }
}
