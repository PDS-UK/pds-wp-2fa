<?php

declare(strict_types=1);

namespace PDS\WP2FA\Policy;

use DateTimeImmutable;

final class GraceExtension
{
    private function __construct(
        private int $userId,
        private EnrollmentCycleId $cycle,
        private DateTimeImmutable $grantedAt,
        private int $requestedSeconds,
        private ?DateTimeImmutable $previousEffectiveDeadline,
        private DateTimeImmutable $grantedUntil,
        private DateTimeImmutable $newEffectiveDeadline,
        private string $grantedBy,
        private string $reason,
    ) {
    }

    public static function grant(
        int $userId,
        EnrollmentCycleId $cycle,
        DateTimeImmutable $grantedAt,
        int $requestedSeconds,
        ?DateTimeImmutable $currentEffectiveDeadline,
        string $grantedBy,
        string $reason,
    ): self {
        if ($userId < 1 || $requestedSeconds < 0 || trim($grantedBy) === '' || trim($reason) === '') {
            throw new \InvalidArgumentException('Grace extension inputs are invalid.');
        }

        $grantedAt = Time::utc($grantedAt);
        $currentEffectiveDeadline = $currentEffectiveDeadline === null
            ? null
            : Time::utc($currentEffectiveDeadline);
        $base = Time::max($currentEffectiveDeadline, $grantedAt);
        if ($base === null) {
            $base = $grantedAt;
        }
        $grantedUntil = Time::addSeconds($base, $requestedSeconds);

        return new self(
            $userId,
            $cycle,
            $grantedAt,
            $requestedSeconds,
            $currentEffectiveDeadline,
            $grantedUntil,
            $grantedUntil,
            $grantedBy,
            $reason,
        );
    }

    public function userId(): int { return $this->userId; }
    public function cycle(): EnrollmentCycleId { return $this->cycle; }
    public function grantedAt(): DateTimeImmutable { return $this->grantedAt; }
    public function requestedSeconds(): int { return $this->requestedSeconds; }
    public function previousEffectiveDeadline(): ?DateTimeImmutable { return $this->previousEffectiveDeadline; }
    public function grantedUntil(): DateTimeImmutable { return $this->grantedUntil; }
    public function newEffectiveDeadline(): DateTimeImmutable { return $this->newEffectiveDeadline; }
    public function grantedBy(): string { return $this->grantedBy; }
    public function reason(): string { return $this->reason; }

    public function appliesTo(int $userId, EnrollmentCycleId $cycle): bool
    {
        return $this->userId === $userId && $this->cycle->equals($cycle);
    }
}
