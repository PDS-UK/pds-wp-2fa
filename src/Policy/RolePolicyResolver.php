<?php

declare(strict_types=1);

namespace PDS\WP2FA\Policy;

final class RolePolicyResolver
{
    public function resolve(RolePolicyResolutionInput $input): RolePolicyResolution
    {
        $currentRoles = [];
        foreach ($input->currentRoles() as $role) {
            $currentRoles[$role->value()] = true;
        }

        $anchors = [];
        foreach ($input->anchors() as $anchor) {
            if ($anchor->userId() === $input->userId()) {
                $anchors[$anchor->roleKey()->value()] = $anchor;
            }
        }

        $policies = [];
        foreach ($input->policies() as $policy) {
            $policies[$policy->roleKey()->value()] = $policy;
        }

        $contributors = [];
        $anchorsToPersist = [];
        foreach ($currentRoles as $roleKey => $_present) {
            $policy = $policies[$roleKey] ?? null;
            if ($policy === null || !$policy->isActive() || $policy->activatedAt() === null) {
                continue;
            }

            $anchor = $anchors[$roleKey] ?? null;
            if ($anchor === null) {
                $affectedSince = $input->firstObservedAt($policy->roleKey()) ?? $policy->activatedAt();
                $anchor = new UserRolePolicyAnchor($input->userId(), $policy->roleKey(), $affectedSince);
                $anchorsToPersist[] = $anchor;
            }

            $deadline = Time::addSeconds($anchor->affectedSince(), $policy->gracePeriodSeconds());
            $contributors[] = new RolePolicyContribution($policy->roleKey(), $anchor->affectedSince(), $deadline);
        }

        usort($contributors, static function (RolePolicyContribution $left, RolePolicyContribution $right): int {
            return strcmp($left->roleKey()->value(), $right->roleKey()->value());
        });

        $protected = $contributors !== [];
        $baseDeadline = null;
        foreach ($contributors as $contributor) {
            $baseDeadline = Time::min($baseDeadline ?? $contributor->deadline(), $contributor->deadline());
        }

        $extensionUntil = null;
        foreach ($input->extensions() as $extension) {
            if (!$extension->appliesTo($input->userId(), $input->cycle())) {
                continue;
            }
            if ($extension->grantedUntil() < $input->now()) {
                continue;
            }
            $extensionUntil = Time::max($extensionUntil, $extension->grantedUntil());
        }

        $effectiveDeadline = $protected && !$input->enrolled()
            ? Time::max($baseDeadline, $extensionUntil)
            : null;
        $overdue = $effectiveDeadline !== null && $input->now()->getTimestamp() >= $effectiveDeadline->getTimestamp();

        return new RolePolicyResolution(
            $protected,
            $contributors,
            $anchorsToPersist,
            $baseDeadline,
            $extensionUntil,
            $effectiveDeadline,
            $overdue,
        );
    }
}
