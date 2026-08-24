<?php

declare(strict_types=1);

namespace PDS\WP2FA\Policy;

use DateTimeImmutable;

final class RolePolicyLifecycle
{
    /** @param list<RolePolicy> $existingPolicies */
    public function reconcile(RoleDiscoverySnapshot $snapshot, array $existingPolicies): RolePolicyLifecycleResult
    {
        $existing = [];
        foreach ($existingPolicies as $policy) {
            if (!$policy instanceof RolePolicy) {
                throw new \InvalidArgumentException('Role-policy reconciliation requires RolePolicy records.');
            }
            $existing[$policy->roleKey()->value()] = $policy;
        }

        $policies = [];
        $events = [];
        $observedAt = $snapshot->observedAt();
        foreach ($snapshot->roleKeys() as $roleKey) {
            $label = $snapshot->labelFor($roleKey);
            $key = $roleKey->value();
            if (!isset($existing[$key])) {
                $policies[$key] = RolePolicy::discovered($roleKey, $label, $observedAt);
                $events[] = new RolePolicyLifecycleEvent('role_policy_discovered', $observedAt, $roleKey, ['label' => $label]);
                continue;
            }

            $policy = $existing[$key];
            $wasOrphaned = $policy->status()->isOrphaned();
            $labelChanged = $policy->currentRoleLabel() !== $label;
            $policies[$key] = $policy->reconcileSeen($label, $observedAt);
            if ($wasOrphaned) {
                $events[] = new RolePolicyLifecycleEvent('role_policy_reappeared', $observedAt, $roleKey, ['label' => $label]);
            }
            if ($labelChanged) {
                $events[] = new RolePolicyLifecycleEvent('role_label_changed', $observedAt, $roleKey, ['label' => $label]);
            }
        }

        foreach ($existing as $key => $policy) {
            if (isset($policies[$key])) {
                continue;
            }
            $orphaned = $policy->markOrphaned($observedAt);
            $policies[$key] = $orphaned;
            if (!$policy->status()->isOrphaned()) {
                $events[] = new RolePolicyLifecycleEvent('role_policy_orphaned', $observedAt, $policy->roleKey());
            }
        }

        ksort($policies, SORT_STRING);
        return new RolePolicyLifecycleResult($policies, $events);
    }

    public function enable(RolePolicy $policy, DateTimeImmutable $at): RolePolicyLifecycleResult
    {
        $wasEnabled = $policy->enabledConfiguration();
        $wasEverEnabled = $policy->activatedAt() !== null;
        $updated = $policy->enable($at);
        $eventType = $wasEnabled ? null : ($wasEverEnabled ? 'role_policy_reenabled' : 'role_policy_enabled');

        return new RolePolicyLifecycleResult(
            [$updated->roleKey()->value() => $updated],
            $eventType === null ? [] : [new RolePolicyLifecycleEvent($eventType, Time::utc($at), $updated->roleKey())],
        );
    }

    public function disable(RolePolicy $policy, DateTimeImmutable $at): RolePolicyLifecycleResult
    {
        $updated = $policy->disable($at);
        $events = $policy->enabledConfiguration()
            ? [new RolePolicyLifecycleEvent('role_policy_disabled', Time::utc($at), $policy->roleKey())]
            : [];

        return new RolePolicyLifecycleResult([$updated->roleKey()->value() => $updated], $events);
    }

    public function setGracePeriod(RolePolicy $policy, int $seconds, DateTimeImmutable $at): RolePolicyLifecycleResult
    {
        $updated = $policy->withGracePeriodSeconds($seconds, $at);
        $events = $updated === $policy
            ? []
            : [new RolePolicyLifecycleEvent('role_policy_grace_changed', Time::utc($at), $policy->roleKey(), ['seconds' => $seconds])];

        return new RolePolicyLifecycleResult([$updated->roleKey()->value() => $updated], $events);
    }
}
