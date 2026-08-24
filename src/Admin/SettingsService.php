<?php

declare(strict_types=1);

namespace PDS\WP2FA\Admin;

final class SettingsService
{
    public function __construct(
        private readonly SettingsRepository $repository,
        private readonly AuditService $audit,
        private readonly AdminTransaction $transaction,
    ) {
    }

    /** @param array<string, mixed> $submitted */
    public function save(
        AdminActor $actor,
        array $submitted,
        ReasonCode $reason,
        string $source = 'web',
        bool $confirmProduction = false,
    ): SettingsSnapshot {
        $current = $this->repository->snapshot();
        $update = SettingsUpdate::fromSubmitted($current, $submitted);
        $environment = $current->deploymentStatus()['environment_type'] ?? 'production';
        if (!is_string($environment)) {
            throw new AdminException('The deployment environment is unavailable.', 'unavailable');
        }

        if ($environment === 'production' && !$update->globalEnforcement()) {
            if ($source !== 'cli' || !$confirmProduction || $reason !== ReasonCode::INCIDENT) {
                throw new AdminException('Production enforcement changes require incident confirmation through WP-CLI.', 'confirmation_required');
            }
        }

        $this->transaction->run(function () use ($actor, $current, $update, $reason): void {
            $this->repository->save($update, $actor);
            if ($current->globalEnforcement() !== $update->globalEnforcement()) {
                $this->audit->record(
                    'global_enforcement_changed',
                    'high',
                    $actor,
                    $reason,
                    [
                        'old_enabled' => $current->globalEnforcement(),
                        'new_enabled' => $update->globalEnforcement(),
                        'environment_type' => $current->deploymentStatus()['environment_type'] ?? 'production',
                    ],
                );
            }
            foreach ($current->rolePolicies() as $policy) {
                $desired = $update->rolePolicies()[$policy->roleKey()];
                if ($policy->enabled() !== $desired['enabled']) {
                    $event = $desired['enabled']
                        ? ($policy->activatedAt() === null ? 'role_policy_enabled' : 'role_policy_reenabled')
                        : 'role_policy_disabled';
                    $this->audit->record($event, 'info', $actor, $reason, [
                        'role_key' => $policy->roleKey(),
                        'grace_period_seconds' => $desired['grace_period_seconds'],
                    ], roleKey: $policy->roleKey());
                }
                if ($policy->gracePeriodSeconds() !== $desired['grace_period_seconds']) {
                    $this->audit->record('role_policy_grace_changed', 'info', $actor, $reason, [
                        'role_key' => $policy->roleKey(),
                        'old_seconds' => $policy->gracePeriodSeconds(),
                        'new_seconds' => $desired['grace_period_seconds'],
                    ], roleKey: $policy->roleKey());
                }
            }
            if ($current->auditRetentionDays() !== $update->auditRetentionDays()) {
                $this->audit->record('retention_policy_changed', 'info', $actor, $reason, [
                    'old_days' => $current->auditRetentionDays(),
                    'new_days' => $update->auditRetentionDays(),
                ]);
            }
        });

        return $this->repository->snapshot();
    }
}
