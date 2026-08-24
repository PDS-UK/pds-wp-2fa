<?php

declare(strict_types=1);

namespace PDS\WP2FA\Admin;

use Closure;

final class StatusService
{
    private readonly Closure $webauthnAvailability;

    public function __construct(
        private readonly SettingsRepository $settings,
        private readonly DeploymentDiagnostics $diagnostics,
        callable $webauthnAvailability,
    ) {
        $this->webauthnAvailability = Closure::fromCallable($webauthnAvailability);
    }

    /** @return array<string, mixed> */
    public function overview(): array
    {
        $settings = $this->settings->snapshot();
        $diagnostics = $this->diagnostics->safeDiagnostics();
        $allowed = [
            'environment_type', 'binding_state', 'identity_epoch', 'non_production_bypass',
            'configured_fingerprint', 'binding_fingerprint',
        ];
        $safe = [];
        foreach ($allowed as $key) {
            if (array_key_exists($key, $diagnostics)) {
                $safe[$key] = $diagnostics[$key];
            }
        }
        $safe['global_enforcement'] = $settings->globalEnforcement();
        $safe['webauthn_available'] = (bool) ($webauthnAvailability)();
        $safe['role_policy_count'] = count($settings->rolePolicies());
        $safe['active_role_policy_count'] = count(array_filter(
            $settings->rolePolicies(),
            static fn (RolePolicySetting $policy): bool => $policy->status() === 'active',
        ));
        $safe['audit_retention_days'] = $settings->auditRetentionDays();

        return $safe;
    }
}
