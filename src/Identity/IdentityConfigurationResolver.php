<?php

declare(strict_types=1);

namespace PDS\WP2FA\Identity;

final class IdentityConfigurationResolver
{
    public function resolve(ConfigurationSources $sources): ConfigurationResolution
    {
        $constantValid = !$sources->constantDefined() || $this->isCanonicalIdentity($sources->constantValue());
        $environmentValid = !$sources->environmentDefined() || $this->isCanonicalIdentity($sources->environmentValue());

        if (!$constantValid) {
            return ConfigurationResolution::error('invalid_constant');
        }

        if (!$environmentValid) {
            return ConfigurationResolution::error('invalid_environment');
        }

        if (!$sources->constantDefined() && !$sources->environmentDefined()) {
            return ConfigurationResolution::unconfigured();
        }

        if ($sources->constantDefined() && $sources->environmentDefined()
            && $sources->constantValue() !== $sources->environmentValue()) {
            return ConfigurationResolution::error('source_conflict');
        }

        $value = $sources->constantDefined()
            ? $sources->constantValue()
            : $sources->environmentValue();

        return ConfigurationResolution::configured(InstallationIdentity::fromCanonicalHex($value));
    }

    /**
     * @param mixed $value
     */
    private function isCanonicalIdentity($value): bool
    {
        return is_string($value)
            && preg_match('/\A[0-9a-f]{64}\z/D', $value) === 1;
    }
}
