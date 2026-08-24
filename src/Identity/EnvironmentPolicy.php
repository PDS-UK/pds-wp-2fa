<?php

declare(strict_types=1);

namespace PDS\WP2FA\Identity;

final class EnvironmentPolicy
{
    private EnvironmentType $environment;

    private bool $nonProductionBypassRequested;

    private bool $productionWebAuthnEnabled;

    private function __construct(
        EnvironmentType $environment,
        bool $nonProductionBypassRequested,
        bool $productionWebAuthnEnabled
    ) {
        $this->environment = $environment;
        $this->nonProductionBypassRequested = $nonProductionBypassRequested;
        $this->productionWebAuthnEnabled = $productionWebAuthnEnabled;
    }

    public static function for(
        EnvironmentType $environment,
        bool $nonProductionBypassRequested = false,
        bool $productionWebAuthnEnabled = true
    ): self {
        return new self($environment, $nonProductionBypassRequested, $productionWebAuthnEnabled);
    }

    public static function local(bool $nonProductionBypassRequested = false): self
    {
        return self::for(EnvironmentType::local(), $nonProductionBypassRequested);
    }

    public static function development(bool $nonProductionBypassRequested = false): self
    {
        return self::for(EnvironmentType::development(), $nonProductionBypassRequested);
    }

    public static function staging(bool $nonProductionBypassRequested = false): self
    {
        return self::for(EnvironmentType::staging(), $nonProductionBypassRequested);
    }

    public static function production(bool $webAuthnEnabled = true): self
    {
        return self::for(EnvironmentType::production(), false, $webAuthnEnabled);
    }

    public function environment(): EnvironmentType
    {
        return $this->environment;
    }

    public function webAuthnEnabled(): bool
    {
        return $this->environment->isProduction() && $this->productionWebAuthnEnabled;
    }

    public function nonProductionBypassApplies(): bool
    {
        return !$this->environment->isProduction() && $this->nonProductionBypassRequested;
    }

    public function enforcementRequired(bool $globalEnforcement): bool
    {
        if (!$globalEnforcement) {
            return false;
        }

        return !$this->nonProductionBypassApplies();
    }
}
