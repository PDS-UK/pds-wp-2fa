<?php

declare(strict_types=1);

namespace PDS\WP2FA\Bootstrap;

use PDS\WP2FA\Method\AuthenticationMethodProvider;
use PDS\WP2FA\Method\ProviderRegistry;

/**
 * Discovers optional providers without making an unavailable adapter a
 * reason to construct a partially working security runtime.
 */
final class ProviderRegistryFactory
{
    /** @var list<class-string<AuthenticationMethodProvider>> */
    private const OPTIONAL_PROVIDERS = [
        'PDS\\WP2FA\\Method\\Provider\\WebAuthn\\WebAuthnProvider',
    ];

    /**
     * @param iterable<AuthenticationMethodProvider> $configured
     * @param list<string>|null $optionalClasses
     */
    public function build(iterable $configured = [], ?array $optionalClasses = null): ProviderRegistry
    {
        $providers = [];
        foreach ($configured as $provider) {
            if (!$provider instanceof AuthenticationMethodProvider) {
                throw new \InvalidArgumentException('Configured providers must implement AuthenticationMethodProvider.');
            }
            $providers[] = $provider;
        }

        foreach ($optionalClasses ?? self::OPTIONAL_PROVIDERS as $class) {
            $provider = $this->instantiate($class);
            if ($provider !== null) {
                $providers[] = $provider;
            }
        }

        return new ProviderRegistry($providers);
    }

    /** @return list<string> */
    public function optionalClasses(): array
    {
        return self::OPTIONAL_PROVIDERS;
    }

    private function instantiate(string $class): ?AuthenticationMethodProvider
    {
        try {
            if (!class_exists($class) || !is_a($class, AuthenticationMethodProvider::class, true)) {
                return null;
            }

            if (is_callable([$class, 'fromRuntime'])) {
                $provider = $class::fromRuntime();
            } else {
                $reflection = new \ReflectionClass($class);
                if (!$reflection->isInstantiable() || $reflection->getConstructor()?->getNumberOfRequiredParameters() > 0) {
                    return null;
                }
                $provider = $reflection->newInstance();
            }

            return $provider instanceof AuthenticationMethodProvider ? $provider : null;
        } catch (\Throwable) {
            return null;
        }
    }
}
