<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method;

final class ProviderRegistry
{
    /** @var array<string, AuthenticationMethodProvider> */
    private array $providers = [];

    /** @param iterable<AuthenticationMethodProvider> $providers */
    public function __construct(iterable $providers)
    {
        foreach ($providers as $provider) {
            $key = $provider->key()->value();
            if (isset($this->providers[$key])) {
                throw new \InvalidArgumentException('Provider keys must be unique.');
            }
            $this->providers[$key] = $provider;
        }
    }

    public function get(ProviderKey $key): AuthenticationMethodProvider
    {
        if (!isset($this->providers[$key->value()])) {
            throw new \InvalidArgumentException('The requested authentication provider is unavailable.');
        }

        return $this->providers[$key->value()];
    }

    public function has(ProviderKey $key): bool
    {
        return isset($this->providers[$key->value()]);
    }

    /** @return list<AuthenticationMethodProvider> */
    public function all(): array
    {
        return array_values($this->providers);
    }
}
