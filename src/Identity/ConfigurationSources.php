<?php

declare(strict_types=1);

namespace PDS\WP2FA\Identity;

/**
 * The two deployment authorities for the active installation identity.
 *
 * This object is an input boundary. It is deliberately not a persistence or
 * diagnostic model, and its debug representation never contains source data.
 */
final class ConfigurationSources
{
    public const NAME = 'PDS_WP_2FA_INSTALLATION_ID';

    private bool $constantDefined;

    /** @var mixed */
    private $constantValue;

    private bool $environmentDefined;

    /** @var mixed */
    private $environmentValue;

    /**
     * @param mixed $constantValue
     * @param mixed $environmentValue
     */
    public function __construct(
        bool $constantDefined,
        $constantValue,
        bool $environmentDefined,
        $environmentValue
    ) {
        $this->constantDefined = $constantDefined;
        $this->constantValue = $constantValue;
        $this->environmentDefined = $environmentDefined;
        $this->environmentValue = $environmentValue;
    }

    public static function none(): self
    {
        return new self(false, null, false, null);
    }

    /**
     * @param mixed $value
     */
    public static function constant($value): self
    {
        return new self(true, $value, false, null);
    }

    /**
     * @param mixed $value
     */
    public static function environment($value): self
    {
        return new self(false, null, true, $value);
    }

    /**
     * @param mixed $constantValue
     * @param mixed $environmentValue
     */
    public static function both($constantValue, $environmentValue): self
    {
        return new self(true, $constantValue, true, $environmentValue);
    }

    /**
     * Read the real PHP process without coupling the domain to WordPress.
     */
    public static function fromRuntime(): self
    {
        $constantDefined = defined(self::NAME);
        $environmentValue = getenv(self::NAME);
        $environmentDefined = $environmentValue !== false;

        return new self(
            $constantDefined,
            $constantDefined ? constant(self::NAME) : null,
            $environmentDefined,
            $environmentDefined ? $environmentValue : null
        );
    }

    public function constantDefined(): bool
    {
        return $this->constantDefined;
    }

    /**
     * @return mixed
     */
    public function constantValue()
    {
        return $this->constantValue;
    }

    public function environmentDefined(): bool
    {
        return $this->environmentDefined;
    }

    /**
     * @return mixed
     */
    public function environmentValue()
    {
        return $this->environmentValue;
    }

    public function __debugInfo(): array
    {
        return [
            'constant_defined' => $this->constantDefined,
            'environment_defined' => $this->environmentDefined,
            'values' => '[redacted]',
        ];
    }
}
