<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method;

final class PolicySnapshot
{
    /** @var array<string, scalar|null> */
    private array $values;

    /** @param array<string, scalar|null> $values */
    private function __construct(array $values)
    {
        $this->values = $values;
    }

    /** @param array<string, scalar|null> $values */
    public static function fromArray(array $values): self
    {
        foreach ($values as $key => $value) {
            if (!is_string($key) || preg_match('/^[a-z][a-z0-9_.-]*$/', $key) !== 1) {
                throw new \InvalidArgumentException('Policy snapshot keys must be stable identifiers.');
            }
            if ($value !== null && !is_scalar($value)) {
                throw new \InvalidArgumentException('Policy snapshots contain scalar values only.');
            }
        }

        return new self($values);
    }

    /** @return array<string, scalar|null> */
    public function toArray(): array
    {
        return $this->values;
    }
}
