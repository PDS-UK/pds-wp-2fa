<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method;

final class MethodSnapshotCollection
{
    /** @var list<MethodSnapshot> */
    private array $items;

    /** @param list<MethodSnapshot> $items */
    public function __construct(array $items)
    {
        $seen = [];
        foreach ($items as $item) {
            if (!$item instanceof MethodSnapshot) {
                throw new \InvalidArgumentException('Method snapshots must be typed values.');
            }
            if (isset($seen[$item->methodId()->value()])) {
                throw new \InvalidArgumentException('Method snapshots cannot contain duplicates.');
            }
            $seen[$item->methodId()->value()] = true;
        }

        $this->items = array_values($items);
    }

    /** @return list<MethodSnapshot> */
    public function all(): array { return $this->items; }

    public function first(): MethodSnapshot
    {
        if ($this->items === []) {
            throw new \LogicException('An interaction requires at least one method snapshot.');
        }

        return $this->items[0];
    }

    public function contains(MethodId $methodId): bool
    {
        foreach ($this->items as $item) {
            if ($item->methodId()->equals($methodId)) {
                return true;
            }
        }

        return false;
    }

    public function find(MethodId $methodId): ?MethodSnapshot
    {
        foreach ($this->items as $item) {
            if ($item->methodId()->equals($methodId)) {
                return $item;
            }
        }

        return null;
    }
}
