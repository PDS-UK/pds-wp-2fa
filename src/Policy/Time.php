<?php

declare(strict_types=1);

namespace PDS\WP2FA\Policy;

use DateTimeImmutable;
use DateTimeZone;

final class Time
{
    public static function utc(DateTimeImmutable $time): DateTimeImmutable
    {
        if ($time->getOffset() === 0) {
            return $time;
        }

        return $time->setTimezone(new DateTimeZone('UTC'));
    }

    public static function addSeconds(DateTimeImmutable $time, int $seconds): DateTimeImmutable
    {
        if ($seconds < 0) {
            throw new \InvalidArgumentException('A duration cannot be negative.');
        }

        return self::utc($time)->modify('+' . $seconds . ' seconds');
    }

    public static function max(?DateTimeImmutable $left, ?DateTimeImmutable $right): ?DateTimeImmutable
    {
        if ($left === null) {
            return $right === null ? null : self::utc($right);
        }

        if ($right === null) {
            return self::utc($left);
        }

        return self::atOrAfter($left, $right) ? self::utc($left) : self::utc($right);
    }

    public static function min(DateTimeImmutable $left, DateTimeImmutable $right): DateTimeImmutable
    {
        return self::atOrBefore($left, $right) ? self::utc($left) : self::utc($right);
    }

    public static function atOrAfter(DateTimeImmutable $left, DateTimeImmutable $right): bool
    {
        return $left->getTimestamp() >= $right->getTimestamp();
    }

    public static function atOrBefore(DateTimeImmutable $left, DateTimeImmutable $right): bool
    {
        return $left->getTimestamp() <= $right->getTimestamp();
    }

    public static function after(DateTimeImmutable $left, DateTimeImmutable $right): bool
    {
        return $left->getTimestamp() > $right->getTimestamp();
    }

    public static function equals(?DateTimeImmutable $left, ?DateTimeImmutable $right): bool
    {
        if ($left === null || $right === null) {
            return $left === $right;
        }

        return $left->getTimestamp() === $right->getTimestamp();
    }

    public static function iso(?DateTimeImmutable $time): ?string
    {
        return $time === null ? null : self::utc($time)->format('c');
    }
}
