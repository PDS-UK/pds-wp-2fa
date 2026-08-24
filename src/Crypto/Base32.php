<?php

declare(strict_types=1);

namespace PDS\WP2FA\Crypto;

final class Base32
{
    private const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    public static function encode(string $bytes): string
    {
        if ($bytes === '') {
            throw new \InvalidArgumentException('Cannot Base32-encode an empty value.');
        }

        $output = '';
        $buffer = 0;
        $bits = 0;

        for ($index = 0, $length = strlen($bytes); $index < $length; ++$index) {
            $buffer = ($buffer << 8) | ord($bytes[$index]);
            $bits += 8;

            while ($bits >= 5) {
                $bits -= 5;
                $output .= self::ALPHABET[($buffer >> $bits) & 31];
                $buffer &= $bits === 0 ? 0 : (1 << $bits) - 1;
            }
        }

        if ($bits > 0) {
            $output .= self::ALPHABET[($buffer << (5 - $bits)) & 31];
        }

        return $output;
    }

    public static function decode(string $value): string
    {
        if ($value === '' || preg_match('/\A[A-Za-z2-7]+\z/D', $value) !== 1) {
            throw new \InvalidArgumentException('Invalid Base32 value.');
        }

        if (in_array(strlen($value) % 8, [1, 3, 6], true)) {
            throw new \InvalidArgumentException('Invalid Base32 length.');
        }

        $value = strtoupper($value);
        $output = '';
        $buffer = 0;
        $bits = 0;

        for ($index = 0, $length = strlen($value); $index < $length; ++$index) {
            $character = strpos(self::ALPHABET, $value[$index]);

            if ($character === false) {
                throw new \InvalidArgumentException('Invalid Base32 value.');
            }

            $buffer = ($buffer << 5) | $character;
            $bits += 5;

            if ($bits >= 8) {
                $bits -= 8;
                $output .= chr(($buffer >> $bits) & 0xff);
                $buffer &= $bits === 0 ? 0 : (1 << $bits) - 1;
            }
        }

        if ($bits > 0 && (($buffer << (8 - $bits)) & 0xff) !== 0) {
            throw new \InvalidArgumentException('Non-canonical Base32 value.');
        }

        return $output;
    }
}
