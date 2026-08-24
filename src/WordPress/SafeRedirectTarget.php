<?php

declare(strict_types=1);

namespace PDS\WP2FA\WordPress;

use Closure;
use RuntimeException;

final class SafeRedirectTarget
{
    private readonly Closure $validateRedirect;
    private readonly Closure $adminUrl;

    public function __construct(callable $validateRedirect, callable $adminUrl)
    {
        $this->validateRedirect = Closure::fromCallable($validateRedirect);
        $this->adminUrl = Closure::fromCallable($adminUrl);
    }

    public static function fromWordPress(): self
    {
        if (!function_exists('wp_validate_redirect') || !function_exists('admin_url')) {
            throw new RuntimeException('WordPress redirect functions are required to validate a redirect target.');
        }

        return new self(
            static fn (string $target, string $fallback): string => (string) \wp_validate_redirect($target, $fallback),
            static fn (): string => (string) \admin_url('/'),
        );
    }

    public function validate(?string $candidate): string
    {
        $fallback = (string) ($this->adminUrl)();
        $validated = ($this->validateRedirect)($candidate ?? '', $fallback);

        if (!is_string($validated) || $validated === '') {
            return $fallback;
        }

        return $this->isAllowedAdminTarget($validated, $fallback) ? $validated : $fallback;
    }

    private function isAllowedAdminTarget(string $target, string $fallback): bool
    {
        $fallbackParts = parse_url($fallback);
        $targetParts = parse_url($target);

        if (!is_array($fallbackParts) || !is_array($targetParts)) {
            return false;
        }

        if (isset($targetParts['user']) || isset($targetParts['pass']) || isset($targetParts['fragment'])) {
            return false;
        }

        if (str_starts_with($target, '//')) {
            return false;
        }

        if (isset($targetParts['host'])) {
            if (!$this->sameSite($targetParts, $fallbackParts)) {
                return false;
            }
        } elseif (isset($targetParts['scheme'])) {
            return false;
        } elseif (!str_starts_with($target, '/')) {
            return false;
        }

        $targetPath = $this->decodedPath($targetParts['path'] ?? '/');
        $adminPath = $this->decodedPath($fallbackParts['path'] ?? '/');
        $adminPath = rtrim($adminPath, '/') ?: '/';

        if (!$this->isWithinAdminPath($targetPath, $adminPath)) {
            return false;
        }

        return !$this->hasSensitiveQueryKey($targetParts['query'] ?? null);
    }

    /**
     * @param array<string, mixed> $target
     * @param array<string, mixed> $fallback
     */
    private function sameSite(array $target, array $fallback): bool
    {
        return strtolower((string) ($target['host'] ?? '')) === strtolower((string) ($fallback['host'] ?? ''))
            && (int) ($target['port'] ?? 0) === (int) ($fallback['port'] ?? 0)
            && strtolower((string) ($target['scheme'] ?? '')) === strtolower((string) ($fallback['scheme'] ?? ''));
    }

    private function decodedPath(string $path): string
    {
        $decoded = rawurldecode($path);
        if (str_contains($decoded, "\0") || str_contains($decoded, '\\')) {
            return "\0";
        }

        foreach (explode('/', $decoded) as $segment) {
            if ($segment === '.' || $segment === '..') {
                return "\0";
            }
        }

        return $decoded;
    }

    private function isWithinAdminPath(string $targetPath, string $adminPath): bool
    {
        if ($targetPath === "\0" || $adminPath === "\0") {
            return false;
        }

        return $adminPath === '/'
            || $targetPath === $adminPath
            || str_starts_with($targetPath, $adminPath . '/');
    }

    private function hasSensitiveQueryKey(?string $query): bool
    {
        if ($query === null || $query === '') {
            return false;
        }

        $parameters = [];
        parse_str($query, $parameters);

        return $this->containsSensitiveKey($parameters);
    }

    /**
     * @param array<mixed> $parameters
     */
    private function containsSensitiveKey(array $parameters): bool
    {
        foreach ($parameters as $key => $value) {
            if (preg_match('/token|challenge|secret|recovery|credential/i', (string) $key) === 1) {
                return true;
            }

            if (is_array($value) && $this->containsSensitiveKey($value)) {
                return true;
            }
        }

        return false;
    }
}
