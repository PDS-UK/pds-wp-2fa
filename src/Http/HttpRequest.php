<?php

declare(strict_types=1);

namespace PDS\WP2FA\Http;

use PDS\WP2FA\WordPress\RequestContext;

final class HttpRequest
{
    /** @param array<string, mixed> $query @param array<string, mixed> $body @param array<string, string> $headers */
    public function __construct(
        private readonly string $method,
        private readonly string $path,
        private readonly array $query,
        private readonly array $body,
        private readonly array $headers,
        private readonly RequestContext $context,
    ) {
        if (!in_array(strtoupper($method), ['GET', 'POST'], true)) {
            throw new \InvalidArgumentException('Only GET and POST route requests are supported.');
        }
    }

    /** @param array<string, mixed> $query @param array<string, mixed> $body @param array<string, string> $headers */
    public static function fromContext(
        string $method,
        string $path,
        array $query,
        array $body,
        array $headers,
        RequestContext $context,
    ): self {
        $normalized = [];
        foreach ($headers as $name => $value) {
            $normalized[strtolower($name)] = $value;
        }

        return new self(strtoupper($method), $path, $query, $body, $normalized, $context);
    }

    public function method(): string { return strtoupper($this->method); }
    public function path(): string { return $this->path; }
    /** @return array<string, mixed> */
    public function query(): array { return $this->query; }
    /** @return array<string, mixed> */
    public function body(): array { return $this->body; }
    public function context(): RequestContext { return $this->context; }
    public function isGet(): bool { return $this->method() === 'GET'; }
    public function isPost(): bool { return $this->method() === 'POST'; }

    public function queryString(string $key): ?string
    {
        $value = $this->query[$key] ?? null;
        return is_string($value) ? $value : null;
    }

    public function bodyString(string $key): ?string
    {
        $value = $this->body[$key] ?? null;
        return is_string($value) ? $value : null;
    }

    public function header(string $name): ?string
    {
        $value = $this->headers[strtolower($name)] ?? null;
        return is_string($value) ? $value : null;
    }

    /** @return array<string, mixed> */
    public function providerInput(): array
    {
        $input = $this->body;
        foreach (['action', '_wpnonce', 'nonce', 'password', 'pds_return_to', 'interaction_reference', 'provider'] as $key) {
            unset($input[$key]);
        }

        return $input;
    }
}
