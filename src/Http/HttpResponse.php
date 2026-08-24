<?php

declare(strict_types=1);

namespace PDS\WP2FA\Http;

final class HttpResponse
{
    /** @param array<string, string> $headers */
    private function __construct(
        private readonly int $status,
        private readonly array $headers,
        private readonly string $body,
    ) {
    }

    public static function html(string $body, int $status = 200, bool $noStore = false): self
    {
        return new self($status, self::contentHeaders('text/html; charset=UTF-8', $noStore), $body);
    }

    /** @param array<string, mixed> $payload */
    public static function json(array $payload, int $status = 200, bool $noStore = false): self
    {
        return new self(
            $status,
            self::contentHeaders('application/json; charset=UTF-8', $noStore),
            json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES),
        );
    }

    public static function redirect(string $location, int $status = 303, bool $noStore = true): self
    {
        $headers = ['Location' => $location];
        if ($noStore) {
            $headers = array_merge($headers, self::noStoreHeaders());
        }

        return new self($status, $headers, '');
    }

    public static function empty(int $status = 204): self
    {
        return new self($status, self::noStoreHeaders(), '');
    }

    public function status(): int { return $this->status; }
    /** @return array<string, string> */
    public function headers(): array { return $this->headers; }
    public function body(): string { return $this->body; }

    public function withHeader(string $name, string $value): self
    {
        $headers = $this->headers;
        $headers[$name] = $value;
        return new self($this->status, $headers, $this->body);
    }

    private static function contentHeaders(string $contentType, bool $noStore): array
    {
        $headers = ['Content-Type' => $contentType];
        return $noStore ? array_merge($headers, self::noStoreHeaders()) : $headers;
    }

    /** @return array<string, string> */
    private static function noStoreHeaders(): array
    {
        return ['Cache-Control' => 'no-store, no-cache, must-revalidate, max-age=0'];
    }
}
