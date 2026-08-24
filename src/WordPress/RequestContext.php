<?php

declare(strict_types=1);

namespace PDS\WP2FA\WordPress;

final class RequestContext
{
    public function __construct(
        private readonly string $type,
        private readonly string $path,
        private readonly ?string $action,
        private readonly ?string $route,
    ) {
    }

    public function type(): string
    {
        return $this->type;
    }

    public function path(): string
    {
        return $this->path;
    }

    public function action(): ?string
    {
        return $this->action;
    }

    public function route(): ?string
    {
        return $this->route;
    }

    public function isAdminGateRequest(): bool
    {
        return RequestType::isAdminGateRequest($this->type);
    }

    public function isRestRequest(): bool
    {
        return RequestType::isRestRequest($this->type);
    }

    public function isNonInteractive(): bool
    {
        return RequestType::isNonInteractive($this->type);
    }
}
