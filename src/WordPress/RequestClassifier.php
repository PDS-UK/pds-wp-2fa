<?php

declare(strict_types=1);

namespace PDS\WP2FA\WordPress;

final class RequestClassifier
{
    public function __construct(private readonly RequestSignals $signals)
    {
    }

    public function classify(): RequestContext
    {
        $type = $this->classifyType();

        return new RequestContext(
            type: $type,
            path: $this->requestPath(),
            action: $this->signals->requestParameter('action'),
            route: $this->signals->requestParameter('route'),
        );
    }

    private function classifyType(): string
    {
        if ($this->signals->isWpCli()) {
            return RequestType::WP_CLI;
        }

        if ($this->signals->isCron()) {
            return RequestType::CRON;
        }

        if ($this->signals->isXmlRpc()) {
            return RequestType::XML_RPC;
        }

        if ($this->signals->isRest()) {
            if ($this->signals->hasAuthenticatedApplicationPassword()) {
                return RequestType::REST_APPLICATION_PASSWORD;
            }

            if ($this->signals->isRestCookieAuthenticated()) {
                return RequestType::REST_COOKIE;
            }

            return RequestType::REST_NON_COOKIE;
        }

        if ($this->signals->isAdmin()) {
            if ($this->signals->isAjax()) {
                return RequestType::AJAX;
            }

            if ($this->isAdminPost()) {
                return RequestType::ADMIN_POST;
            }

            return RequestType::ORDINARY_ADMIN;
        }

        return RequestType::FRONTEND;
    }

    private function isAdminPost(): bool
    {
        return basename(rtrim($this->requestPath(), '/')) === 'admin-post.php';
    }

    private function requestPath(): string
    {
        $path = parse_url($this->signals->requestUri(), PHP_URL_PATH);

        return is_string($path) && $path !== '' ? $path : '/';
    }
}
