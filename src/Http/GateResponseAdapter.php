<?php

declare(strict_types=1);

namespace PDS\WP2FA\Http;

use PDS\WP2FA\WordPress\GateDecision;
use PDS\WP2FA\WordPress\RequestContext;
use PDS\WP2FA\WordPress\RequestType;

final class GateResponseAdapter
{
    public function response(RequestContext $context, GateDecision $decision): HttpResponse
    {
        if ($decision->outcome() === GateDecision::REDIRECT) {
            return HttpResponse::redirect($decision->target() ?? '/', $decision->status() ?? 302);
        }

        if (in_array($decision->outcome(), [GateDecision::ALLOW, GateDecision::BYPASS], true)) {
            return HttpResponse::empty();
        }

        $status = $decision->status() ?? 403;
        $code = $decision->code() ?? 'pds_wp_2fa_denied';
        $message = $decision->message() ?? 'This request is not permitted.';

        if (in_array($context->type(), [RequestType::AJAX, RequestType::REST_COOKIE], true)) {
            return HttpResponse::json([
                'success' => false,
                'data' => ['code' => $code, 'message' => $message],
            ], $status, true);
        }

        return HttpResponse::html(
            '<!doctype html><html><head><meta charset="UTF-8"><title>Two-factor authentication</title></head>'
            . '<body><main><h1>Two-factor authentication</h1><p>'
            . htmlspecialchars($message, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')
            . '</p></main></body></html>',
            $status,
            true,
        );
    }
}
