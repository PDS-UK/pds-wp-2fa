<?php

declare(strict_types=1);

namespace PDS\WP2FA\Runtime;

use PDS\WP2FA\Http\GateResponseAdapter;
use PDS\WP2FA\WordPress\GateDecision;
use PDS\WP2FA\WordPress\RequestContext;
use PDS\WP2FA\WordPress\RequestType;

/** Converts gate decisions into terminating WordPress responses. */
final class RuntimeResponseEmitter
{
    public function __construct(
        private readonly GateResponseAdapter $responses = new GateResponseAdapter(),
        ?callable $terminate = null,
    ) {
        $this->terminate = $terminate === null
            ? static function (): never { exit; }
            : \Closure::fromCallable($terminate);
    }

    /** @var \Closure():never */
    private readonly \Closure $terminate;

    public function admin(RequestContext $context, GateDecision $decision): void
    {
        $response = $this->responses->response($context, $decision);
        if (in_array($decision->outcome(), [GateDecision::ALLOW, GateDecision::BYPASS], true)) {
            return;
        }

        if ($decision->outcome() === GateDecision::REDIRECT) {
            if (function_exists('wp_safe_redirect')) {
                \wp_safe_redirect($response->headers()['Location'] ?? '/');
            } else {
                header('Location: ' . ($response->headers()['Location'] ?? '/'), true, $response->status());
            }
            ($this->terminate)();
        }

        $message = $decision->message() ?? 'This request is not permitted.';
        $status = $response->status();
        if ($context->type() === RequestType::AJAX) {
            $payload = ['code' => $decision->code() ?? 'pds_wp_2fa_denied', 'message' => $message];
            if (function_exists('wp_send_json_error')) {
                \wp_send_json_error($payload, $status);
            }
            if (function_exists('status_header')) {
                \status_header($status);
            } else {
                http_response_code($status);
            }
            echo json_encode(['success' => false, 'data' => $payload], JSON_UNESCAPED_SLASHES);
            ($this->terminate)();
        }
        if (function_exists('wp_die')) {
            \wp_die($message, 'PDS WP 2FA', ['response' => $status]);
        }

        if (function_exists('status_header')) {
            \status_header($status);
        } else {
            http_response_code($status);
        }
        echo htmlspecialchars($message, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        ($this->terminate)();
    }

    public function restError(RequestContext $context, GateDecision $decision): mixed
    {
        if (class_exists('WP_Error')) {
            return new \WP_Error(
                $decision->code() ?? 'pds_wp_2fa_denied',
                $decision->message() ?? 'This request is not permitted.',
                ['status' => $decision->status() ?? 403],
            );
        }

        throw new \RuntimeException('WordPress REST error support is unavailable.');
    }
}
