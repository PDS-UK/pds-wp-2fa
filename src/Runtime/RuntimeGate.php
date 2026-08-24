<?php

declare(strict_types=1);

namespace PDS\WP2FA\Runtime;

use PDS\WP2FA\WordPress\Gate;
use PDS\WP2FA\WordPress\GateDecision;
use PDS\WP2FA\WordPress\RequestContext;
use PDS\WP2FA\WordPress\RequestType;

/**
 * Runtime safety boundary. The optional delegate is only used after every
 * required runtime dependency is ready; otherwise interactive requests get
 * the fixed 503 response and non-interactive boundaries remain untouched.
 */
final class RuntimeGate implements Gate
{
    private const MESSAGE = 'Two-factor authentication is temporarily unavailable. Contact an administrator.';

    public function __construct(
        private readonly RuntimeState $runtime,
        private readonly ?Gate $delegate = null,
    ) {
    }

    public function decide(RequestContext $context): GateDecision
    {
        if ($context->isNonInteractive() || $context->type() === RequestType::FRONTEND) {
            return GateDecision::bypass();
        }

        $interactive = $context->isAdminGateRequest() || $context->type() === RequestType::REST_COOKIE;
        if (!$interactive) {
            return GateDecision::bypass();
        }

        if (!$this->runtime->status()->isReady() || $this->delegate === null) {
            return GateDecision::deny(503, 'pds_wp_2fa_unavailable', self::MESSAGE);
        }

        try {
            return $this->delegate->decide($context);
        } catch (\Throwable) {
            return GateDecision::deny(503, 'pds_wp_2fa_unavailable', self::MESSAGE);
        }
    }
}
