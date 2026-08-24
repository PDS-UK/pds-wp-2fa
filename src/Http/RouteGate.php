<?php

declare(strict_types=1);

namespace PDS\WP2FA\Http;

use PDS\WP2FA\WordPress\Gate;
use PDS\WP2FA\WordPress\GateDecision;
use PDS\WP2FA\WordPress\RequestContext;
use PDS\WP2FA\WordPress\RequestType;

final class RouteGate implements Gate
{
    private const UNAVAILABLE_MESSAGE = 'Two-factor authentication is temporarily unavailable. Contact an administrator.';
    private const ADMIN_PENDING_MESSAGE = 'Complete two-factor authentication before continuing.';
    private const REST_PENDING_MESSAGE = 'Complete two-factor authentication before using this REST API.';

    public function __construct(
        private readonly AuthenticationContextProvider $authentication,
        private readonly UrlGenerator $urls,
    ) {
    }

    public function decide(RequestContext $context): GateDecision
    {
        if ($context->isNonInteractive() || $context->type() === RequestType::FRONTEND) {
            return GateDecision::bypass();
        }

        if (!in_array($context->type(), [
            RequestType::ORDINARY_ADMIN,
            RequestType::AJAX,
            RequestType::ADMIN_POST,
            RequestType::REST_COOKIE,
        ], true)) {
            return GateDecision::bypass();
        }

        $snapshot = $this->authentication->snapshot();
        if (!$snapshot->identityAvailable() && $snapshot->cookieAuthenticated()) {
            return GateDecision::deny(503, 'pds_wp_2fa_unavailable', self::UNAVAILABLE_MESSAGE);
        }

        if ($snapshot->isAuthenticated() && $snapshot->protected() && $snapshot->state() === \PDS\WP2FA\Method\SessionState::INVALIDATED) {
            return GateDecision::deny(403, 'pds_wp_2fa_session_invalidated', self::ADMIN_PENDING_MESSAGE);
        }

        if (!$snapshot->isAuthenticated() || !$snapshot->protected() || !$snapshot->isPending()) {
            return GateDecision::allow();
        }

        return match ($context->type()) {
            RequestType::REST_COOKIE => GateDecision::deny(403, 'pds_wp_2fa_pending', self::REST_PENDING_MESSAGE),
            RequestType::AJAX => GateDecision::deny(403, 'pds_wp_2fa_pending', self::ADMIN_PENDING_MESSAGE),
            RequestType::ADMIN_POST => $this->adminPostDecision($context, $snapshot),
            RequestType::ORDINARY_ADMIN => $this->adminDecision($context, $snapshot),
            default => GateDecision::bypass(),
        };
    }

    private function adminDecision(RequestContext $context, AuthenticationSnapshot $snapshot): GateDecision
    {
        $route = $context->route();
        if (Route::isView($route) && $this->viewAllowed($route, $snapshot)) {
            return GateDecision::allow();
        }

        if ($snapshot->policyMode() === AuthenticationSnapshot::MODE_GRACE) {
            return GateDecision::allow();
        }

        return GateDecision::redirect($this->urls->adminPage($this->requiredRoute($snapshot)));
    }

    private function adminPostDecision(RequestContext $context, AuthenticationSnapshot $snapshot): GateDecision
    {
        $action = $context->action();
        if ($snapshot->isSatisfied() && $action === Route::RECOVERY_REGENERATE_ACTION) {
            return GateDecision::allow();
        }

        if ($snapshot->isPending() && Route::isPendingAction($action)) {
            return GateDecision::allow();
        }

        return GateDecision::deny(403, 'pds_wp_2fa_pending', self::ADMIN_PENDING_MESSAGE);
    }

    public static function requiredRoute(AuthenticationSnapshot $snapshot): string
    {
        if (!$snapshot->hasActiveMethod()) {
            return Route::ENROLL;
        }

        return Route::CHALLENGE;
    }

    public static function viewAllowed(string $route, AuthenticationSnapshot $snapshot): bool
    {
        if (!$snapshot->isPending()) {
            return $snapshot->isSatisfied() && $route === Route::RECOVERY;
        }

        return match ($route) {
            Route::CHALLENGE => $snapshot->policyMode() === AuthenticationSnapshot::MODE_CHALLENGE,
            Route::RECOVERY => $snapshot->policyMode() === AuthenticationSnapshot::MODE_CHALLENGE
                && $snapshot->hasRecoveryCodes(),
            Route::ENROLL => in_array($snapshot->policyMode(), [
                AuthenticationSnapshot::MODE_GRACE,
                AuthenticationSnapshot::MODE_ENROLLMENT_REQUIRED,
            ], true),
            default => false,
        };
    }
}
