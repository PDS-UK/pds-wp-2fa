<?php

declare(strict_types=1);

namespace PDS\WP2FA\Http;

use PDS\WP2FA\Method\InteractionReference;
use PDS\WP2FA\Method\ProviderKey;
use PDS\WP2FA\Method\UntrustedInput;
use PDS\WP2FA\WordPress\RequestType;
use PDS\WP2FA\WordPress\SafeRedirectTarget;

final class RouteController
{
    private const READ_CAPABILITY = 'read';

    public function __construct(
        private readonly AuthenticationContextProvider $authentication,
        private readonly FactorOperations $operations,
        private readonly NonceVerifier $nonces,
        private readonly CapabilityChecker $capabilities,
        private readonly RateLimiter $rateLimiter,
        private readonly ReauthenticationVerifier $reauthentication,
        private readonly SafeRedirectTarget $targets,
        private readonly PageRenderer $renderer,
        private readonly UrlGenerator $urls,
    ) {
    }

    public function handle(HttpRequest $request): HttpResponse
    {
        $context = $request->context();
        if ($context->type() === RequestType::ORDINARY_ADMIN && $request->isGet()) {
            return $this->handleView($request);
        }
        if ($context->type() === RequestType::ADMIN_POST && $request->isPost()) {
            return $this->handleAction($request);
        }

        return HttpResponse::empty();
    }

    private function handleView(HttpRequest $request): HttpResponse
    {
        if ($request->queryString('page') !== Route::PAGE) {
            return HttpResponse::empty();
        }

        $authentication = $this->authentication->snapshot();
        if (!$authentication->identityAvailable() && $authentication->cookieAuthenticated()) {
            return $this->unavailable();
        }

        $target = $this->target($request);
        if (!$authentication->isAuthenticated()) {
            return HttpResponse::redirect($this->urls->login($target), 302);
        }

        $route = $request->context()->route() ?? $request->queryString('route');
        if ($route === null && $authentication->policyMode() === AuthenticationSnapshot::MODE_GRACE) {
            $route = Route::ENROLL;
        }
        if (!is_string($route) || !RouteGate::viewAllowed($route, $authentication)) {
            return HttpResponse::redirect(
                $this->urls->adminPage(RouteGate::requiredRoute($authentication), $target),
                302,
            );
        }

        return HttpResponse::html($this->renderer->render($route, ['return_to' => $target], $authentication), 200, true);
    }

    private function handleAction(HttpRequest $request): HttpResponse
    {
        $action = $request->bodyString('action') ?? $request->context()->action();
        if (!Route::isAction($action)) {
            return HttpResponse::empty();
        }

        $authentication = $this->authentication->snapshot();
        $target = $this->target($request);
        if (!$authentication->identityAvailable() && $authentication->cookieAuthenticated()) {
            return $this->unavailable();
        }
        if (!$authentication->isAuthenticated() || $authentication->session() === null || $authentication->userId() === null) {
            return HttpResponse::redirect($this->urls->login($target), 302);
        }
        if (!$this->capabilities->allows($authentication->userId(), self::READ_CAPABILITY)) {
            return $this->failureResponse($action, $authentication, $target, 'pds_wp_2fa_forbidden', 403);
        }
        if (!$this->nonces->verify($action, $request->bodyString('_wpnonce') ?? $request->bodyString('nonce'))) {
            return $this->failureResponse($action, $authentication, $target, 'pds_wp_2fa_nonce_invalid', 403);
        }
        if (!$this->stateAllows($action, $authentication)) {
            return $this->failureResponse($action, $authentication, $target, 'pds_wp_2fa_pending', 403);
        }

        if ($action === Route::RECOVERY_REGENERATE_ACTION) {
            $password = $request->bodyString('password');
            if ($password === null || !$this->reauthentication->verify($authentication->userId(), $password)) {
                return $this->failureResponse($action, $authentication, $target, 'pds_wp_2fa_reauth_required', 403);
            }
        }

        if ($this->isProofAction($action)) {
            $limit = $this->rateLimiter->check($action, $authentication);
            if (!$limit->allowed()) {
                return $this->failureResponse($action, $authentication, $target, 'pds_wp_2fa_rate_limited', 429)
                    ->withHeader('Retry-After', (string) $limit->retryAfter());
            }
        }

        try {
            $result = $this->dispatchAction($action, $request, $authentication);
        } catch (\InvalidArgumentException) {
            return $this->failureResponse($action, $authentication, $target, 'pds_wp_2fa_invalid_interaction', 422);
        } catch (\Throwable) {
            // Provider/library details must never cross the route boundary.
            return $this->failureResponse($action, $authentication, $target, 'pds_wp_2fa_unavailable', 503);
        }

        if (!$result->succeeded() && $result->countsAsFailure()) {
            $this->rateLimiter->recordFailure($action, $authentication);
        }

        if ($result->succeeded()) {
            return $this->successResponse($action, $result, $authentication, $target);
        }

        $code = $result->code() ?? 'pds_wp_2fa_invalid_proof';
        $status = $result->status() === FactorOperationResult::EXPIRED ? 422 : 422;
        return $this->failureResponse($action, $authentication, $target, $code, $status, $result->payload());
    }

    private function dispatchAction(string $action, HttpRequest $request, AuthenticationSnapshot $authentication): FactorOperationResult
    {
        $input = new UntrustedInput($request->providerInput());
        return match ($action) {
            Route::ENROLLMENT_BEGIN_ACTION => $this->operations->beginEnrollment(
                $authentication,
                ProviderKey::fromString($request->bodyString('provider') ?? 'totp'),
            ),
            Route::ENROLLMENT_COMPLETE_ACTION => $this->operations->completeEnrollment(
                $authentication,
                $this->interaction($request),
                $input,
            ),
            Route::ENROLLMENT_CANCEL_ACTION => $this->operations->cancelEnrollment(
                $authentication,
                $this->interaction($request),
            ),
            Route::CHALLENGE_ACTION => $this->operations->authenticate(
                $authentication,
                $this->interaction($request),
                $input,
            ),
            Route::RECOVERY_ACTION => $this->operations->recover(
                $authentication,
                $this->interaction($request),
                $input,
            ),
            Route::RECOVERY_REGENERATE_ACTION => $this->operations->regenerateRecovery($authentication, $input),
            default => throw new \LogicException('Unsupported two-factor route action.'),
        };
    }

    private function interaction(HttpRequest $request): InteractionReference
    {
        $reference = $request->bodyString('interaction_reference');
        if ($reference === null) {
            throw new \InvalidArgumentException('An interaction reference is required.');
        }

        return InteractionReference::fromString($reference);
    }

    private function stateAllows(string $action, AuthenticationSnapshot $authentication): bool
    {
        if ($action === Route::RECOVERY_REGENERATE_ACTION) {
            return $authentication->isSatisfied();
        }
        if (!$authentication->isPending()) {
            return false;
        }
        if (in_array($action, [Route::ENROLLMENT_COMPLETE_ACTION, Route::ENROLLMENT_CANCEL_ACTION], true)) {
            return true;
        }
        if ($action === Route::ENROLLMENT_BEGIN_ACTION) {
            return in_array($authentication->policyMode(), [
                AuthenticationSnapshot::MODE_GRACE,
                AuthenticationSnapshot::MODE_ENROLLMENT_REQUIRED,
            ], true);
        }
        if ($action === Route::RECOVERY_ACTION) {
            return $authentication->policyMode() === AuthenticationSnapshot::MODE_CHALLENGE
                && $authentication->hasRecoveryCodes();
        }

        return $action === Route::CHALLENGE_ACTION
            && $authentication->policyMode() === AuthenticationSnapshot::MODE_CHALLENGE;
    }

    private function isProofAction(string $action): bool
    {
        return in_array($action, [
            Route::CHALLENGE_ACTION,
            Route::RECOVERY_ACTION,
            Route::ENROLLMENT_COMPLETE_ACTION,
            Route::RECOVERY_REGENERATE_ACTION,
        ], true);
    }

    private function successResponse(
        string $action,
        FactorOperationResult $result,
        AuthenticationSnapshot $authentication,
        string $target,
    ): HttpResponse {
        return match ($action) {
            Route::CHALLENGE_ACTION, Route::RECOVERY_ACTION => HttpResponse::redirect($target, 303),
            Route::ENROLLMENT_BEGIN_ACTION, Route::ENROLLMENT_CANCEL_ACTION => HttpResponse::redirect(
                $this->urls->adminPage(Route::ENROLL, $target),
                303,
            ),
            Route::ENROLLMENT_COMPLETE_ACTION => $this->renderSuccess(
                Route::ENROLL,
                $result,
                $authentication,
                $target,
                [
                    'continue_url' => $this->urls->adminPage(Route::CHALLENGE, $target),
                    'completed' => true,
                ],
            ),
            Route::RECOVERY_REGENERATE_ACTION => $this->renderSuccess(
                Route::RECOVERY,
                $result,
                $authentication,
                $target,
                ['management' => true, 'completed' => true],
            ),
            default => HttpResponse::empty(),
        };
    }

    /** @param array<string, mixed> $extra */
    private function renderSuccess(
        string $route,
        FactorOperationResult $result,
        AuthenticationSnapshot $authentication,
        string $target,
        array $extra,
    ): HttpResponse {
        return HttpResponse::html($this->renderer->render(
            $route,
            array_merge($result->payload(), $extra, ['return_to' => $target]),
            $authentication,
        ), 200, true);
    }

    /** @param array<string, mixed> $payload */
    private function failureResponse(
        string $action,
        AuthenticationSnapshot $authentication,
        string $target,
        string $code,
        int $status,
        array $payload = [],
    ): HttpResponse {
        $route = match ($action) {
            Route::RECOVERY_ACTION, Route::RECOVERY_REGENERATE_ACTION => Route::RECOVERY,
            Route::CHALLENGE_ACTION => Route::CHALLENGE,
            default => Route::ENROLL,
        };
        $view = array_merge($payload, [
            'error' => self::message($code),
            'return_to' => $target,
            'management' => $action === Route::RECOVERY_REGENERATE_ACTION,
        ]);

        return HttpResponse::html($this->renderer->render($route, $view, $authentication), $status, true);
    }

    private function target(HttpRequest $request): string
    {
        return $this->targets->validate(
            $request->bodyString('pds_return_to') ?? $request->queryString('pds_return_to'),
        );
    }

    private function unavailable(): HttpResponse
    {
        return HttpResponse::html(
            '<!doctype html><html><head><meta charset="UTF-8"><title>Two-factor authentication unavailable</title></head>'
            . '<body><main><h1>Two-factor authentication unavailable</h1><p>'
            . self::message('pds_wp_2fa_unavailable') . '</p></main></body></html>',
            503,
            true,
        );
    }

    private static function message(string $code): string
    {
        return match ($code) {
            'pds_wp_2fa_invalid_totp' => 'That verification code was not accepted. Check the code and try again.',
            'pds_wp_2fa_invalid_webauthn' => 'That security-key response was not accepted. Try again or use another method.',
            'pds_wp_2fa_webauthn_cancelled' => 'No security-key response was received. Try again or use another method.',
            'pds_wp_2fa_invalid_recovery' => 'That recovery code was not accepted. Check the code and try again.',
            'pds_wp_2fa_enrollment_invalid' => 'We could not verify that setup. Check the code or security-key response and try again.',
            'pds_wp_2fa_enrollment_expired' => 'Your setup session expired. Start enrollment again.',
            'pds_wp_2fa_nonce_invalid' => 'This form has expired or cannot be verified. Refresh the page and try again.',
            'pds_wp_2fa_session_expired' => 'Your sign-in session expired. Sign in again to continue.',
            'pds_wp_2fa_rate_limited' => 'Too many verification attempts. Wait and try again, or use another recovery option.',
            'pds_wp_2fa_pending' => 'Complete two-factor authentication before continuing.',
            'pds_wp_2fa_forbidden' => 'You are not allowed to manage two-factor authentication for this account.',
            'pds_wp_2fa_reauth_required' => 'Enter your current password again to continue.',
            'pds_wp_2fa_invalid_interaction' => 'That setup session is no longer valid. Start again.',
            'pds_wp_2fa_unavailable' => 'Two-factor authentication is temporarily unavailable. Contact an administrator.',
            default => 'That request could not be completed. Try again.',
        };
    }
}
