<?php

declare(strict_types=1);

namespace PDS\WP2FA\Tests\Unit\WordPress;

use PDS\WP2FA\WordPress\AdminInitHook;
use PDS\WP2FA\WordPress\CallableGate;
use PDS\WP2FA\WordPress\CallableRequestSignals;
use PDS\WP2FA\WordPress\GateDecision;
use PDS\WP2FA\WordPress\RequestClassifier;
use PDS\WP2FA\WordPress\RequestContext;
use PDS\WP2FA\WordPress\RequestType;
use PDS\WP2FA\WordPress\RestAuthenticationErrorsHook;
use PDS\WP2FA\WordPress\WordPressGateHooks;
use PDS\WP2FA\WordPress\CallableHookRegistrar;
use PHPUnit\Framework\TestCase;

final class HookDelegationTest extends TestCase
{
    public function testAdminInitDelegatesInteractiveAdminRequestsToTheCentralGate(): void
    {
        $decisions = [];
        $delegated = [];
        $hook = new AdminInitHook(
            $this->classifier(['isAdmin' => true]),
            new CallableGate(static function (RequestContext $context): GateDecision {
                return GateDecision::deny(403, 'pds_wp_2fa_pending', 'Complete two-factor authentication before continuing.');
            }),
            static function (RequestContext $context, GateDecision $decision) use (&$decisions, &$delegated): void {
                $delegated[] = $context->type();
                $decisions[] = $decision;
            },
        );

        $hook();

        self::assertSame([RequestType::ORDINARY_ADMIN], $delegated);
        self::assertCount(1, $decisions);
        self::assertSame(GateDecision::DENY, $decisions[0]->outcome());
    }

    public function testAdminInitDoesNotDelegateNonInteractiveRequests(): void
    {
        $called = false;
        $hook = new AdminInitHook(
            $this->classifier(['isAdmin' => true, 'isWpCli' => true]),
            new CallableGate(static fn (): GateDecision => GateDecision::deny(403, 'unexpected', 'unexpected')),
            static function () use (&$called): void {
                $called = true;
            },
        );

        $hook();

        self::assertFalse($called);
    }

    public function testRestFilterPreservesAnExistingAuthenticationResult(): void
    {
        $existing = new \stdClass();
        $gateCalled = false;
        $hook = new RestAuthenticationErrorsHook(
            $this->classifier(['isRest' => true, 'isRestCookieAuthenticated' => true]),
            new CallableGate(static function () use (&$gateCalled): GateDecision {
                $gateCalled = true;
                return GateDecision::deny(403, 'unexpected', 'unexpected');
            }),
            static fn (): mixed => null,
        );

        self::assertSame($existing, $hook($existing));
        self::assertFalse($gateCalled);
    }

    public function testRestFilterBypassesApplicationPasswordsAndOtherProviders(): void
    {
        $gateCalled = 0;
        $gate = new CallableGate(static function () use (&$gateCalled): GateDecision {
            ++$gateCalled;
            return GateDecision::deny(403, 'unexpected', 'unexpected');
        });
        $delegate = static fn (): mixed => new \stdClass();

        $applicationPassword = new RestAuthenticationErrorsHook(
            $this->classifier(['isRest' => true, 'hasAuthenticatedApplicationPassword' => true]),
            $gate,
            $delegate,
        );
        $other = new RestAuthenticationErrorsHook(
            $this->classifier(['isRest' => true]),
            $gate,
            $delegate,
        );

        self::assertNull($applicationPassword(null));
        self::assertNull($other(null));
        self::assertSame(0, $gateCalled);
    }

    public function testRestFilterDelegatesOnlyCookieAuthenticatedRequests(): void
    {
        $received = [];
        $hook = new RestAuthenticationErrorsHook(
            $this->classifier(['isRest' => true, 'isRestCookieAuthenticated' => true]),
            new CallableGate(static fn (): GateDecision => GateDecision::deny(
                403,
                'pds_wp_2fa_pending',
                'Complete two-factor authentication before using this REST API.',
            )),
            static function (RequestContext $context, GateDecision $decision) use (&$received): object {
                $received = [$context, $decision];
                return (object) ['code' => $decision->code()];
            },
        );

        $result = $hook(null);

        self::assertIsObject($result);
        self::assertSame('pds_wp_2fa_pending', $result->code);
        self::assertSame(RequestType::REST_COOKIE, $received[0]->type());
    }

    public function testRegistrationUsesTheWordPressHookNamesAndBoundaryPriorities(): void
    {
        $actions = [];
        $filters = [];
        $registrar = new CallableHookRegistrar(
            static function (string $hook, callable $callback, int $priority, int $acceptedArgs) use (&$actions): void {
                $actions[] = [$hook, $priority, $acceptedArgs, $callback];
            },
            static function (string $hook, callable $callback, int $priority, int $acceptedArgs) use (&$filters): void {
                $filters[] = [$hook, $priority, $acceptedArgs, $callback];
            },
        );
        $registration = new WordPressGateHooks(
            $registrar,
            new AdminInitHook(
                $this->classifier(['isAdmin' => true]),
                new CallableGate(static fn (): GateDecision => GateDecision::allow()),
                static function (): void {},
            ),
            new RestAuthenticationErrorsHook(
                $this->classifier(['isRest' => true, 'isRestCookieAuthenticated' => true]),
                new CallableGate(static fn (): GateDecision => GateDecision::allow()),
                static fn (): mixed => null,
            ),
        );

        $registration->register();

        self::assertSame(['admin_init', 1, 0], array_slice($actions[0], 0, 3));
        self::assertSame(['rest_authentication_errors', 110, 1], array_slice($filters[0], 0, 3));
    }

    /**
     * @param array<string, bool|string|null> $overrides
     */
    private function classifier(array $overrides = []): RequestClassifier
    {
        $values = array_merge([
            'isAdmin' => false,
            'isAjax' => false,
            'isRest' => false,
            'hasAuthenticatedApplicationPassword' => false,
            'isRestCookieAuthenticated' => false,
            'isXmlRpc' => false,
            'isWpCli' => false,
            'isCron' => false,
            'requestUri' => '/',
            'action' => null,
            'route' => null,
        ], $overrides);

        return new RequestClassifier(new CallableRequestSignals(
            isAdmin: static fn (): bool => (bool) $values['isAdmin'],
            isAjax: static fn (): bool => (bool) $values['isAjax'],
            isRest: static fn (): bool => (bool) $values['isRest'],
            hasAuthenticatedApplicationPassword: static fn (): bool => (bool) $values['hasAuthenticatedApplicationPassword'],
            isRestCookieAuthenticated: static fn (): bool => (bool) $values['isRestCookieAuthenticated'],
            isXmlRpc: static fn (): bool => (bool) $values['isXmlRpc'],
            isWpCli: static fn (): bool => (bool) $values['isWpCli'],
            isCron: static fn (): bool => (bool) $values['isCron'],
            requestUri: static fn (): string => (string) $values['requestUri'],
            requestParameter: static fn (string $name): ?string => $values[$name] ?? null,
        ));
    }
}
