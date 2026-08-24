<?php

declare(strict_types=1);

namespace PDS\WP2FA\Tests\Unit\WordPress;

use PDS\WP2FA\WordPress\CallableRequestSignals;
use PDS\WP2FA\WordPress\RequestClassifier;
use PDS\WP2FA\WordPress\RequestType;
use PHPUnit\Framework\TestCase;

final class RequestClassifierTest extends TestCase
{
    public function testClassifiesAnOrdinaryAdminScreen(): void
    {
        $context = $this->classifier(['isAdmin' => true])->classify();

        self::assertSame(RequestType::ORDINARY_ADMIN, $context->type());
        self::assertTrue($context->isAdminGateRequest());
    }

    public function testClassifiesAjaxBeforeAnOrdinaryAdminScreen(): void
    {
        $context = $this->classifier([
            'isAdmin' => true,
            'isAjax' => true,
            'requestUri' => '/wp-admin/admin-ajax.php',
            'action' => 'pds_wp_2fa_challenge',
        ])->classify();

        self::assertSame(RequestType::AJAX, $context->type());
        self::assertSame('pds_wp_2fa_challenge', $context->action());
    }

    public function testClassifiesAdminPostFromTheEndpointPath(): void
    {
        $context = $this->classifier([
            'isAdmin' => true,
            'requestUri' => '/wp-admin/admin-post.php?action=pds_wp_2fa_challenge',
            'action' => 'pds_wp_2fa_challenge',
        ])->classify();

        self::assertSame(RequestType::ADMIN_POST, $context->type());
    }

    public function testDistinguishesCookieApplicationPasswordAndOtherRestRequests(): void
    {
        $cookie = $this->classifier([
            'isRest' => true,
            'isRestCookieAuthenticated' => true,
        ])->classify();
        $applicationPassword = $this->classifier([
            'isRest' => true,
            'hasAuthenticatedApplicationPassword' => true,
            'isRestCookieAuthenticated' => true,
        ])->classify();
        $other = $this->classifier(['isRest' => true])->classify();

        self::assertSame(RequestType::REST_COOKIE, $cookie->type());
        self::assertSame(RequestType::REST_APPLICATION_PASSWORD, $applicationPassword->type());
        self::assertSame(RequestType::REST_NON_COOKIE, $other->type());
    }

    public function testNonInteractiveSignalsTakePrecedenceOverBrowserClassification(): void
    {
        $xmlRpc = $this->classifier([
            'isAdmin' => true,
            'isXmlRpc' => true,
        ])->classify();
        $cli = $this->classifier([
            'isAdmin' => true,
            'isWpCli' => true,
        ])->classify();
        $cron = $this->classifier([
            'isAdmin' => true,
            'isCron' => true,
        ])->classify();

        self::assertSame(RequestType::XML_RPC, $xmlRpc->type());
        self::assertSame(RequestType::WP_CLI, $cli->type());
        self::assertSame(RequestType::CRON, $cron->type());
        self::assertFalse($xmlRpc->isAdminGateRequest());
    }

    public function testClassifiesAnOrdinaryFrontendRequest(): void
    {
        $context = $this->classifier()->classify();

        self::assertSame(RequestType::FRONTEND, $context->type());
        self::assertFalse($context->isAdminGateRequest());
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
            requestParameter: static fn (string $name): ?string => $values[
                $name === 'action' ? 'action' : ($name === 'route' ? 'route' : $name)
            ] ?? null,
        ));
    }
}
