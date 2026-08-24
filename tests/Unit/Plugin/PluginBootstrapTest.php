<?php

declare(strict_types=1);

namespace PDS\WP2FA\Tests\Unit\Plugin;

use PHPUnit\Framework\TestCase;
use PDS\WP2FA\Bootstrap\PluginBootstrap;
use PDS\WP2FA\Bootstrap\RuntimeHookSet;
use PDS\WP2FA\Identity\IdentityConfigurationResolver;
use PDS\WP2FA\Identity\InstallationIdentityRuntime;
use PDS\WP2FA\Method\ProviderRegistry;
use PDS\WP2FA\Runtime\RuntimeGate;
use PDS\WP2FA\Runtime\RuntimeResponseEmitter;
use PDS\WP2FA\Runtime\RuntimeState;
use PDS\WP2FA\Runtime\UnavailableIdentityBindingReader;
use PDS\WP2FA\WordPress\GateDecision;
use PDS\WP2FA\WordPress\HookRegistrar;
use PDS\WP2FA\WordPress\RequestClassifier;
use PDS\WP2FA\WordPress\RequestContext;
use PDS\WP2FA\WordPress\RequestType;
use PDS\WP2FA\WordPress\CallableRequestSignals;
use PDS\WP2FA\Plugin;

final class PluginBootstrapTest extends TestCase
{
    protected function tearDown(): void
    {
        Plugin::resetForTests();
    }

    public function testHookRegistrationIsIdempotentAndCoversRuntimeBoundaries(): void
    {
        $registrar = new RecordingHookRegistrar();
        $runtime = $this->unavailableRuntime();
        $classifier = new RequestClassifier(new CallableRequestSignals(
            static fn (): bool => true,
            static fn (): bool => false,
            static fn (): bool => false,
            static fn (): bool => false,
            static fn (): bool => false,
            static fn (): bool => false,
            static fn (): bool => false,
            static fn (): bool => false,
            static fn (): string => '/wp-admin/',
            static fn (string $name): ?string => null,
        ));
        $hooks = new RuntimeHookSet(
            $registrar,
            $runtime,
            $classifier,
            new RuntimeGate($runtime),
            new RuntimeResponseEmitter(terminate: static function (): never { throw new \RuntimeException('terminated'); }),
        );

        $hooks->register();
        $hooks->register();

        self::assertTrue($hooks->isRegistered());
        self::assertSame(
            count(array_unique(array_map(static fn (array $hook): string => $hook['hook'], $registrar->hooks))),
            count($registrar->hooks),
        );
        self::assertContains('admin_init', $registrar->hookNames());
        self::assertContains('rest_authentication_errors', $registrar->hookNames());
        self::assertContains('init', $registrar->hookNames());
        self::assertContains('rest_api_init', $registrar->hookNames());
        self::assertContains('admin_menu', $registrar->hookNames());
        self::assertContains('wp_cli_init', $registrar->hookNames());
        self::assertContains('admin_post_' . \PDS\WP2FA\Http\Route::CHALLENGE_ACTION, $registrar->hookNames());
    }

    public function testUnavailableRuntimeDeniesInteractiveRequests(): void
    {
        $runtime = $this->unavailableRuntime();
        $gate = new RuntimeGate($runtime);

        $decision = $gate->decide(new RequestContext(RequestType::ORDINARY_ADMIN, '/wp-admin/', null, null));
        self::assertSame(GateDecision::DENY, $decision->outcome());
        self::assertSame(503, $decision->status());
        self::assertSame('pds_wp_2fa_unavailable', $decision->code());
    }

    public function testNonInteractiveRequestsKeepTheirExistingBoundary(): void
    {
        $runtime = $this->unavailableRuntime();
        $gate = new RuntimeGate($runtime);

        $decision = $gate->decide(new RequestContext(RequestType::WP_CLI, '/', null, null));
        self::assertSame(GateDecision::BYPASS, $decision->outcome());
    }

    public function testPluginBootIsIdempotentWithAnInjectedBootstrap(): void
    {
        $registrar = new RecordingHookRegistrar();
        $runtime = $this->unavailableRuntime();
        $classifier = new RequestClassifier(new CallableRequestSignals(
            static fn (): bool => false,
            static fn (): bool => false,
            static fn (): bool => false,
            static fn (): bool => false,
            static fn (): bool => false,
            static fn (): bool => false,
            static fn (): bool => false,
            static fn (): bool => false,
            static fn (): string => '/',
            static fn (string $name): ?string => null,
        ));
        $hooks = new RuntimeHookSet(
            $registrar,
            $runtime,
            $classifier,
            new RuntimeGate($runtime),
            new RuntimeResponseEmitter(terminate: static function (): never { throw new \RuntimeException('terminated'); }),
        );
        $bootstrap = new PluginBootstrap('/tmp/pds-wp-2fa.php', $runtime, $hooks, new ProviderRegistry([]));

        self::assertSame($bootstrap, Plugin::boot($bootstrap));
        $registeredHookCount = count($registrar->hooks);
        self::assertSame($bootstrap, Plugin::boot());
        self::assertCount($registeredHookCount, $registrar->hooks);
        self::assertTrue($bootstrap->isRegistered());
    }

    public function testActivationFailsClosedWithoutAConfiguredDatabase(): void
    {
        $runtime = $this->unavailableRuntime();
        $registrar = new RecordingHookRegistrar();
        $classifier = new RequestClassifier(new CallableRequestSignals(
            static fn (): bool => false,
            static fn (): bool => false,
            static fn (): bool => false,
            static fn (): bool => false,
            static fn (): bool => false,
            static fn (): bool => false,
            static fn (): bool => false,
            static fn (): bool => false,
            static fn (): string => '/',
            static fn (string $name): ?string => null,
        ));
        $hooks = new RuntimeHookSet(
            $registrar,
            $runtime,
            $classifier,
            new RuntimeGate($runtime),
            new RuntimeResponseEmitter(terminate: static function (): never { throw new \RuntimeException('terminated'); }),
        );
        $bootstrap = new PluginBootstrap('/tmp/pds-wp-2fa.php', $runtime, $hooks, new ProviderRegistry([]));

        $this->expectException(\RuntimeException::class);
        $bootstrap->activate();
    }

    private function unavailableRuntime(): RuntimeState
    {
        $reader = new UnavailableIdentityBindingReader();

        return new RuntimeState(
            new InstallationIdentityRuntime(new IdentityConfigurationResolver(), $reader),
            $reader,
            null,
            'production',
        );
    }
}

final class RecordingHookRegistrar implements HookRegistrar
{
    /** @var list<array{hook:string,callback:callable,priority:int,args:int}> */
    public array $hooks = [];

    public function addAction(string $hook, callable $callback, int $priority, int $acceptedArgs): void
    {
        $this->hooks[] = compact('hook', 'callback', 'priority', 'acceptedArgs');
    }

    public function addFilter(string $hook, callable $callback, int $priority, int $acceptedArgs): void
    {
        $this->hooks[] = compact('hook', 'callback', 'priority', 'acceptedArgs');
    }

    /** @return list<string> */
    public function hookNames(): array
    {
        return array_map(static fn (array $hook): string => $hook['hook'], $this->hooks);
    }
}
