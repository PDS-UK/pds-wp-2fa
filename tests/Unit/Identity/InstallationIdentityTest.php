<?php

declare(strict_types=1);

use PDS\WP2FA\Identity\ConfigurationResolution;
use PDS\WP2FA\Identity\ConfigurationSources;
use PDS\WP2FA\Identity\EnvironmentPolicy;
use PDS\WP2FA\Identity\EnvironmentType;
use PDS\WP2FA\Identity\IdentityBindingState;
use PDS\WP2FA\Identity\IdentityConfigurationResolver;
use PDS\WP2FA\Identity\IdentityFingerprint;
use PDS\WP2FA\Identity\IdentityGenerator;
use PDS\WP2FA\Identity\InstallationBinding;
use PDS\WP2FA\Identity\InstallationIdentity;
use PDS\WP2FA\Identity\InstallationIdentityRuntime;
use PDS\WP2FA\Identity\RandomBytesSource;

spl_autoload_register(static function (string $class): void {
    $prefix = 'PDS\\WP2FA\\Identity\\';

    if (strncmp($class, $prefix, strlen($prefix)) !== 0) {
        return;
    }

    $relative = substr($class, strlen($prefix));
    $path = __DIR__ . '/../../../src/Identity/' . str_replace('\\', '/', $relative) . '.php';

    if (is_file($path)) {
        require_once $path;
    }
});

final class FixedRandomBytes implements RandomBytesSource
{
    public function __construct(private string $bytes)
    {
    }

    public function bytes(int $length): string
    {
        if (strlen($this->bytes) !== $length) {
            throw new RuntimeException('Unexpected random byte length.');
        }

        return $this->bytes;
    }
}

final class RecordingBindingStore implements \PDS\WP2FA\Identity\IdentityBindingReader
{
    public int $reads = 0;

    public function __construct(private ?InstallationBinding $binding)
    {
    }

    public function read(): ?InstallationBinding
    {
        $this->reads++;

        return $this->binding;
    }
}

function expectSame(mixed $expected, mixed $actual, string $message): void
{
    if ($expected !== $actual) {
        throw new RuntimeException($message . "\nExpected: " . var_export($expected, true) . "\nActual: " . var_export($actual, true));
    }
}

function expectTrue(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function expectFalse(bool $condition, string $message): void
{
    expectTrue(!$condition, $message);
}

function expectThrows(callable $callable, string $message): void
{
    try {
        $callable();
    } catch (Throwable $exception) {
        return;
    }

    throw new RuntimeException($message);
}

function testGeneratesCanonicalIdentityFromSecureRandomSource(): void
{
    $identity = (new IdentityGenerator(new FixedRandomBytes(str_repeat("\xab", 32))))->generateCanonicalHex();

    expectSame(str_repeat('ab', 32), $identity, 'Generated identity must be lowercase canonical hex.');
    expectSame(64, strlen($identity), 'Generated identity must represent exactly 32 bytes.');
}

function testRejectsNonCanonicalConfigurationValues(): void
{
    $resolver = new IdentityConfigurationResolver();

    foreach (['', str_repeat('a', 63), str_repeat('a', 65), str_repeat('A', 64), ' ' . str_repeat('a', 63), str_repeat('g', 64)] as $invalid) {
        $result = $resolver->resolve(ConfigurationSources::constant($invalid));
        expectSame(ConfigurationResolution::CONFIGURATION_ERROR, $result->status(), 'Invalid identity must fail closed.');
    }
}

function testConstantAndEnvironmentMustAgreeExactly(): void
{
    $value = str_repeat('1', 64);
    $resolver = new IdentityConfigurationResolver();

    $matching = $resolver->resolve(ConfigurationSources::both($value, $value));
    expectSame(ConfigurationResolution::CONFIGURED, $matching->status(), 'Matching sources should configure the identity.');

    $conflict = $resolver->resolve(ConfigurationSources::both($value, str_repeat('2', 64)));
    expectSame(ConfigurationResolution::CONFIGURATION_ERROR, $conflict->status(), 'Conflicting sources must fail closed.');
    expectSame('source_conflict', $conflict->errorCode(), 'Conflict classification must be stable.');
}

function testMissingConfigurationIsUnconfiguredAndDoesNotReadBinding(): void
{
    $store = new RecordingBindingStore(null);
    $runtime = new InstallationIdentityRuntime(new IdentityConfigurationResolver(), $store);

    $state = $runtime->inspect(ConfigurationSources::none(), 'production');

    expectSame(IdentityBindingState::UNCONFIGURED, $state->status(), 'Missing configuration must be unconfigured.');
    expectSame(0, $store->reads, 'Unavailable configuration must not read security binding state.');
    expectFalse($state->allowsSecurityState(), 'Unconfigured identity must fail closed.');
}

function testFingerprintsAreKnownGoodAndCompareConstantTime(): void
{
    $identity = InstallationIdentity::fromCanonicalHex(str_repeat('01', 32));
    $fingerprint = $identity->fingerprint();

    expectSame(
        '72cd6e8422c407fb6d098690f1130b7ded7ec2f7f5e1d30bd9d521f015363793',
        $fingerprint->hex(),
        'Fingerprint must be SHA-256 of the decoded 32-byte identity.'
    );
    expectTrue($fingerprint->equals(IdentityFingerprint::fromHex($fingerprint->hex())), 'Equal fingerprints must match.');
    expectFalse($fingerprint->equals(IdentityFingerprint::fromBytes(str_repeat("\0", 32))), 'Foreign fingerprints must not match.');
}

function testIdentityDoesNotRevealRawValueInDomainOutput(): void
{
    $raw = str_repeat('c', 64);
    $identity = InstallationIdentity::fromCanonicalHex($raw);

    expectSame('[redacted]', (string) $identity, 'Identity string conversion must be redacted.');
    expectFalse(str_contains(json_encode($identity, JSON_THROW_ON_ERROR), $raw), 'JSON output must not contain the raw identity.');
    expectFalse(str_contains(var_export($identity, true), $raw), 'Debug output must not contain the raw identity.');
}

function testEnvironmentClassifierDefaultsSafelyAndPolicyCannotBypassProduction(): void
{
    expectSame(EnvironmentType::PRODUCTION, EnvironmentType::classify(null)->value(), 'Missing environment must default to production.');
    expectSame(EnvironmentType::PRODUCTION, EnvironmentType::classify('invalid')->value(), 'Invalid environment must default to production.');

    foreach ([EnvironmentType::LOCAL, EnvironmentType::DEVELOPMENT, EnvironmentType::STAGING] as $environment) {
        $policy = EnvironmentPolicy::for(EnvironmentType::classify($environment), true);
        expectFalse($policy->webAuthnEnabled(), 'WebAuthn must be disabled outside production in phase one.');
        expectTrue($policy->nonProductionBypassApplies(), 'Explicit non-production bypass should apply outside production.');
        expectFalse($policy->enforcementRequired(true), 'An explicit non-production bypass should disable enforcement there.');
    }

    $production = EnvironmentPolicy::for(EnvironmentType::classify(EnvironmentType::PRODUCTION), true);
    expectTrue($production->webAuthnEnabled(), 'Production policy should allow WebAuthn subject to its policy.');
    expectFalse($production->nonProductionBypassApplies(), 'Non-production bypass must not apply in production.');
    expectTrue($production->enforcementRequired(true), 'Production enforcement cannot be weakened by a non-production bypass.');
}

function testRuntimeStateIsActiveOnlyForMatchingFingerprintEpochAndEnvironment(): void
{
    $value = str_repeat('4', 64);
    $configuration = (new IdentityConfigurationResolver())->resolve(ConfigurationSources::constant($value));

    $activeBinding = new InstallationBinding($configuration->fingerprint(), 7, EnvironmentType::production());
    $activeRuntime = new InstallationIdentityRuntime(new IdentityConfigurationResolver(), new RecordingBindingStore($activeBinding));
    $active = $activeRuntime->inspect(ConfigurationSources::constant($value), EnvironmentType::PRODUCTION);
    expectSame(IdentityBindingState::ACTIVE, $active->status(), 'Matching binding must be active.');
    expectTrue($active->allowsSecurityState(), 'Only active binding state may use security records.');
    expectSame(7, $active->epoch(), 'Active state must expose the binding epoch.');

    $foreign = new InstallationBinding(InstallationIdentity::fromCanonicalHex(str_repeat('5', 64))->fingerprint(), 7, EnvironmentType::production());
    $foreignRuntime = new InstallationIdentityRuntime(new IdentityConfigurationResolver(), new RecordingBindingStore($foreign));
    $mismatch = $foreignRuntime->inspect(ConfigurationSources::constant($value), EnvironmentType::PRODUCTION);
    expectSame(IdentityBindingState::IDENTITY_MISMATCH, $mismatch->status(), 'Foreign fingerprint must fail closed.');

    $environmentRuntime = new InstallationIdentityRuntime(new IdentityConfigurationResolver(), new RecordingBindingStore($activeBinding));
    $environmentMismatch = $environmentRuntime->inspect(ConfigurationSources::constant($value), EnvironmentType::STAGING);
    expectSame(IdentityBindingState::IDENTITY_MISMATCH, $environmentMismatch->status(), 'Environment mismatch must fail closed.');
}

function testRedactedDiagnosticsContainStateButNoRawIdentity(): void
{
    $raw = str_repeat('6', 64);
    $runtime = new InstallationIdentityRuntime(new IdentityConfigurationResolver(), new RecordingBindingStore(null));
    $state = $runtime->inspect(ConfigurationSources::constant($raw), EnvironmentType::PRODUCTION);
    $diagnostics = $state->diagnostics();
    $encoded = json_encode($diagnostics, JSON_THROW_ON_ERROR);

    expectSame(IdentityBindingState::UNINITIALIZED, $state->status(), 'Configured identity without binding must be uninitialized.');
    expectSame('pds_wp_2fa_unavailable', $diagnostics['error_code'], 'Unavailable state must use the fixed public error code.');
    expectTrue(isset($diagnostics['configured_fingerprint']), 'Diagnostics should expose a redacted configured fingerprint.');
    expectFalse(str_contains($encoded, $raw), 'Diagnostics must never include the raw identity.');
    expectFalse(str_contains($encoded, str_repeat('6', 32)), 'Diagnostics must not expose recognizable raw identity fragments.');
}

function testBindingPersistenceShapeContainsFingerprintEpochAndEnvironmentOnly(): void
{
    $raw = str_repeat('7', 64);
    $binding = new InstallationBinding(
        InstallationIdentity::fromCanonicalHex($raw)->fingerprint(),
        3,
        EnvironmentType::staging()
    );
    $record = $binding->toPersistenceRecord();

    expectSame(1, $record['installation_id'], 'Binding record must be the single-site singleton.');
    expectSame(32, strlen($record['identity_hash']), 'Persistence must receive a 32-byte fingerprint.');
    expectSame(3, $record['identity_epoch'], 'Persistence must receive the current epoch.');
    expectSame(EnvironmentType::STAGING, $record['environment_type'], 'Persistence must receive the classified environment.');
    expectFalse(str_contains(serialize($record), $raw), 'Persisted domain output must not contain the raw identity.');
}

$tests = [
    'testGeneratesCanonicalIdentityFromSecureRandomSource',
    'testRejectsNonCanonicalConfigurationValues',
    'testConstantAndEnvironmentMustAgreeExactly',
    'testMissingConfigurationIsUnconfiguredAndDoesNotReadBinding',
    'testFingerprintsAreKnownGoodAndCompareConstantTime',
    'testIdentityDoesNotRevealRawValueInDomainOutput',
    'testEnvironmentClassifierDefaultsSafelyAndPolicyCannotBypassProduction',
    'testRuntimeStateIsActiveOnlyForMatchingFingerprintEpochAndEnvironment',
    'testRedactedDiagnosticsContainStateButNoRawIdentity',
    'testBindingPersistenceShapeContainsFingerprintEpochAndEnvironmentOnly',
];

$failures = 0;

foreach ($tests as $test) {
    try {
        $test();
        echo ". {$test}\n";
    } catch (Throwable $exception) {
        $failures++;
        fwrite(STDERR, "F {$test}: {$exception->getMessage()}\n");
    }
}

if ($failures > 0) {
    exit(1);
}

echo count($tests) . " identity tests passed.\n";
