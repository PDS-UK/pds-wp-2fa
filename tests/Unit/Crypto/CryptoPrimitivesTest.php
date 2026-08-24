<?php

declare(strict_types=1);

namespace PDS\WP2FA\Tests\Unit\Crypto;

require_once __DIR__ . '/bootstrap.php';

use PDS\WP2FA\Crypto\Base32;
use PDS\WP2FA\Crypto\ProvisioningUri;
use PDS\WP2FA\Crypto\RecoveryCodeGenerator;
use PDS\WP2FA\Crypto\RecoveryCodeHasher;
use PDS\WP2FA\Crypto\RecoveryCodeRecord;
use PDS\WP2FA\Crypto\RecoveryCodeStore;
use PDS\WP2FA\Crypto\RecoveryCodeVerifier;
use PDS\WP2FA\Crypto\SecretEnvelope;
use PDS\WP2FA\Crypto\SecretProtector;
use PDS\WP2FA\Crypto\Totp;
use PDS\WP2FA\Crypto\TotpProfile;
use PDS\WP2FA\Crypto\UnixClock;
use PHPUnit\Framework\TestCase;

final class CryptoPrimitivesTest extends TestCase
{
    public function testRfc6238Sha1VectorsAreGeneratedWithAnInjectedClock(): void
    {
        $secret = '12345678901234567890';
        $vectors = [
            59 => '287082',
            1111111109 => '081804',
            1111111111 => '050471',
            1234567890 => '005924',
            2000000000 => '279037',
            20000000000 => '353130',
        ];

        foreach ($vectors as $unixTime => $expected) {
            $totp = new Totp(new FrozenClock($unixTime));

            self::assertSame($expected, $totp->generate($secret));
        }
    }

    public function testTotpAcceptsOnlyTheBoundedAdjacentWindowAndReportsTheStep(): void
    {
        $clock = new FrozenClock(90);
        $totp = new Totp($clock, new TotpProfile(window: 1));
        $secret = '12345678901234567890';

        $previous = $totp->generate($secret, 60);
        $current = $totp->generate($secret, 90);
        $next = $totp->generate($secret, 120);
        $outside = $totp->generate($secret, 150);

        self::assertTrue($totp->verify($previous, $secret)->isValid());
        self::assertSame(2, $totp->verify($previous, $secret)->acceptedStep());
        self::assertTrue($totp->verify($current, $secret)->isValid());
        self::assertTrue($totp->verify($next, $secret)->isValid());
        self::assertFalse($totp->verify($outside, $secret)->isValid());
        self::assertSame('invalid_code', $totp->verify($outside, $secret)->reason());
    }

    public function testTotpRejectsAPreviouslyAcceptedStepAsReplay(): void
    {
        $totp = new Totp(new FrozenClock(90));
        $secret = '12345678901234567890';
        $code = $totp->generate($secret);

        $result = $totp->verify($code, $secret, lastAcceptedStep: 3);

        self::assertFalse($result->isValid());
        self::assertSame('already_accepted', $result->reason());
        self::assertSame(3, $result->matchedStep());
    }

    public function testBase32UsesUnpaddedCanonicalEncoding(): void
    {
        self::assertSame('MZXW6YTBOI', Base32::encode('foobar'));
        self::assertSame('foobar', Base32::decode('MZXW6YTBOI'));
        self::assertSame('foobar', Base32::decode('mzxw6ytboi'));

        $this->expectException(\InvalidArgumentException::class);
        Base32::decode('MZXW6YTO=');
    }

    public function testProvisioningUriContainsOnlyTheFixedTrustedProfile(): void
    {
        $secret = '12345678901234567890';

        $uri = ProvisioningUri::build('Acme Co', 'alice@example.com', $secret);

        self::assertSame(
            'otpauth://totp/Acme%20Co:alice%40example.com'
            . '?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
            . '&issuer=Acme%20Co&algorithm=SHA1&digits=6&period=30',
            $uri,
        );
    }

    public function testRecoveryCodesAreTenIndependentGrouped128BitValues(): void
    {
        $next = 0;
        $generator = new RecoveryCodeGenerator(static function (int $length) use (&$next): string {
            $value = str_repeat(chr($next), $length);
            ++$next;

            return $value;
        });

        $bundle = $generator->generate();
        $codes = $bundle->codes();

        self::assertCount(10, $codes);
        self::assertCount(10, array_unique($codes));

        foreach ($codes as $index => $code) {
            self::assertMatchesRegularExpression('/\A[0-9A-F]{32}\z/', $code);
            self::assertSame(7, substr_count($bundle->formattedCodes()[$index], '-'));
        }
    }

    public function testRecoveryNormalizationAndPasswordHashVerification(): void
    {
        $normalizer = new \PDS\WP2FA\Crypto\RecoveryCodeNormalizer();
        $hasher = new RecoveryCodeHasher();
        $canonical = 'AB12CD34EF567890123456789ABCDEF0';
        $hash = $hasher->hash($canonical);

        self::assertSame($canonical, $normalizer->normalize("ab12-cd34\t ef56 7890 1234 5678 9abc-def0"));
        self::assertTrue($hasher->verify("ab12-cd34 ef56-7890-1234-5678-9abc-def0", $hash));
        self::assertFalse($hasher->verify('AB12-CD34-EF56-7890-1234-5678-9ABC-DEF1', $hash));

        $this->expectException(\InvalidArgumentException::class);
        $normalizer->normalize('AB12_CD34EF567890123456789ABCDEF0');
    }

    public function testRecoveryVerificationRequiresAnAtomicSuccessfulConsume(): void
    {
        $hasher = new RecoveryCodeHasher();
        $record = new RecoveryCodeRecord('code-1', $hasher->hash('AB12CD34EF567890123456789ABCDEF0'));
        $store = new InMemoryRecoveryCodeStore([$record]);
        $verifier = new RecoveryCodeVerifier($hasher);

        $accepted = $verifier->verifyAndConsume(
            'ab12-cd34-ef56-7890-1234-5678-9abc-def0',
            'generation-1',
            $store,
        );

        self::assertTrue($accepted->isSuccessful());
        self::assertSame('code-1', $accepted->codeId());
        self::assertSame(1, $store->consumeAttempts);

        $replayed = $verifier->verifyAndConsume(
            'AB12CD34EF567890123456789ABCDEF0',
            'generation-1',
            $store,
        );

        self::assertFalse($replayed->isSuccessful());
        self::assertSame('not_found', $replayed->reason());
    }

    public function testRecoveryVerificationReportsAConcurrentAtomicUseLoss(): void
    {
        $hasher = new RecoveryCodeHasher();
        $record = new RecoveryCodeRecord('code-1', $hasher->hash('AB12CD34EF567890123456789ABCDEF0'));
        $store = new InMemoryRecoveryCodeStore([$record], false);
        $verifier = new RecoveryCodeVerifier($hasher);

        $result = $verifier->verifyAndConsume(
            'AB12CD34EF567890123456789ABCDEF0',
            'generation-1',
            $store,
        );

        self::assertFalse($result->isSuccessful());
        self::assertSame('already_used', $result->reason());
    }

    public function testSecretProtectionRoundTripsAndAuthenticatesBinding(): void
    {
        if (!function_exists('sodium_crypto_aead_xchacha20poly1305_ietf_encrypt')) {
            self::markTestSkipped('libsodium is required for secret-protection tests.');
        }

        $protector = new SecretProtector(str_repeat('k', 32), str_repeat('s', 32));
        $binding = SecretBindingFactory::make('method-1', 42);
        $plaintext = '12345678901234567890';

        $envelope = $protector->encrypt($plaintext, $binding);

        self::assertStringStartsWith('pds-wp-2fa:v1:1:', $envelope);
        self::assertSame($plaintext, $protector->decrypt($envelope, $binding));
        self::assertNotSame($envelope, $protector->encrypt($plaintext, $binding));

        $wrongBinding = SecretBindingFactory::make('method-2', 42);
        $this->expectException(\RuntimeException::class);
        $protector->decrypt($envelope, $wrongBinding);
    }

    public function testSecretProtectionRejectsTamperingAndMalformedKeysWithoutLeakingPlaintext(): void
    {
        if (!function_exists('sodium_crypto_aead_xchacha20poly1305_ietf_encrypt')) {
            self::markTestSkipped('libsodium is required for secret-protection tests.');
        }

        $plaintext = 'sensitive-totp-secret';
        $protector = new SecretProtector(str_repeat('k', 32), str_repeat('s', 32));
        $binding = SecretBindingFactory::make('method-1', 42);
        $envelope = $protector->encrypt($plaintext, $binding);
        $tampered = substr($envelope, 0, -1) . (substr($envelope, -1) === 'A' ? 'B' : 'A');

        try {
            $protector->decrypt($tampered, $binding);
            self::fail('Tampered ciphertext should not decrypt.');
        } catch (\RuntimeException $exception) {
            self::assertStringNotContainsString($plaintext, $exception->getMessage());
        }

        $this->expectException(\InvalidArgumentException::class);
        new SecretProtector('too-short', str_repeat('s', 32));
    }

    public function testSecretEnvelopeParserRejectsInvalidVersionsAndLengths(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        SecretEnvelope::parse('pds-wp-2fa:v2:1:AAAA:AAAA');
    }
}

final class FrozenClock implements UnixClock
{
    public function __construct(private readonly int $time)
    {
    }

    public function now(): int
    {
        return $this->time;
    }
}

final class InMemoryRecoveryCodeStore implements RecoveryCodeStore
{
    /** @var array<string, RecoveryCodeRecord> */
    private array $records;

    public int $consumeAttempts = 0;

    /** @param array<int, RecoveryCodeRecord> $records */
    public function __construct(array $records, private readonly bool $allowConsume = true)
    {
        $this->records = [];

        foreach ($records as $record) {
            $this->records[$record->id()] = $record;
        }
    }

    public function unused(string $generationId): iterable
    {
        if ($generationId !== 'generation-1') {
            return [];
        }

        return $this->records;
    }

    public function consumeIfUnused(string $codeId): bool
    {
        ++$this->consumeAttempts;

        if (!$this->allowConsume || !isset($this->records[$codeId])) {
            return false;
        }

        unset($this->records[$codeId]);

        return true;
    }
}

final class SecretBindingFactory
{
    public static function make(string $methodId, int $userId): \PDS\WP2FA\Crypto\SecretBinding
    {
        return new \PDS\WP2FA\Crypto\SecretBinding(
            installationIdentityHash: 'installation-hash',
            installationEpoch: 7,
            userId: $userId,
            methodId: $methodId,
            providerKey: 'totp',
        );
    }
}
