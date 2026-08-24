<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method;

interface AuthenticationMethodProvider
{
    public function key(): ProviderKey;

    public function capabilities(): ProviderCapabilities;

    public function startEnrollment(ProviderContext $context): ProviderStart;

    public function completeEnrollment(
        ProviderContext $context,
        ProviderStart $start,
        UntrustedInput $input,
    ): EnrollmentResult;

    public function startVerification(ProviderContext $context): ProviderStart;

    public function verify(
        ProviderContext $context,
        ProviderStart $start,
        UntrustedInput $input,
    ): VerificationResult;

    /** Provider-specific persistence is deferred to this transaction hook. */
    public function commitVerification(
        ProviderContext $context,
        VerificationResult $result,
    ): VerificationCommit;

    /** This operation is terminal and must be idempotent in an adapter. */
    public function revoke(
        ProviderContext $context,
        MethodRecord $method,
        RevocationReason $reason,
    ): void;
}
