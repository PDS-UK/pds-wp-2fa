<?php

declare(strict_types=1);

namespace PDS\WP2FA\Http;

use PDS\WP2FA\Method\InteractionReference;
use PDS\WP2FA\Method\ProviderKey;
use PDS\WP2FA\Method\UntrustedInput;

/**
 * Application seam for the provider-neutral Method transaction layer.
 * Implementations own persistence transactions and provider exceptions.
 */
interface FactorOperations
{
    public function beginEnrollment(AuthenticationSnapshot $authentication, ProviderKey $provider): FactorOperationResult;

    public function completeEnrollment(
        AuthenticationSnapshot $authentication,
        InteractionReference $interaction,
        UntrustedInput $input,
    ): FactorOperationResult;

    public function cancelEnrollment(
        AuthenticationSnapshot $authentication,
        InteractionReference $interaction,
    ): FactorOperationResult;

    public function authenticate(
        AuthenticationSnapshot $authentication,
        InteractionReference $interaction,
        UntrustedInput $input,
    ): FactorOperationResult;

    public function recover(
        AuthenticationSnapshot $authentication,
        InteractionReference $interaction,
        UntrustedInput $input,
    ): FactorOperationResult;

    public function regenerateRecovery(
        AuthenticationSnapshot $authentication,
        UntrustedInput $input,
    ): FactorOperationResult;
}
