<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method\Provider\WebAuthn;

use PDS\WP2FA\Method\ProviderContext;
use PDS\WP2FA\Method\ProviderServerState;
use PDS\WP2FA\Method\ProviderStart;

final class WebAuthnInteractionBinding
{
    private const VERSION = 1;

    /** @param array<string, mixed> $extra */
    public static function forContext(ProviderContext $context, string $operation, array $extra = []): ProviderServerState
    {
        return new ProviderServerState([
            'version' => self::VERSION,
            'operation' => $operation,
            'user_id' => $context->userId()->value(),
            'installation_hash' => $context->installation()->hash(),
            'installation_epoch' => $context->installation()->epoch(),
            'session' => $context->session()->value(),
            'interaction_id' => $context->interactionId()->value(),
            'challenge' => $context->challenge()->value(),
            ...$extra,
        ]);
    }

    public static function assertMatches(ProviderContext $context, ProviderStart $start, string $operation): void
    {
        if (!$start->hasReference()) {
            throw WebAuthnException::unavailable();
        }
        $state = $start->serverState()->toArray();
        $expected = [
            'version' => self::VERSION,
            'operation' => $operation,
            'user_id' => $context->userId()->value(),
            'installation_hash' => $context->installation()->hash(),
            'installation_epoch' => $context->installation()->epoch(),
            'session' => $context->session()->value(),
            'interaction_id' => $context->interactionId()->value(),
            'challenge' => $context->challenge()->value(),
        ];
        foreach ($expected as $key => $value) {
            if (!array_key_exists($key, $state) || !is_scalar($state[$key]) || (string) $state[$key] !== (string) $value) {
                throw WebAuthnException::invalidInput();
            }
        }
        if (!$start->reference()->id()->equals($context->interactionId())) {
            throw WebAuthnException::invalidInput();
        }
    }
}
