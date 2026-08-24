<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method;

enum VerificationFailureReason: string
{
    case INVALID_PROOF = 'invalid_proof';
    case MALFORMED_INPUT = 'malformed_input';
    case PROVIDER_UNAVAILABLE = 'provider_unavailable';
    case REPLAYED_PROOF = 'replayed_proof';
}
