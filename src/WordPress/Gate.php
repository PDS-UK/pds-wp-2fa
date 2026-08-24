<?php

declare(strict_types=1);

namespace PDS\WP2FA\WordPress;

interface Gate
{
    public function decide(RequestContext $context): GateDecision;
}
