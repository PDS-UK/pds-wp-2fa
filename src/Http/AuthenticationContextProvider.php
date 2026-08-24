<?php

declare(strict_types=1);

namespace PDS\WP2FA\Http;

interface AuthenticationContextProvider
{
    public function snapshot(): AuthenticationSnapshot;
}
