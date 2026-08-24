<?php

declare(strict_types=1);

namespace PDS\WP2FA\Admin;

interface SettingsRepository
{
    public function snapshot(): SettingsSnapshot;

    public function save(SettingsUpdate $update, AdminActor $actor): void;
}
