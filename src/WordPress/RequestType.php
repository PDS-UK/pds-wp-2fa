<?php

declare(strict_types=1);

namespace PDS\WP2FA\WordPress;

final class RequestType
{
    public const ORDINARY_ADMIN = 'ordinary_admin';
    public const AJAX = 'ajax';
    public const ADMIN_POST = 'admin_post';
    public const REST_COOKIE = 'rest_cookie';
    public const REST_APPLICATION_PASSWORD = 'rest_application_password';
    public const REST_NON_COOKIE = 'rest_non_cookie';
    public const REST_OTHER = self::REST_NON_COOKIE;
    public const XML_RPC = 'xml_rpc';
    public const WP_CLI = 'wp_cli';
    public const CRON = 'cron';
    public const FRONTEND = 'frontend';

    private function __construct()
    {
    }

    public static function isAdminGateRequest(string $type): bool
    {
        return in_array($type, [self::ORDINARY_ADMIN, self::AJAX, self::ADMIN_POST], true);
    }

    public static function isRestRequest(string $type): bool
    {
        return in_array($type, [
            self::REST_COOKIE,
            self::REST_APPLICATION_PASSWORD,
            self::REST_NON_COOKIE,
        ], true);
    }

    public static function isNonInteractive(string $type): bool
    {
        return in_array($type, [self::XML_RPC, self::WP_CLI, self::CRON], true);
    }
}
