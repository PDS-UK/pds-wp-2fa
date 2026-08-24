<?php
/**
 * Plugin Name: PDS WP 2FA
 * Plugin URI: https://github.com/PDS-UK/pds-wp-2fa
 * Description: Role-based two-factor authentication for WordPress.
 * Version: 0.1.0
 * Requires at least: 6.8
 * Requires PHP: 8.3
 * Update URI: https://github.com/PDS-UK/pds-wp-2fa
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: pds-wp-2fa
 * Domain Path: /languages
 */

declare(strict_types=1);

defined('ABSPATH') || exit;

if (!defined('PDS_WP_2FA_VERSION')) {
    define('PDS_WP_2FA_VERSION', '0.1.0');
}

if (!defined('PDS_WP_2FA_PLUGIN_FILE')) {
    define('PDS_WP_2FA_PLUGIN_FILE', __FILE__);
}

$pds_wp_2fa_bootstrap_failure = static function (string $message): never {
    $full_message = sprintf('PDS WP 2FA could not start: %s', $message);

    if (function_exists('wp_die')) {
        wp_die($full_message, 'PDS WP 2FA', ['response' => 500]);
    }

    throw new RuntimeException($full_message);
};

if (!class_exists('PDS\\WP2FA\\Plugin')) {
    $autoload_candidates = [__DIR__ . '/vendor/autoload.php'];

    if (defined('PDS_WP_2FA_COMPOSER_AUTOLOAD')) {
        $autoload_candidates[] = (string) constant('PDS_WP_2FA_COMPOSER_AUTOLOAD');
    }

    if (defined('WP_CONTENT_DIR')) {
        $content_directory = rtrim((string) constant('WP_CONTENT_DIR'), DIRECTORY_SEPARATOR);
        $autoload_candidates[] = $content_directory . '/vendor/autoload.php';
        $autoload_candidates[] = dirname($content_directory) . '/vendor/autoload.php';
        $autoload_candidates[] = dirname($content_directory, 2) . '/vendor/autoload.php';
    }

    $wordpress_directory = rtrim(ABSPATH, DIRECTORY_SEPARATOR);
    $autoload_candidates[] = $wordpress_directory . '/vendor/autoload.php';
    $autoload_candidates[] = dirname($wordpress_directory) . '/vendor/autoload.php';
    $autoload_candidates[] = dirname($wordpress_directory, 2) . '/vendor/autoload.php';

    $autoload_candidates = array_values(array_unique(array_filter($autoload_candidates)));
    $autoload_path = null;

    foreach ($autoload_candidates as $candidate) {
        if (is_file($candidate) && is_readable($candidate)) {
            $autoload_path = $candidate;
            break;
        }
    }

    if ($autoload_path === null) {
        $pds_wp_2fa_bootstrap_failure(
            'The project Composer autoloader was not found. Deploy vendor/autoload.php '
            . 'with the plugin, or define PDS_WP_2FA_COMPOSER_AUTOLOAD before loading it.'
        );
    }

    require_once $autoload_path;
}

if (!class_exists('PDS\\WP2FA\\Plugin')) {
    $pds_wp_2fa_bootstrap_failure(
        'The PDS\\WP2FA\\Plugin class is unavailable. Install the package dependencies '
        . 'and regenerate the project Composer autoloader.'
    );
}

\PDS\WP2FA\Plugin::boot();
