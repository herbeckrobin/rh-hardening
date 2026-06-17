<?php

/**
 * Plugin Name:       RH Hardening
 * Plugin URI:        https://github.com/herbeckrobin/rh-hardening
 * Update URI:        https://github.com/herbeckrobin/rh-hardening
 * Description:       Security-Hardening für WordPress: User-Enumeration blocken, Feeds aus, Security-Header, WP-Schmodder und XML-RPC raus. Teil der rh-blueprint Kollektion.
 * Version:           0.1.2
 * Requires at least: 6.5
 * Requires PHP:      8.1
 * Author:            Robin Herbeck
 * Author URI:        https://robinherbeck.de
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       rh-hardening
 */

declare(strict_types=1);

if (! defined('ABSPATH')) {
    exit;
}

define('RHHARD_VERSION', '0.1.2');
define('RHHARD_PLUGIN_FILE', __FILE__);
define('RHHARD_PLUGIN_DIR', plugin_dir_path(__FILE__));

$rhhard_autoload = RHHARD_PLUGIN_DIR . 'vendor/autoload.php';

if (! is_readable($rhhard_autoload)) {
    add_action('admin_notices', static function (): void {
        echo '<div class="notice notice-error"><p><strong>RH Hardening:</strong> Composer-Dependencies fehlen. Bitte <code>composer install</code> im Plugin-Verzeichnis ausführen.</p></div>';
    });
    return;
}

require_once $rhhard_autoload;

RhHardening\Plugin::boot();
