<?php

declare(strict_types=1);

namespace RhHardening;

use RhHardening\Admin\HardeningGroup;
use WP;

/**
 * Die eigentliche Hardening-Logik. Portiert aus dem michelberger-heizung-Theme,
 * jede Maßnahme an ihrem Settings-Schalter gated.
 *
 * Hook-Reihenfolge ist kritisch und bewusst so gewählt:
 * - `?author=` über `parse_request` (NICHT `template_redirect`), sonst leakt der
 *   WP-Canonical-Redirect den Login-Namen, bevor wir blocken.
 * - Feeds über `template_redirect` + `is_feed()` (die `do_feed*`-Hooks greifen nicht,
 *   WP routet Feed-Requests vorher direkt zur Feed-Funktion).
 *
 * boot() läuft auf `init` (über den Core-Hook). Alle registrierten Hooks feuern
 * nach `init`, das Entfernen der wp_head-Actions wirkt vor dem späteren wp_head.
 */
final class Hardening
{
    public function boot(): void
    {
        if ($this->enabled(HardeningGroup::FIELD_REMOVE_CLUTTER)) {
            $this->removeClutter();
        }

        if ($this->enabled(HardeningGroup::FIELD_DISABLE_XMLRPC)) {
            add_filter('xmlrpc_enabled', '__return_false');
        }

        if ($this->enabled(HardeningGroup::FIELD_DISABLE_FEEDS)) {
            add_action('template_redirect', [$this, 'killFeeds'], 1);
        }

        if ($this->enabled(HardeningGroup::FIELD_BLOCK_USER_ENUM)) {
            add_filter('rest_endpoints', [$this, 'blockRestUserEndpoints']);
            add_action('parse_request', [$this, 'blockAuthorEnumeration']);
        }

        if ($this->enabled(HardeningGroup::FIELD_SECURITY_HEADERS)) {
            add_action('send_headers', [$this, 'sendSecurityHeaders']);
        }
    }

    private function enabled(string $field): bool
    {
        return (bool) rhbp_setting(HardeningGroup::GROUP_ID, $field, true);
    }

    /**
     * WP-Standard-Schmodder aus dem <head> entfernen.
     */
    private function removeClutter(): void
    {
        remove_action('wp_head', 'print_emoji_detection_script', 7);
        remove_action('wp_print_styles', 'print_emoji_styles');
        remove_action('admin_print_scripts', 'print_emoji_detection_script');
        remove_action('admin_print_styles', 'print_emoji_styles');
        remove_filter('the_content_feed', 'wp_staticize_emoji');
        remove_filter('comment_text_rss', 'wp_staticize_emoji');
        remove_filter('wp_mail', 'wp_staticize_emoji_for_email');
        remove_action('wp_head', 'wp_generator');
        remove_action('wp_head', 'wlwmanifest_link');
        remove_action('wp_head', 'rsd_link');
        remove_action('wp_head', 'wp_shortlink_wp_head');
        remove_action('wp_head', 'feed_links_extra', 3);
        remove_action('wp_head', 'feed_links', 2);
    }

    /**
     * Feeds ausschalten, greift vor dem WP-Feed-Routing.
     */
    public function killFeeds(): void
    {
        if (is_feed()) {
            wp_die(esc_html__('Feeds sind deaktiviert.', 'rh-hardening'), '', ['response' => 404]);
        }
    }

    /**
     * REST-API: User-Endpoints für nicht eingeloggte Besucher entfernen (kein User-Enum).
     *
     * @param array<string, mixed> $endpoints
     * @return array<string, mixed>
     */
    public function blockRestUserEndpoints(array $endpoints): array
    {
        if (! is_user_logged_in()) {
            unset($endpoints['/wp/v2/users']);
            unset($endpoints['/wp/v2/users/(?P<id>[\d]+)']);
        }

        return $endpoints;
    }

    /**
     * User-Enumeration über ?author=N und /author/<slug>/ blocken.
     * Früh, vor dem WP-Canonical-Redirect, der den Login-Namen leaken würde.
     */
    public function blockAuthorEnumeration(WP $wp): void
    {
        if (is_user_logged_in()) {
            return;
        }

        $authorQuery = ! empty($wp->query_vars['author_name']) || ! empty($wp->query_vars['author']);

        if (isset($_GET['author']) || $authorQuery) {
            status_header(404);
            nocache_headers();
            wp_die(esc_html__('Not found.', 'rh-hardening'), '', ['response' => 404]);
        }
    }

    /**
     * Security-Header, Fallback falls Nginx/Coolify sie nicht setzt.
     */
    public function sendSecurityHeaders(): void
    {
        if (headers_sent()) {
            return;
        }

        header_remove('X-Powered-By');
        header('X-Content-Type-Options: nosniff');
        header('Referrer-Policy: strict-origin-when-cross-origin');
        header('Permissions-Policy: camera=(), microphone=(), geolocation=(), interest-cohort=()');
        header('X-Frame-Options: SAMEORIGIN');

        if (is_ssl()) {
            header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
        }
    }
}
