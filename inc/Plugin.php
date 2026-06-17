<?php

declare(strict_types=1);

namespace RhHardening;

use RhBlueprint\Core\Core;
use RhBlueprint\Core\Settings\SettingsPage;
use RhHardening\Admin\HardeningGroup;

/**
 * Bootstrap von rh-hardening.
 *
 * Hängt am Core-Hook `rh-blueprint/core/booted` (feuert auf `init`). Reines
 * Toggle-Modul: eine Settings-Gruppe (vom Core automatisch gerendert) plus die
 * Hardening-Logik, jede Maßnahme an ihrem Schalter gated. Braucht nur den Core,
 * keine db-engine und keine eigene Admin-Page.
 */
final class Plugin
{
    public static function boot(): void
    {
        // Im WordPress.org-Build wird der UpdateChecker entfernt (WP.org liefert
        // Updates selbst), darum defensiv prüfen.
        if (class_exists(UpdateChecker::class)) {
            (new UpdateChecker())->boot();
        }

        add_action('rh-blueprint/core/booted', [self::class, 'onCoreBooted']);
    }

    public static function onCoreBooted(Core $core): void
    {
        $core->settings()->registerTab('hardening', __('Sicherheit', 'rh-hardening'), 40);
        $core->settings()->registerGroup(new HardeningGroup());

        (new Hardening())->boot();

        // Entkopplung: rh-hardening steuert seinen Dashboard-Quick-Link selbst bei.
        add_filter('rh-blueprint/dashboard/quick_links', static function (array $links): array {
            $links[] = [
                'label' => __('Sicherheit', 'rh-hardening'),
                'url' => admin_url('admin.php?page=' . SettingsPage::MENU_SLUG . '&tab=hardening'),
                'icon' => 'shield',
            ];
            return $links;
        });
    }
}
