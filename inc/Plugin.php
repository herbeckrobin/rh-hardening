<?php

declare(strict_types=1);

namespace RhHardening;

use RhBlueprint\Core\Core;
use RhBlueprint\Core\Settings\SettingsPage;
use RhHardening\Admin\HardeningGroup;
use RhHardening\Admin\SecurityPanel;
use RhHardening\Integrity\ScanRunner;
use RhHardening\Notify\Mailer;
use RhHardening\Prevention\Access;
use RhHardening\Prevention\RestGate;
use RhHardening\Prevention\Uploads;
use RhHardening\Radar\Radar;
use RhHardening\Shield\Shield;
use RhHardening\Watch\ChangeWatch;

/**
 * Bootstrap von rh-hardening.
 *
 * Hängt am Core-Hook `rh-blueprint/core/booted` (feuert auf `init`). Das Modul
 * arbeitet in drei Schichten, die sich klar trennen lassen:
 *
 *   Prävention   nimmt Angriffsfläche weg, gesteuert über Schalter
 *   Chronik      hält fest, woran man eine Übernahme zuerst erkennt
 *   Meldung      schickt raus, was jemand ansehen sollte
 *
 * Grundsatz über allem: das Modul verändert die Website nie eigenmächtig. Es
 * sperrt, was eingestellt ist, und meldet den Rest. Kein automatisches Update,
 * kein automatisches Deaktivieren, kein Zurückstufen von Benutzern.
 *
 * Braucht nur den Core, keine db-engine.
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

        register_activation_hook(RHHARD_PLUGIN_FILE, [Installer::class, 'activate']);
        register_deactivation_hook(RHHARD_PLUGIN_FILE, [Installer::class, 'deactivate']);

        (new Installer())->boot();

        // Die Beobachtung hängt früher als der Rest: der Core bootet erst auf
        // init, und eine Lücke, die vorher einen Administrator anlegt, soll
        // trotzdem in der Chronik landen.
        add_action('plugins_loaded', static function (): void {
            (new ChangeWatch())->boot();
        }, 1);

        // Der Prüflauf wird von WP-Cron angetrieben, auch ohne Admin-Aufruf.
        (new ScanRunner())->boot();

        add_action('rh-blueprint/core/booted', [self::class, 'onCoreBooted']);
    }

    public static function onCoreBooted(Core $core): void
    {
        $core->settings()->registerTab('hardening', __('Sicherheit', 'rh-hardening'), 40);
        $core->settings()->registerGroup(new HardeningGroup());

        // Prävention
        (new Hardening())->boot();
        (new RestGate())->boot();
        (new Access())->boot();
        (new Uploads())->boot();
        (new Shield())->boot();

        // Radar und Meldung
        (new Radar())->boot();
        (new Mailer())->boot();

        if (is_admin()) {
            (new SecurityPanel())->boot();
        }

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
