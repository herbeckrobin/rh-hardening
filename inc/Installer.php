<?php

declare(strict_types=1);

namespace RhHardening;

use RhHardening\Log\EventLog;
use RhHardening\Integrity\ScanRunner;
use RhHardening\Notify\Mailer;
use RhHardening\Radar\Radar;
use RhHardening\Shield\Shield;

/**
 * Einrichtung und Nachziehen bei jedem Update.
 *
 * Wichtig ist der versionsgesteuerte Weg: der Aktivierungs-Hook läuft bei einem
 * Auto-Update NICHT, das Plugin wird im Hintergrund ausgetauscht und einfach
 * weiterbenutzt. Was beim Update mitkommen muss (Tabellenstand, geschriebene
 * Dateien, Cron), gehört deshalb hinter einen Versionsvergleich auf init.
 */
final class Installer
{
    private const VERSION_OPTION = 'rhhard_installed_version';
    private const PURGE_CRON = 'rh_hardening_purge';

    public function boot(): void
    {
        add_action('init', [$this, 'maybeUpgrade'], 99);
        add_action(self::PURGE_CRON, [EventLog::class, 'purge']);
    }

    /**
     * Läuft beim Aktivieren über den Plugin-Hook.
     */
    public static function activate(): void
    {
        self::install();
    }

    public static function deactivate(): void
    {
        Mailer::clearCron();

        // Ein abgeschaltetes Plugin darf nicht weiter Aufrufe abweisen: der
        // Wall in mu-plugins läuft sonst unabhängig davon weiter.
        (new Shield())->remove();

        foreach ([self::PURGE_CRON, ScanRunner::CRON_WEEKLY, ScanRunner::CRON_TICK, Radar::CRON] as $hook) {
            $timestamp = wp_next_scheduled($hook);

            if ($timestamp) {
                wp_unschedule_event($timestamp, $hook);
            }
        }
    }

    /**
     * Zieht nach, wenn die gespeicherte Version nicht der laufenden entspricht.
     * Deckt Installation, Update, Wiederherstellung und Sync in einem ab.
     */
    public function maybeUpgrade(): void
    {
        if (get_option(self::VERSION_OPTION) === RHHARD_VERSION) {
            return;
        }

        self::install();
    }

    private static function install(): void
    {
        EventLog::install();
        Mailer::scheduleCron();

        if (! wp_next_scheduled(self::PURGE_CRON)) {
            wp_schedule_event(time() + HOUR_IN_SECONDS, 'daily', self::PURGE_CRON);
        }

        if (! wp_next_scheduled(Radar::CRON)) {
            wp_schedule_event(time() + (3 * HOUR_IN_SECONDS), 'daily', Radar::CRON);
        }

        if (! wp_next_scheduled(ScanRunner::CRON_WEEKLY)) {
            wp_schedule_event(time() + (2 * HOUR_IN_SECONDS), 'weekly', ScanRunner::CRON_WEEKLY);
        }

        /**
         * Dateien, die das Modul auf die Platte schreibt, neu auslegen.
         * Hängt unter anderem die .htaccess im Upload-Verzeichnis daran.
         */
        do_action('rh-hardening/ensure_files');

        update_option(self::VERSION_OPTION, RHHARD_VERSION, false);
    }
}
