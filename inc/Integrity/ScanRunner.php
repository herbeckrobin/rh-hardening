<?php

declare(strict_types=1);

namespace RhHardening\Integrity;

use RhHardening\Log\Event;
use RhHardening\Log\EventLog;

/**
 * Treibt den Prüflauf in Häppchen voran.
 *
 * Angetrieben wird über WP-Cron: nach jedem Tick plant sich der nächste selbst,
 * solange noch etwas zu tun ist. Kein Loopback-Selbstaufruf wie in rh-sync, das
 * wäre für einen Dateiabgleich überzogen. WP-Cron braucht Besucher auf der
 * Website, und die hat eine Kundenseite.
 */
final class ScanRunner
{
    public const CRON_TICK = 'rh_hardening_scan_tick';
    public const CRON_WEEKLY = 'rh_hardening_scan_weekly';
    public const RESULT_OPTION = 'rhhard_scan_result';

    /** Zeitbudget je Tick. Bewusst klein, damit auch ein Hoster mit dreissig Sekunden Grenze durchkommt. */
    private const BUDGET = 8.0;

    private const LOCK_TRANSIENT = 'rhhard_scan_lock';

    public function boot(): void
    {
        add_action(self::CRON_TICK, [$this, 'tick']);
        add_action(self::CRON_WEEKLY, [$this, 'startScheduled']);
    }

    /**
     * Startet einen Durchlauf, wenn nicht schon einer läuft.
     */
    public function start(string $trigger = 'manuell'): bool
    {
        $job = ScanJob::load();

        if ($job->isRunning() && ! $job->isStale()) {
            return false;
        }

        ScanJob::start($trigger);
        $this->scheduleNextTick();

        return true;
    }

    public function startScheduled(): void
    {
        $this->start('automatisch');
    }

    /**
     * Ein Arbeitspaket. Läuft bis zum Zeitbudget und plant sich neu, falls nötig.
     */
    public function tick(): void
    {
        if (get_transient(self::LOCK_TRANSIENT)) {
            return;
        }

        set_transient(self::LOCK_TRANSIENT, 1, 60);

        try {
            $this->advance();
        } catch (\Throwable $e) {
            $job = ScanJob::load();
            $job->fail($e->getMessage());

            EventLog::record(Event::warn(
                Event::TYPE_SCAN_COMPLETED,
                __('Der Prüflauf ist abgebrochen.', 'rh-hardening'),
                ['grund' => $e->getMessage()]
            ));
        } finally {
            delete_transient(self::LOCK_TRANSIENT);
        }
    }

    private function advance(): void
    {
        $job = ScanJob::load();

        if (! $job->isRunning()) {
            return;
        }

        $deadline = microtime(true) + self::BUDGET;

        while (microtime(true) < $deadline) {
            $scanner = $this->scannerFor($job->stage);

            if ($scanner === null) {
                $this->complete($job);

                return;
            }

            $stageDone = $scanner->run($job, $deadline);

            if (! $stageDone) {
                $job->save();
                $this->scheduleNextTick();

                return;
            }

            $next = $job->nextStage();

            if ($next === null) {
                $this->complete($job);

                return;
            }

            $job->stage = $next;
            $job->cursor = 0;
            $job->subCursor = 0;
            $job->save();
        }

        $job->save();
        $this->scheduleNextTick();
    }

    private function scannerFor(string $stage): ?StageScanner
    {
        return match ($stage) {
            'core' => new CoreScan(),
            'plugins' => new PluginScan(),
            'hidden' => new HiddenScan(),
            'uploads' => new UploadScan(),
            default => null,
        };
    }

    private function complete(ScanJob $job): void
    {
        $job->finish();

        update_option(
            self::RESULT_OPTION,
            [
                'finished' => time(),
                'duration' => max(0, time() - $job->startedAt),
                'files' => $job->filesChecked,
                'findings' => $job->findings,
                'trigger' => $job->trigger,
            ],
            false
        );

        $this->report($job);
    }

    /**
     * Schreibt die Funde in die Chronik. Ein Eintrag je Art, nicht je Datei:
     * bei einem übernommenen Kern wären das sonst tausende Zeilen.
     */
    private function report(ScanJob $job): void
    {
        foreach (self::findingTypes() as $key => $meta) {
            $count = $job->findingCount($key);

            if ($count === 0) {
                continue;
            }

            // Nicht prüfbare Plugins sind der Normalfall bei eigenen Modulen
            // und gekauften Plugins. Das gehört in die Ansicht, nicht in die
            // Chronik, sonst steht dort bei jedem Lauf dasselbe Rauschen.
            if (empty($meta['log'])) {
                continue;
            }

            $files = $job->findings[$key] ?? [];

            EventLog::record(new Event(
                $meta['type'],
                $meta['severity'],
                sprintf($meta['message'], $count),
                [
                    'dateien' => implode(', ', array_slice($files, 0, 10)),
                    'anzahl' => $count,
                ]
            ));
        }

        if ($job->totalFindings() === 0) {
            EventLog::record(Event::info(
                Event::TYPE_SCAN_COMPLETED,
                sprintf(
                    /* translators: %d: Anzahl geprüfter Dateien */
                    __('Prüflauf ohne Befund, %d Dateien verglichen', 'rh-hardening'),
                    $job->filesChecked
                ),
                ['ausloeser' => $job->trigger]
            ));
        }
    }

    /**
     * @return array<string, array{type: string, severity: string, message: string, label: string, log: bool}>
     */
    public static function findingTypes(): array
    {
        return [
            'core_modified' => [
                'type' => Event::TYPE_INTEGRITY_FAILED,
                'severity' => Event::SEVERITY_CRITICAL,
                'message' => __('%d Datei(en) des WordPress-Kerns weichen von der amtlichen Fassung ab', 'rh-hardening'),
                'label' => __('Kern verändert', 'rh-hardening'),
                'log' => true,
            ],
            'core_missing' => [
                'type' => Event::TYPE_INTEGRITY_FAILED,
                'severity' => Event::SEVERITY_WARN,
                'message' => __('%d Datei(en) des WordPress-Kerns fehlen', 'rh-hardening'),
                'label' => __('Kern unvollständig', 'rh-hardening'),
                'log' => true,
            ],
            'core_unavailable' => [
                'type' => Event::TYPE_INTEGRITY_FAILED,
                'severity' => Event::SEVERITY_WARN,
                'message' => __('Die Prüfsummen des Kerns waren nicht abrufbar (%d)', 'rh-hardening'),
                'label' => __('Kern nicht prüfbar', 'rh-hardening'),
                'log' => true,
            ],
            'plugin_extra' => [
                'type' => Event::TYPE_INTEGRITY_FAILED,
                'severity' => Event::SEVERITY_CRITICAL,
                'message' => __('%d zusätzliche PHP-Datei(en) in Plugin-Ordnern, die es dort nicht geben dürfte', 'rh-hardening'),
                'label' => __('Fremde Datei im Plugin', 'rh-hardening'),
                'log' => true,
            ],
            'plugin_modified' => [
                'type' => Event::TYPE_INTEGRITY_FAILED,
                'severity' => Event::SEVERITY_CRITICAL,
                'message' => __('%d Plugin-Datei(en) weichen von der ausgelieferten Fassung ab', 'rh-hardening'),
                'label' => __('Plugin verändert', 'rh-hardening'),
                'log' => true,
            ],
            'plugin_unverifiable' => [
                'type' => Event::TYPE_INTEGRITY_FAILED,
                'severity' => Event::SEVERITY_INFO,
                'message' => __('%d Plugin(s) sind nicht gegen wordpress.org prüfbar', 'rh-hardening'),
                'label' => __('Nicht prüfbar', 'rh-hardening'),
                'log' => false,
            ],
            'hidden_new' => [
                'type' => Event::TYPE_FILE_CHANGED,
                'severity' => Event::SEVERITY_CRITICAL,
                'message' => __('%d neue Datei(en) an einer Stelle, die WordPress ungefragt lädt', 'rh-hardening'),
                'label' => __('Neu an heikler Stelle', 'rh-hardening'),
                'log' => true,
            ],
            'hidden_modified' => [
                'type' => Event::TYPE_FILE_CHANGED,
                'severity' => Event::SEVERITY_CRITICAL,
                'message' => __('%d Datei(en) an heikler Stelle wurden verändert', 'rh-hardening'),
                'label' => __('Verändert an heikler Stelle', 'rh-hardening'),
                'log' => true,
            ],
            'hidden_removed' => [
                'type' => Event::TYPE_FILE_CHANGED,
                'severity' => Event::SEVERITY_WARN,
                'message' => __('%d Datei(en) an heikler Stelle sind verschwunden', 'rh-hardening'),
                'label' => __('Entfernt an heikler Stelle', 'rh-hardening'),
                'log' => true,
            ],
            'upload_executable' => [
                'type' => Event::TYPE_SUSPICIOUS_UPLOAD,
                'severity' => Event::SEVERITY_CRITICAL,
                'message' => __('%d ausführbare Datei(en) im Upload-Verzeichnis', 'rh-hardening'),
                'label' => __('Ausführbares im Upload', 'rh-hardening'),
                'log' => true,
            ],
        ];
    }

    private function scheduleNextTick(): void
    {
        if (! wp_next_scheduled(self::CRON_TICK)) {
            wp_schedule_single_event(time() + 30, self::CRON_TICK);
        }
    }

    /**
     * @return array<string, mixed>|null
     */
    public static function lastResult(): ?array
    {
        $stored = get_option(self::RESULT_OPTION, null);

        return is_array($stored) ? $stored : null;
    }
}
