<?php

declare(strict_types=1);

namespace RhHardening\Shield;

use RhHardening\Admin\HardeningGroup;
use RhHardening\Log\Event;
use RhHardening\Log\EventLog;
use RhHardening\Support\Env;
use RhHardening\Support\Log;

/**
 * Legt den Schutzwall aus und hält ihn aktuell.
 *
 * Der Wall ist eine eigenständige Datei in mu-plugins, weil er laufen muss,
 * bevor WordPress die REST-Schnittstelle aufbaut. Er wird bei Aktivierung und
 * bei jedem Plugin-Update neu geschrieben, denn ein Auto-Update tauscht nur
 * die Plugin-Dateien aus und ruft keinen Aktivierungs-Hook auf.
 *
 * Weil mu-plugins gleichzeitig der Lieblingsplatz für Hintertüren ist, kennt
 * das Modul den erwarteten Fingerabdruck seiner eigenen Datei. Weicht sie ab,
 * ist das ein kritischer Fund und kein Schönheitsfehler.
 */
final class Shield
{
    public const FILENAME = 'rh-hardening-shield.php';
    public const VERSION_PLACEHOLDER = '__RHHARD_SHIELD_VERSION__';

    public const STATE_ACTIVE = 'active';
    public const STATE_MISSING = 'missing';
    public const STATE_OUTDATED = 'outdated';
    public const STATE_TAMPERED = 'tampered';
    public const STATE_UNWRITABLE = 'unwritable';
    public const STATE_DISABLED = 'disabled';

    public function boot(): void
    {
        add_action('rh-hardening/ensure_files', [$this, 'sync']);
        add_action('init', [$this, 'drainQueue'], 20);

        // Billiger Selbsttest bei jedem Aufruf: fehlt die Datei, wird sie
        // sofort neu ausgelegt. Kostet ein is_file und deckt jeden Weg ab, auf
        // dem sie abhandenkommt.
        //
        // Bewusst nicht am Aktivierungs-Hook aufgehängt. Der feuert nicht
        // verlässlich, und ein Schutzwall, der an einem Hook hängt, ist genau
        // dann weg, wenn man ihn braucht.
        add_action('init', [$this, 'ensurePresent'], 5);
    }

    /**
     * Legt die Datei neu aus, wenn sie fehlt. Absichtlich nur ein is_file und
     * kein Inhaltsvergleich, damit das bei jedem Aufruf tragbar bleibt. Ob der
     * Inhalt stimmt, prüft sync() beim Update und die Anzeige im Backend.
     */
    public function ensurePresent(): void
    {
        if (! $this->enabled()) {
            return;
        }

        $path = $this->path();

        if ($path !== '' && ! is_file($path)) {
            $this->sync();
        }
    }

    /**
     * Sorgt dafür, dass die Datei dem entspricht, was sie sein soll.
     * Idempotent, kann bei jedem Aufruf laufen.
     */
    public function sync(): void
    {
        if (! $this->enabled()) {
            $this->remove();

            return;
        }

        Rules::ensureDefaults();

        $state = $this->state();

        if ($state === self::STATE_ACTIVE) {
            return;
        }

        if ($state === self::STATE_TAMPERED) {
            EventLog::record(Event::critical(
                Event::TYPE_FILE_CHANGED,
                __('Der Schutzwall in mu-plugins wurde verändert und wird jetzt neu ausgelegt.', 'rh-hardening'),
                ['datei' => self::FILENAME]
            ));
        }

        if (! $this->deploy()) {
            // Ohne diese Meldung liefe das Modul auf einem Hoster mit
            // gesperrtem mu-plugins dauerhaft ohne seine wichtigste Schicht,
            // und niemand wüsste davon.
            Log::incident(
                Event::TYPE_FILE_CHANGED,
                __('Der Schutzwall konnte nicht ausgelegt werden. Auf dieser Website greift er nicht.', 'rh-hardening'),
                ['verzeichnis' => defined('WPMU_PLUGIN_DIR') ? WPMU_PLUGIN_DIR : '?']
            );
        }
    }

    public function deploy(): bool
    {
        if (! Env::has('file_put_contents')) {
            return false;
        }

        $dir = $this->directory();

        if ($dir === '') {
            return false;
        }

        if (! is_dir($dir) && ! wp_mkdir_p($dir)) {
            return false;
        }

        $written = @file_put_contents($this->path(), $this->rendered());

        return $written !== false;
    }

    public function remove(): void
    {
        $path = $this->path();

        if ($path !== '' && is_file($path)) {
            @unlink($path);
        }
    }

    /**
     * Zustand der Datei, für die Anzeige und für den Wächter.
     */
    public function state(): string
    {
        if (! $this->enabled()) {
            return self::STATE_DISABLED;
        }

        $path = $this->path();

        if ($path === '') {
            return self::STATE_UNWRITABLE;
        }

        if (! is_file($path)) {
            return is_writable(dirname($path)) || wp_mkdir_p(dirname($path))
                ? self::STATE_MISSING
                : self::STATE_UNWRITABLE;
        }

        $actual = (string) @file_get_contents($path);

        if ($actual === $this->rendered()) {
            return self::STATE_ACTIVE;
        }

        // Steht eine andere Version drin, ist es schlicht ein alter Stand.
        // Steht dieselbe drin und der Inhalt weicht ab, hat jemand daran gedreht.
        if (str_contains($actual, "define('RHHARD_SHIELD', '" . RHHARD_VERSION . "')")) {
            return self::STATE_TAMPERED;
        }

        return self::STATE_OUTDATED;
    }

    /**
     * Übernimmt die Treffer des Walls in die Chronik. Der Wall selbst kann das
     * nicht, dort ist die Chronik-Maschine noch nicht geladen.
     */
    public function drainQueue(): void
    {
        $queue = get_option(Rules::QUEUE_OPTION, []);

        if (! is_array($queue) || $queue === []) {
            return;
        }

        delete_option(Rules::QUEUE_OPTION);

        // Zusammengefasst, nicht einzeln: ein Scanner erzeugt sonst hunderte Zeilen.
        $byRule = [];

        foreach ($queue as $entry) {
            $rule = (string) ($entry['regel'] ?? 'unbekannt');
            $byRule[$rule] ??= ['ziel' => (string) ($entry['ziel'] ?? ''), 'defekt' => ! empty($entry['defekt'])];
        }

        foreach ($byRule as $rule => $data) {
            if ($data['defekt']) {
                EventLog::record(Event::warn(
                    Event::TYPE_REQUEST_BLOCKED,
                    sprintf(
                        /* translators: %s: Name der Regel */
                        __('Die Regel "%s" des Schutzwalls hat ein ungültiges Muster und greift nicht.', 'rh-hardening'),
                        $rule
                    ),
                    ['regel' => $rule]
                ));

                continue;
            }

            // Bewusst ohne Anzahl: geschrieben wird höchstens einmal pro
            // Minute, eine Zahl wäre also erfunden. Wer wissen will, wie oft
            // es passiert, sieht es an der Häufigkeit dieser Einträge.
            EventLog::record(Event::info(
                Event::TYPE_REQUEST_BLOCKED,
                sprintf(
                    /* translators: %s: Name der Regel */
                    __('Der Schutzwall hat Aufrufe abgewiesen, Regel "%s".', 'rh-hardening'),
                    $rule
                ),
                ['regel' => $rule, 'beispiel' => $data['ziel']]
            ));
        }
    }

    public function path(): string
    {
        $dir = $this->directory();

        return $dir === '' ? '' : $dir . '/' . self::FILENAME;
    }

    /**
     * Gehört dieser Pfad zum Wall? Der Wächter über die heiklen Stellen darf
     * die eigene Datei nicht als Fremdkörper melden, prüft sie aber über den
     * Zustand oben mit.
     */
    public function isOwnFile(string $path): bool
    {
        $own = $this->path();

        return $own !== '' && wp_normalize_path($path) === wp_normalize_path($own);
    }

    private function directory(): string
    {
        if (! defined('WPMU_PLUGIN_DIR')) {
            return '';
        }

        return untrailingslashit(WPMU_PLUGIN_DIR);
    }

    /**
     * Die Vorlage mit eingesetzter Version. Genau dieser Inhalt muss auf der
     * Platte liegen, sonst stimmt etwas nicht.
     */
    private function rendered(): string
    {
        static $cache = null;

        if ($cache !== null) {
            return $cache;
        }

        $template = (string) @file_get_contents(__DIR__ . '/template.php');

        $cache = str_replace(self::VERSION_PLACEHOLDER, RHHARD_VERSION, $template);

        return $cache;
    }

    private function enabled(): bool
    {
        return (bool) rhbp_setting(HardeningGroup::GROUP_ID, HardeningGroup::FIELD_SHIELD, true);
    }
}
