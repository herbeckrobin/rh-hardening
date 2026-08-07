<?php

declare(strict_types=1);

namespace RhHardening\Integrity;

use RhHardening\Shield\Shield;

/**
 * Bewacht die Stellen, an denen sich eine Hintertür am liebsten einnistet.
 *
 * Das sind nicht die Plugin-Ordner, sondern die Orte, die niemand ansieht und
 * die WordPress ungefragt einbindet: mu-plugins wird ohne Aktivierung geladen,
 * die Drop-ins ebenso, und die wp-config.php ist die erste Datei überhaupt.
 * Der Payload aus dem April-2026-Angriff schrieb sich genau dorthin, und das
 * spätere Update hat ihn nicht wieder entfernt.
 *
 * Prüfsummen gibt es dafür nirgends, deshalb arbeitet dieser Abschnitt mit
 * einer eigenen Grundlinie: beim ersten Lauf wird der Zustand festgehalten,
 * danach zählt jede Abweichung. Weil sich diese Dateien auch legitim ändern
 * (ein Hoster schreibt eine Drop-in, DDEV baut die wp-config.php neu), lässt
 * sich der aktuelle Zustand mit einem Klick als neue Grundlinie übernehmen.
 */
final class HiddenScan implements StageScanner
{
    public const BASELINE_OPTION = 'rhhard_baseline';

    /** Drop-ins, die WordPress ohne Aktivierung lädt. */
    private const DROPINS = [
        'object-cache.php',
        'advanced-cache.php',
        'db.php',
        'maintenance.php',
        'sunrise.php',
        'php-error.php',
        'fatal-error-handler.php',
    ];

    public function run(ScanJob $job, float $deadline): bool
    {
        $current = $this->currentState();
        $baseline = get_option(self::BASELINE_OPTION, null);

        if (! is_array($baseline)) {
            // Erster Lauf: Grundlinie anlegen, nichts melden.
            self::storeBaseline($current);

            return true;
        }

        foreach ($current as $path => $hash) {
            $job->filesChecked++;

            if (! isset($baseline[$path])) {
                $job->addFinding('hidden_new', $this->shorten($path));
                continue;
            }

            if ($baseline[$path] !== $hash) {
                $job->addFinding('hidden_modified', $this->shorten($path));
            }
        }

        foreach (array_keys($baseline) as $path) {
            if (! isset($current[$path])) {
                $job->addFinding('hidden_removed', $this->shorten((string) $path));
            }
        }

        return true;
    }

    /**
     * Übernimmt den aktuellen Zustand als neue Grundlinie.
     */
    public static function acceptCurrentState(): int
    {
        $state = (new self())->currentState();
        self::storeBaseline($state);

        return count($state);
    }

    public static function hasBaseline(): bool
    {
        return is_array(get_option(self::BASELINE_OPTION, null));
    }

    /**
     * @param array<string, string> $state
     */
    private static function storeBaseline(array $state): void
    {
        update_option(self::BASELINE_OPTION, $state, false);
    }

    /**
     * @return array<string, string> Pfad zu sha256
     */
    private function currentState(): array
    {
        $state = [];

        foreach ($this->watchedFiles() as $path) {
            if (! is_file($path) || ! is_readable($path)) {
                continue;
            }

            $hash = hash_file('sha256', $path);

            if (is_string($hash)) {
                $state[$path] = $hash;
            }
        }

        return $state;
    }

    /**
     * @return array<int, string>
     */
    private function watchedFiles(): array
    {
        $files = [];

        // wp-config.php liegt je nach Aufbau eine Ebene über dem Kern.
        foreach ([ABSPATH . 'wp-config.php', dirname(ABSPATH) . '/wp-config.php'] as $config) {
            if (is_file($config)) {
                $files[] = $config;
                break;
            }
        }

        $files[] = ABSPATH . '.htaccess';

        foreach (self::DROPINS as $dropin) {
            $files[] = WP_CONTENT_DIR . '/' . $dropin;
        }

        if (defined('WPMU_PLUGIN_DIR') && is_dir(WPMU_PLUGIN_DIR)) {
            $shield = new Shield();

            foreach ((array) glob(WPMU_PLUGIN_DIR . '/*') as $entry) {
                if (! is_file($entry)) {
                    continue;
                }

                // Die eigene Wall-Datei gehört dorthin. Ob sie unverändert ist,
                // prüft der Wall selbst über seinen Zustand, sonst würde jedes
                // Plugin-Update hier als Verdachtsfall auflaufen.
                if ($shield->isOwnFile($entry)) {
                    continue;
                }

                $files[] = $entry;
            }
        }

        return array_values(array_filter($files, 'is_file'));
    }

    /**
     * Absoluten Pfad auf etwas Lesbares kürzen.
     */
    private function shorten(string $path): string
    {
        $root = dirname(ABSPATH);

        return ltrim(str_replace($root, '', $path), '/\\');
    }
}
