<?php

declare(strict_types=1);

namespace RhHardening\Radar;

use RhHardening\Log\Event;
use RhHardening\Log\EventLog;

/**
 * Erkennt Plugins, die im Verzeichnis verschwunden oder verwaist sind.
 *
 * Der wichtigste Fund ist das Verschwinden. Ein Plugin, das gestern noch auf
 * wordpress.org stand und heute nicht mehr, wurde geschlossen, und geschlossen
 * wird fast immer aus einem Grund: eine ungefixte Lücke oder untergeschobener
 * Code. Im April 2026 traf das an einem Tag 31 Plugins auf einen Schlag.
 *
 * Ein einfacher 404 taugt dafür nicht als Alarm, denn er trifft auch jedes
 * Plugin, das nie im Verzeichnis war: eigene Module, gekaufte Premium-Plugins.
 * Deshalb wird der zuletzt bekannte Zustand gemerkt, und gemeldet wird der
 * Übergang von "steht im Verzeichnis" zu "steht nicht mehr drin".
 *
 * Das zweite Signal ist Stillstand: seit über einem Jahr kein Update. Das ist
 * kein Alarm, sondern ein Hinweis für das nächste Gespräch mit dem Kunden.
 */
final class AbandonedWatch
{
    public const STATE_OPTION = 'rhhard_directory_state';

    /** Ab wann ein Plugin als stehengelassen gilt. */
    private const STALE_AFTER_DAYS = 365;

    public function run(): array
    {
        require_once ABSPATH . 'wp-admin/includes/plugin.php';

        $directory = new PluginDirectory();
        $previous = get_option(self::STATE_OPTION, []);
        $previous = is_array($previous) ? $previous : [];
        $current = [];
        $report = ['disappeared' => [], 'stale' => [], 'listed' => 0, 'unlisted' => 0];

        foreach (array_keys(get_plugins()) as $file) {
            $slug = dirname((string) $file);

            if ($slug === '.' || $slug === '') {
                continue;
            }

            $info = $directory->lookup($slug);

            if ($info['state'] === PluginDirectory::STATE_UNKNOWN) {
                // Nichts gelernt, alten Stand behalten.
                if (isset($previous[$slug])) {
                    $current[$slug] = $previous[$slug];
                }

                continue;
            }

            $wasListed = ($previous[$slug]['state'] ?? '') === PluginDirectory::STATE_LISTED;

            if ($info['state'] === PluginDirectory::STATE_MISSING) {
                $report['unlisted']++;

                if ($wasListed) {
                    $report['disappeared'][] = $slug;
                }

                $current[$slug] = ['state' => PluginDirectory::STATE_MISSING];

                continue;
            }

            $report['listed']++;
            $current[$slug] = [
                'state' => PluginDirectory::STATE_LISTED,
                'updated' => $info['updated'] ?? '',
            ];

            if ($this->isStale($info['updated'] ?? '')) {
                $report['stale'][] = $slug;
            }
        }

        update_option(self::STATE_OPTION, $current, false);

        $this->report($report);

        return $report;
    }

    /**
     * @param array{disappeared: array<int, string>, stale: array<int, string>} $report
     */
    private function report(array $report): void
    {
        if ($report['disappeared'] !== []) {
            EventLog::record(Event::critical(
                Event::TYPE_VULNERABILITY,
                sprintf(
                    /* translators: %s: Liste von Plugin-Namen */
                    __('Aus dem Plugin-Verzeichnis verschwunden: %s. Ein Plugin wird dort fast nur wegen einer ungefixten Lücke oder untergeschobenem Code geschlossen.', 'rh-hardening'),
                    implode(', ', $report['disappeared'])
                ),
                ['plugins' => implode(', ', $report['disappeared'])]
            ));
        }

        if ($report['stale'] !== []) {
            EventLog::record(Event::warn(
                Event::TYPE_VULNERABILITY,
                sprintf(
                    /* translators: 1: Anzahl, 2: Liste von Plugin-Namen */
                    __('%1$d Plugin(s) seit über einem Jahr ohne Update: %2$s', 'rh-hardening'),
                    count($report['stale']),
                    implode(', ', array_slice($report['stale'], 0, 10))
                ),
                ['plugins' => implode(', ', $report['stale'])]
            ));
        }
    }

    private function isStale(string $updated): bool
    {
        if ($updated === '') {
            return false;
        }

        $timestamp = strtotime($updated);

        if ($timestamp === false) {
            return false;
        }

        return (time() - $timestamp) > (self::STALE_AFTER_DAYS * DAY_IN_SECONDS);
    }

    /**
     * Beim ersten Lauf gibt es noch keinen Vergleichsstand. Dann nur merken,
     * nicht melden, sonst wäre jedes eigene Modul ein Fehlalarm.
     */
    public static function hasState(): bool
    {
        $stored = get_option(self::STATE_OPTION, null);

        return is_array($stored) && $stored !== [];
    }
}
