<?php

declare(strict_types=1);

namespace RhHardening\Shield;

/**
 * Der Regelsatz des Schutzwalls.
 *
 * Bewusst vier Regeltypen und nicht mehr. Eine neue Regel soll eine Zeile sein
 * und kein Nachmittag, sonst wird sie im Ernstfall nicht geschrieben.
 *
 *   route             eine REST-Route ist für alle dicht
 *   namespace_guest   eine REST-Route ist für Nichtangemeldete dicht
 *   param             ein Muster in einem benannten Parameter wird abgewiesen
 *   component         alle REST-Routen einer Komponente sind dicht
 *
 * Der letzte Typ ist der Anschluss für später: meldet das Radar eine Lücke in
 * einem Plugin, für das es noch keinen Fix gibt, kann genau diese Komponente
 * eingesperrt werden, ohne sie zu deaktivieren.
 *
 * Was der Wall NICHT kann: einen direkten Aufruf einer Plugin-Datei abfangen.
 * Der läuft nicht über index.php, also läuft WordPress dabei gar nicht. Dafür
 * ist die Sperre im Upload-Verzeichnis und die Serverkonfiguration zuständig.
 */
final class Rules
{
    public const OPTION = 'rhhard_shield_rules';
    public const QUEUE_OPTION = 'rhhard_shield_queue';

    /**
     * Grundregeln, die auf jeder Seite Sinn ergeben.
     *
     * @return array<int, array<string, string>>
     */
    public static function defaults(): array
    {
        return [
            [
                'id' => 'batch-endpoint',
                'type' => 'namespace_guest',
                'value' => '/batch/v1',
                // Bewusst nur für Nichtangemeldete: wp2shell (CVE-2026-63030)
                // war ohne Anmeldung ausnutzbar, dort greift die Sperre. Für
                // alle zu wäre riskant, weil der Site-Editor diese Route zum
                // gleichzeitigen Speichern mehrerer Vorlagen benutzt.
                'note' => 'wp2shell (CVE-2026-63030) lief ohne Anmeldung über diese Route.',
            ],
            [
                'id' => 'user-listing',
                'type' => 'namespace_guest',
                'value' => '/wp/v2/users',
                'note' => 'Gibt ohne Anmeldung die Anmeldenamen preis.',
            ],
            [
                'id' => 'site-health',
                'type' => 'namespace_guest',
                'value' => '/wp-site-health/v1',
                'note' => 'Verrät Aufbau und Versionen der Installation.',
            ],
            [
                'id' => 'author-notin-injection',
                'type' => 'param',
                'param' => 'author__not_in',
                'pattern' => '/(union[\s\/*]|select[\s\/*].*from|sleep\s*\(|benchmark\s*\(|information_schema)/i',
                'note' => 'Der zweite Teil von wp2shell (CVE-2026-60137) schleuste hier SQL ein.',
            ],
        ];
    }

    /**
     * Legt den Grundregelsatz an, falls noch keiner da ist, und hält die
     * Grundregeln aktuell, ohne selbst hinzugefügte zu überschreiben.
     */
    public static function ensureDefaults(): void
    {
        $stored = get_option(self::OPTION, null);
        $custom = [];

        if (is_array($stored) && isset($stored['rules']) && is_array($stored['rules'])) {
            $defaultIds = array_column(self::defaults(), 'id');

            foreach ($stored['rules'] as $rule) {
                if (is_array($rule) && ! in_array($rule['id'] ?? '', $defaultIds, true)) {
                    $custom[] = $rule;
                }
            }
        }

        self::save(array_merge(self::defaults(), $custom), true);
    }

    /**
     * @param array<int, array<string, string>> $rules
     */
    public static function save(array $rules, bool $active): void
    {
        // autoload, weil der Wall die Regeln bei JEDEM Aufruf braucht. Als
        // Teil des ohnehin geladenen Options-Satzes kostet das keine eigene
        // Abfrage.
        update_option(self::OPTION, ['active' => $active, 'rules' => array_values($rules)], true);
    }

    /**
     * @return array<int, array<string, string>>
     */
    public static function all(): array
    {
        $stored = get_option(self::OPTION, null);

        if (! is_array($stored) || ! isset($stored['rules']) || ! is_array($stored['rules'])) {
            return [];
        }

        return $stored['rules'];
    }

    /**
     * Sperrt alle REST-Routen einer Komponente. Anschluss für das Radar:
     * bekannte Lücke, kein Fix verfügbar, Seite soll trotzdem laufen.
     */
    public static function containComponent(string $namespace, string $reason): void
    {
        $namespace = trim($namespace, '/');

        if ($namespace === '') {
            return;
        }

        $rules = self::all();

        foreach ($rules as $rule) {
            if (($rule['id'] ?? '') === 'contain-' . $namespace) {
                return;
            }
        }

        $rules[] = [
            'id' => 'contain-' . $namespace,
            'type' => 'component',
            'value' => '/' . $namespace,
            'note' => $reason,
        ];

        self::save($rules, true);
    }

    public static function removeRule(string $id): void
    {
        $rules = array_filter(
            self::all(),
            static fn (array $rule): bool => ($rule['id'] ?? '') !== $id
        );

        self::save($rules, true);
    }
}
