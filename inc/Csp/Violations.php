<?php

declare(strict_types=1);

namespace RhHardening\Csp;

/**
 * Sammelt, was eine Content-Security-Policy blockieren würde.
 *
 * Eine CSP lässt sich nicht am Schreibtisch schreiben. Man setzt sie erst nur
 * beobachtend, sammelt ein paar Tage, was sie blockiert hätte, und schaltet sie
 * dann scharf. Ohne diesen Zwischenschritt sperrt man die halbe Website aus.
 *
 * Gespeichert wird bewusst gruppiert und nicht als Liste einzelner Meldungen:
 * eine Seite mit einem eingebundenen Schriftarten-Dienst erzeugt sonst tausende
 * identische Einträge. Interessant ist "diese Regel, diese Quelle, so oft",
 * nicht jeder einzelne Aufruf.
 *
 * Was NICHT gespeichert wird: Adressparameter, Verweisquellen, Herkunft. Eine
 * Meldung nennt die Seite, auf der es passiert ist, und die wird auf den Pfad
 * gekürzt. Damit bleibt nichts übrig, das auf eine Person zeigt.
 */
final class Violations
{
    public const OPTION = 'rhhard_csp_violations';

    /** Mehr verschiedene Fälle werden nicht festgehalten. */
    private const MAX_GROUPS = 120;

    /** Bremse gegen Flutung: so oft wird höchstens geschrieben. */
    private const WRITE_EVERY = 10;
    private const WRITE_TRANSIENT = 'rhhard_csp_wrote';

    /**
     * Nimmt eine Meldung auf.
     *
     * @param array<string, mixed> $report
     */
    public static function add(array $report): void
    {
        $direktive = self::directive((string) ($report['effective-directive'] ?? $report['violated-directive'] ?? ''));
        $quelle = self::origin((string) ($report['blocked-uri'] ?? ''));
        $seite = self::path((string) ($report['document-uri'] ?? ''));

        if ($direktive === '' || $quelle === '') {
            return;
        }

        // Nur die erste Meldung einer Zehn-Sekunden-Spanne schreibt wirklich.
        // Ein Seitenaufruf erzeugt sonst Dutzende Schreibvorgänge.
        if (get_transient(self::WRITE_TRANSIENT)) {
            return;
        }

        set_transient(self::WRITE_TRANSIENT, 1, self::WRITE_EVERY);

        $gruppen = self::all();
        $schluessel = $direktive . '|' . $quelle;

        if (isset($gruppen[$schluessel])) {
            $gruppen[$schluessel]['anzahl']++;
            $gruppen[$schluessel]['zuletzt'] = time();
        } elseif (count($gruppen) < self::MAX_GROUPS) {
            $gruppen[$schluessel] = [
                'direktive' => $direktive,
                'quelle' => $quelle,
                'seite' => $seite,
                'anzahl' => 1,
                'zuletzt' => time(),
            ];
        } else {
            return;
        }

        update_option(self::OPTION, $gruppen, false);
    }

    /**
     * @return array<string, array<string, mixed>>
     */
    public static function all(): array
    {
        $stored = get_option(self::OPTION, []);

        return is_array($stored) ? $stored : [];
    }

    public static function clear(): void
    {
        delete_option(self::OPTION);
    }

    /**
     * Baut aus dem Gesammelten einen Vorschlag für die Regeln.
     *
     * Bewusst nur ein Vorschlag: was hier auftaucht, ist das, was die Website
     * tatsächlich lädt. Ob es das auch laden SOLL, entscheidet ein Mensch.
     */
    public static function suggestion(): string
    {
        $nachDirektive = [];

        foreach (self::all() as $gruppe) {
            $d = (string) $gruppe['direktive'];
            $q = (string) $gruppe['quelle'];

            $nachDirektive[$d] ??= [];

            if (! in_array($q, $nachDirektive[$d], true)) {
                $nachDirektive[$d][] = $q;
            }
        }

        if ($nachDirektive === []) {
            return '';
        }

        ksort($nachDirektive);
        $zeilen = [];

        foreach ($nachDirektive as $direktive => $quellen) {
            sort($quellen);
            $zeilen[] = $direktive . " 'self' " . implode(' ', $quellen);
        }

        return implode('; ', $zeilen);
    }

    /**
     * Nur der Ursprung, nicht die vollständige Adresse. Für die Regel zählt der
     * Host, alles danach wäre unnötiger Ballast und könnte Parameter enthalten.
     */
    private static function origin(string $uri): string
    {
        $uri = trim($uri);

        if ($uri === '') {
            return '';
        }

        // Der Browser meldet bei eingebetteten Inhalten Schlüsselwörter statt Adressen.
        if (in_array($uri, ['inline', 'eval', 'data', 'blob', 'self', 'wasm-eval'], true)) {
            return $uri;
        }

        $teile = wp_parse_url($uri);

        if (! is_array($teile) || empty($teile['host'])) {
            return '';
        }

        $host = strtolower($teile['host']);

        // Prüfen statt säubern: aus einem präparierten Wert soll kein
        // zusammengeklebter Rest werden, der dann im Vorschlag landet.
        if (preg_match('/^[a-z0-9.\-]{1,180}$/', $host) !== 1) {
            return '';
        }

        $schema = ! empty($teile['scheme']) && in_array($teile['scheme'], ['http', 'https', 'ws', 'wss'], true)
            ? $teile['scheme']
            : 'https';

        return $schema . '://' . $host;
    }

    private static function path(string $uri): string
    {
        $pfad = wp_parse_url(trim($uri), PHP_URL_PATH);

        if (! is_string($pfad) || $pfad === '') {
            return '/';
        }

        $pfad = substr($pfad, 0, 120);

        return preg_match('#^[a-zA-Z0-9/._\-]+$#', $pfad) === 1 ? $pfad : '/';
    }

    /**
     * Eine CSP-Direktive besteht aus Kleinbuchstaben und Bindestrichen, sonst
     * nichts. Alles andere wird verworfen statt zurechtgeschnitten: ein Rest,
     * der nach dem Säubern übrigbleibt, wäre in der Regel-Liste nur Müll.
     *
     * Bewusst ein Muster und keine feste Liste, damit eine künftige Direktive
     * nicht an einer veralteten Aufzählung scheitert.
     */
    private static function directive(string $wert): string
    {
        $wert = strtolower(trim($wert));

        return preg_match('/^[a-z][a-z\-]{1,60}$/', $wert) === 1 ? $wert : '';
    }
}
