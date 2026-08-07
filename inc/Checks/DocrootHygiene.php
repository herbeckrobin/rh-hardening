<?php

declare(strict_types=1);

namespace RhHardening\Checks;

use RhHardening\Log\Event;
use RhHardening\Support\Loopback;
use RhHardening\Log\EventLog;

/**
 * Sucht Dateien, die im öffentlichen Verzeichnis nichts verloren haben.
 *
 * Das sind die Überbleibsel echter Arbeit: ein Datenbank-Auszug vom Umzug, ein
 * adminer.php vom Debuggen, eine wp-config.php.bak vom schnellen Ändern, ein
 * offenes .git-Verzeichnis vom Deploy. Jede einzelne davon reicht, um eine
 * ansonsten gut gehärtete Website komplett zu übernehmen.
 *
 * Der Fund allein sagt noch nichts. Entscheidend ist, ob die Datei von aussen
 * abrufbar ist, deshalb wird jeder Treffer zusätzlich per HTTP geprüft.
 * Gelöscht wird nichts, das entscheidet ein Mensch.
 */
final class DocrootHygiene
{
    /** Höchstens so viele Treffer per HTTP nachprüfen, damit der Lauf kurz bleibt. */
    private const MAX_PROBES = 25;

    /**
     * Dateinamen-Muster, die im Wurzelverzeichnis gesucht werden.
     *
     * @var array<int, string>
     */
    private const PATTERNS = [
        'info.php',
        'phpinfo.php',
        'test.php',
        'adminer.php',
        'adminer-*.php',
        '*.sql',
        '*.sql.gz',
        '*.zip',
        '*.tar.gz',
        '*.bak',
        'wp-config.php.*',
        'wp-config.*.php',
        '.env',
        '.env.*',
        'error_log',
        'debug.log',
    ];

    /**
     * Verzeichnisse, deren blosse Erreichbarkeit ein Fund ist.
     *
     * @var array<int, string>
     */
    private const DIRECTORIES = [
        '.git/config',
        '.svn/entries',
        'node_modules/.package-lock.json',
    ];

    /**
     * Führt den Durchlauf aus und schreibt die Funde in die Chronik.
     *
     * @return array<int, array{pfad: string, url: string, erreichbar: bool}>
     */
    public function run(): array
    {
        $findings = [];

        foreach ($this->candidates() as $relative) {
            $url = home_url('/' . ltrim($relative, '/'));
            $reachable = $this->isReachable($url, count($findings));

            $findings[] = [
                'pfad' => $relative,
                'url' => $url,
                'erreichbar' => $reachable,
            ];
        }

        $this->report($findings);

        return $findings;
    }

    /**
     * @return array<int, string>
     */
    private function candidates(): array
    {
        $root = untrailingslashit(ABSPATH);
        $found = [];

        foreach (self::PATTERNS as $pattern) {
            $matches = glob($root . '/' . $pattern, GLOB_NOSORT);

            if ($matches === false) {
                continue;
            }

            foreach ($matches as $path) {
                if (! is_file($path)) {
                    continue;
                }

                $relative = ltrim(str_replace($root, '', $path), '/\\');

                if ($this->isKnownGood($relative)) {
                    continue;
                }

                $found[$relative] = true;
            }
        }

        foreach (self::DIRECTORIES as $marker) {
            if (file_exists($root . '/' . $marker)) {
                $found[$marker] = true;
            }
        }

        return array_keys($found);
    }

    /**
     * Dateien, die zwar auf ein Muster passen, aber zum Kern gehören.
     */
    private function isKnownGood(string $relative): bool
    {
        return in_array($relative, ['wp-config-sample.php'], true);
    }

    private function isReachable(string $url, int $alreadyProbed): bool
    {
        if ($alreadyProbed >= self::MAX_PROBES) {
            return false;
        }

        $result = Loopback::request($url, 'HEAD', ['timeout' => 8]);
        $response = $result['response'];

        if (is_wp_error($response)) {
            return false;
        }

        return (int) wp_remote_retrieve_response_code($response) === 200;
    }

    /**
     * @param array<int, array{pfad: string, url: string, erreichbar: bool}> $findings
     */
    private function report(array $findings): void
    {
        $reachable = array_values(array_filter($findings, static fn (array $f): bool => $f['erreichbar']));

        if ($reachable === []) {
            return;
        }

        foreach ($reachable as $finding) {
            EventLog::record(Event::critical(
                Event::TYPE_DOCROOT_FINDING,
                sprintf(
                    /* translators: %s: Dateiname */
                    __('Datei im Wurzelverzeichnis von aussen abrufbar: %s', 'rh-hardening'),
                    $finding['pfad']
                ),
                ['pfad' => $finding['pfad'], 'url' => $finding['url']]
            ));
        }
    }
}
