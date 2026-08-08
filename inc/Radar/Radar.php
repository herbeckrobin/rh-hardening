<?php

declare(strict_types=1);

namespace RhHardening\Radar;

use RhHardening\Log\Event;
use RhHardening\Log\EventLog;
use RhHardening\Support\Log;

/**
 * Gleicht die installierte Software gegen den Schwachstellen-Feed ab.
 *
 * Der Ablauf ist bewusst zweistufig und sparsam, weil das täglich auf jeder
 * Kundenseite läuft:
 *
 *   1. Verzeichnis holen (rund 540 KB, zwölf Stunden zwischengespeichert).
 *   2. Lokal filtern: welches installierte Teil liegt überhaupt unterhalb der
 *      höchsten je gemeldeten Fassung. In der Regel bleibt hier nichts übrig.
 *   3. Nur für die Kandidaten die Einzelheiten holen und die Bereiche prüfen.
 *
 * Gemeldet wird nur, was noch nicht gemeldet wurde. Sonst stünde jeden Tag
 * dasselbe in der Chronik, und nach einer Woche liest es niemand mehr.
 *
 * Das Radar greift nicht ein. Es sperrt nichts und aktualisiert nichts.
 */
final class Radar
{
    public const CRON = 'rh_hardening_radar';
    public const RESULT_OPTION = 'rhhard_radar_result';
    public const SEEN_OPTION = 'rhhard_radar_seen';

    public function boot(): void
    {
        add_action(self::CRON, [$this, 'run']);
    }

    /**
     * @return array{status: string, geprueft: int, kandidaten: int, treffer: array<int, array<string, mixed>>}
     */
    public function run(): array
    {
        $client = new FeedClient();

        if (! $client->isEnabled()) {
            return $this->store('abgeschaltet', 0, 0, []);
        }

        $installed = $this->installedSoftware();
        $index = $client->index();

        if ($index === null) {
            Log::note('Radar ohne Verzeichnis, Lauf übersprungen');

            return $this->store('Verzeichnis nicht abrufbar', count($installed), 0, []);
        }

        // Stufe 2: alles wegwerfen, was schon an der höchsten je gemeldeten
        // Fassung vorbei ist. Gesucht wird im Text, damit das Verzeichnis nicht
        // als Array im Speicher landen muss.
        $candidates = [];

        foreach ($installed as $key => $info) {
            $highest = FeedClient::highestAffected($index, $key);

            if ($highest === null) {
                continue;
            }

            if (VersionRange::couldBeAffected($info['version'], $highest)) {
                $candidates[$key] = $info;
            }
        }

        if ($candidates === []) {
            return $this->store('ok', count($installed), 0, []);
        }

        $hits = [];

        foreach ($client->details(array_keys($candidates)) as $entry) {
            $key = (string) ($entry['key'] ?? '');

            if (! isset($candidates[$key]) || ! is_array($entry['ranges'] ?? null)) {
                continue;
            }

            if (! VersionRange::matchesAny($candidates[$key]['version'], $entry['ranges'])) {
                continue;
            }

            $hits[] = [
                'id' => (string) ($entry['id'] ?? ''),
                'key' => $key,
                'name' => $candidates[$key]['name'],
                'version' => $candidates[$key]['version'],
                'titel' => (string) ($entry['title'] ?? ''),
                'cve' => $entry['cve'] ?? null,
                'score' => $entry['score'] ?? null,
                'rating' => (string) ($entry['rating'] ?? ''),
                'gefixt_in' => is_array($entry['patchedVersions'] ?? null)
                    ? implode(', ', $entry['patchedVersions'])
                    : '',
                'patch_verfuegbar' => (bool) ($entry['patched'] ?? false),
            ];
        }

        $this->report($hits);

        return $this->store('ok', count($installed), count($candidates), $hits);
    }

    /**
     * Alles, was hier installiert ist, in der Schreibweise des Feeds.
     *
     * @return array<string, array{version: string, name: string}>
     */
    private function installedSoftware(): array
    {
        require_once ABSPATH . 'wp-admin/includes/plugin.php';

        $software = [
            'c:wordpress' => [
                'version' => (string) get_bloginfo('version'),
                'name' => 'WordPress',
            ],
        ];

        foreach (get_plugins() as $file => $data) {
            $slug = dirname((string) $file);

            if ($slug === '.' || $slug === '') {
                continue;
            }

            $software['p:' . $slug] = [
                'version' => (string) ($data['Version'] ?? ''),
                'name' => (string) ($data['Name'] ?? $slug),
            ];
        }

        foreach (wp_get_themes() as $slug => $theme) {
            $software['t:' . $slug] = [
                'version' => (string) $theme->get('Version'),
                'name' => (string) $theme->get('Name'),
            ];
        }

        return array_filter($software, static fn (array $i): bool => $i['version'] !== '');
    }

    /**
     * @param array<int, array<string, mixed>> $hits
     */
    private function report(array $hits): void
    {
        if ($hits === []) {
            return;
        }

        $seen = get_option(self::SEEN_OPTION, []);
        $seen = is_array($seen) ? $seen : [];
        $fresh = [];

        foreach ($hits as $hit) {
            $fingerprint = $hit['id'] . '|' . $hit['version'];

            if (! in_array($fingerprint, $seen, true)) {
                $fresh[] = $hit;
                $seen[] = $fingerprint;
            }
        }

        // Die Liste nicht unbegrenzt wachsen lassen.
        update_option(self::SEEN_OPTION, array_slice($seen, -500), false);

        foreach ($fresh as $hit) {
            $critical = $this->isCritical($hit);

            EventLog::record(new Event(
                Event::TYPE_VULNERABILITY,
                $critical ? Event::SEVERITY_CRITICAL : Event::SEVERITY_WARN,
                sprintf(
                    /* translators: 1: Name, 2: installierte Fassung, 3: Einstufung */
                    __('Bekannte Lücke in %1$s %2$s (%3$s)', 'rh-hardening'),
                    $hit['name'],
                    $hit['version'],
                    $hit['rating'] !== '' ? $hit['rating'] : __('ohne Einstufung', 'rh-hardening')
                ),
                [
                    'titel' => $hit['titel'],
                    'cve' => $hit['cve'] ?? '',
                    'punktzahl' => $hit['score'] ?? '',
                    'behebung' => $hit['patch_verfuegbar']
                        ? sprintf(
                            /* translators: %s: Fassung mit dem Fix */
                            __('Update auf %s einspielen', 'rh-hardening'),
                            $hit['gefixt_in']
                        )
                        : __('Es gibt noch keinen Fix. Abwägen, ob das Teil vorerst raus kann.', 'rh-hardening'),
                    'quelle' => 'Wordfence Intelligence',
                ]
            ));
        }
    }

    /**
     * @param array<string, mixed> $hit
     */
    private function isCritical(array $hit): bool
    {
        if (strtolower((string) $hit['rating']) === 'critical') {
            return true;
        }

        return is_numeric($hit['score']) && (float) $hit['score'] >= 9.0;
    }

    /**
     * @param array<int, array<string, mixed>> $hits
     * @return array{status: string, geprueft: int, kandidaten: int, treffer: array<int, array<string, mixed>>}
     */
    private function store(string $status, int $checked, int $candidates, array $hits): array
    {
        $result = [
            'status' => $status,
            'geprueft' => $checked,
            'kandidaten' => $candidates,
            'treffer' => $hits,
            'zeitpunkt' => time(),
        ];

        update_option(self::RESULT_OPTION, $result, false);

        return $result;
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
