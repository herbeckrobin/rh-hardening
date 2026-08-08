<?php

declare(strict_types=1);

namespace RhHardening\Radar;

use RhHardening\Admin\HardeningGroup;
use RhHardening\Support\Env;
use RhHardening\Support\Log;

/**
 * Holt die Schwachstellendaten vom Verteiler.
 *
 * Zwei Stufen, weil der Rohbestand über 20 MB gross ist und json_decode
 * darauf ein Vielfaches an Arbeitsspeicher braucht:
 *
 *   1. Das Verzeichnis nennt nur, welcher Slug je betroffen war und bis zu
 *      welcher Fassung. Rund 540 KB. Damit entscheidet die Website lokal.
 *   2. Nur für die verbliebenen Kandidaten werden die Einzelheiten geholt.
 *
 * Bis zur ersten Nachfrage verlässt keine Information über die Website den
 * Server. Gibt es einen Kandidaten, geht dessen Slug an den Verteiler, und
 * das ist Robins eigener, kein fremder Dienst.
 */
final class FeedClient
{
    /**
     * Feste Adresse. Bewusst kein Eingabefeld: die Adresse gehört zum Modul und
     * nicht zur Pflege einer Kundenseite. Wer sie doch umbiegen muss (eigene
     * Instanz, Test), setzt die Konstante RH_HARDENING_FEED_URL in der
     * wp-config.php, so wie bei RH_SMTP_PASS in rh-smtp.
     */
    private const DEFAULT_ENDPOINT = 'https://robinherbeck.com/api/security-feed';

    /**
     * Erkennungszeichen der Suite. Ausdrücklich KEIN Geheimnis, es steht in
     * jedem Release-ZIP. Es hält Bots vom Verteiler fern und macht echte
     * Anfragen zuordenbar, mehr soll es nicht leisten.
     */
    private const MODULE_TOKEN = 'rhbp-suite-feed-2026';

    private const INDEX_TRANSIENT = 'rhhard_feed_index';
    private const INDEX_TTL = 12 * HOUR_IN_SECONDS;

    /** Nicht mehr Slugs auf einmal nachfragen, der Verteiler deckelt bei 200. */
    private const CHUNK = 100;

    /**
     * Das Verzeichnis als Text, eine Zeile je Slug: "p:mein-plugin 1.2.3".
     *
     * Bewusst NICHT als Array: dekodiert kostet das Verzeichnis mit seinen
     * 18.000 Einträgen rund 25 MB, gemessen. Bei einem Hoster mit 64 MB Grenze
     * und WordPress-Grundlast ist damit Schluss, und das Radar fiele
     * stillschweigend aus. Als Text sind es ein paar hundert Kilobyte, und die
     * gut zwanzig eigenen Slugs sucht man einzeln darin.
     *
     * @return string|null null, wenn nichts zu holen war
     */
    public function index(bool $force = false): ?string
    {
        if (! $force) {
            $cached = get_transient(self::INDEX_TRANSIENT);

            if (is_string($cached)) {
                return $cached;
            }
        }

        $url = $this->endpoint();

        if ($url === '') {
            return null;
        }

        // Das Verzeichnis liegt bei rund einem halben Megabyte. Ist nicht
        // einmal das Doppelte davon frei, gar nicht erst anfangen.
        if (! Env::hasHeadroom(4 * MB_IN_BYTES)) {
            Log::note('Radar übersprungen, zu wenig Arbeitsspeicher frei', [
                'grenze' => (string) ini_get('memory_limit'),
            ]);

            return null;
        }

        $response = wp_remote_get($url, $this->args());

        if (is_wp_error($response)) {
            Log::note('Verzeichnis nicht abrufbar', ['grund' => $response->get_error_message()]);

            return null;
        }

        $code = (int) wp_remote_retrieve_response_code($response);

        if ($code !== 200) {
            Log::note('Verzeichnis nicht abrufbar', ['status' => (string) $code]);

            return null;
        }

        $data = json_decode((string) wp_remote_retrieve_body($response), true);

        if (! is_array($data) || ! isset($data['index']) || ! is_string($data['index'])) {
            Log::note('Verzeichnis in unerwartetem Format');

            return null;
        }

        set_transient(self::INDEX_TRANSIENT, $data['index'], self::INDEX_TTL);

        return $data['index'];
    }

    /**
     * Höchste je betroffene Fassung für einen Slug, ohne das ganze Verzeichnis
     * in den Speicher zu holen. Ein strpos über ein paar hundert Kilobyte
     * kostet nichts, zwanzigmal aufgerufen erst recht nicht.
     */
    public static function highestAffected(string $index, string $key): ?string
    {
        $needle = "\n" . $key . ' ';
        $position = str_starts_with($index, $key . ' ') ? 0 : strpos($index, $needle);

        if ($position === false) {
            return null;
        }

        $start = $position === 0 ? strlen($key) + 1 : $position + strlen($needle);
        $end = strpos($index, "\n", $start);
        $value = $end === false ? substr($index, $start) : substr($index, $start, $end - $start);

        return trim($value);
    }

    /**
     * Einzelheiten zu bestimmten Slugs.
     *
     * @param array<int, string> $keys
     * @return array<int, array<string, mixed>>
     */
    public function details(array $keys): array
    {
        $url = $this->endpoint();

        if ($url === '' || $keys === []) {
            return [];
        }

        $found = [];

        foreach (array_chunk(array_values($keys), self::CHUNK) as $chunk) {
            $response = wp_remote_get(
                add_query_arg('slugs', implode(',', $chunk), $url),
                $this->args()
            );

            if (is_wp_error($response)) {
                Log::note('Einzelheiten nicht abrufbar', ['grund' => $response->get_error_message()]);

                continue;
            }

            if ((int) wp_remote_retrieve_response_code($response) !== 200) {
                Log::note('Einzelheiten nicht abrufbar', [
                    'status' => (string) wp_remote_retrieve_response_code($response),
                ]);

                continue;
            }

            $data = json_decode((string) wp_remote_retrieve_body($response), true);

            if (is_array($data) && isset($data['vulnerabilities']) && is_array($data['vulnerabilities'])) {
                $found = array_merge($found, $data['vulnerabilities']);
            }
        }

        return $found;
    }

    /**
     * Die Website nennt dem Verteiler ihre Domain. Damit lässt sich dort ein
     * Limit je Website statt je IP führen und im Ernstfall eine einzelne
     * sperren, ohne dass hier etwas eingestellt werden muss.
     *
     * @return array<string, mixed>
     */
    private function args(): array
    {
        $host = wp_parse_url(home_url('/'), PHP_URL_HOST);

        return [
            'timeout' => 45,
            'headers' => [
                'X-RH-Token' => self::MODULE_TOKEN,
                'X-RH-Site' => is_string($host) ? $host : '',
            ],
        ];
    }

    public function endpoint(): string
    {
        $url = defined('RH_HARDENING_FEED_URL') && is_string(RH_HARDENING_FEED_URL)
            ? RH_HARDENING_FEED_URL
            : self::DEFAULT_ENDPOINT;

        return esc_url_raw($url);
    }

    /**
     * Das Radar läuft, solange es nicht ausgeschaltet ist.
     */
    public function isEnabled(): bool
    {
        return (bool) rhbp_setting(HardeningGroup::GROUP_ID, HardeningGroup::FIELD_RADAR, true);
    }

    public function forget(): void
    {
        delete_transient(self::INDEX_TRANSIENT);
    }
}
