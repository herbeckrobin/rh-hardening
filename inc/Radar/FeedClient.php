<?php

declare(strict_types=1);

namespace RhHardening\Radar;

use RhHardening\Admin\HardeningGroup;

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

    private const INDEX_TRANSIENT = 'rhhard_feed_index';
    private const INDEX_TTL = 12 * HOUR_IN_SECONDS;

    /** Nicht mehr Slugs auf einmal nachfragen, der Verteiler deckelt bei 200. */
    private const CHUNK = 100;

    /**
     * Das Verzeichnis: Slug-Schlüssel zur höchsten je betroffenen Fassung.
     *
     * @return array<string, string>|null null, wenn der Verteiler nicht erreichbar ist
     */
    public function index(bool $force = false): ?array
    {
        if (! $force) {
            $cached = get_transient(self::INDEX_TRANSIENT);

            if (is_array($cached)) {
                return $cached;
            }
        }

        $url = $this->endpoint();

        if ($url === '') {
            return null;
        }

        $response = wp_remote_get($url, ['timeout' => 45]);

        if (is_wp_error($response) || (int) wp_remote_retrieve_response_code($response) !== 200) {
            return null;
        }

        $data = json_decode((string) wp_remote_retrieve_body($response), true);

        if (! is_array($data) || ! isset($data['index']) || ! is_array($data['index'])) {
            return null;
        }

        set_transient(self::INDEX_TRANSIENT, $data['index'], self::INDEX_TTL);

        return $data['index'];
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
                ['timeout' => 45]
            );

            if (is_wp_error($response) || (int) wp_remote_retrieve_response_code($response) !== 200) {
                continue;
            }

            $data = json_decode((string) wp_remote_retrieve_body($response), true);

            if (is_array($data) && isset($data['vulnerabilities']) && is_array($data['vulnerabilities'])) {
                $found = array_merge($found, $data['vulnerabilities']);
            }
        }

        return $found;
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
