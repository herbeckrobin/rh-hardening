<?php

declare(strict_types=1);

namespace RhHardening\Radar;

/**
 * Fragt das Plugin-Verzeichnis von wordpress.org nach einem Plugin.
 *
 * Bewusst NICHT über plugins_api(): dort hängen sich Update-Prüfer fremder
 * Plugins ein und beantworten die Frage selbst. Gemessen an dieser
 * Installation liefert plugins_api() auch für rh-hardening ein Ergebnis,
 * obwohl das Modul nie auf wordpress.org war. Für die Frage "kennt das
 * Verzeichnis dieses Plugin überhaupt" ist die Funktion damit wertlos.
 */
final class PluginDirectory
{
    private const ENDPOINT = 'https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request%5Bslug%5D=';
    private const CACHE_PREFIX = 'rhhard_dir_';
    private const CACHE_TTL = 12 * HOUR_IN_SECONDS;

    public const STATE_LISTED = 'listed';
    public const STATE_MISSING = 'missing';
    public const STATE_UNKNOWN = 'unknown';

    /**
     * @return array{state: string, version?: string, updated?: string, installs?: int}
     */
    public function lookup(string $slug): array
    {
        $key = self::CACHE_PREFIX . md5($slug);
        $cached = get_transient($key);

        if (is_array($cached)) {
            return $cached;
        }

        $response = wp_remote_get(self::ENDPOINT . rawurlencode($slug), ['timeout' => 15]);

        if (is_wp_error($response)) {
            // Netzproblem ist keine Aussage über das Plugin.
            return ['state' => self::STATE_UNKNOWN];
        }

        $code = (int) wp_remote_retrieve_response_code($response);
        $data = json_decode((string) wp_remote_retrieve_body($response), true);

        if ($code === 404 || (is_array($data) && isset($data['error']))) {
            $result = ['state' => self::STATE_MISSING];
        } elseif ($code === 200 && is_array($data) && isset($data['version'])) {
            $result = [
                'state' => self::STATE_LISTED,
                'version' => (string) $data['version'],
                'updated' => (string) ($data['last_updated'] ?? ''),
                'installs' => (int) ($data['active_installs'] ?? 0),
            ];
        } else {
            return ['state' => self::STATE_UNKNOWN];
        }

        set_transient($key, $result, self::CACHE_TTL);

        return $result;
    }
}
