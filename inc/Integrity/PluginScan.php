<?php

declare(strict_types=1);

namespace RhHardening\Integrity;

/**
 * Vergleicht installierte Plugins mit den Prüfsummen von wordpress.org.
 *
 * Der wichtigste Fund ist nicht die veränderte Datei, sondern die
 * ZUSÄTZLICHE: eine PHP-Datei im Plugin-Ordner, die in der amtlichen Liste
 * nicht vorkommt. Genau so sahen die Hintertüren aus, die im April 2026 über
 * gekaufte Plugins ausgeliefert wurden.
 *
 * Plugins, die es nicht auf wordpress.org gibt (eigene Module, gekaufte
 * Premium-Plugins), liefern eine 404. Das ist kein Fund, sondern schlicht
 * "nicht prüfbar", und wird auch so gezählt. Ein Fehlalarm wäre hier teurer
 * als eine Lücke in der Abdeckung.
 */
final class PluginScan implements StageScanner
{
    private const ENDPOINT = 'https://downloads.wordpress.org/plugin-checksums/%s/%s.json';
    private const CACHE_PREFIX = 'rhhard_pchk_';
    private const CACHE_TTL = 7 * DAY_IN_SECONDS;

    /** Dateien, die Plugins im Betrieb selbst anlegen, sind kein Fund. */
    private const IGNORED_EXTENSIONS = ['log', 'txt', 'json', 'lock', 'cache', 'tmp', 'map'];

    public function run(ScanJob $job, float $deadline): bool
    {
        $plugins = $this->pluginList();
        $total = count($plugins);

        while ($job->cursor < $total) {
            if (microtime(true) >= $deadline) {
                return false;
            }

            $entry = $plugins[$job->cursor];
            $done = $this->scanPlugin($job, $entry['slug'], $entry['version'], $deadline);

            if (! $done) {
                return false;
            }

            $job->cursor++;
            $job->subCursor = 0;
        }

        return true;
    }

    /**
     * @return array<int, array{slug: string, version: string}>
     */
    private function pluginList(): array
    {
        require_once ABSPATH . 'wp-admin/includes/plugin.php';

        $list = [];

        foreach (get_plugins() as $file => $data) {
            $slug = dirname($file);

            // Ein Plugin, das direkt im plugins-Ordner liegt, hat keinen Slug-Ordner.
            if ($slug === '.' || $slug === '') {
                continue;
            }

            $list[] = ['slug' => $slug, 'version' => (string) ($data['Version'] ?? '')];
        }

        return $list;
    }

    private function scanPlugin(ScanJob $job, string $slug, string $version, float $deadline): bool
    {
        if ($version === '') {
            return true;
        }

        $expected = $this->checksums($slug, $version);

        if ($expected === null) {
            // Nicht auf wordpress.org, also keine Vergleichsgrundlage.
            $job->addFinding('plugin_unverifiable', $slug);

            return true;
        }

        $dir = WP_PLUGIN_DIR . '/' . $slug;
        $files = $this->filesIn($dir);
        $total = count($files);

        while ($job->subCursor < $total) {
            if (microtime(true) >= $deadline) {
                return false;
            }

            $relative = $files[$job->subCursor];
            $job->subCursor++;
            $job->filesChecked++;

            $path = $dir . '/' . $relative;

            if (! isset($expected[$relative])) {
                if ($this->isSuspiciousExtra($relative)) {
                    $job->addFinding('plugin_extra', $slug . '/' . $relative);
                }

                continue;
            }

            if (! $this->matches($path, $expected[$relative])) {
                $job->addFinding('plugin_modified', $slug . '/' . $relative);
            }
        }

        return true;
    }

    /**
     * Nur PHP-Dateien, die nicht in der amtlichen Liste stehen, sind ein Fund.
     * Alles andere (Logs, Cache, erzeugte Dateien) entsteht im Betrieb legitim
     * und würde nur Lärm machen.
     */
    private function isSuspiciousExtra(string $relative): bool
    {
        $extension = strtolower(pathinfo($relative, PATHINFO_EXTENSION));

        if (in_array($extension, self::IGNORED_EXTENSIONS, true)) {
            return false;
        }

        return in_array($extension, ['php', 'phtml', 'php5', 'phar'], true);
    }

    /**
     * @param array{md5?: string, sha256?: string|array<int, string>} $entry
     */
    private function matches(string $path, array $entry): bool
    {
        if (! is_readable($path)) {
            return true;
        }

        // Die Liste führt teils mehrere gültige Prüfsummen je Datei (Zeilenenden).
        if (isset($entry['sha256'])) {
            $valid = (array) $entry['sha256'];

            return in_array(hash_file('sha256', $path), $valid, true);
        }

        if (isset($entry['md5'])) {
            $valid = (array) $entry['md5'];

            return in_array(md5_file($path), $valid, true);
        }

        return true;
    }

    /**
     * @return array<string, array<string, mixed>>|null
     */
    private function checksums(string $slug, string $version): ?array
    {
        $key = self::CACHE_PREFIX . md5($slug . '|' . $version);
        $cached = get_transient($key);

        if ($cached === 'none') {
            return null;
        }

        if (is_array($cached)) {
            return $cached;
        }

        $response = wp_remote_get(
            sprintf(self::ENDPOINT, rawurlencode($slug), rawurlencode($version)),
            ['timeout' => 15]
        );

        if (is_wp_error($response) || (int) wp_remote_retrieve_response_code($response) !== 200) {
            // Auch einen Fehlschlag merken, sonst rennt jeder Tick erneut los.
            set_transient($key, 'none', DAY_IN_SECONDS);

            return null;
        }

        $data = json_decode((string) wp_remote_retrieve_body($response), true);

        if (! is_array($data) || ! isset($data['files']) || ! is_array($data['files'])) {
            set_transient($key, 'none', DAY_IN_SECONDS);

            return null;
        }

        set_transient($key, $data['files'], self::CACHE_TTL);

        return $data['files'];
    }

    /**
     * Alle Dateien eines Verzeichnisses, relativ und in stabiler Reihenfolge.
     * Die Reihenfolge muss stabil sein, sonst springt der Cursor zwischen zwei
     * Ticks auf eine andere Datei.
     *
     * @return array<int, string>
     */
    private function filesIn(string $dir): array
    {
        if (! is_dir($dir)) {
            return [];
        }

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::LEAVES_ONLY
        );

        $files = [];
        $prefix = strlen($dir) + 1;

        foreach ($iterator as $file) {
            if ($file->isFile()) {
                $files[] = substr($file->getPathname(), $prefix);
            }
        }

        sort($files);

        return $files;
    }
}
