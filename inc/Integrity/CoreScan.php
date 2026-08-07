<?php

declare(strict_types=1);

namespace RhHardening\Integrity;

/**
 * Vergleicht die Dateien des WordPress-Kerns mit den amtlichen Prüfsummen.
 *
 * Die Liste kommt von api.wordpress.org und ist die einzige Quelle, die sagen
 * kann, wie eine Kern-Datei auszusehen hat. Wer eine Hintertür in eine
 * Kern-Datei schreibt, fällt hier auf, egal wie gut sie versteckt ist.
 *
 * wp-content bleibt bewusst aussen vor: Themes und Plugins werden dort legitim
 * geändert und gelöscht. WP-CLI macht bei `core verify-checksums` dieselbe
 * Ausnahme.
 */
final class CoreScan implements StageScanner
{
    private const CACHE_KEY = 'rhhard_core_checksums';
    private const CACHE_TTL = 12 * HOUR_IN_SECONDS;

    public function run(ScanJob $job, float $deadline): bool
    {
        $checksums = $this->checksums();

        if ($checksums === null) {
            // Keine Liste, keine Aussage. Lieber nichts sagen als falsch melden.
            $job->addFinding('core_unavailable', __('Prüfsummen des Kerns nicht abrufbar', 'rh-hardening'));

            return true;
        }

        $files = array_keys($checksums);
        $total = count($files);

        while ($job->cursor < $total) {
            if (microtime(true) >= $deadline) {
                return false;
            }

            $relative = $files[$job->cursor];
            $job->cursor++;

            if ($this->isExcluded($relative)) {
                continue;
            }

            $path = ABSPATH . $relative;
            $job->filesChecked++;

            if (! file_exists($path)) {
                $job->addFinding('core_missing', $relative);
                continue;
            }

            if (! is_readable($path)) {
                continue;
            }

            if (md5_file($path) !== $checksums[$relative]) {
                $job->addFinding('core_modified', $relative);
            }
        }

        return true;
    }

    /**
     * @return array<string, string>|null
     */
    private function checksums(): ?array
    {
        $cached = get_transient(self::CACHE_KEY);

        if (is_array($cached)) {
            return $cached;
        }

        require_once ABSPATH . 'wp-admin/includes/update.php';

        $version = get_bloginfo('version');
        $locale = get_locale();
        $checksums = get_core_checksums($version, $locale);

        // Manche Sprachfassungen liefern nichts, dann auf Englisch ausweichen.
        if (! is_array($checksums) && $locale !== 'en_US') {
            $checksums = get_core_checksums($version, 'en_US');
        }

        if (! is_array($checksums) || $checksums === []) {
            return null;
        }

        set_transient(self::CACHE_KEY, $checksums, self::CACHE_TTL);

        return $checksums;
    }

    private function isExcluded(string $relative): bool
    {
        return str_starts_with($relative, 'wp-content/');
    }
}
