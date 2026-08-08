<?php

declare(strict_types=1);

namespace RhHardening\Prevention;

use RhHardening\Admin\HardeningGroup;
use RhHardening\Support\Env;
use RhHardening\Support\Loopback;
use RhHardening\Support\Log;

/**
 * Sperrt die Ausführung von PHP im Upload-Verzeichnis.
 *
 * Der Standardweg einer Übernahme endet damit, dass eine PHP-Datei im
 * Upload-Verzeichnis liegt und direkt aufgerufen wird. Liegt sie da, ist es
 * ohnehin zu spät, aber ohne Ausführungsrecht ist sie eine tote Datei.
 *
 * Wir schreiben nur eine .htaccess (Apache und LiteSpeed). Nginx liest die
 * nicht, dort muss die Regel in die Server-Konfiguration, deshalb prüft das
 * Modul zusätzlich mit einem echten Aufruf nach, ob die Sperre wirklich greift,
 * statt sich auf die geschriebene Datei zu verlassen.
 */
final class Uploads
{
    private const MARKER = 'rh-hardening';
    private const PROBE_PREFIX = 'rh-hardening-probe-';
    private const PROBE_TOKEN = 'rh-hardening-probe-ok';
    private const STATUS_OPTION = 'rhhard_uploads_status';

    /**
     * @var array<int, string>
     */
    private const RULES = [
        '<Files *.php>',
        '  <IfModule mod_authz_core.c>',
        '    Require all denied',
        '  </IfModule>',
        '  <IfModule !mod_authz_core.c>',
        '    Order allow,deny',
        '    Deny from all',
        '  </IfModule>',
        '</Files>',
    ];

    public function boot(): void
    {
        if (! (bool) rhbp_setting(HardeningGroup::GROUP_ID, HardeningGroup::FIELD_UPLOADS_NO_PHP, true)) {
            return;
        }

        add_action('rh-hardening/ensure_files', [$this, 'writeRules']);
    }

    /**
     * Schreibt die Regeln in wp-content/uploads/.htaccess.
     * Idempotent, WordPress verwaltet den markierten Block selbst.
     */
    public function writeRules(): bool
    {
        $dir = $this->uploadsDir();

        if ($dir === '') {
            return false;
        }

        $file = trailingslashit($dir) . '.htaccess';

        if (! is_writable($dir) && ! file_exists($file)) {
            Log::incident(
                \RhHardening\Log\Event::TYPE_DOCROOT_FINDING,
                __('Die Sperre für das Upload-Verzeichnis konnte nicht geschrieben werden, das Verzeichnis ist nicht beschreibbar.', 'rh-hardening'),
                ['verzeichnis' => $dir]
            );

            return false;
        }

        require_once ABSPATH . 'wp-admin/includes/misc.php';

        return (bool) insert_with_markers($file, self::MARKER, self::RULES);
    }

    /**
     * Prüft mit einem echten Aufruf, ob PHP im Upload-Verzeichnis läuft.
     * Legt dafür kurz eine Sonde an und entfernt sie wieder.
     *
     * @return array{status: string, message: string}
     */
    public function probe(): array
    {
        $dir = $this->uploadsDir();
        $url = $this->uploadsUrl();

        if ($dir === '' || $url === '') {
            return $this->status('unknown', __('Upload-Verzeichnis nicht ermittelbar.', 'rh-hardening'));
        }

        if (! Env::has('file_put_contents') || ! Env::has('unlink')) {
            Log::note('Sonde nicht möglich, Dateifunktionen gesperrt');

            return $this->status('unknown', __('Die Prüfung ist auf diesem Server nicht möglich, weil Dateifunktionen gesperrt sind.', 'rh-hardening'));
        }

        // Reste früherer Läufe wegräumen, bevor eine neue Sonde entsteht.
        $this->removeStaleProbes($dir);

        // Zufälliger Name: eine erratbare Datei im öffentlichen Verzeichnis
        // wäre genau das, wovor dieses Modul warnt.
        $name = self::PROBE_PREFIX . bin2hex(random_bytes(8)) . '.php';
        $path = trailingslashit($dir) . $name;
        $written = @file_put_contents($path, "<?php echo '" . self::PROBE_TOKEN . "';");

        if ($written === false) {
            Log::note('Sonde nicht schreibbar', ['verzeichnis' => $dir]);

            return $this->status('unknown', __('Sonde konnte nicht geschrieben werden, Verzeichnis ist nicht beschreibbar.', 'rh-hardening'));
        }

        try {
            $result = Loopback::request(trailingslashit($url) . $name);
            $response = $result['response'];

            if (is_wp_error($response)) {
                Log::note('Sonde nicht abrufbar', ['grund' => $response->get_error_message()]);

                return $this->status('unknown', sprintf(
                    /* translators: %s: Fehlermeldung */
                    __('Sonde nicht abrufbar: %s', 'rh-hardening'),
                    $response->get_error_message()
                ));
            }

            $hint = $result['unverified']
                ? ' ' . __('(Das Zertifikat der Website war dabei nicht prüfbar.)', 'rh-hardening')
                : '';

            $code = (int) wp_remote_retrieve_response_code($response);
            $body = (string) wp_remote_retrieve_body($response);

            if ($code >= 400) {
                return $this->status('blocked', sprintf(
                    /* translators: 1: HTTP-Statuscode, 2: Hinweis zum Zertifikat */
                    __('Sperre greift, der Aufruf wird mit %1$d abgewiesen.%2$s', 'rh-hardening'),
                    $code,
                    $hint
                ));
            }

            if (str_contains($body, self::PROBE_TOKEN)) {
                return $this->status('executing', __('PHP wird im Upload-Verzeichnis ausgeführt. Auf Nginx muss die Regel in die Server-Konfiguration, eine .htaccess reicht dort nicht.', 'rh-hardening') . $hint);
            }

            return $this->status('blocked', __('Sperre greift, die Datei wird nicht als PHP ausgeführt.', 'rh-hardening') . $hint);
        } finally {
            // Auch bei einem Fehler oder Abbruch: die Sonde muss weg.
            @unlink($path);
        }
    }

    /**
     * Entfernt Sonden, die ein abgebrochener Lauf liegen gelassen hat.
     *
     * Stirbt der Prozess zwischen Schreiben und Aufräumen (Zeitlimit, Speicher,
     * abgeschossener Worker), bliebe sonst eine ausführbare Datei im
     * öffentlichen Verzeichnis stehen.
     */
    private function removeStaleProbes(string $dir): void
    {
        if (! Env::has('glob') || ! Env::has('unlink')) {
            return;
        }

        $matches = glob(trailingslashit($dir) . self::PROBE_PREFIX . '*.php', GLOB_NOSORT);

        if ($matches === false) {
            return;
        }

        foreach ($matches as $stale) {
            @unlink($stale);
            Log::note('Übrig gebliebene Sonde entfernt', ['datei' => basename($stale)]);
        }
    }

    /**
     * Gehört diese Datei zu einer Sonde? Der eigene Prüflauf soll sie nicht als
     * Fund melden, sonst zeigt sich das Modul selbst an.
     */
    public static function isProbeFile(string $filename): bool
    {
        return str_starts_with(basename($filename), self::PROBE_PREFIX);
    }

    /**
     * @return array{status: string, message: string, checked: int}|null
     */
    public static function lastStatus(): ?array
    {
        $stored = get_option(self::STATUS_OPTION, null);

        return is_array($stored) ? $stored : null;
    }

    /**
     * @return array{status: string, message: string}
     */
    private function status(string $status, string $message): array
    {
        update_option(
            self::STATUS_OPTION,
            ['status' => $status, 'message' => $message, 'checked' => time()],
            false
        );

        return ['status' => $status, 'message' => $message];
    }

    private function uploadsDir(): string
    {
        $upload = wp_get_upload_dir();

        return empty($upload['error']) && ! empty($upload['basedir']) ? (string) $upload['basedir'] : '';
    }

    private function uploadsUrl(): string
    {
        $upload = wp_get_upload_dir();

        return empty($upload['error']) && ! empty($upload['baseurl']) ? (string) $upload['baseurl'] : '';
    }

}
