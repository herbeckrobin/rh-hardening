<?php

declare(strict_types=1);

namespace RhHardening\Integrity;

/**
 * Sucht ausführbaren Code im Upload-Verzeichnis.
 *
 * Dort gehört keine einzige PHP-Datei hin. Findet sich eine, ist entweder ein
 * Plugin schlecht gebaut oder es liegt eine Webshell da. Beides will man wissen.
 *
 * Bewusst kein Schadcode-Suchlauf über alle Dateien: das ist ein Wettrennen
 * gegen Firmen mit eigenen Forschungsteams, das hier niemand gewinnt. Die
 * Dateiendung reicht für den Fall, um den es geht, und macht keinen Lärm.
 */
final class UploadScan implements StageScanner
{
    /** @var array<int, string> */
    private const EXECUTABLE = ['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'php8', 'phar', 'pht', 'phps'];

    /** Notbremse bei sehr grossen Mediatheken. */
    private const MAX_FILES = 200000;

    public function run(ScanJob $job, float $deadline): bool
    {
        $dir = $this->uploadsDir();

        if ($dir === '') {
            return true;
        }

        $index = 0;

        foreach ($this->walk($dir) as $path) {
            $index++;

            // Bis zur Stelle vorspulen, an der der letzte Tick aufgehört hat.
            if ($index <= $job->cursor) {
                continue;
            }

            if ($index > self::MAX_FILES) {
                return true;
            }

            $job->cursor = $index;
            $job->filesChecked++;

            if ($this->isExecutable($path)) {
                $job->addFinding('upload_executable', $this->shorten($path, $dir));
            }

            if (microtime(true) >= $deadline) {
                return false;
            }
        }

        return true;
    }

    /**
     * Trifft auch getarnte Doppelendungen wie schaden.php.jpg, die über eine
     * schlecht konfigurierte Einbindung trotzdem ausgeführt werden können.
     */
    private function isExecutable(string $path): bool
    {
        $name = strtolower(basename($path));

        foreach (explode('.', $name) as $index => $part) {
            if ($index === 0) {
                continue;
            }

            if (in_array($part, self::EXECUTABLE, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return \Generator<string>
     */
    private function walk(string $dir): \Generator
    {
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::LEAVES_ONLY
        );

        foreach ($iterator as $file) {
            if ($file->isFile()) {
                yield $file->getPathname();
            }
        }
    }

    private function uploadsDir(): string
    {
        $upload = wp_get_upload_dir();

        if (! empty($upload['error']) || empty($upload['basedir'])) {
            return '';
        }

        $dir = (string) $upload['basedir'];

        return is_dir($dir) ? $dir : '';
    }

    private function shorten(string $path, string $dir): string
    {
        return ltrim(str_replace($dir, '', $path), '/\\');
    }
}
