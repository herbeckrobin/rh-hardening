<?php

declare(strict_types=1);

namespace RhHardening\Support;

use RhBlueprint\Core\Support\Bytes;

/**
 * Was diese Umgebung kann und was nicht.
 *
 * Auf günstigen Hostern sind Funktionen per `disable_functions` gesperrt. Ein
 * vorangestelltes @ hilft dabei nicht: es unterdrückt Warnungen, aber nicht den
 * Fatal Error "Call to undefined function". Genau daran ist rh-sync zweimal auf
 * echten Kundenseiten gestorben, einmal an `disk_free_space` und einmal an
 * `set_time_limit`.
 *
 * Deshalb fragt jede Stelle, die eine solche Funktion braucht, vorher hier
 * nach. Fehlt sie, fällt die betroffene Prüfung aus und sagt das, statt die
 * Seite mitzureissen.
 */
final class Env
{
    /**
     * Funktionen, ohne die einzelne Prüfungen nicht arbeiten können.
     *
     * @var array<int, string>
     */
    private const NEEDED = [
        'glob',
        'file_put_contents',
        'file_get_contents',
        'unlink',
        'md5_file',
        'hash_file',
        'inet_pton',
        'inet_ntop',
    ];

    /** @var array<string, bool> */
    private static array $cache = [];

    public static function has(string $function): bool
    {
        return self::$cache[$function] ??= function_exists($function);
    }

    /**
     * Alle gebrauchten Funktionen, die hier fehlen.
     *
     * @return array<int, string>
     */
    public static function missing(): array
    {
        return array_values(array_filter(
            self::NEEDED,
            static fn (string $f): bool => ! self::has($f)
        ));
    }

    /**
     * Speichergrenze in Bytes, 0 heisst unbegrenzt.
     */
    public static function memoryLimit(): int
    {
        return Bytes::memoryLimit();
    }

    /**
     * Bleibt für einen Arbeitsschritt genug Speicher übrig?
     *
     * Lieber vorher aussteigen und das sagen, als mitten im Lauf vom Speicher
     * erschlagen zu werden. Ein Absturz hinterlässt keine Spur, ein Hinweis schon.
     */
    public static function hasHeadroom(int $neededBytes): bool
    {
        return Bytes::hasHeadroom($neededBytes);
    }

    /**
     * Läuft WP-Cron überhaupt? Ohne ihn rührt sich weder Prüflauf noch Radar.
     */
    public static function cronDisabled(): bool
    {
        return defined('DISABLE_WP_CRON') && DISABLE_WP_CRON;
    }
}
