<?php

declare(strict_types=1);

namespace RhHardening\Radar;

/**
 * Prüft, ob eine installierte Fassung in einem als verwundbar gemeldeten
 * Bereich liegt.
 *
 * Die Bereiche kommen aus dem Feed in dieser Form, am echten Datensatz geprüft:
 *
 *   from_version "*"    keine Untergrenze, betrifft alles bis oben
 *   from_inclusive      Grenze selbst betroffen oder nicht
 *   to_version "1.37"   Obergrenze
 *   to_inclusive        dito
 *
 * Verglichen wird mit version_compare, das ist derselbe Massstab, den
 * WordPress selbst für Plugin-Versionen anlegt.
 */
final class VersionRange
{
    /**
     * Liegt die Fassung in mindestens einem der Bereiche?
     *
     * @param array<int, array<string, mixed>> $ranges
     */
    public static function matchesAny(string $version, array $ranges): bool
    {
        foreach ($ranges as $range) {
            if (is_array($range) && self::matches($version, $range)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param array<string, mixed> $range
     */
    public static function matches(string $version, array $range): bool
    {
        $version = self::normalize($version);

        if ($version === '') {
            return false;
        }

        $from = self::normalize((string) ($range['from_version'] ?? '*'));
        $to = self::normalize((string) ($range['to_version'] ?? '*'));

        if ($from !== '' && $from !== '*') {
            $operator = ! empty($range['from_inclusive']) ? '>=' : '>';

            if (! version_compare($version, $from, $operator)) {
                return false;
            }
        }

        if ($to !== '' && $to !== '*') {
            $operator = ! empty($range['to_inclusive']) ? '<=' : '<';

            if (! version_compare($version, $to, $operator)) {
                return false;
            }
        }

        // Ein Bereich ganz ohne Grenzen betrifft jede Fassung.
        return true;
    }

    /**
     * Kann die Fassung überhaupt betroffen sein, gemessen an der höchsten je
     * gemeldeten Fassung aus dem Verzeichnis? Das ist die billige Vorprüfung,
     * die den Abruf der Einzelheiten in den allermeisten Fällen erspart.
     */
    public static function couldBeAffected(string $version, string $highestAffected): bool
    {
        $highestAffected = self::normalize($highestAffected);

        if ($highestAffected === '*' || $highestAffected === '') {
            return true;
        }

        $version = self::normalize($version);

        if ($version === '') {
            return true;
        }

        return version_compare($version, $highestAffected, '<=');
    }

    /**
     * WordPress-Versionen tragen manchmal Beiwerk, das version_compare
     * durcheinanderbringt. Alles außer Ziffern, Punkten und den üblichen
     * Trennern fliegt raus.
     */
    private static function normalize(string $version): string
    {
        $version = trim($version);

        if ($version === '*') {
            return '*';
        }

        $version = preg_replace('/[^0-9a-zA-Z.\-+]/', '', $version) ?? '';

        return trim($version);
    }
}
