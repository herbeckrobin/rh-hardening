<?php

declare(strict_types=1);

namespace RhHardening\Shield;

/**
 * Vergleicht REST-Routen so, wie WordPress sie auflöst.
 *
 * WordPress matcht Routen ohne Rücksicht auf Groß- und Kleinschreibung
 * (class-wp-rest-server.php, preg_match mit Flag i). Ein Vergleich, der das
 * nicht tut, lässt /Batch/v1 durch, während /batch/v1 geblockt wird. Genau so
 * kam die wp2shell-Welle vom 20.09.2026 an der Sperre vorbei.
 *
 * Deshalb wird jede Route vor dem Vergleich in zwei Fassungen gebracht:
 *
 *   roh        klein geschrieben, doppelte Slashes zusammengefasst
 *   dekodiert  dasselbe, zusätzlich URL-dekodiert (auch mehrfach kodiert)
 *
 * Eine Sperre greift, wenn EINE der Fassungen passt. Eine Freigabe gilt nur,
 * wenn ALLE Fassungen passen. So kann die Normalisierung nie aus einer
 * gesperrten Route eine freigegebene machen.
 *
 * Dieselbe Rechnung steckt als Funktion in template.php, weil der Schutzwall
 * läuft, bevor dieses Plugin geladen ist. Der Test prüft, dass beide Seiten
 * dasselbe liefern.
 */
final class RouteMatch
{
    /** Mehr Kodier-Schichten nimmt kein Server auseinander. */
    private const MAX_DECODE_ROUNDS = 3;

    public static function normalize(string $route, bool $decode): string
    {
        if ($decode) {
            for ($round = 0; $round < self::MAX_DECODE_ROUNDS; $round++) {
                $decoded = rawurldecode($route);

                if ($decoded === $route) {
                    break;
                }

                $route = $decoded;
            }
        }

        $route = strtolower($route);

        return (string) preg_replace('#/+#', '/', '/' . $route);
    }

    /**
     * @return array<int, string>
     */
    public static function variants(string $route): array
    {
        return array_values(array_unique([
            self::normalize($route, false),
            self::normalize($route, true),
        ]));
    }

    /**
     * Sperr-Vergleich: trifft, sobald eine Fassung mit dem Präfix beginnt.
     */
    public static function startsWith(string $route, string $prefix): bool
    {
        $prefix = trim($prefix, '/');

        if ($prefix === '') {
            return false;
        }

        $prefix = self::normalize($prefix, true);

        foreach (self::variants($route) as $variant) {
            if (str_starts_with($variant, $prefix)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Freigabe-Vergleich: jede Fassung muss unter einem der Präfixe liegen.
     *
     * @param array<int, string> $prefixes
     */
    public static function coveredBy(string $route, array $prefixes): bool
    {
        $normalized = [];

        foreach ($prefixes as $prefix) {
            $prefix = trim((string) $prefix, '/');

            if ($prefix !== '') {
                $normalized[] = self::normalize($prefix, true);
            }
        }

        foreach (self::variants($route) as $variant) {
            $covered = false;

            foreach ($normalized as $prefix) {
                if (str_starts_with($variant, $prefix)) {
                    $covered = true;
                    break;
                }
            }

            if (! $covered) {
                return false;
            }
        }

        return true;
    }
}
