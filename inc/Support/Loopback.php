<?php

declare(strict_types=1);

namespace RhHardening\Support;

use WP_Error;

/**
 * Ruft die eigene Website auf, um einen Zustand zu messen statt ihn anzunehmen.
 *
 * Zwei Prüfungen brauchen das: die Sonde im Upload-Verzeichnis und die Frage,
 * ob ein Fund im Wurzelverzeichnis von außen abrufbar ist. Deshalb steht es
 * hier einmal und nicht zweimal.
 *
 * Zum Zertifikat: der erste Versuch prüft es. Schlägt er daran fehl, folgt ein
 * zweiter ohne Prüfung, und das Ergebnis wird als solches gekennzeichnet. Der
 * Grund ist praktisch: hinter einem Proxy, in einer lokalen Umgebung oder bei
 * einer Zwischenstellung mit eigenem Zertifikat wäre die Prüfung sonst dauerhaft
 * ergebnislos, und "weiß ich nicht" ist die schlechteste aller Antworten auf
 * die Frage, ob im Upload-Verzeichnis PHP läuft. Das Ziel ist die eigene
 * Domain, ein Angreifer in der Mitte gewinnt hier nichts.
 */
final class Loopback
{
    /**
     * @param array<string, mixed> $args
     * @return array{response: array<mixed>|WP_Error, unverified: bool}
     */
    public static function request(string $url, string $method = 'GET', array $args = []): array
    {
        $args = array_merge([
            'timeout' => 10,
            'redirection' => 0,
            'sslverify' => true,
        ], $args);

        $response = self::dispatch($url, $method, $args);

        if (! self::isCertificateProblem($response)) {
            return ['response' => $response, 'unverified' => false];
        }

        $args['sslverify'] = false;

        return ['response' => self::dispatch($url, $method, $args), 'unverified' => true];
    }

    /**
     * @param array<string, mixed> $args
     * @return array<mixed>|WP_Error
     */
    private static function dispatch(string $url, string $method, array $args)
    {
        return $method === 'HEAD'
            ? wp_remote_head($url, $args)
            : wp_remote_get($url, $args);
    }

    /**
     * @param array<mixed>|WP_Error $response
     */
    private static function isCertificateProblem($response): bool
    {
        if (! is_wp_error($response)) {
            return false;
        }

        $message = strtolower($response->get_error_message());

        foreach (['certificate', 'ssl', 'zertifikat'] as $needle) {
            if (str_contains($message, $needle)) {
                return true;
            }
        }

        return false;
    }
}
