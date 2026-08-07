<?php

declare(strict_types=1);

namespace RhHardening\Support;

/**
 * Herkunft eines Requests, datenschutzfrei protokolliert.
 *
 * Wir speichern NIE die volle IP und auch keinen Hash davon. Ein Hash wäre ein
 * Pseudonym und damit weiterhin personenbezogen, das würde einen Eintrag in der
 * Datenschutzerklärung des Kunden nötig machen.
 *
 * Gekürzt wird deshalb hart:
 *   IPv4  ->  die letzten ZWEI Bytes auf 0 (89.14.203.7 wird zu 89.14.0.0)
 *   IPv6  ->  alles nach den ersten 48 Bit weg (2001:db8:1234::/48)
 *
 * Zwei von vier genullten Bytes gelten als nicht mehr personenbezogen, das ist
 * der Maßstab, den auch Matomo für seine anonymisierten Logs anlegt. Ein
 * einzelner Besucher lässt sich daraus nicht mehr herausrechnen, ein Netzblock
 * schon, und für "kommen die Treffer alle aus derselben Ecke" reicht das.
 *
 * Preis dieser Entscheidung: gezieltes Sperren einzelner IPs ist damit aus dem
 * Log heraus nicht möglich. Das ist Aufgabe von rh-login, nicht der Chronik.
 */
final class Ip
{
    /**
     * Gekürzte Herkunft des aktuellen Requests, leer wenn nicht ermittelbar.
     */
    public static function current(): string
    {
        $raw = isset($_SERVER['REMOTE_ADDR']) ? (string) wp_unslash($_SERVER['REMOTE_ADDR']) : '';

        return self::truncate($raw);
    }

    /**
     * Kürzt eine IP so weit, dass sie keinen Personenbezug mehr trägt.
     */
    public static function truncate(string $ip): string
    {
        $ip = trim($ip);

        if ($ip === '') {
            return '';
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            $parts = explode('.', $ip);

            return $parts[0] . '.' . $parts[1] . '.0.0';
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
            $packed = @inet_pton($ip);

            if ($packed === false) {
                return '';
            }

            // Erste 48 Bit behalten, den Rest nullen.
            $masked = substr($packed, 0, 6) . str_repeat("\0", 10);
            $result = @inet_ntop($masked);

            return is_string($result) ? $result : '';
        }

        return '';
    }
}
