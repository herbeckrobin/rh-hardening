<?php

declare(strict_types=1);

namespace RhHardening\Support;

use RhHardening\Log\Event;
use RhHardening\Log\EventLog;

/**
 * Was schiefgeht, muss eine Spur hinterlassen.
 *
 * Vor diesem Helfer verschwand jeder Fehlschlag: ein nicht ausrollbarer
 * Schutzwall, ein nicht erreichbarer Feed, eine nicht versendete Mail. Das
 * Modul sah dann von aussen aus wie eines, das läuft, und tat nichts. Bei einem
 * Sicherheitsmodul ist genau das der gefährlichste Zustand.
 *
 * Zwei Wege, bewusst getrennt:
 *   note()     nur ins PHP-Fehlerprotokoll, für Betriebsfehler
 *   incident() zusätzlich in die Chronik, wenn der Schutz selbst ausfällt
 *
 * Es werden keine personenbezogenen Daten geschrieben. Was in die Chronik geht,
 * durchläuft dieselben Regeln wie jeder andere Eintrag.
 */
final class Log
{
    private const PREFIX = 'rh-hardening: ';

    /** Damit ein wiederkehrender Fehler das Protokoll nicht flutet. */
    private const THROTTLE_PREFIX = 'rhhard_log_';
    private const THROTTLE_TTL = HOUR_IN_SECONDS;

    /**
     * @param array<string, scalar|null> $context
     */
    public static function note(string $message, array $context = []): void
    {
        self::write($message, $context);
    }

    /**
     * Der Schutz selbst fällt aus. Das gehört ins Protokoll UND in die Chronik,
     * damit es jemand sieht, ohne in Server-Logs zu steigen.
     *
     * @param array<string, scalar|null> $context
     */
    public static function incident(string $type, string $message, array $context = []): void
    {
        self::write($message, $context);

        // Höchstens ein Chronik-Eintrag je Art und Stunde: ein dauerhaft
        // kaputter Zustand soll melden, aber nicht die Chronik zumüllen.
        $key = self::THROTTLE_PREFIX . md5($type . '|' . $message);

        if (get_transient($key)) {
            return;
        }

        set_transient($key, 1, self::THROTTLE_TTL);

        EventLog::record(Event::warn($type, $message, $context));
    }

    /**
     * @param array<string, scalar|null> $context
     */
    private static function write(string $message, array $context): void
    {
        if (! function_exists('error_log')) {
            return;
        }

        $line = self::PREFIX . $message;

        foreach ($context as $key => $value) {
            if ($value === null || $value === '') {
                continue;
            }

            $line .= sprintf(' | %s=%s', $key, (string) $value);
        }

        error_log($line);
    }
}
