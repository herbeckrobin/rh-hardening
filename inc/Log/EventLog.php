<?php

declare(strict_types=1);

namespace RhHardening\Log;

use RhHardening\Support\Ip;

/**
 * Ablage der Sicherheits-Chronik in einer eigenen Tabelle.
 *
 * Eigene Tabelle statt Options, weil die Chronik wächst und indiziert abgefragt
 * werden muss. Sie enthält bewusst keine personenbezogenen Daten: die Herkunft
 * steht nur gekürzt drin (siehe Ip), Benutzer nur als ID, kein Klartext-Name,
 * kein User-Agent.
 */
final class EventLog
{
    public const TABLE = 'rhhard_events';

    /** Aufbewahrung in Tagen, darunter wird täglich aufgeräumt. */
    public const RETENTION_DAYS = 90;

    /** Notbremse gegen ein volllaufendes Log bei einer Endlosschleife. */
    private const MAX_ROWS = 20000;

    public static function tableName(): string
    {
        global $wpdb;

        return $wpdb->prefix . self::TABLE;
    }

    /**
     * Legt die Tabelle an bzw. zieht sie auf den aktuellen Stand.
     * Läuft bei Aktivierung und versionsgesteuert bei jedem Plugin-Update.
     */
    public static function install(): void
    {
        global $wpdb;

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';

        $table = self::tableName();
        $charset = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE {$table} (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            created_at DATETIME NOT NULL,
            type VARCHAR(40) NOT NULL,
            severity VARCHAR(10) NOT NULL,
            message TEXT NOT NULL,
            context LONGTEXT NULL,
            ip_prefix VARCHAR(45) NOT NULL DEFAULT '',
            user_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
            notified TINYINT(1) NOT NULL DEFAULT 0,
            PRIMARY KEY (id),
            KEY created_at (created_at),
            KEY severity_notified (severity, notified),
            KEY type (type)
        ) {$charset};";

        dbDelta($sql);
    }

    /**
     * Schreibt einen Vorgang in die Chronik und gibt die neue ID zurück (0 bei Fehler).
     */
    public static function record(Event $event): int
    {
        global $wpdb;

        $context = $event->context === []
            ? null
            : (string) wp_json_encode($event->context, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        $ok = $wpdb->insert(
            self::tableName(),
            [
                'created_at' => current_time('mysql', true),
                'type' => $event->type,
                'severity' => $event->severity,
                'message' => $event->message,
                'context' => $context,
                'ip_prefix' => Ip::current(),
                'user_id' => $event->userId > 0 ? $event->userId : get_current_user_id(),
                'notified' => 0,
            ],
            ['%s', '%s', '%s', '%s', '%s', '%s', '%d', '%d']
        );

        if ($ok === false) {
            return 0;
        }

        $id = (int) $wpdb->insert_id;

        /**
         * Ein frisch protokollierter Vorgang. Hier hängt der Mailversand dran.
         */
        do_action('rh-hardening/event_recorded', $event, $id);

        return $id;
    }

    /**
     * Chronik-Einträge, neueste zuerst.
     *
     * @param array{severity?: string, type?: string, since?: string, limit?: int, offset?: int, notified?: int} $args
     * @return array<int, object>
     */
    public static function query(array $args = []): array
    {
        global $wpdb;

        $table = self::tableName();
        $where = ['1=1'];
        $params = [];

        if (! empty($args['severity']) && in_array($args['severity'], Event::severities(), true)) {
            $where[] = 'severity = %s';
            $params[] = $args['severity'];
        }

        if (! empty($args['type'])) {
            $where[] = 'type = %s';
            $params[] = (string) $args['type'];
        }

        if (! empty($args['since'])) {
            $where[] = 'created_at >= %s';
            $params[] = (string) $args['since'];
        }

        if (isset($args['notified'])) {
            $where[] = 'notified = %d';
            $params[] = (int) $args['notified'];
        }

        $limit = isset($args['limit']) ? max(1, min(500, (int) $args['limit'])) : 50;
        $offset = isset($args['offset']) ? max(0, (int) $args['offset']) : 0;

        $sql = 'SELECT * FROM ' . $table
            . ' WHERE ' . implode(' AND ', $where)
            . ' ORDER BY created_at DESC, id DESC LIMIT %d OFFSET %d';

        $params[] = $limit;
        $params[] = $offset;

        // $table stammt aus $wpdb->prefix, alle Werte gehen durch prepare().
        return (array) $wpdb->get_results($wpdb->prepare($sql, ...$params));
    }

    /**
     * Anzahl Einträge je Schweregrad seit einem Zeitpunkt.
     *
     * @return array<string, int>
     */
    public static function countsSince(string $since): array
    {
        global $wpdb;

        $table = self::tableName();
        $rows = (array) $wpdb->get_results(
            $wpdb->prepare(
                'SELECT severity, COUNT(*) AS total FROM ' . $table . ' WHERE created_at >= %s GROUP BY severity',
                $since
            )
        );

        $counts = array_fill_keys(Event::severities(), 0);

        foreach ($rows as $row) {
            $counts[(string) $row->severity] = (int) $row->total;
        }

        return $counts;
    }

    /**
     * Markiert Einträge als gemeldet, damit der Sammelbericht sie nicht doppelt schickt.
     *
     * @param array<int, int> $ids
     */
    public static function markNotified(array $ids): void
    {
        global $wpdb;

        $ids = array_values(array_filter(array_map('intval', $ids)));

        if ($ids === []) {
            return;
        }

        $placeholders = implode(',', array_fill(0, count($ids), '%d'));
        $table = self::tableName();

        $wpdb->query(
            $wpdb->prepare(
                'UPDATE ' . $table . ' SET notified = 1 WHERE id IN (' . $placeholders . ')',
                ...$ids
            )
        );
    }

    /**
     * Räumt alte Einträge weg. Läuft täglich per Cron.
     */
    public static function purge(): void
    {
        global $wpdb;

        $table = self::tableName();
        $cutoff = gmdate('Y-m-d H:i:s', time() - (self::RETENTION_DAYS * DAY_IN_SECONDS));

        $wpdb->query(
            $wpdb->prepare('DELETE FROM ' . $table . ' WHERE created_at < %s', $cutoff)
        );

        // Zweite Bremse: bei Überlauf die ältesten Zeilen kappen, egal wie jung.
        $total = (int) $wpdb->get_var('SELECT COUNT(*) FROM ' . $table);

        if ($total > self::MAX_ROWS) {
            $wpdb->query(
                $wpdb->prepare(
                    'DELETE FROM ' . $table . ' ORDER BY created_at ASC, id ASC LIMIT %d',
                    $total - self::MAX_ROWS
                )
            );
        }
    }
}
