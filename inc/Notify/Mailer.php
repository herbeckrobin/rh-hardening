<?php

declare(strict_types=1);

namespace RhHardening\Notify;

use RhHardening\Admin\HardeningGroup;
use RhHardening\Log\Event;
use RhHardening\Log\EventLog;

/**
 * Meldung per Mail. Das Modul greift nicht ein, es schreibt und meldet.
 *
 * Zwei Stufen, damit nicht jede Kleinigkeit weckt:
 *   - Kritisch geht sofort raus, einzeln.
 *   - Alles andere sammelt sich und geht als Wochenbericht.
 *
 * Empfänger ist per Default die Admin-Adresse der Site, in der Praxis trägt man
 * dort die Adresse des Betreuers ein, nicht die des Endkunden.
 */
final class Mailer
{
    private const CRON_DIGEST = 'rh_hardening_digest';

    /** Bremse gegen Mailfluten, wenn eine Ursache viele Vorgänge auslöst. */
    private const THROTTLE_TRANSIENT = 'rhhard_mail_throttle';
    private const THROTTLE_MAX_PER_HOUR = 10;

    public function boot(): void
    {
        add_action('rh-hardening/event_recorded', [$this, 'onEvent'], 10, 2);
        add_action(self::CRON_DIGEST, [$this, 'sendDigest']);
    }

    public static function scheduleCron(): void
    {
        if (! wp_next_scheduled(self::CRON_DIGEST)) {
            wp_schedule_event(time() + HOUR_IN_SECONDS, 'weekly', self::CRON_DIGEST);
        }
    }

    public static function clearCron(): void
    {
        $timestamp = wp_next_scheduled(self::CRON_DIGEST);

        if ($timestamp) {
            wp_unschedule_event($timestamp, self::CRON_DIGEST);
        }
    }

    public function onEvent(Event $event, int $id): void
    {
        if ($event->severity !== Event::SEVERITY_CRITICAL) {
            return;
        }

        if (! $this->notificationsEnabled() || $this->throttled()) {
            return;
        }

        $sent = $this->send(
            sprintf(
                /* translators: %s: Domain der Website */
                __('[Sicherheit] Auffälligkeit auf %s', 'rh-hardening'),
                $this->siteHost()
            ),
            $this->criticalBody($event)
        );

        if ($sent) {
            EventLog::markNotified([$id]);
        }
    }

    /**
     * Wochenbericht über alles, was noch nicht gemeldet wurde.
     */
    public function sendDigest(): void
    {
        if (! $this->notificationsEnabled()) {
            return;
        }

        $since = gmdate('Y-m-d H:i:s', time() - WEEK_IN_SECONDS);
        $pending = EventLog::query([
            'since' => $since,
            'notified' => 0,
            'limit' => 200,
        ]);

        if ($pending === []) {
            return;
        }

        $lines = [];
        $ids = [];

        foreach ($pending as $row) {
            $ids[] = (int) $row->id;
            $lines[] = sprintf(
                '%s  [%s]  %s',
                get_date_from_gmt((string) $row->created_at, 'd.m.Y H:i'),
                Event::severityLabel((string) $row->severity),
                (string) $row->message
            );
        }

        $body = implode("\n", [
            sprintf(
                /* translators: %s: Domain der Website */
                __('Wochenbericht Sicherheit für %s', 'rh-hardening'),
                $this->siteHost()
            ),
            '',
            sprintf(
                /* translators: %d: Anzahl der Vorgänge */
                _n('%d Vorgang in den letzten sieben Tagen:', '%d Vorgänge in den letzten sieben Tagen:', count($lines), 'rh-hardening'),
                count($lines)
            ),
            '',
            implode("\n", $lines),
            '',
            __('Vollständige Chronik:', 'rh-hardening'),
            $this->chronicleUrl(),
        ]);

        if ($this->send(
            sprintf(
                /* translators: %s: Domain der Website */
                __('[Sicherheit] Wochenbericht %s', 'rh-hardening'),
                $this->siteHost()
            ),
            $body
        )) {
            EventLog::markNotified($ids);
        }
    }

    private function criticalBody(Event $event): string
    {
        $lines = [
            __('Auf dieser Website ist etwas aufgefallen, das nach einer Übernahme aussehen kann.', 'rh-hardening'),
            '',
            sprintf(__('Website: %s', 'rh-hardening'), home_url('/')),
            sprintf(__('Zeitpunkt: %s', 'rh-hardening'), current_time('d.m.Y H:i')),
            sprintf(__('Vorgang: %s', 'rh-hardening'), $event->message),
            '',
        ];

        foreach ($event->context as $key => $value) {
            if ($value === null || $value === '') {
                continue;
            }
            $lines[] = sprintf('%s: %s', $key, (string) $value);
        }

        $lines[] = '';
        $lines[] = __('Das Modul hat nichts verändert. Bitte selbst nachsehen:', 'rh-hardening');
        $lines[] = $this->chronicleUrl();

        return implode("\n", $lines);
    }

    private function send(string $subject, string $body): bool
    {
        $to = $this->recipient();

        if ($to === '') {
            return false;
        }

        return (bool) wp_mail($to, $subject, $body);
    }

    private function recipient(): string
    {
        $configured = (string) rhbp_setting(HardeningGroup::GROUP_ID, HardeningGroup::FIELD_NOTIFY_EMAIL, '');
        $email = $configured !== '' ? $configured : (string) get_option('admin_email', '');

        return is_email($email) ? $email : '';
    }

    private function notificationsEnabled(): bool
    {
        return (bool) rhbp_setting(HardeningGroup::GROUP_ID, HardeningGroup::FIELD_NOTIFY, true);
    }

    /**
     * Höchstens zehn Sofortmails pro Stunde. Was darüber liegt, steht weiter in
     * der Chronik und geht mit dem Wochenbericht raus.
     */
    private function throttled(): bool
    {
        $count = (int) get_transient(self::THROTTLE_TRANSIENT);

        if ($count >= self::THROTTLE_MAX_PER_HOUR) {
            return true;
        }

        set_transient(self::THROTTLE_TRANSIENT, $count + 1, HOUR_IN_SECONDS);

        return false;
    }

    private function siteHost(): string
    {
        $host = wp_parse_url(home_url('/'), PHP_URL_HOST);

        return is_string($host) ? $host : 'WordPress';
    }

    private function chronicleUrl(): string
    {
        return admin_url('admin.php?page=rh-blueprint&tab=hardening');
    }
}
