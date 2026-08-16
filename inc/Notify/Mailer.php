<?php

declare(strict_types=1);

namespace RhHardening\Notify;

use RhBlueprint\Core\Mail\Mail;
use RhBlueprint\Core\Mail\MailKind;
use RhBlueprint\Core\Mail\MailMessage;
use RhBlueprint\Core\Mail\MailSettings;
use RhBlueprint\Core\Mail\ReportSection;
use RhHardening\Admin\HardeningGroup;
use RhHardening\Log\Event;
use RhHardening\Log\EventLog;
use RhHardening\Support\Log;

/**
 * Meldung per Mail. Das Modul greift nicht ein, es schreibt und meldet.
 *
 * Zwei Wege, damit nicht jede Kleinigkeit weckt:
 *   - Kritisches geht sofort raus, als eigene Mail.
 *   - Alles andere wird ein Abschnitt im Sammelbericht der Suite.
 *
 * Einen eigenen Wochenbericht gibt es nicht mehr. Er stand neben dem
 * Sammelbericht und sagte dasselbe, nur in einer zweiten Mail. Ohne ein
 * installiertes E-Mail-Modul bekommt diese Website also keinen Wochenbericht,
 * darauf weist der Hinweis im Tab hin.
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

    /** Kennungen der Mail-Arten, die dieses Modul verschickt. */
    public const KIND_ALERT = 'hardening.alert';
    public const KIND_REPORT = 'hardening.report';

    public function boot(): void
    {
        $this->registerKinds();

        add_action('rh-hardening/event_recorded', [$this, 'onEvent'], 10, 2);

        // Beitrag zum Sammelbericht der Suite. Wird nur abgefragt, wenn das
        // E-Mail-Modul einen Bericht verschickt.
        add_filter('rh-blueprint/report/sections', [$this, 'reportSection'], 10, 2);

        // Hinweis im eigenen Tab, falls es hier keinen Sammelbericht gibt.
        add_filter('rh-blueprint/addon_hints', [$this, 'addonHint']);
    }

    /**
     * Was dieses Modul verschicken kann. Daraus baut der Core die Oberfläche
     * hinter dem Briefumschlag im Sicherheits-Tab.
     */
    private function registerKinds(): void
    {
        MailKind::register(self::KIND_ALERT, [
            'module' => 'hardening',
            'label' => __('Sicherheitsmeldung', 'rh-hardening'),
            'summary' => __('Sobald etwas nach einem Eingriff von aussen aussieht, etwa eine veränderte Datei an heikler Stelle.', 'rh-hardening'),
            'timing' => MailKind::TIMING_IMMEDIATE,
            'urgent' => true,
        ]);

        MailKind::register(self::KIND_REPORT, [
            'module' => 'hardening',
            'label' => __('Abschnitt Sicherheit', 'rh-hardening'),
            'summary' => __('Geprüfte Dateien, Zustand des Schutzwalls und was angesehen gehört.', 'rh-hardening'),
            'timing' => MailKind::TIMING_REPORT,
        ]);
    }

    /**
     * @param array<int, ReportSection> $sections
     * @return array<int, ReportSection>
     */
    public function reportSection(array $sections, int $since): array
    {
        if (! MailSettings::enabled(self::KIND_REPORT)) {
            return $sections;
        }

        $report = new DigestReport(gmdate('Y-m-d H:i:s', $since));
        $sections[] = $report->buildSection($this->chronicleUrl());

        return $sections;
    }

    /**
     * @param array<int, array{tab: string, module: string, benefit: string}> $hints
     * @return array<int, array{tab: string, module: string, benefit: string}>
     */
    public function addonHint(array $hints): array
    {
        $hints[] = [
            'tab' => 'hardening',
            'module' => 'rh-smtp',
            'benefit' => __('Sicherheitsmeldungen im Aussehen der Suite, ein gemeinsamer Bericht mit den anderen Modulen und ein Schutz davor, dass eine Testkopie echte Mails verschickt.', 'rh-hardening'),
        ];

        return $hints;
    }

    /**
     * Nichts mehr einzuplanen: den Wochenbericht verschickt der Sammelbericht
     * der Suite. Die Methode bleibt, weil der Installer sie aufruft, und raeumt
     * den alten Termin gleich mit weg.
     */
    public static function scheduleCron(): void
    {
        self::clearCron();
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

        // Betreff ohne Domain und ohne Themen-Klammer: beides setzt die
        // Betreffkonvention des E-Mail-Moduls davor, sonst steht es doppelt da.
        $sent = $this->send(
            __('Auffälligkeit auf der Website', 'rh-hardening'),
            $this->criticalMessage($event)
        );

        if ($sent) {
            EventLog::markNotified([$id]);
        }
    }


    private function criticalMessage(Event $event): MailMessage
    {
        $message = new MailMessage(
            __('Sicherheitsmeldung', 'rh-hardening'),
            $this->siteHost()
        );

        $message->kind(self::KIND_ALERT);
        $message->status(MailMessage::TONE_ALERT, $event->message);
        $message->text(__('Das sieht nach einem Eingriff von aussen aus. Das Modul hat nichts verändert, es meldet nur.', 'rh-hardening'));

        $rows = [
            __('Website', 'rh-hardening') => home_url('/'),
            __('Zeitpunkt', 'rh-hardening') => current_time('d.m.Y H:i'),
        ];

        foreach ($event->context as $key => $value) {
            if ($value === null || $value === '') {
                continue;
            }

            $rows[ucfirst((string) $key)] = (string) $value;
        }

        $message->rows($rows);
        $message->button(__('In der Chronik nachsehen', 'rh-hardening'), $this->chronicleUrl());

        return $message;
    }

    private function send(string $subject, MailMessage $message): bool
    {
        $to = $this->recipient();

        if ($to === '') {
            Log::note('Meldung nicht verschickt, kein gültiger Empfänger hinterlegt');

            return false;
        }

        $sent = Mail::send($to, $subject, $message, $this->footerNote());

        if (! $sent) {
            // Eine Meldung, die nicht ankommt, ist schlimmer als keine: man
            // hält die Website für beobachtet, und sie ist es nicht.
            Log::note('Meldung konnte nicht verschickt werden', ['betreff' => $subject]);
        }

        return $sent;
    }

    private function footerNote(): string
    {
        return sprintf(
            /* translators: %s: Domain der Website */
            __('Automatische Nachricht von %s, verschickt vom Sicherheits-Modul der Website.', 'rh-hardening'),
            $this->siteHost()
        );
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
