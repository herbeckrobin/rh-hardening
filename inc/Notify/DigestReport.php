<?php

declare(strict_types=1);

namespace RhHardening\Notify;

use RhBlueprint\Core\Mail\MailMessage;
use RhBlueprint\Core\Mail\ReportSection;
use RhHardening\Integrity\ScanRunner;
use RhHardening\Log\Event;
use RhHardening\Log\EventLog;
use RhHardening\Shield\Rules;
use RhHardening\Shield\Shield;

/**
 * Baut den Beitrag dieses Moduls zum Sammelbericht der Suite.
 *
 * Einen eigenen Wochenbericht verschickt rh-hardening nicht mehr. Er stand
 * neben dem Sammelbericht und sagte dasselbe, nur in einer zweiten Mail.
 *
 * Ausgewertet wird, nicht abgeschrieben. Vorher war der Bericht eine Abschrift
 * der Chronik, eine Zeile je Vorgang. Bei einem Scanner, der eine Woche lang
 * alle paar Minuten anklopft, sind das neunzig gleichlautende Zeilen, und der
 * eine Eintrag, auf den es ankommt, geht darin unter. Stattdessen:
 *
 *   1. Was geprüft wurde. Der Nachweis, dass die Website betreut ist, auch und
 *      gerade wenn nichts passiert ist.
 *   2. Abgewehrtes, nach Art zusammengefasst und in Klartext.
 *   3. Was jemand ansehen sollte, einzeln und vollständig.
 */
final class DigestReport
{
    /** Mehr Einzelvorgänge braucht niemand in einer Mail. */
    private const MAX_DETAILS = 15;

    /** Obergrenze für die Auswertung. Darüber wird die Zahl nur noch geschätzt. */
    private const QUERY_LIMIT = 500;

    private int $criticalCount = 0;
    private int $warnCount = 0;

    /** @var array<string, array{count: int, last: string}> */
    private array $blocked = [];

    /** @var array<int, array{text: string, tone: string, meta: string}> */
    private array $details = [];

    public function __construct(private readonly string $since)
    {
    }

    /**
     * Derselbe Inhalt als Abschnitt für den Sammelbericht der Suite.
     *
     * Bewusst aus derselben Auswertung wie die eigene Mail. Ein Modul, das
     * seinen Beitrag zweimal beschreibt, hat über kurz oder lang zwei
     * verschiedene Wahrheiten.
     */
    public function buildSection(string $chronicleUrl): ReportSection
    {
        $rows = EventLog::query([
            'since' => $this->since,
            'limit' => self::QUERY_LIMIT,
        ]);

        foreach ($rows as $row) {
            $this->sort($row);
        }

        $status = match (true) {
            $this->criticalCount > 0 => ReportSection::STATUS_ALERT,
            $this->warnCount > 0 => ReportSection::STATUS_WARN,
            default => ReportSection::STATUS_OK,
        };

        $section = new ReportSection(
            'hardening',
            __('Sicherheit', 'rh-hardening'),
            $status,
            $this->sectionSummary()
        );

        // Im Sammelbericht nur, was Aufmerksamkeit braucht, plus der Nachweis
        // der Prüfung. Die Aufzählung des Grundrauschens würde den Bericht
        // wieder zu dem machen, was wir gerade abgeschafft haben.
        $detail = new MailMessage('');
        $this->addChecks($detail);
        $this->addBlocked($detail);

        if ($this->details !== []) {
            $detail->section(__('Das gehört angesehen', 'rh-hardening'));
            $detail->bullets($this->details);
        }

        $section->detail($detail)->link($chronicleUrl);

        return $section;
    }

    private function sectionSummary(): string
    {
        if ($this->criticalCount > 0) {
            return sprintf(
                /* translators: %d: Anzahl */
                _n('%d ernster Vorgang', '%d ernste Vorgänge', $this->criticalCount, 'rh-hardening'),
                $this->criticalCount
            );
        }

        if ($this->warnCount > 0) {
            return sprintf(
                /* translators: %d: Anzahl */
                _n('%d Punkt zum Ansehen', '%d Punkte zum Ansehen', $this->warnCount, 'rh-hardening'),
                $this->warnCount
            );
        }

        $blocked = array_sum(array_column($this->blocked, 'count'));

        if ($blocked > 0) {
            return sprintf(
                /* translators: %s: Anzahl abgewehrter Zugriffe */
                __('unauffällig, %s Zugriffe abgewehrt', 'rh-hardening'),
                number_format_i18n($blocked)
            );
        }

        return __('unauffällig', 'rh-hardening');
    }

    /**
     * Sortiert einen Vorgang ein: abgewehrte Zugriffe werden gezählt, alles
     * andere kommt einzeln in den Bericht.
     */
    private function sort(object $row): void
    {
        $severity = (string) $row->severity;
        $type = (string) $row->type;

        if ($severity === Event::SEVERITY_CRITICAL) {
            $this->criticalCount++;
        } elseif ($severity === Event::SEVERITY_WARN) {
            $this->warnCount++;
        }

        $when = get_date_from_gmt((string) $row->created_at, 'd.m.Y H:i');

        // Abgewehrtes ist Masse und wird gebündelt, aber nur solange es die
        // harmlose Sorte ist. Eine Regel mit kaputtem Muster kommt als
        // Auffälligkeit durch, sonst fiele sie zwischen die Stühle.
        if ($type === Event::TYPE_REQUEST_BLOCKED && $severity === Event::SEVERITY_INFO) {
            $context = $this->context($row);
            $rule = (string) ($context['regel'] ?? 'unbekannt');

            if (! isset($this->blocked[$rule])) {
                $this->blocked[$rule] = ['count' => 0, 'last' => $when];
            }

            $this->blocked[$rule]['count']++;

            return;
        }

        // Notizen ohne eigene Aussage (etwa "Prüfung von Hand ausgelöst")
        // gehören nicht in die Aufzählung der Auffälligkeiten.
        if ($severity === Event::SEVERITY_INFO && $type === Event::TYPE_SCAN_COMPLETED) {
            return;
        }

        if (count($this->details) >= self::MAX_DETAILS) {
            return;
        }

        $this->details[] = [
            'text' => (string) $row->message,
            'tone' => $severity === Event::SEVERITY_CRITICAL
                ? MailMessage::TONE_ALERT
                : ($severity === Event::SEVERITY_WARN ? MailMessage::TONE_WARN : MailMessage::TONE_INFO),
            'meta' => $when,
        ];
    }


    /**
     * Der Nachweis-Teil: was hat das Modul in dieser Woche tatsächlich getan.
     * Wichtiger Teil des Berichts, denn ohne ihn steht in einer ruhigen Woche
     * nichts drin, und man kann Ruhe nicht von Ausfall unterscheiden.
     */
    private function addChecks(MailMessage $message): void
    {
        $message->section(__('Was geprüft wurde', 'rh-hardening'));

        $rows = [];
        $result = ScanRunner::lastResult();

        if (is_array($result) && ! empty($result['finished'])) {
            $finished = (int) $result['finished'];
            $files = (int) ($result['files'] ?? 0);
            $findings = is_array($result['findings'] ?? null) ? $result['findings'] : [];

            // Nicht prüfbare Plugins sind kein Fund, sondern der Normalfall:
            // alles, was nicht aus dem Verzeichnis von wordpress.org kommt,
            // lässt sich nicht gegen ein Original vergleichen.
            unset($findings['plugin_unverifiable']);

            $rows[__('Dateien der Website', 'rh-hardening')] = sprintf(
                /* translators: 1: Datum, 2: Anzahl Dateien, 3: Ergebnis */
                __('%1$s geprüft, %2$s Dateien, %3$s', 'rh-hardening'),
                wp_date('d.m.Y', $finished),
                number_format_i18n($files),
                $findings === []
                    ? __('unverändert', 'rh-hardening')
                    : __('mit Befund, siehe unten', 'rh-hardening')
            );
        } else {
            $rows[__('Dateien der Website', 'rh-hardening')] = __('in diesem Zeitraum nicht geprüft', 'rh-hardening');
        }

        $shieldState = (new Shield())->state();
        $rows[__('Schutzwall', 'rh-hardening')] = match ($shieldState) {
            Shield::STATE_ACTIVE => __('aktiv', 'rh-hardening'),
            Shield::STATE_DISABLED => __('ausgeschaltet', 'rh-hardening'),
            Shield::STATE_UNWRITABLE => __('greift nicht, Verzeichnis nicht beschreibbar', 'rh-hardening'),
            default => __('greift nicht, bitte nachsehen', 'rh-hardening'),
        };

        $message->rows($rows);
    }

    /**
     * Abgewehrtes, nach Art gebündelt und in Klartext übersetzt.
     */
    private function addBlocked(MailMessage $message): void
    {
        if ($this->blocked === []) {
            return;
        }

        uasort($this->blocked, static fn (array $a, array $b): int => $b['count'] <=> $a['count']);

        $total = array_sum(array_column($this->blocked, 'count'));

        $message->section(__('Abgewehrte Zugriffe', 'rh-hardening'));

        $items = [];

        foreach ($this->blocked as $rule => $data) {
            $items[] = [
                'text' => Rules::label($rule),
                'meta' => sprintf(
                    /* translators: 1: Anzahl, 2: Zeitpunkt */
                    _n('%1$s mal, zuletzt am %2$s', '%1$s mal, zuletzt am %2$s', $data['count'], 'rh-hardening'),
                    number_format_i18n($data['count']),
                    $data['last']
                ),
            ];
        }

        $message->bullets($items);

        $message->text(
            $total >= 20
                ? __('Alle diese Aufrufe wurden abgewiesen, bevor WordPress sie verarbeitet hat. Anfragen dieser Art bekommt jede Website ab, die öffentlich erreichbar ist. Handeln muss hier niemand.', 'rh-hardening')
                : __('Alle diese Aufrufe wurden abgewiesen, bevor WordPress sie verarbeitet hat. Handeln muss hier niemand.', 'rh-hardening')
        );

        $message->muted(__('Gezählt wird höchstens ein Eintrag pro Minute. Die tatsächliche Zahl der Aufrufe liegt darüber, oft deutlich.', 'rh-hardening'));
    }



    /**
     * @return array<string, mixed>
     */
    private function context(object $row): array
    {
        $raw = (string) ($row->context ?? '');

        if ($raw === '') {
            return [];
        }

        $decoded = json_decode($raw, true);

        return is_array($decoded) ? $decoded : [];
    }
}
