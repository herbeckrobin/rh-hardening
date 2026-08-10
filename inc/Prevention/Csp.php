<?php

declare(strict_types=1);

namespace RhHardening\Prevention;

use RhHardening\Admin\HardeningGroup;
use RhHardening\Csp\Violations;
use RhHardening\Support\Log;
use WP_REST_Request;
use WP_REST_Response;

/**
 * Content-Security-Policy: der einzige Header, der Cross-Site-Scripting wirklich
 * stoppt, und der einzige, den man nicht blind setzen kann.
 *
 * Deshalb drei Stufen:
 *
 *   aus         nichts passiert
 *   beobachten  die Regeln gelten nur auf dem Papier, der Browser meldet, was
 *               er blockiert HÄTTE. Nichts an der Website ändert sich.
 *   scharf      die Regeln greifen wirklich
 *
 * Der Weg führt immer über "beobachten": ein paar Tage sammeln, den Vorschlag
 * ansehen, dann scharf schalten. Wer direkt scharf schaltet, sperrt zuverlässig
 * die halbe Website aus.
 *
 * Zum Meldeweg: `report-uri` gilt als veraltet, aber Firefox unterstützt
 * `report-to` für CSP bis heute nicht. Deshalb beide, plus den zugehörigen
 * Reporting-Endpoints-Header. Browser, die beides kennen, nehmen report-to und
 * ignorieren report-uri von allein.
 */
final class Csp
{
    public const MODE_OFF = 'off';
    public const MODE_REPORT = 'report';
    public const MODE_ENFORCE = 'enforce';

    public const ROUTE_NAMESPACE = 'rh-hardening/v1';
    public const ROUTE = '/csp-report';

    /** Nach so vielen Tagen schaltet sich die Sammlung von selbst ab. */
    public const COLLECT_DAYS = 3;

    public const COLLECT_UNTIL_OPTION = 'rhhard_csp_collect_until';

    /** Grösser angenommene Meldungen werden verworfen. */
    private const MAX_BODY = 16384;

    /**
     * Womit ein Beobachtungslauf anfängt, wenn noch keine Regeln dastehen.
     *
     * Absichtlich streng: der Sinn des Laufs ist, dass möglichst viel gemeldet
     * wird. Was die Website wirklich braucht, ergibt sich danach aus dem
     * Gesammelten. Ein 'unsafe-inline' bei style-src ist trotzdem drin, sonst
     * meldet jedes Theme tausendfach dieselbe eingebettete Formatierung und
     * die Liste besteht nur noch daraus.
     */
    public const STARTER_POLICY = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'";

    public function boot(): void
    {
        if ($this->mode() === self::MODE_OFF) {
            return;
        }

        add_action('send_headers', [$this, 'sendHeaders']);
        add_action('rest_api_init', [$this, 'registerRoute']);
    }

    public function sendHeaders(): void
    {
        if (headers_sent() || is_admin()) {
            return;
        }

        $policy = trim((string) rhbp_setting(HardeningGroup::GROUP_ID, HardeningGroup::FIELD_CSP_POLICY, ''));

        if ($policy === '') {
            return;
        }

        $sammelt = self::isCollecting();

        if ($sammelt) {
            $url = rest_url(self::ROUTE_NAMESPACE . self::ROUTE);

            // Beide Wege, siehe Kommentar oben.
            header('Reporting-Endpoints: rh-hardening="' . $url . '"');
            $policy .= '; report-uri ' . $url . '; report-to rh-hardening';
        }

        $header = $this->mode() === self::MODE_ENFORCE
            ? 'Content-Security-Policy'
            : 'Content-Security-Policy-Report-Only';

        header($header . ': ' . $policy);
    }

    /**
     * Die Route existiert nur, solange gesammelt wird. Ein dauerhaft offener
     * Schreib-Endpunkt auf jeder Kundenseite wäre genau die Art Angriffsfläche,
     * die dieses Modul sonst wegnimmt.
     */
    public function registerRoute(): void
    {
        if (! self::isCollecting()) {
            return;
        }

        register_rest_route(self::ROUTE_NAMESPACE, self::ROUTE, [
            'methods' => 'POST',
            'callback' => [$this, 'receive'],
            'permission_callback' => '__return_true',
        ]);
    }

    public function receive(WP_REST_Request $request): WP_REST_Response
    {
        // Immer dasselbe zurückgeben, egal was passiert: der Browser kann mit
        // einer Antwort nichts anfangen, und wer den Endpunkt absucht, soll
        // daraus nichts ablesen können.
        $antwort = new WP_REST_Response(null, 204);

        $roh = $request->get_body();

        if ($roh === '' || strlen($roh) > self::MAX_BODY) {
            return $antwort;
        }

        $daten = json_decode($roh, true);

        if (! is_array($daten)) {
            return $antwort;
        }

        foreach ($this->extract($daten) as $meldung) {
            Violations::add($meldung);
        }

        return $antwort;
    }

    /**
     * Die zwei Meldewege schicken unterschiedlich aufgebaute Daten:
     * report-uri ein einzelnes Objekt unter "csp-report", report-to eine Liste
     * von Meldungen mit dem Inhalt unter "body".
     *
     * @param array<mixed> $daten
     * @return array<int, array<string, mixed>>
     */
    private function extract(array $daten): array
    {
        if (isset($daten['csp-report']) && is_array($daten['csp-report'])) {
            return [$daten['csp-report']];
        }

        $meldungen = [];

        foreach ($daten as $eintrag) {
            if (is_array($eintrag) && isset($eintrag['body']) && is_array($eintrag['body'])) {
                $meldungen[] = $eintrag['body'];
            }
        }

        // Höchstens ein paar auf einmal, damit eine präparierte Anfrage nicht
        // hunderte Schreibversuche auslöst.
        return array_slice($meldungen, 0, 10);
    }

    /**
     * Schaltet die Sammlung ein und setzt das Ablaufdatum.
     */
    public static function startCollecting(): int
    {
        $bis = time() + (self::COLLECT_DAYS * DAY_IN_SECONDS);
        update_option(self::COLLECT_UNTIL_OPTION, $bis, false);

        Log::note('CSP-Sammlung eingeschaltet', ['bis' => gmdate('c', $bis)]);

        return $bis;
    }

    public static function stopCollecting(): void
    {
        delete_option(self::COLLECT_UNTIL_OPTION);
    }

    /**
     * Läuft die Sammlung gerade? Das Ablaufdatum wirkt von allein, es braucht
     * keinen Cron dafür.
     */
    public static function isCollecting(): bool
    {
        $bis = (int) get_option(self::COLLECT_UNTIL_OPTION, 0);

        return $bis > time();
    }

    public static function collectingUntil(): int
    {
        return (int) get_option(self::COLLECT_UNTIL_OPTION, 0);
    }

    private function mode(): string
    {
        $mode = (string) rhbp_setting(HardeningGroup::GROUP_ID, HardeningGroup::FIELD_CSP_MODE, self::MODE_OFF);

        return in_array($mode, [self::MODE_OFF, self::MODE_REPORT, self::MODE_ENFORCE], true)
            ? $mode
            : self::MODE_OFF;
    }
}
