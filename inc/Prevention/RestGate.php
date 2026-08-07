<?php

declare(strict_types=1);

namespace RhHardening\Prevention;

use RhHardening\Admin\HardeningGroup;
use RhHardening\Log\Event;
use RhHardening\Log\EventLog;
use WP_Error;
use WP_REST_Request;
use WP_REST_Server;

/**
 * Torwächter vor der REST-Schnittstelle.
 *
 * Die REST-Schnittstelle ist heute die grösste unauthentifizierte Angriffsfläche
 * von WordPress. wp2shell (CVE-2026-63030) lief über /wp-json/batch/v1: der
 * Batch-Endpoint validiert und führt in zwei getrennten Schleifen aus, und wenn
 * die auseinanderlaufen, greift die Rechteprüfung der zweiten Anfrage nicht mehr.
 *
 * Zwei Stufen:
 *
 *   Standard  Gäste kommen an bekannte Problem-Routen nicht heran (Batch,
 *             Benutzerliste). Der Rest bleibt offen, damit nichts kaputtgeht.
 *
 *   Streng    Gäste kommen nur noch an Namensräume, die auf der Liste stehen.
 *             Wirksamer, braucht aber einen Durchlauf über die Site, weil
 *             Formular- und Shop-Plugins eigene Namensräume mitbringen.
 *
 * Was geblockt wird, landet in der Chronik. Damit sieht man nach dem Umschalten
 * auf Streng innerhalb eines Tages, was noch auf die Liste muss.
 */
final class RestGate
{
    public const MODE_OFF = 'off';
    public const MODE_STANDARD = 'standard';
    public const MODE_STRICT = 'strict';

    /**
     * Routen, die für Gäste nie erreichbar sein müssen.
     * Präfix-Vergleich, damit auch Unterrouten mitgefangen werden.
     *
     * @var array<int, string>
     */
    private const BLOCKED_FOR_GUESTS = [
        '/batch/v1',
        '/wp/v2/users',
        '/wp-site-health/v1',
    ];

    /**
     * Namensräume, die im strengen Modus immer erlaubt bleiben, weil ohne sie
     * sichtbar etwas kaputtgeht.
     *
     * @var array<int, string>
     */
    private const ALWAYS_ALLOWED = [
        'oembed/1.0',
    ];

    /** Gegen Log-Fluten: pro Route höchstens ein Eintrag je Stunde. */
    private const LOG_THROTTLE_PREFIX = 'rhhard_restlog_';

    public function boot(): void
    {
        if ($this->mode() === self::MODE_OFF) {
            return;
        }

        add_filter('rest_pre_dispatch', [$this, 'guard'], 5, 3);
    }

    /**
     * @param mixed $result
     * @return mixed
     */
    public function guard($result, WP_REST_Server $server, WP_REST_Request $request)
    {
        // Ein Fehler von früher gewinnt, wir hängen uns nicht davor.
        if ($result !== null) {
            return $result;
        }

        if (is_user_logged_in()) {
            return $result;
        }

        $route = (string) $request->get_route();

        if (! $this->isBlocked($route)) {
            return $result;
        }

        $this->logBlocked($route);

        return new WP_Error(
            'rest_forbidden',
            __('Dieser Bereich der Schnittstelle ist ohne Anmeldung nicht erreichbar.', 'rh-hardening'),
            ['status' => rest_authorization_required_code()]
        );
    }

    private function isBlocked(string $route): bool
    {
        $route = '/' . ltrim($route, '/');

        foreach (self::BLOCKED_FOR_GUESTS as $blocked) {
            if (str_starts_with($route, $blocked)) {
                return true;
            }
        }

        if ($this->mode() !== self::MODE_STRICT) {
            return false;
        }

        foreach ($this->allowedNamespaces() as $namespace) {
            if (str_starts_with($route, '/' . trim($namespace, '/'))) {
                return false;
            }
        }

        return true;
    }

    /**
     * @return array<int, string>
     */
    private function allowedNamespaces(): array
    {
        $raw = (string) rhbp_setting(HardeningGroup::GROUP_ID, HardeningGroup::FIELD_REST_ALLOWLIST, '');
        $list = preg_split('/[\s,]+/', $raw) ?: [];
        $list = array_filter(array_map('trim', $list));

        $namespaces = array_merge(self::ALWAYS_ALLOWED, $list);

        /**
         * Namensräume, die Gäste im strengen Modus erreichen dürfen.
         *
         * @param array<int, string> $namespaces
         */
        return (array) apply_filters('rh-hardening/rest/allowed_namespaces', $namespaces);
    }

    private function logBlocked(string $route): void
    {
        $key = self::LOG_THROTTLE_PREFIX . md5($route);

        if (get_transient($key)) {
            return;
        }

        set_transient($key, 1, HOUR_IN_SECONDS);

        EventLog::record(Event::info(
            Event::TYPE_REQUEST_BLOCKED,
            sprintf(
                /* translators: %s: REST-Route */
                __('Zugriff ohne Anmeldung auf %s abgewiesen', 'rh-hardening'),
                $route
            ),
            ['route' => $route, 'modus' => $this->mode()]
        ));
    }

    private function mode(): string
    {
        $mode = (string) rhbp_setting(HardeningGroup::GROUP_ID, HardeningGroup::FIELD_REST_MODE, self::MODE_STANDARD);

        return in_array($mode, [self::MODE_OFF, self::MODE_STANDARD, self::MODE_STRICT], true)
            ? $mode
            : self::MODE_STANDARD;
    }
}
