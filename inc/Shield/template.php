<?php

/**
 * RH Hardening Schutzwall
 *
 * Diese Datei wird vom Plugin "RH Hardening" erzeugt und bei jedem Update neu
 * ausgelegt. Änderungen von Hand gehen dabei verloren, und das Plugin meldet
 * sie außerdem als Verdachtsfall.
 *
 * Sie liegt in mu-plugins, weil sie laufen muss, bevor WordPress die REST-
 * Schnittstelle überhaupt aufbaut. Genau dort lag der Fehler bei wp2shell: die
 * Rechteprüfung fiel INNERHALB der Verarbeitung aus, ein Riegel davor greift
 * trotzdem.
 *
 * Grundsatz für alles hier drin: im Zweifel durchlassen. Ein Schutzwall, der
 * eine Kundenseite lahmlegt, ist teurer als die Lücke, die er verhindert.
 *
 * Version: __RHHARD_SHIELD_VERSION__
 */

declare(strict_types=1);

if (! defined('ABSPATH') || defined('RHHARD_SHIELD')) {
    return;
}

define('RHHARD_SHIELD', '__RHHARD_SHIELD_VERSION__');

(static function (): void {
    try {
        $rules = get_option('rhhard_shield_rules', null);

        if (! is_array($rules) || empty($rules['active'])) {
            return;
        }

        $uri = isset($_SERVER['REQUEST_URI']) ? (string) $_SERVER['REQUEST_URI'] : '';

        if ($uri === '') {
            return;
        }

        $path = (string) parse_url($uri, PHP_URL_PATH);
        $restRoute = rhhard_shield_rest_route($path);

        // Angemeldete Besucher laufen durch. Hier gibt es noch keine Sitzung,
        // deshalb reicht die Frage, ob überhaupt ein Anmelde-Cookie mitkommt.
        // Die richtige Prüfung macht das Plugin später, das hier ist der Riegel
        // gegen alles, was ohne jede Anmeldung anklopft.
        $looksLoggedIn = rhhard_shield_has_auth_cookie();

        foreach ((array) ($rules['rules'] ?? []) as $rule) {
            if (! is_array($rule) || empty($rule['type'])) {
                continue;
            }

            $hit = match ($rule['type']) {
                'route' => $restRoute !== null && rhhard_shield_starts_with($restRoute, (string) ($rule['value'] ?? '')),
                'namespace_guest' => ! $looksLoggedIn
                    && $restRoute !== null
                    && rhhard_shield_starts_with($restRoute, (string) ($rule['value'] ?? '')),
                'param' => rhhard_shield_param_hit((string) ($rule['param'] ?? ''), (string) ($rule['pattern'] ?? '')),
                'component' => $restRoute !== null
                    && rhhard_shield_starts_with($restRoute, (string) ($rule['value'] ?? '')),
                default => false,
            };

            if ($hit) {
                rhhard_shield_block((string) ($rule['id'] ?? $rule['type']), $restRoute ?? $path);
            }
        }
    } catch (\Throwable $e) {
        // Nie die Seite mitreißen. Ein stiller Ausfall des Walls ist besser
        // als eine weiße Seite beim Kunden.
        return;
    }
})();

/**
 * Ermittelt die REST-Route, egal ob sie über /wp-json/ oder ?rest_route= kommt.
 */
function rhhard_shield_rest_route(string $path): ?string
{
    if (isset($_GET['rest_route'])) {
        $route = (string) $_GET['rest_route'];

        return '/' . ltrim($route, '/');
    }

    $prefix = '/wp-json/';
    $position = strpos($path, $prefix);

    if ($position === false) {
        return null;
    }

    return '/' . ltrim(substr($path, $position + strlen($prefix)), '/');
}

function rhhard_shield_starts_with(string $haystack, string $needle): bool
{
    if ($needle === '') {
        return false;
    }

    $needle = '/' . trim($needle, '/');
    $haystack = '/' . ltrim($haystack, '/');

    return str_starts_with($haystack, $needle);
}

/**
 * Sucht ein Muster in einem benannten Parameter, egal ob er per URL oder im
 * Rumpf ankommt. Der Vergleich läuft auch über verschachtelte Werte, weil
 * genau dort die Einschleusung bei wp2shell steckte.
 */
function rhhard_shield_param_hit(string $param, string $pattern): bool
{
    if ($param === '' || $pattern === '') {
        return false;
    }

    foreach ([$_GET, $_POST] as $source) {
        if (! is_array($source) || ! array_key_exists($param, $source)) {
            continue;
        }

        $values = is_array($source[$param]) ? $source[$param] : [$source[$param]];

        foreach ($values as $value) {
            if (! is_scalar($value)) {
                continue;
            }

            if (preg_match($pattern, (string) $value) === 1) {
                return true;
            }
        }
    }

    return false;
}

function rhhard_shield_has_auth_cookie(): bool
{
    foreach (array_keys($_COOKIE ?? []) as $name) {
        if (str_starts_with((string) $name, 'wordpress_logged_in_')) {
            return true;
        }
    }

    return false;
}

/**
 * Abweisen und den Treffer für die Chronik hinterlegen. Geschrieben wird in
 * eine Warteschlange, weil die Chronik-Maschine des Plugins hier noch nicht
 * geladen ist.
 */
function rhhard_shield_block(string $ruleId, string $target): void
{
    $queue = get_option('rhhard_shield_queue', []);

    if (! is_array($queue)) {
        $queue = [];
    }

    if (count($queue) < 50) {
        $queue[] = [
            'regel' => $ruleId,
            'ziel' => $target,
            'zeit' => time(),
        ];

        update_option('rhhard_shield_queue', $queue, false);
    }

    if (! headers_sent()) {
        header('Content-Type: application/json; charset=utf-8');
        header('X-Robots-Tag: noindex');
        status_header(403);
    }

    echo '{"code":"rhhard_blocked","message":"Dieser Aufruf wurde abgewiesen."}';
    exit;
}
