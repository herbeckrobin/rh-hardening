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

/** Werte über dieser Grösse gehen nicht durch den Mustervergleich. */
define('RHHARD_SHIELD_MAX_VALUE', 8192);

/**
 * Grössere JSON-Rümpfe werden nicht zerlegt. Das Dekodieren kostet Speicher,
 * und ein Speicherfehler lässt sich nicht abfangen, er würde die Seite mitreißen.
 */
define('RHHARD_SHIELD_MAX_BODY', 1048576);

/** So oft darf die Warteschlange höchstens geschrieben werden. */
define('RHHARD_SHIELD_WRITE_EVERY', 60);

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
        $restRoutes = rhhard_shield_rest_routes($path);
        $restRoute = $restRoutes[0] ?? null;
        $sources = null;

        // Angemeldete Besucher laufen durch. Hier gibt es noch keine Sitzung,
        // deshalb reicht die Frage, ob überhaupt ein Anmelde-Cookie mitkommt.
        // Die richtige Prüfung macht das Plugin später, das hier ist der Riegel
        // gegen alles, was ohne jede Anmeldung anklopft.
        $looksLoggedIn = rhhard_shield_has_auth_cookie();

        foreach ((array) ($rules['rules'] ?? []) as $rule) {
            if (! is_array($rule) || empty($rule['type'])) {
                continue;
            }

            $value = (string) ($rule['value'] ?? '');

            $hit = match ($rule['type']) {
                'route', 'component' => rhhard_shield_any_starts_with($restRoutes, $value),
                'namespace_guest' => ! $looksLoggedIn && rhhard_shield_any_starts_with($restRoutes, $value),
                // Die Quellen werden erst beim ersten Parameter-Treffer
                // eingelesen, weil dafür der Rumpf zerlegt werden muss.
                'param' => rhhard_shield_param_hit($rule, $sources ??= rhhard_shield_param_sources($restRoute !== null)),
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
 * Sammelt alle Wege, auf denen eine REST-Route ankommen kann: rest_route im
 * Rumpf, rest_route in der URL und der Pfad unter /wp-json/. WordPress nimmt
 * davon genau einen, welchen, hängt von der Reihenfolge in class-wp.php ab.
 * Der Wall prüft alle, dann muss er diese Reihenfolge nicht nachbauen.
 *
 * @return array<int, string>
 */
function rhhard_shield_rest_routes(string $path): array
{
    $routes = [];

    foreach ([$_POST, $_GET] as $source) {
        if (isset($source['rest_route']) && is_string($source['rest_route'])) {
            $routes[] = '/' . ltrim($source['rest_route'], '/');
        }
    }

    $prefix = '/wp-json/';
    $position = stripos($path, $prefix);

    if ($position !== false) {
        $routes[] = '/' . ltrim(substr($path, $position + strlen($prefix)), '/');
    }

    return $routes;
}

/**
 * Bringt eine Route in die Form, in der verglichen wird. WordPress löst Routen
 * ohne Rücksicht auf Groß- und Kleinschreibung auf, ein direkter Vergleich ließ
 * deshalb /Batch/v1 durch. Dieselbe Rechnung steckt in
 * RhHardening\Shield\RouteMatch, der Test hält beide gleich.
 */
function rhhard_shield_normalize(string $route, bool $decode): string
{
    if ($decode) {
        for ($round = 0; $round < 3; $round++) {
            $decoded = rawurldecode($route);

            if ($decoded === $route) {
                break;
            }

            $route = $decoded;
        }
    }

    $route = strtolower($route);

    return (string) preg_replace('#/+#', '/', '/' . $route);
}

/**
 * Trifft, sobald eine Fassung der Route (roh oder dekodiert) mit dem Präfix
 * beginnt. Für Sperren ist das die sichere Richtung.
 */
function rhhard_shield_starts_with(string $haystack, string $needle): bool
{
    $needle = trim($needle, '/');

    if ($needle === '') {
        return false;
    }

    $needle = rhhard_shield_normalize($needle, true);

    foreach ([false, true] as $decode) {
        if (str_starts_with(rhhard_shield_normalize($haystack, $decode), $needle)) {
            return true;
        }
    }

    return false;
}

/**
 * @param array<int, string> $routes
 */
function rhhard_shield_any_starts_with(array $routes, string $needle): bool
{
    foreach ($routes as $route) {
        if (rhhard_shield_starts_with($route, $needle)) {
            return true;
        }
    }

    return false;
}

/**
 * Sucht ein Muster in einem benannten Parameter, egal ob er per URL oder im
 * Rumpf ankommt. Der Vergleich läuft auch über verschachtelte Werte, weil
 * genau dort die Einschleusung bei wp2shell steckte.
 *
 * Zwei Vorsichtsmassnahmen, weil das hier bei JEDEM Aufruf läuft:
 *
 *   1. Sehr lange Werte gehen gar nicht erst durch den Mustervergleich. Ein
 *      Parameter dieser Grösse ist ohnehin kein Normalfall, und ein ungünstiges
 *      Muster könnte sich daran festfressen.
 *   2. Ein ungültiges Muster liefert von preg_match false. Das darf nicht als
 *      "kein Treffer" durchgehen, sonst schützt eine kaputte Regel stillschweigend
 *      nicht mehr. Es wird vermerkt und die Regel greift nicht.
 */
function rhhard_shield_param_hit(array $rule, array $sources): bool
{
    $param = (string) ($rule['param'] ?? '');
    $pattern = (string) ($rule['pattern'] ?? '');
    $ruleId = (string) ($rule['id'] ?? 'unbenannt');

    if ($param === '' || $pattern === '') {
        return false;
    }

    $values = [];

    foreach ($sources as $source) {
        rhhard_shield_collect($source, $param, $values);
    }

    foreach ($values as $value) {
        if (strlen($value) > RHHARD_SHIELD_MAX_VALUE) {
            return true;
        }

        $hit = @preg_match($pattern, $value);

        if ($hit === false) {
            rhhard_shield_broken_rule($ruleId);

            return false;
        }

        if ($hit === 1) {
            return true;
        }
    }

    return false;
}

/**
 * Woher Parameter kommen können: URL, Formular-Rumpf und bei REST-Aufrufen ein
 * JSON-Rumpf. Den liest WordPress für REST genauso ein wie ein Formular.
 *
 * @return array<int, array<mixed>>
 */
function rhhard_shield_param_sources(bool $isRest): array
{
    $sources = [$_GET, $_POST];

    if ($isRest) {
        $json = rhhard_shield_json_body();

        if ($json !== null) {
            $sources[] = $json;
        }
    }

    return $sources;
}

/**
 * @return array<mixed>|null
 */
function rhhard_shield_json_body(): ?array
{
    $type = (string) ($_SERVER['CONTENT_TYPE'] ?? $_SERVER['HTTP_CONTENT_TYPE'] ?? '');

    if (stripos($type, 'json') === false) {
        return null;
    }

    // php://input lässt sich mehrfach lesen, WordPress bekommt den Rumpf
    // später unverändert.
    $raw = file_get_contents('php://input', false, null, 0, RHHARD_SHIELD_MAX_BODY + 1);

    if (! is_string($raw) || $raw === '' || strlen($raw) > RHHARD_SHIELD_MAX_BODY) {
        return null;
    }

    $data = json_decode($raw, true);

    return is_array($data) ? $data : null;
}

/**
 * Liest den Parameter genau dort, wo WordPress ihn auch liest: auf der obersten
 * Ebene der Quelle und, beim Batch-Aufruf, in jeder Unteranfrage unter
 * requests[n].body oder als Anfragezeile in requests[n].path. Dort lief die
 * Einschleusung bei wp2shell.
 *
 * Bewusst keine Suche in beliebiger Tiefe: WordPress wertet dort nichts aus,
 * und eine Suche mit Obergrenze ließe sich mit vorgeschaltetem Füllmaterial
 * ins Leere laufen lassen.
 *
 * @param mixed              $source
 * @param array<int, string> $values
 */
function rhhard_shield_collect($source, string $param, array &$values): void
{
    if (! is_array($source)) {
        return;
    }

    if (array_key_exists($param, $source)) {
        rhhard_shield_scalars($source[$param], $values);
    }

    if (! isset($source['requests']) || ! is_array($source['requests'])) {
        return;
    }

    foreach ($source['requests'] as $request) {
        if (! is_array($request)) {
            continue;
        }

        if (isset($request['body']) && is_array($request['body']) && array_key_exists($param, $request['body'])) {
            rhhard_shield_scalars($request['body'][$param], $values);
        }

        if (isset($request['path']) && is_string($request['path']) && str_contains($request['path'], '?')) {
            parse_str((string) parse_url($request['path'], PHP_URL_QUERY), $query);

            if (array_key_exists($param, $query)) {
                rhhard_shield_scalars($query[$param], $values);
            }
        }
    }
}

/**
 * @param mixed              $value
 * @param array<int, string> $values
 */
function rhhard_shield_scalars($value, array &$values): void
{
    if (is_scalar($value)) {
        $values[] = (string) $value;

        return;
    }

    if (! is_array($value)) {
        return;
    }

    array_walk_recursive($value, static function ($item) use (&$values): void {
        if (is_scalar($item)) {
            $values[] = (string) $item;
        }
    });
}

/**
 * Vermerkt eine Regel, deren Muster nicht übersetzbar ist. Höchstens einmal je
 * Stunde, damit ein dauerhaft kaputter Regelsatz nicht das Protokoll flutet.
 */
function rhhard_shield_broken_rule(string $ruleId): void
{
    $key = 'rhhard_shield_broken_' . md5($ruleId);

    if (get_transient($key)) {
        return;
    }

    set_transient($key, 1, HOUR_IN_SECONDS);

    if (function_exists('error_log')) {
        error_log('rh-hardening: Regel "' . $ruleId . '" hat ein ungültiges Muster und greift nicht.');
    }

    $queue = get_option('rhhard_shield_queue', []);
    $queue = is_array($queue) ? $queue : [];

    if (count($queue) < 50) {
        $queue[] = ['regel' => $ruleId, 'ziel' => 'ungültiges Muster', 'zeit' => time(), 'defekt' => true];
        update_option('rhhard_shield_queue', $queue, false);
    }
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
    // Gedrosselt schreiben: ein Scanner mit tausenden Treffern soll nicht
    // tausende Schreibvorgänge in der Datenbank auslösen. Sonst macht der
    // Schutz den Angriff teurer für den Server statt billiger.
    if (! get_transient('rhhard_shield_wrote')) {
        set_transient('rhhard_shield_wrote', 1, RHHARD_SHIELD_WRITE_EVERY);

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
    }

    if (! headers_sent()) {
        header('Content-Type: application/json; charset=utf-8');
        header('X-Robots-Tag: noindex');
        status_header(403);
    }

    echo '{"code":"rhhard_blocked","message":"Dieser Aufruf wurde abgewiesen."}';
    exit;
}
