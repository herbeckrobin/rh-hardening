<?php

/**
 * Prüfungen rund um die Content-Security-Policy, ohne laufendes WordPress.
 *
 *   php tests/csp-test.php
 *
 * Zwei Dinge sind hier wichtig genug für einen eigenen Test: dass aus einer
 * Browser-Meldung nichts Personenbezogenes in der Datenbank landet, und dass
 * der Endpunkt beide Meldeformate versteht. Das zweite fällt sonst erst auf,
 * wenn jemand mit dem falschen Browser die Sammlung laufen lässt und drei Tage
 * später nichts dasteht.
 */

declare(strict_types=1);

$base = dirname(__DIR__);

require $base . '/vendor/autoload.php';

// --- WordPress-Ersatz, gerade so viel wie die zwei Klassen brauchen ---

$GLOBALS['stub_options'] = [];
$GLOBALS['stub_transients'] = [];

function get_option(string $name, mixed $default = false): mixed
{
    return $GLOBALS['stub_options'][$name] ?? $default;
}

function update_option(string $name, mixed $value, mixed $autoload = null): bool
{
    $GLOBALS['stub_options'][$name] = $value;

    return true;
}

function delete_option(string $name): bool
{
    unset($GLOBALS['stub_options'][$name]);

    return true;
}

function get_transient(string $key): mixed
{
    return $GLOBALS['stub_transients'][$key] ?? false;
}

function set_transient(string $key, mixed $value, int $ttl = 0): bool
{
    $GLOBALS['stub_transients'][$key] = $value;

    return true;
}

function wp_parse_url(string $url, int $component = -1): mixed
{
    return parse_url($url, $component);
}

use RhHardening\Csp\Violations;

$failures = 0;

function check(string $name, mixed $got, mixed $want): void
{
    global $failures;

    $ok = $got === $want;

    if (! $ok) {
        $failures++;
    }

    printf(
        "%-52s %s%s\n",
        $name,
        $ok ? 'OK' : 'FEHLER',
        $ok ? '' : sprintf('  ist=%s soll=%s', var_export($got, true), var_export($want, true))
    );
}

/** Zwischen zwei Meldungen muss die Schreibbremse gelöst werden. */
function melde(array $report): void
{
    $GLOBALS['stub_transients'] = [];
    Violations::add($report);
}

function reset_all(): void
{
    $GLOBALS['stub_options'] = [];
    $GLOBALS['stub_transients'] = [];
}

echo "Was gespeichert wird\n";

reset_all();
melde([
    'effective-directive' => 'script-src',
    'blocked-uri' => 'https://cdn.example.com/tracker.js?uid=4711&sid=abc',
    'document-uri' => 'https://kunde.de/kontakt/?name=Max+Mustermann',
    'referrer' => 'https://google.de/search?q=geheim',
]);

$eintrag = array_values(Violations::all())[0];

check('nur der Ursprung, keine Parameter', $eintrag['quelle'], 'https://cdn.example.com');
check('nur der Pfad der Seite', $eintrag['seite'], '/kontakt/');
check('die Verweisquelle wird gar nicht erst gespeichert', isset($eintrag['referrer']), false);
check('die Regel steht drin', $eintrag['direktive'], 'script-src');

echo "\nZusammenfassen statt sammeln\n";

reset_all();

for ($i = 0; $i < 40; $i++) {
    melde([
        'effective-directive' => 'font-src',
        'blocked-uri' => 'https://fonts.gstatic.com/s/x.woff2',
        'document-uri' => 'https://kunde.de/seite-' . $i . '/',
    ]);
}

$alle = Violations::all();
check('40 Meldungen ergeben einen Eintrag', count($alle), 1);
check('gezählt wurde trotzdem jede', array_values($alle)[0]['anzahl'], 40);

echo "\nDie Schreibbremse\n";

reset_all();
Violations::add(['effective-directive' => 'img-src', 'blocked-uri' => 'https://a.de/1.png', 'document-uri' => '/']);
// Ohne Rücksetzen des Transients: die zweite Meldung darf nicht durchkommen.
Violations::add(['effective-directive' => 'img-src', 'blocked-uri' => 'https://b.de/2.png', 'document-uri' => '/']);
check('zweite Meldung derselben Sekunde wird verworfen', count(Violations::all()), 1);

echo "\nWas verworfen wird\n";

reset_all();
melde(['effective-directive' => '', 'blocked-uri' => 'https://a.de', 'document-uri' => '/']);
check('Meldung ohne Regel', count(Violations::all()), 0);

melde(['effective-directive' => 'script-src', 'blocked-uri' => '', 'document-uri' => '/']);
check('Meldung ohne Quelle', count(Violations::all()), 0);

reset_all();
melde([
    'effective-directive' => "script-src'; drop table x; --",
    'blocked-uri' => 'https://a.de/<script>alert(1)</script>',
    'document-uri' => '/',
]);
check('präparierte Regel wird verworfen, nicht geflickt', count(Violations::all()), 0);

reset_all();
melde([
    'effective-directive' => 'script-src',
    'blocked-uri' => 'https://a.de/<script>alert(1)</script>',
    'document-uri' => '/pfad/<img>',
]);
$eintrag = array_values(Violations::all())[0];
check('nur der Host der Quelle', $eintrag['quelle'], 'https://a.de');
check('unsauberer Pfad wird zu /', $eintrag['seite'], '/');

reset_all();
melde(['effective-directive' => 'SCRIPT-SRC', 'blocked-uri' => 'https://A.DE/x.js', 'document-uri' => '/']);
$eintrag = array_values(Violations::all())[0];
check('Großschreibung vereinheitlicht', $eintrag['direktive'] . ' ' . $eintrag['quelle'], 'script-src https://a.de');

reset_all();
melde(['effective-directive' => 'script-src', 'blocked-uri' => 'javascript:alert(1)', 'document-uri' => '/']);
check('Schema, das keine Quelle ist', count(Violations::all()), 0);

echo "\nSchlüsselwörter statt Adressen\n";

reset_all();
melde(['effective-directive' => 'script-src-elem', 'blocked-uri' => 'inline', 'document-uri' => '/']);
check('inline bleibt inline', array_values(Violations::all())[0]['quelle'], 'inline');

echo "\nDer Vorschlag\n";

reset_all();
melde(['effective-directive' => 'script-src', 'blocked-uri' => 'https://b.de/x.js', 'document-uri' => '/']);
melde(['effective-directive' => 'script-src', 'blocked-uri' => 'https://a.de/y.js', 'document-uri' => '/']);
melde(['effective-directive' => 'font-src', 'blocked-uri' => 'https://f.de/x.woff2', 'document-uri' => '/']);

check(
    'nach Regel gebündelt, self immer dabei',
    Violations::suggestion(),
    "font-src 'self' https://f.de; script-src 'self' https://a.de https://b.de"
);

reset_all();
check('ohne Gesammeltes kein Vorschlag', Violations::suggestion(), '');

echo "\nDie zwei Meldeformate\n";

$extract = (new ReflectionClass(\RhHardening\Prevention\Csp::class))->getMethod('extract');
$csp = (new ReflectionClass(\RhHardening\Prevention\Csp::class))->newInstanceWithoutConstructor();

// So schickt der alte Weg (report-uri, was Firefox nutzt).
$alt = $extract->invoke($csp, ['csp-report' => ['effective-directive' => 'script-src']]);
check('report-uri: ein Objekt', count($alt), 1);
check('report-uri: Inhalt kommt an', $alt[0]['effective-directive'], 'script-src');

// So schickt der neue Weg (report-to).
$neu = $extract->invoke($csp, [
    ['type' => 'csp-violation', 'body' => ['effectiveDirective' => 'img-src', 'effective-directive' => 'img-src']],
    ['type' => 'csp-violation', 'body' => ['effective-directive' => 'font-src']],
]);
check('report-to: Liste von Meldungen', count($neu), 2);
check('report-to: Inhalt aus body', $neu[1]['effective-directive'], 'font-src');

$viele = $extract->invoke($csp, array_fill(0, 500, ['body' => ['effective-directive' => 'x']]));
check('gedeckelt, damit eine Anfrage nicht flutet', count($viele), 10);

check('Unsinn ergibt nichts', $extract->invoke($csp, ['nur', 'strings']), []);

echo "\n" . ($failures === 0 ? "alles grün\n" : sprintf("%d Fehler\n", $failures));

exit($failures === 0 ? 0 : 1);
