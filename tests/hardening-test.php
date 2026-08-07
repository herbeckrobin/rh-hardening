<?php

/**
 * Prüfungen, die ohne laufendes WordPress möglich sind.
 *
 *   php tests/hardening-test.php
 *
 * Schwerpunkt ist die IP-Kürzung: davon hängt ab, ob die Chronik ohne Eintrag
 * in der Datenschutzerklärung des Kunden auskommt. Wenn hier etwas rot wird,
 * ist das kein Schönheitsfehler.
 */

declare(strict_types=1);

$base = dirname(__DIR__);

require $base . '/vendor/autoload.php';

// Der Core kommt zur Laufzeit über seinen eigenen Version-Negotiation-Loader,
// nicht über diesen Autoloader. Für den Klassen-Check reicht das Interface.
require $base . '/vendor/rh/blueprint-core/src/Settings/GroupInterface.php';
require $base . '/vendor/rh/blueprint-core/src/Settings/SettingField.php';

if (! function_exists('__')) {
    function __(string $text, ?string $domain = null): string
    {
        return $text;
    }
}

use RhHardening\Admin\HardeningGroup;
use RhHardening\Support\Ip;

$failures = 0;

function check(string $name, mixed $got, mixed $want): void
{
    global $failures;

    $ok = $got === $want;

    if (! $ok) {
        $failures++;
    }

    printf(
        "%-48s %s%s\n",
        $name,
        $ok ? 'OK' : 'FEHLER',
        $ok ? '' : sprintf('  ist=%s soll=%s', var_export($got, true), var_export($want, true))
    );
}

echo "IP-Kürzung\n";
check('IPv4 wird auf /16 gekürzt', Ip::truncate('89.14.203.7'), '89.14.0.0');
check('IPv4 privat', Ip::truncate('192.168.178.42'), '192.168.0.0');
check('IPv4 Rand', Ip::truncate('255.255.255.255'), '255.255.0.0');
check('IPv6 wird auf /48 gekürzt', Ip::truncate('2001:0db8:1234:5678:9abc:def0:1234:5678'), '2001:db8:1234::');
check('IPv6 in Kurzschreibweise', Ip::truncate('2a02:8071:5:1::1'), '2a02:8071:5::');
check('leere Eingabe', Ip::truncate(''), '');
check('kein gültiger Wert', Ip::truncate('not-an-ip'), '');
check('Einschleus-Versuch', Ip::truncate("1.2.3.4', (select 1)--"), '');
check(
    'zwei Rechner im selben Netz sind nicht unterscheidbar',
    Ip::truncate('89.14.203.7') === Ip::truncate('89.14.11.200'),
    true
);

echo "\nKlassen\n";
foreach ([
    'RhHardening\Plugin',
    'RhHardening\Installer',
    'RhHardening\Log\Event',
    'RhHardening\Log\EventLog',
    'RhHardening\Notify\Mailer',
    'RhHardening\Watch\ChangeWatch',
    'RhHardening\Prevention\RestGate',
    'RhHardening\Prevention\Access',
    'RhHardening\Prevention\Uploads',
    'RhHardening\Checks\DocrootHygiene',
    'RhHardening\Admin\HardeningGroup',
    'RhHardening\Admin\SecurityPanel',
    'RhHardening\Support\Loopback',
    'RhHardening\Integrity\ScanJob',
    'RhHardening\Integrity\ScanRunner',
    'RhHardening\Integrity\CoreScan',
    'RhHardening\Integrity\PluginScan',
    'RhHardening\Integrity\HiddenScan',
    'RhHardening\Integrity\UploadScan',
    'RhHardening\Shield\Shield',
    'RhHardening\Shield\Rules',
    'RhHardening\Radar\PluginDirectory',
    'RhHardening\Radar\AbandonedWatch',
    'RhHardening\Radar\Radar',
    'RhHardening\Radar\FeedClient',
    'RhHardening\Radar\VersionRange',
] as $class) {
    check('lädt ' . $class, class_exists($class), true);
}

echo "\nSettings-Gruppe\n";
$group = new HardeningGroup();
$ids = [];

foreach ($group->fields() as $field) {
    $ids[] = $field->id;

    if ($field->type === 'select') {
        check(
            'Default liegt in den Auswahlwerten: ' . $field->id,
            array_key_exists((string) $field->default, $field->choices),
            true
        );
    }
}

check('Feld-IDs sind eindeutig', count($ids) === count(array_unique($ids)), true);
check('Zurückstufen ist ab Werk aus', $group->fields()[array_search(
    HardeningGroup::FIELD_DEMOTE_ROGUE_ADMIN,
    $ids,
    true
)]->default, false);

echo "\nPrüflauf-Zustand\n";
$job = new RhHardening\Integrity\ScanJob();
$job->stage = 'core';
check('Abschnitte folgen aufeinander', $job->nextStage(), 'plugins');
$job->stage = 'uploads';
check('nach dem letzten Abschnitt ist Schluss', $job->nextStage(), null);

$job = new RhHardening\Integrity\ScanJob();
for ($i = 0; $i < 60; $i++) {
    $job->addFinding('core_modified', 'datei-' . $i . '.php');
}
check('Fundliste ist gedeckelt', $job->findingCount('core_modified'), 25);
check('Gesamtzahl zählt nur Festgehaltenes', $job->totalFindings(), 25);

$job->status = RhHardening\Integrity\ScanJob::STATUS_RUNNING;
$job->updatedAt = time();
check('frischer Lauf gilt nicht als abgestürzt', $job->isStale(), false);
$job->updatedAt = time() - 3600;
check('stehengebliebener Lauf gilt als abgestürzt', $job->isStale(), true);

$types = RhHardening\Integrity\ScanRunner::findingTypes();
check('nicht prüfbare Plugins gehen nicht in die Chronik', $types['plugin_unverifiable']['log'], false);
check('veränderter Kern geht in die Chronik', $types['core_modified']['log'], true);

echo "\nSchutzwall\n";
$rules = RhHardening\Shield\Rules::defaults();
$byId = array_column($rules, null, 'id');
check('Grundregeln vorhanden', count($rules), 4);
check(
    'die Batch-Route ist nur für Gäste gesperrt',
    $byId['batch-endpoint']['type'],
    'namespace_guest'
);
check('SQL-Muster trifft die Einschleusung', preg_match($byId['author-notin-injection']['pattern'], '1 UNION SELECT pass FROM wp_users'), 1);
check('SQL-Muster trifft eine harmlose Zahl nicht', preg_match($byId['author-notin-injection']['pattern'], '5'), 0);
check('SQL-Muster trifft eine harmlose Liste nicht', preg_match($byId['author-notin-injection']['pattern'], '3,7,12'), 0);

$template = file_get_contents(dirname(__DIR__) . '/inc/Shield/template.php');
check('Vorlage bricht bei einem Fehler nicht die Seite', str_contains($template, 'catch (\\Throwable'), true);
check('Vorlage trägt einen Platzhalter für die Version', str_contains($template, '__RHHARD_SHIELD_VERSION__'), true);

echo "\nVersionsvergleich\n";
use RhHardening\Radar\VersionRange;

// Der Bereich aus einem echten Datensatz: alles bis einschliesslich 6.0.5
$bis605 = [['from_version' => '*', 'from_inclusive' => true, 'to_version' => '6.0.5', 'to_inclusive' => true]];
check('betroffene Fassung wird erkannt', VersionRange::matchesAny('6.0', $bis605), true);
check('die Obergrenze selbst ist betroffen', VersionRange::matchesAny('6.0.5', $bis605), true);
check('die gefixte Fassung ist es nicht', VersionRange::matchesAny('6.0.6', $bis605), false);
check('eine viel neuere erst recht nicht', VersionRange::matchesAny('6.1.6', $bis605), false);

// Grenze ausschliessend
$unter2 = [['from_version' => '1.0', 'from_inclusive' => true, 'to_version' => '2.0', 'to_inclusive' => false]];
check('ausschliessende Obergrenze', VersionRange::matchesAny('2.0', $unter2), false);
check('knapp darunter trifft', VersionRange::matchesAny('1.9.9', $unter2), true);
check('unterhalb der Untergrenze trifft nicht', VersionRange::matchesAny('0.9', $unter2), false);

// Vorprüfung gegen das Verzeichnis
check('gleiche Fassung wie die höchste betroffene', VersionRange::couldBeAffected('7.0.2', '7.0.2'), true);
check('eine Stelle neuer fällt raus', VersionRange::couldBeAffected('7.0.3', '7.0.2'), false);
check('ohne Obergrenze immer prüfen', VersionRange::couldBeAffected('9.9.9', '*'), true);
check('ohne Angabe lieber prüfen', VersionRange::couldBeAffected('1.0', ''), true);

printf("\n%s\n", $failures === 0 ? 'alles grün' : $failures . ' Fehler');

exit($failures === 0 ? 0 : 1);
