<?php

declare(strict_types=1);

namespace RhHardening\Admin;

use RhBlueprint\Core\Admin\MailPanel;

/**
 * Die Gliederung des Sicherheits-Tabs.
 *
 * Sechzehn Schalter untereinander sind eine Wand, durch die niemand
 * hindurchsieht. Deshalb vier Bereiche, und in jedem Bereich kurze Abschnitte
 * mit höchstens einer Handvoll Zeilen. Eine Ebene, nicht mehr: mehrere
 * Verschachtelungen machen es schlimmer statt besser.
 *
 * Reihenfolge nach Praxis, nicht nach Technik: was am meisten schützt, steht
 * oben.
 */
final class Sections
{
    public const TAB_OVERVIEW = 'ueberblick';
    public const TAB_PROTECT = 'schutz';
    public const TAB_WATCH = 'ueberwachung';
    public const TAB_LOG = 'chronik';

    /**
     * @return array<string, string>
     */
    public static function tabs(): array
    {
        $tabs = [
            self::TAB_OVERVIEW => __('Überblick', 'rh-hardening'),
            self::TAB_PROTECT => __('Schutz', 'rh-hardening'),
            self::TAB_WATCH => __('Überwachung', 'rh-hardening'),
            self::TAB_LOG => __('Chronik', 'rh-hardening'),
        ];

        // Die Mail-Einstellungen des Moduls kommen aus dem Core, gehören aber
        // in diese Leiste und nicht in eine zweite darüber.
        $mail = MailPanel::tabLabel('hardening');

        if ($mail !== null) {
            $tabs[MailPanel::TAB] = $mail;
        }

        return $tabs;
    }

    public static function current(): string
    {
        $requested = isset($_GET['sub']) ? sanitize_key((string) wp_unslash($_GET['sub'])) : '';

        return array_key_exists($requested, self::tabs()) ? $requested : self::TAB_OVERVIEW;
    }

    /**
     * Abschnitte je Bereich, jeder mit seinen Feld-IDs.
     *
     * @return array<int, array{titel: string, hinweis: string, felder: array<int, string>}>
     */
    public static function groupsFor(string $tab): array
    {
        return match ($tab) {
            self::TAB_PROTECT => [
                [
                    'titel' => __('Von außen', 'rh-hardening'),
                    'hinweis' => __('Nimmt Angreifern die Wege, die sie ohne Anmeldung nutzen können.', 'rh-hardening'),
                    'felder' => [
                        HardeningGroup::FIELD_SHIELD,
                        HardeningGroup::FIELD_REST_MODE,
                        HardeningGroup::FIELD_CSP_MODE,
                        HardeningGroup::FIELD_BLOCK_USER_ENUM,
                        HardeningGroup::FIELD_DISABLE_XMLRPC,
                        HardeningGroup::FIELD_UPLOADS_NO_PHP,
                        HardeningGroup::FIELD_SECURITY_HEADERS,
                        HardeningGroup::FIELD_DISABLE_FEEDS,
                        HardeningGroup::FIELD_REMOVE_CLUTTER,
                    ],
                ],
                [
                    'titel' => __('Zugang', 'rh-hardening'),
                    'hinweis' => __('Begrenzt, was mit gestohlenen Zugangsdaten möglich ist.', 'rh-hardening'),
                    'felder' => [
                        HardeningGroup::FIELD_DISABLE_APP_PASSWORDS,
                        HardeningGroup::FIELD_SESSION_HARDENING,
                        HardeningGroup::FIELD_DISALLOW_FILE_EDIT,
                        HardeningGroup::FIELD_DISALLOW_FILE_MODS,
                    ],
                ],
            ],
            self::TAB_WATCH => [
                [
                    'titel' => __('Beobachten', 'rh-hardening'),
                    'hinweis' => __('Erkennt, wenn jemand schon drin ist. Verändert wird nichts, außer wo es ausdrücklich dabeisteht.', 'rh-hardening'),
                    'felder' => [
                        HardeningGroup::FIELD_WATCH_CHANGES,
                        HardeningGroup::FIELD_RADAR,
                        HardeningGroup::FIELD_DEMOTE_ROGUE_ADMIN,
                    ],
                ],
                [
                    'titel' => __('Melden', 'rh-hardening'),
                    'hinweis' => __('Kritisches geht sofort raus, alles andere sammelt sich zum Wochenbericht.', 'rh-hardening'),
                    'felder' => [
                        HardeningGroup::FIELD_NOTIFY,
                    ],
                ],
            ],
            default => [],
        };
    }

    /**
     * Ein knapper Satz je Einstellung für die Zeile.
     *
     * Absichtlich getrennt von der ausführlichen Beschreibung des Feldes: in
     * der Zeile zählt, dass alle gleich hoch sind und man in einem Blick durch
     * die Liste kommt. Wer es genauer wissen will, findet die lange Fassung in
     * der Anleitung und hinter dem Zahnrad.
     *
     * @return array<string, string>
     */
    public static function shortTexts(): array
    {
        return [
            HardeningGroup::FIELD_SHIELD => __('Weist Angriffe ab, bevor WordPress überhaupt startet.', 'rh-hardening'),
            HardeningGroup::FIELD_CSP_MODE => __('Sagt dem Browser, welche Quellen er laden darf.', 'rh-hardening'),
            HardeningGroup::FIELD_REST_MODE => __('Sperrt Gästen die bekannten Problem-Routen der Schnittstelle.', 'rh-hardening'),
            HardeningGroup::FIELD_BLOCK_USER_ENUM => __('Verhindert, dass Anmeldenamen von außen auslesbar sind.', 'rh-hardening'),
            HardeningGroup::FIELD_DISABLE_XMLRPC => __('Schaltet eine alte Schnittstelle ab, die kaum noch gebraucht wird.', 'rh-hardening'),
            HardeningGroup::FIELD_UPLOADS_NO_PHP => __('Macht hochgeladene Schadcode-Dateien wirkungslos.', 'rh-hardening'),
            HardeningGroup::FIELD_SECURITY_HEADERS => __('Setzt die üblichen Schutz-Header, falls der Server es nicht tut.', 'rh-hardening'),
            HardeningGroup::FIELD_DISABLE_FEEDS => __('Liefert RSS- und Atom-Feeds als 404 aus.', 'rh-hardening'),
            HardeningGroup::FIELD_REMOVE_CLUTTER => __('Nimmt Versionsangaben und Altlasten aus dem Seitenkopf.', 'rh-hardening'),
            HardeningGroup::FIELD_DISABLE_APP_PASSWORDS => __('Schließt einen zweiten Anmeldeweg, der an Login-Sperren vorbeiläuft.', 'rh-hardening'),
            HardeningGroup::FIELD_SESSION_HARDENING => __('Wirft bei jedem Passwortwechsel alle anderen Geräte hinaus.', 'rh-hardening'),
            HardeningGroup::FIELD_DISALLOW_FILE_EDIT => __('Nimmt den Datei-Editor aus dem Backend.', 'rh-hardening'),
            HardeningGroup::FIELD_DISALLOW_FILE_MODS => __('Sperrt jede Installation und jedes Update, auch automatische.', 'rh-hardening'),
            HardeningGroup::FIELD_WATCH_CHANGES => __('Hält fest, wer Plugins, Themes und Konten verändert.', 'rh-hardening'),
            HardeningGroup::FIELD_RADAR => __('Prüft täglich, ob für die installierte Software Lücken bekannt sind.', 'rh-hardening'),
            HardeningGroup::FIELD_DEMOTE_ROGUE_ADMIN => __('Setzt einen neu aufgetauchten Administrator sofort zurück.', 'rh-hardening'),
            HardeningGroup::FIELD_NOTIFY => __('Schickt Auffälligkeiten per Mail heraus.', 'rh-hardening'),
        ];
    }

    /**
     * Felder, die hinter dem Zahnrad noch etwas einzustellen haben.
     *
     * @return array<string, array<int, string>>
     */
    public static function extras(): array
    {
        return [
            HardeningGroup::FIELD_REST_MODE => [
                HardeningGroup::FIELD_REST_MODE,
                HardeningGroup::FIELD_REST_ALLOWLIST,
            ],
            HardeningGroup::FIELD_CSP_MODE => [
                HardeningGroup::FIELD_CSP_MODE,
                HardeningGroup::FIELD_CSP_POLICY,
            ],
            HardeningGroup::FIELD_NOTIFY => [
                HardeningGroup::FIELD_NOTIFY_EMAIL,
            ],
        ];
    }
}
