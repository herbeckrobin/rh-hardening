<?php

declare(strict_types=1);

namespace RhHardening\Admin;

use RhBlueprint\Core\Settings\GroupInterface;
use RhBlueprint\Core\Settings\SettingField;
use RhHardening\Prevention\RestGate;

/**
 * Settings-Gruppe für das Security-Hardening.
 *
 * Anders als die Admin-Eingriffe des Core sind diese Schalter per Default AN:
 * Hardening ist der Standard für jede produktive Site, abschalten ist die Ausnahme.
 * Die zwei Ausnahmen von dieser Regel sind bewusst gesetzt und unten begründet.
 * Der Core rendert die Gruppe automatisch unter dem Tab "Sicherheit".
 */
final class HardeningGroup implements GroupInterface
{
    public const GROUP_ID = 'hardening';

    // Bestand
    public const FIELD_BLOCK_USER_ENUM = 'block_user_enum';
    public const FIELD_DISABLE_FEEDS = 'disable_feeds';
    public const FIELD_SECURITY_HEADERS = 'security_headers';
    public const FIELD_REMOVE_CLUTTER = 'remove_clutter';
    public const FIELD_DISABLE_XMLRPC = 'disable_xmlrpc';

    // Angriffsfläche
    public const FIELD_SHIELD = 'shield';
    public const FIELD_REST_MODE = 'rest_mode';
    public const FIELD_REST_ALLOWLIST = 'rest_allowlist';
    public const FIELD_DISABLE_APP_PASSWORDS = 'disable_app_passwords';
    public const FIELD_UPLOADS_NO_PHP = 'uploads_no_php';
    public const FIELD_SESSION_HARDENING = 'session_hardening';
    public const FIELD_DISALLOW_FILE_EDIT = 'disallow_file_edit';
    public const FIELD_DISALLOW_FILE_MODS = 'disallow_file_mods';

    // Radar
    public const FIELD_RADAR = 'radar';

    // Chronik und Meldung
    public const FIELD_WATCH_CHANGES = 'watch_changes';
    public const FIELD_DEMOTE_ROGUE_ADMIN = 'demote_rogue_admin';
    public const FIELD_NOTIFY = 'notify';
    public const FIELD_NOTIFY_EMAIL = 'notify_email';

    public function id(): string
    {
        return self::GROUP_ID;
    }

    public function tab(): string
    {
        return 'hardening';
    }

    public function title(): string
    {
        return __('Hardening', 'rh-hardening');
    }

    public function description(): string
    {
        return __('Standard-Sicherheitsvorkehrungen für jede produktive Site. Die meisten sind per Default an und sollten nur abgeschaltet werden, wenn ein Baustein bewusst nicht gewünscht ist. Dieses Modul verändert die Website nie von sich aus: es sperrt, was hier eingestellt ist, und meldet alles andere.', 'rh-hardening');
    }

    public function fields(): array
    {
        return [
            new SettingField(
                id: self::FIELD_BLOCK_USER_ENUM,
                type: SettingField::TYPE_BOOLEAN,
                label: __('User-Enumeration blocken', 'rh-hardening'),
                description: __('Sperrt die REST-Endpoints /wp/v2/users sowie ?author=N und /author/<slug>/ für nicht eingeloggte Besucher. Verhindert, dass Login-Namen auslesbar sind.', 'rh-hardening'),
                default: true,
                keywords: ['user', 'enumeration', 'author', 'rest', 'brute force', 'login'],
            ),
            new SettingField(
                id: self::FIELD_SHIELD,
                type: SettingField::TYPE_BOOLEAN,
                label: __('Schutzwall vor WordPress', 'rh-hardening'),
                description: __('Legt eine kleine Datei in mu-plugins ab, die Aufrufe prüft, bevor WordPress die REST-Schnittstelle überhaupt aufbaut. Nur so lässt sich eine Lücke abfangen, die wie wp2shell mitten in der Verarbeitung zuschlägt. Die Datei wird bei jedem Update neu ausgelegt, ihr Zustand steht unten. Wird sie verändert, meldet das Modul das als Verdachtsfall.', 'rh-hardening'),
                default: true,
                keywords: ['firewall', 'waf', 'mu-plugin', 'shield', 'wp2shell', 'batch'],
            ),
            new SettingField(
                id: self::FIELD_REST_MODE,
                type: SettingField::TYPE_SELECT,
                label: __('REST-Schnittstelle für Gäste', 'rh-hardening'),
                description: __('Standard sperrt die bekannten Problem-Routen, darunter /wp-json/batch/v1, über die im Juli 2026 die wp2shell-Kette lief. Streng dreht das um: Gäste erreichen nur noch, was unten auf der Liste steht. Streng ist wirksamer, braucht aber einen Durchlauf über die Website, weil Formular- und Shop-Plugins eigene Namensräume mitbringen. Was abgewiesen wird, steht in der Chronik.', 'rh-hardening'),
                default: RestGate::MODE_STANDARD,
                choices: [
                    RestGate::MODE_OFF => __('Aus, alles offen wie bei WordPress', 'rh-hardening'),
                    RestGate::MODE_STANDARD => __('Standard, bekannte Problem-Routen sperren', 'rh-hardening'),
                    RestGate::MODE_STRICT => __('Streng, nur die Liste unten erlauben', 'rh-hardening'),
                ],
                keywords: ['rest', 'api', 'batch', 'wp2shell', 'wp-json', 'namespace'],
            ),
            new SettingField(
                id: self::FIELD_REST_ALLOWLIST,
                type: SettingField::TYPE_TEXTAREA,
                label: __('Erlaubte Namensräume (nur im strengen Modus)', 'rh-hardening'),
                description: __('Ein Namensraum pro Zeile, zum Beispiel contact-form-7/v1 oder wc/store. oembed/1.0 ist immer erlaubt. Nach dem Umschalten auf Streng zeigt die Chronik innerhalb eines Tages, was hier noch fehlt.', 'rh-hardening'),
                default: '',
                keywords: ['namespace', 'allowlist', 'rest', 'ausnahme'],
            ),
            new SettingField(
                id: self::FIELD_DISABLE_APP_PASSWORDS,
                type: SettingField::TYPE_BOOLEAN,
                label: __('Anwendungspasswörter abschalten', 'rh-hardening'),
                description: __('Anwendungspasswörter sind seit WordPress 5.6 ein zweiter Anmeldeweg über die REST-Schnittstelle, an dem Login-Sperren und Zwei-Faktor vorbeilaufen. Nur einschalten lassen, wenn ein externes System sich wirklich anmelden muss.', 'rh-hardening'),
                default: true,
                keywords: ['application password', 'anwendungspasswort', 'rest', 'login', 'api'],
            ),
            new SettingField(
                id: self::FIELD_UPLOADS_NO_PHP,
                type: SettingField::TYPE_BOOLEAN,
                label: __('PHP im Upload-Verzeichnis sperren', 'rh-hardening'),
                description: __('Schreibt eine .htaccess, die den Aufruf von PHP-Dateien unter wp-content/uploads verbietet. Der Zustand wird zusätzlich mit einem echten Aufruf geprüft und unten angezeigt, denn auf Nginx muss die Regel in die Server-Konfiguration.', 'rh-hardening'),
                default: true,
                keywords: ['uploads', 'php', 'htaccess', 'webshell', 'backdoor'],
            ),
            new SettingField(
                id: self::FIELD_SESSION_HARDENING,
                type: SettingField::TYPE_BOOLEAN,
                label: __('Sitzungen härten', 'rh-hardening'),
                description: __('Beendet bei jedem Passwortwechsel alle übrigen Sitzungen und verkürzt die Cookie-Laufzeit auf zwölf Stunden, mit "angemeldet bleiben" auf sieben Tage. Nimmt einem gestohlenen Cookie den Wert.', 'rh-hardening'),
                default: true,
                keywords: ['session', 'cookie', 'logout', 'passwort'],
            ),
            new SettingField(
                id: self::FIELD_DISALLOW_FILE_EDIT,
                type: SettingField::TYPE_BOOLEAN,
                label: __('Datei-Editor im Backend sperren', 'rh-hardening'),
                description: __('Der Editor unter Design und Plugins ist der bequemste Weg, aus einem gekaperten Administrator-Konto eine dauerhafte Hintertür zu machen. Für die Pflege einer Website wird er nicht gebraucht.', 'rh-hardening'),
                default: true,
                keywords: ['editor', 'DISALLOW_FILE_EDIT', 'theme editor', 'plugin editor'],
            ),
            new SettingField(
                id: self::FIELD_DISALLOW_FILE_MODS,
                type: SettingField::TYPE_BOOLEAN,
                label: __('Installieren und Aktualisieren komplett sperren', 'rh-hardening'),
                description: __('Sperrt zusätzlich jede Installation und jedes Update über das Backend, auch automatische. Nur für fertig ausgelieferte Websites, deren Pflege über Deployment läuft. Per Default aus, weil das sonst die Sicherheitsupdates mit abschaltet.', 'rh-hardening'),
                default: false,
                keywords: ['DISALLOW_FILE_MODS', 'update', 'install', 'freeze', 'deployment'],
            ),
            new SettingField(
                id: self::FIELD_DISABLE_FEEDS,
                type: SettingField::TYPE_BOOLEAN,
                label: __('Feeds deaktivieren', 'rh-hardening'),
                description: __('Liefert RSS-/Atom-Feeds als 404 aus. Sinnvoll bei Sites ohne Blog, die keine Feeds brauchen.', 'rh-hardening'),
                default: true,
                keywords: ['feed', 'rss', 'atom', '404'],
            ),
            new SettingField(
                id: self::FIELD_SECURITY_HEADERS,
                type: SettingField::TYPE_BOOLEAN,
                label: __('Security-Header setzen', 'rh-hardening'),
                description: __('Setzt X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-Frame-Options und HSTS (nur über HTTPS) und entfernt X-Powered-By. Fallback, falls der Server die Header nicht selbst setzt.', 'rh-hardening'),
                default: true,
                keywords: ['header', 'hsts', 'x-frame', 'referrer', 'permissions', 'csp'],
            ),
            new SettingField(
                id: self::FIELD_REMOVE_CLUTTER,
                type: SettingField::TYPE_BOOLEAN,
                label: __('WP-Schmodder entfernen', 'rh-hardening'),
                description: __('Räumt den <head> auf: Generator-Tag, WLW-Manifest, RSD-Link, Shortlink, Feed-Links und das Emoji-Script raus. Weniger Angriffsfläche und Version-Leak.', 'rh-hardening'),
                default: true,
                keywords: ['generator', 'emoji', 'head', 'wlwmanifest', 'rsd', 'version'],
            ),
            new SettingField(
                id: self::FIELD_DISABLE_XMLRPC,
                type: SettingField::TYPE_BOOLEAN,
                label: __('XML-RPC deaktivieren', 'rh-hardening'),
                description: __('Schaltet die XML-RPC-Schnittstelle ab. Häufiger Vektor für Brute-Force- und Pingback-Angriffe, von modernen Sites praktisch nie gebraucht.', 'rh-hardening'),
                default: true,
                keywords: ['xmlrpc', 'pingback', 'brute force'],
            ),
            new SettingField(
                id: self::FIELD_RADAR,
                type: SettingField::TYPE_BOOLEAN,
                label: __('Auf bekannte Lücken prüfen', 'rh-hardening'),
                description: __('Holt täglich ein Verzeichnis bekannter Schwachstellen und gleicht es gegen die installierten Plugins, Themes und den WordPress-Kern ab. Der Abgleich passiert auf dieser Website; solange nichts zutrifft, verlässt keine Information über sie den Server. Gefunden wird nur gemeldet, eingespielt wird nichts.', 'rh-hardening'),
                default: true,
                keywords: ['feed', 'radar', 'schwachstelle', 'cve', 'wordfence', 'lücke'],
            ),
            new SettingField(
                id: self::FIELD_WATCH_CHANGES,
                type: SettingField::TYPE_BOOLEAN,
                label: __('Chronik führen', 'rh-hardening'),
                description: __('Hält fest, wenn ein Plugin aktiviert, ein Theme gewechselt oder ein Administrator angelegt oder hochgestuft wird. Ein neuer Administrator ist das Signal, das fast jede Übernahme hinterlässt, egal welche Lücke davor stand. Es wird nichts rückgängig gemacht, nur festgehalten und gemeldet.', 'rh-hardening'),
                default: true,
                keywords: ['chronik', 'log', 'audit', 'admin', 'protokoll'],
            ),
            new SettingField(
                id: self::FIELD_DEMOTE_ROGUE_ADMIN,
                type: SettingField::TYPE_BOOLEAN,
                label: __('Neue Administratoren sofort zurückstufen', 'rh-hardening'),
                description: __('Taucht ein neuer Administrator auf oder wird jemand hochgestuft, wird die Rolle sofort auf Abonnent gesetzt und gemeldet. Ein Angreifer verliert damit den Zugang, bevor die Mail gelesen ist. War es ein echter Kollege, setzt man die Rolle mit zwei Klicks zurück. Nie angetastet werden Super-Admins im Netzwerk, Vorgänge über WP-CLI und der letzte verbliebene Administrator. Per Default aus, weil hier als Einziges tatsächlich eingegriffen wird.', 'rh-hardening'),
                default: false,
                keywords: ['admin', 'rogue', 'zurückstufen', 'demote', 'übernahme', 'rolle'],
            ),
            new SettingField(
                id: self::FIELD_NOTIFY,
                type: SettingField::TYPE_BOOLEAN,
                label: __('Per Mail melden', 'rh-hardening'),
                description: __('Kritische Vorgänge gehen sofort raus, alles andere sammelt sich zu einem Wochenbericht. Höchstens zehn Sofortmails pro Stunde, der Rest wandert in den Wochenbericht.', 'rh-hardening'),
                default: true,
                keywords: ['mail', 'benachrichtigung', 'alert', 'bericht'],
            ),
            new SettingField(
                id: self::FIELD_NOTIFY_EMAIL,
                type: SettingField::TYPE_EMAIL,
                label: __('Empfänger', 'rh-hardening'),
                description: __('Leer lassen nimmt die Admin-Adresse der Website. In der Betreuung gehört hier die Adresse des Betreuers hinein, nicht die des Endkunden.', 'rh-hardening'),
                default: '',
                keywords: ['mail', 'empfänger', 'adresse'],
            ),
        ];
    }
}
