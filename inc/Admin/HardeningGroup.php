<?php

declare(strict_types=1);

namespace RhHardening\Admin;

use RhBlueprint\Core\Settings\GroupInterface;
use RhBlueprint\Core\Settings\SettingField;

/**
 * Settings-Gruppe für das Security-Hardening.
 *
 * Anders als die Admin-Eingriffe des Core sind diese Schalter per Default AN:
 * Hardening ist der Standard für jede produktive Site, abschalten ist die Ausnahme.
 * Der Core rendert die Gruppe automatisch unter dem Tab "Sicherheit".
 */
final class HardeningGroup implements GroupInterface
{
    public const GROUP_ID = 'hardening';

    public const FIELD_BLOCK_USER_ENUM = 'block_user_enum';
    public const FIELD_DISABLE_FEEDS = 'disable_feeds';
    public const FIELD_SECURITY_HEADERS = 'security_headers';
    public const FIELD_REMOVE_CLUTTER = 'remove_clutter';
    public const FIELD_DISABLE_XMLRPC = 'disable_xmlrpc';

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
        return __('Standard-Sicherheitsmaßnahmen für jede produktive Site. Alle sind per Default an und sollten nur abgeschaltet werden, wenn ein Baustein bewusst nicht gewünscht ist.', 'rh-hardening');
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
        ];
    }
}
