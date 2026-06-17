# RH Hardening

Security-Baseline für jede produktive WordPress-Site. Teil der rh-blueprint Kollektion.

Bündelt die Härtungs-Maßnahmen, die sonst in jeder `functions.php` wieder von Hand landen, als ein- und ausschaltbare Bausteine. Alle Maßnahmen sind per Default an, weil sie der Standard für eine Live-Site sind.

## Was es macht

- **User-Enumeration blocken**: sperrt `/wp-json/wp/v2/users` und `?author=N` / `/author/<slug>/` für nicht eingeloggte Besucher, damit Login-Namen nicht auslesbar sind (Brute-Force-Schutz).
- **Feeds deaktivieren**: RSS/Atom-Feeds liefern 404, sinnvoll bei Sites ohne Blog.
- **Security-Header**: `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `X-Frame-Options` und HSTS (nur über HTTPS), plus Entfernen von `X-Powered-By`. Fallback, falls der Server die Header nicht selbst setzt.
- **WP-Schmodder entfernen**: Generator-Tag, WLW-Manifest, RSD-Link, Shortlink, Feed-Links und das Emoji-Script raus dem `<head>`.
- **XML-RPC deaktivieren**: schließt einen häufigen Brute-Force- und Pingback-Vektor.

Die Hook-Reihenfolge ist bewusst gewählt: `?author=` läuft auf `parse_request` (vor dem Canonical-Redirect, der den Namen sonst leakt), Feeds auf `template_redirect`.

## Einstellungen

Im Backend unter **RH Blueprint → Sicherheit**. Jede der fünf Maßnahmen ist einzeln abschaltbar, falls ein Baustein bewusst nicht gewünscht ist.

## Installation

ZIP unter **Plugins → Plugin hochladen** installieren und aktivieren. Der geteilte Core ist gebündelt, keine weitere Installation nötig.

## Voraussetzungen

WordPress 6.5+, PHP 8.1+.
