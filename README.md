# RH Hardening

Security-Baseline für jede produktive WordPress-Site. Teil der rh-blueprint Kollektion.

Bündelt die Härtungs-Maßnahmen, die sonst in jeder `functions.php` wieder von Hand landen, als ein- und ausschaltbare Bausteine. Alle Maßnahmen sind per Default an, weil sie der Standard für eine Live-Site sind.

## Was es macht

- **User-Enumeration blocken**: sperrt `/wp-json/wp/v2/users` und `?author=N` / `/author/<slug>/` für nicht eingeloggte Besucher, damit Login-Namen nicht auslesbar sind (Brute-Force-Schutz).
- **Feeds deaktivieren**: RSS/Atom-Feeds liefern 404, sinnvoll bei Sites ohne Blog.
- **Security-Header**: `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `X-Frame-Options` und HSTS (nur über HTTPS), plus Entfernen von `X-Powered-By`. Fallback, falls der Server die Header nicht selbst setzt.
- **WP-Schmodder entfernen**: Generator-Tag, WLW-Manifest, RSD-Link, Shortlink, Feed-Links und das Emoji-Script raus dem `<head>`.
- **XML-RPC deaktivieren**: schließt einen häufigen Brute-Force- und Pingback-Vektor.
- **Content-Security-Policy**: sagt dem Browser, aus welchen Quellen er laden darf. Der einzige Header, der Cross-Site-Scripting wirklich stoppt.

Die Hook-Reihenfolge ist bewusst gewählt: `?author=` läuft auf `parse_request` (vor dem Canonical-Redirect, der den Namen sonst leakt), Feeds auf `template_redirect`.

## Die Policy einführen

Eine Content-Security-Policy lässt sich nicht am Schreibtisch schreiben. Wer sie blind scharf schaltet, sperrt zuverlässig die halbe Website aus, weil jedes Formular-Plugin und jede eingebundene Schriftart eine eigene Quelle mitbringt. Deshalb drei Stufen und ein Weg dazwischen:

1. **Einschalten.** Der Schalter setzt den beobachtenden Modus und startet die Sammlung für drei Tage. An der Website ändert sich nichts, der Browser meldet nur, was die Regeln blockiert hätten.
2. **Warten und die Website benutzen.** Formulare abschicken, Shop-Seiten öffnen, alles anfassen, was Besucher auch anfassen. Was nie aufgerufen wird, taucht auch nicht auf.
3. **Vorschlag ansehen.** Hinter dem Zahnrad steht, was gesammelt wurde, und die daraus gebauten Regeln. Das ist der Ist-Zustand, nicht der Soll-Zustand: eine fremde Quelle in dieser Liste kann genauso gut der Einbruch sein, den die Policy verhindern soll. Prüfen, dann übernehmen.
4. **Scharf schalten.** Erst jetzt.

Die Sammlung schaltet sich nach drei Tagen von allein ab, und mit ihr verschwindet der Meldeweg. Ein dauerhaft offener Endpunkt, den jeder beschreiben kann, wäre genau die Angriffsfläche, die dieses Modul sonst wegnimmt.

Gespeichert wird nur, welche Regel welche Quelle wie oft betraf. Keine Adressparameter, keine Verweisquelle, keine Herkunft der Besucher. Damit braucht die Sammlung keinen Eintrag in der Datenschutzerklärung.

## Einstellungen

Im Backend unter **RH Blueprint → Sicherheit**. Jede der fünf Maßnahmen ist einzeln abschaltbar, falls ein Baustein bewusst nicht gewünscht ist.

## Installation

ZIP unter **Plugins → Plugin hochladen** installieren und aktivieren. Der geteilte Core ist gebündelt, keine weitere Installation nötig.

## Voraussetzungen

WordPress 6.5+, PHP 8.1+.
