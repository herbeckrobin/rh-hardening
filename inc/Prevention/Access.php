<?php

declare(strict_types=1);

namespace RhHardening\Prevention;

use RhHardening\Admin\HardeningGroup;

/**
 * Zugangs-Härtung: die Wege zu, über die ein Angreifer mit gestohlenen oder
 * erratenen Zugangsdaten ins Backend kommt.
 *
 * Drei Eingriffe, die einzeln klein sind und zusammen den Unterschied machen:
 *
 *   Anwendungspasswörter   Seit WordPress 5.6 im Kern, ein zweiter Anmeldeweg
 *                          über die REST-Schnittstelle, an dem Login-Sperren
 *                          und Zwei-Faktor vorbeilaufen. Fast keine Website
 *                          braucht sie.
 *
 *   Sitzungen              Wer ein Passwort ändert, will alle anderen Geräte
 *                          hinauswerfen. WordPress lässt sie sonst offen, ein
 *                          gestohlenes Sitzungs-Cookie bleibt also gültig.
 *
 *   Dateibearbeitung       Der Editor im Backend ist der bequemste Weg, aus
 *                          einem gekaperten Administrator-Konto eine dauerhafte
 *                          Hintertür zu machen.
 */
final class Access
{
    public function boot(): void
    {
        if ($this->enabled(HardeningGroup::FIELD_DISABLE_APP_PASSWORDS)) {
            add_filter('wp_is_application_passwords_available', '__return_false');
        }

        if ($this->enabled(HardeningGroup::FIELD_SESSION_HARDENING)) {
            add_action('after_password_reset', [$this, 'destroyOtherSessions'], 10, 1);
            add_action('profile_update', [$this, 'onProfileUpdate'], 10, 2);
            add_filter('auth_cookie_expiration', [$this, 'cookieLifetime'], 10, 3);
        }

        if ($this->enabled(HardeningGroup::FIELD_DISALLOW_FILE_EDIT)) {
            $this->define('DISALLOW_FILE_EDIT', true);
        }

        if ($this->enabled(HardeningGroup::FIELD_DISALLOW_FILE_MODS, false)) {
            $this->define('DISALLOW_FILE_MODS', true);
        }
    }

    /**
     * Nach einem Passwort-Reset alle übrigen Sitzungen beenden.
     *
     * @param \WP_User $user
     */
    public function destroyOtherSessions($user): void
    {
        if (! $user instanceof \WP_User) {
            return;
        }

        $sessions = \WP_Session_Tokens::get_instance($user->ID);
        $sessions->destroy_all();
    }

    /**
     * Beim Ändern des Passworts im Profil dasselbe. WordPress hält die eigene
     * Sitzung offen, die anderen fliegen raus.
     *
     * @param int      $userId
     * @param \WP_User $oldUserData
     */
    public function onProfileUpdate($userId, $oldUserData): void
    {
        if (! $oldUserData instanceof \WP_User) {
            return;
        }

        $current = get_userdata((int) $userId);

        if (! $current instanceof \WP_User) {
            return;
        }

        if ($current->user_pass === $oldUserData->user_pass) {
            return;
        }

        $sessions = \WP_Session_Tokens::get_instance((int) $userId);

        if ((int) $userId === get_current_user_id()) {
            $sessions->destroy_others(wp_get_session_token());
            return;
        }

        $sessions->destroy_all();
    }

    /**
     * Kürzere Cookie-Laufzeit. Ein gestohlenes Cookie ist damit schneller wertlos.
     * "Angemeldet bleiben" bleibt möglich, nur nicht mehr zwei Wochen lang.
     */
    public function cookieLifetime(int $length, int $userId, bool $remember): int
    {
        return $remember ? (7 * DAY_IN_SECONDS) : (12 * HOUR_IN_SECONDS);
    }

    /**
     * Konstante setzen, ohne eine bereits gesetzte zu überschreiben. Steht sie
     * schon in der wp-config.php, hat die Vorrang.
     */
    private function define(string $name, bool $value): void
    {
        if (! defined($name)) {
            define($name, $value);
        }
    }

    private function enabled(string $field, bool $default = true): bool
    {
        return (bool) rhbp_setting(HardeningGroup::GROUP_ID, $field, $default);
    }
}
