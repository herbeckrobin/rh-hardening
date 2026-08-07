<?php

declare(strict_types=1);

namespace RhHardening\Watch;

use RhHardening\Admin\HardeningGroup;
use RhHardening\Log\Event;
use RhHardening\Log\EventLog;
use WP_User;

/**
 * Beobachtet die Vorgänge, an denen man eine Übernahme zuerst sieht.
 *
 * Reihenfolge nach Praxiswert: ein neu angelegter Administrator und eine
 * heimlich aktivierte Plugin-Datei sind die zwei Signale, die fast jede
 * Angriffskette hinterlässt, egal welche Lücke davor stand.
 *
 * Das Modul meldet und greift nicht ein. Die einzige Ausnahme ist das
 * Zurückstufen eines neuen Administrators, und die ist per Default aus und
 * dreifach gesichert (siehe canDemote).
 */
final class ChangeWatch
{
    /** Schutz gegen die Rekursion, die set_role auslösen würde. */
    private bool $demoting = false;

    public function boot(): void
    {
        // Die Haken hängen bewusst früh und ohne Blick auf den Schalter: der
        // Core ist auf plugins_loaded noch nicht da. Ob gemeldet wird,
        // entscheidet jeder Handler selbst, kurz bevor er schreibt.
        add_action('activated_plugin', [$this, 'onPluginActivated'], 10, 1);
        add_action('deactivated_plugin', [$this, 'onPluginDeactivated'], 10, 1);
        add_action('switch_theme', [$this, 'onThemeSwitched'], 10, 1);

        // Rollen: einmal beim Anlegen, einmal bei jeder späteren Änderung.
        add_action('user_register', [$this, 'onUserRegistered'], 10, 1);
        add_action('set_user_role', [$this, 'onRoleChanged'], 10, 3);
    }

    public function onPluginActivated(string $plugin): void
    {
        if (! $this->enabled()) {
            return;
        }

        EventLog::record(Event::warn(
            Event::TYPE_PLUGIN_ACTIVATED,
            sprintf(
                /* translators: %s: Plugin-Datei */
                __('Plugin aktiviert: %s', 'rh-hardening'),
                $plugin
            ),
            ['plugin' => $plugin, 'durch' => $this->actor()]
        ));
    }

    public function onPluginDeactivated(string $plugin): void
    {
        if (! $this->enabled()) {
            return;
        }

        EventLog::record(Event::info(
            Event::TYPE_PLUGIN_DEACTIVATED,
            sprintf(
                /* translators: %s: Plugin-Datei */
                __('Plugin deaktiviert: %s', 'rh-hardening'),
                $plugin
            ),
            ['plugin' => $plugin, 'durch' => $this->actor()]
        ));
    }

    public function onThemeSwitched(string $newName): void
    {
        if (! $this->enabled()) {
            return;
        }

        EventLog::record(Event::warn(
            Event::TYPE_THEME_SWITCHED,
            sprintf(
                /* translators: %s: Name des Themes */
                __('Theme gewechselt zu: %s', 'rh-hardening'),
                $newName
            ),
            ['theme' => $newName, 'durch' => $this->actor()]
        ));
    }

    public function onUserRegistered(int $userId): void
    {
        if (! $this->enabled()) {
            return;
        }

        $user = get_userdata($userId);

        if (! $user instanceof WP_User || ! $this->isPrivileged($user)) {
            return;
        }

        $demoted = $this->maybeDemote($userId);

        EventLog::record(Event::critical(
            Event::TYPE_ADMIN_CREATED,
            sprintf(
                /* translators: %s: Benutzername */
                __('Neuer Benutzer mit Administrationsrechten angelegt: %s', 'rh-hardening'),
                $user->user_login
            ),
            [
                'benutzer' => $user->user_login,
                'rollen' => implode(', ', (array) $user->roles),
                'durch' => $this->actor(),
                'reaktion' => $this->reactionLabel($demoted),
            ]
        ));
    }

    /**
     * @param array<int, string> $oldRoles
     */
    public function onRoleChanged(int $userId, string $role, array $oldRoles): void
    {
        if (! $this->enabled() || $this->demoting || ! $this->isPrivilegedRole($role)) {
            return;
        }

        // Beim Anlegen feuert user_register bereits, hier nicht doppelt melden.
        if ($oldRoles === []) {
            return;
        }

        // War der Benutzer vorher schon Administrator, ist das keine Hochstufung.
        // Ohne diese Prüfung würde jedes Speichern eines Admin-Profils melden.
        foreach ($oldRoles as $oldRole) {
            if ($this->isPrivilegedRole((string) $oldRole)) {
                return;
            }
        }

        $demoted = $this->maybeDemote($userId);

        $user = get_userdata($userId);
        $login = $user instanceof WP_User ? $user->user_login : (string) $userId;

        EventLog::record(Event::critical(
            Event::TYPE_ROLE_ESCALATED,
            sprintf(
                /* translators: 1: Benutzername, 2: neue Rolle */
                __('Benutzer %1$s auf die Rolle %2$s hochgestuft', 'rh-hardening'),
                $login,
                $role
            ),
            [
                'benutzer' => $login,
                'neue_rolle' => $role,
                'alte_rollen' => implode(', ', $oldRoles),
                'durch' => $this->actor(),
                'reaktion' => $this->reactionLabel($demoted),
            ]
        ));
    }

    /**
     * Stuft den Benutzer auf Abonnent zurück, wenn der Schalter an ist und alle
     * Sicherungen greifen. Gibt zurück, ob wirklich eingegriffen wurde.
     */
    private function maybeDemote(int $userId): bool
    {
        if (! $this->canDemote($userId)) {
            return false;
        }

        $user = get_userdata($userId);

        if (! $user instanceof WP_User) {
            return false;
        }

        // set_role feuert set_user_role erneut, deshalb der Riegel.
        $this->demoting = true;
        $user->set_role('subscriber');
        $this->demoting = false;

        // Wer schon eine Sitzung hat, verliert sie mit der Rolle.
        \WP_Session_Tokens::get_instance($userId)->destroy_all();

        return true;
    }

    /**
     * Drei Sicherungen, damit der Schalter niemanden aussperrt:
     *
     *   1. Super-Admins im Netzwerk bleiben unangetastet.
     *   2. Vorgänge über WP-CLI sind Deployment, kein Angriff.
     *   3. Es muss danach noch mindestens ein Administrator übrig bleiben.
     */
    private function canDemote(int $userId): bool
    {
        if (! (bool) rhbp_setting(HardeningGroup::GROUP_ID, HardeningGroup::FIELD_DEMOTE_ROGUE_ADMIN, false)) {
            return false;
        }

        if (defined('WP_CLI') && WP_CLI) {
            return false;
        }

        if (is_multisite() && is_super_admin($userId)) {
            return false;
        }

        return $this->otherAdministratorsExist($userId);
    }

    /**
     * Gibt es außer diesem Benutzer noch einen Administrator?
     */
    private function otherAdministratorsExist(int $userId): bool
    {
        $admins = get_users([
            'role' => 'administrator',
            'exclude' => [$userId],
            'number' => 1,
            'fields' => 'ID',
        ]);

        return $admins !== [];
    }

    private function reactionLabel(bool $demoted): string
    {
        return $demoted
            ? __('auf Abonnent zurückgestuft und Sitzungen beendet', 'rh-hardening')
            : __('nur gemeldet, nichts verändert', 'rh-hardening');
    }

    private function enabled(): bool
    {
        return function_exists('rhbp_setting')
            && (bool) rhbp_setting(HardeningGroup::GROUP_ID, HardeningGroup::FIELD_WATCH_CHANGES, true);
    }

    private function isPrivileged(WP_User $user): bool
    {
        foreach ((array) $user->roles as $role) {
            if ($this->isPrivilegedRole((string) $role)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Administrator und (im Netzwerk) Super-Admin. Editor bewusst nicht, das
     * wäre in einer Redaktion Dauerlärm.
     */
    private function isPrivilegedRole(string $role): bool
    {
        return in_array($role, ['administrator'], true);
    }

    /**
     * Wer den Vorgang ausgelöst hat, als Klartext für die Mail.
     * Ohne eingeloggten Benutzer ist das der interessante Fall.
     */
    private function actor(): string
    {
        if (defined('WP_CLI') && WP_CLI) {
            return 'WP-CLI';
        }

        $user = wp_get_current_user();

        if ($user instanceof WP_User && $user->ID > 0) {
            return $user->user_login;
        }

        return __('niemand eingeloggt', 'rh-hardening');
    }
}
