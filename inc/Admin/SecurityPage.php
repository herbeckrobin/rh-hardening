<?php

declare(strict_types=1);

namespace RhHardening\Admin;

use RhBlueprint\Core\Settings\SettingField;
use RhBlueprint\Core\Settings\SettingsHub;
use RhBlueprint\Core\Settings\SettingsPage;

/**
 * Der Sicherheits-Tab.
 *
 * Bewusst NICHT über die GroupInterface-Automatik des Core: die rendert eine
 * Formularliste, und sechzehn Schalter untereinander sind unbrauchbar. Hier
 * wird selbst gerendert, gespeichert wird weiter in dieselbe Option
 * (rhbp_settings_hardening), damit rhbp_setting() unverändert funktioniert.
 * Dasselbe Muster wie in rh-tracking.
 *
 * Jede Zeile zeigt Name, einen Satz Erklärung und einen Schalter. Was darüber
 * hinausgeht, sitzt hinter dem Zahnrad. So bleibt die Seite auf einen Blick
 * lesbar und die Einzelheiten sind trotzdem einen Klick entfernt.
 */
final class SecurityPage
{
    public const ACTION_TOGGLE = 'rh_hardening_toggle';
    public const ACTION_SAVE = 'rh_hardening_save';

    public function boot(): void
    {
        add_action('admin_post_' . self::ACTION_TOGGLE, [$this, 'handleToggle']);
        add_action('admin_post_' . self::ACTION_SAVE, [$this, 'handleSave']);
    }

    /**
     * Die Zeilen und Modals des aktuellen Bereichs.
     */
    public function renderSettings(string $tab): void
    {
        foreach (Sections::groupsFor($tab) as $group) {
            printf(
                '<div class="rhhard-group"><h3 class="rhhard-group__title">%s</h3><p class="rhhard-group__hint">%s</p>',
                esc_html($group['titel']),
                esc_html($group['hinweis'])
            );

            echo '<div class="rhhard-rows">';

            foreach ($group['felder'] as $fieldId) {
                $this->renderRow($fieldId);
            }

            echo '</div></div>';
        }

        foreach (Sections::groupsFor($tab) as $group) {
            foreach ($group['felder'] as $fieldId) {
                if (isset(Sections::extras()[$fieldId])) {
                    $this->renderModal($fieldId);
                }
            }
        }
    }

    private function renderRow(string $fieldId): void
    {
        $field = $this->field($fieldId);

        if ($field === null) {
            return;
        }

        $isSelect = $field->type === SettingField::TYPE_SELECT;
        $value = $this->value($fieldId);
        $on = $isSelect ? ((string) $value !== 'off') : (bool) $value;

        echo '<div class="rhbp-card rhhard-row">';

        echo '<div class="rhhard-row__text">';
        printf('<strong class="rhhard-row__name">%s</strong>', esc_html($field->label));
        printf('<span class="rhhard-row__desc">%s</span>', esc_html($this->shortDescription($field)));
        echo '</div>';

        echo '<div class="rhhard-row__actions">';

        // Drei feste Spalten, damit die Kanten über alle Zeilen fluchten:
        // Zusatz, Schalter, Zahnrad. Wo nichts hingehört, bleibt der Platz leer.
        printf('<span class="rhhard-row__note">%s</span>', $this->note($fieldId, $on, $value));
        // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- toggleForm() baut sein Markup aus escapten Teilen.
        echo $this->toggleForm($fieldId, $on, $isSelect);
        echo '<span class="rhhard-row__gear">';

        if (isset(Sections::extras()[$fieldId])) {
            printf(
                '<button type="button" class="rhbp-btn rhbp-btn--icon" data-rhbp-modal-open="%s" title="%s" aria-label="%s">%s</button>',
                esc_attr('rhhard-' . $fieldId),
                esc_attr__('Einstellungen', 'rh-hardening'),
                esc_attr__('Einstellungen', 'rh-hardening'),
                $this->gearIcon()
            );
        }

        echo '</span>';
        echo '</div>';
        echo '</div>';
    }

    /**
     * Der Schalter schickt sich selbst ab, damit kein Speichern-Knopf nötig ist.
     */
    private function toggleForm(string $fieldId, bool $on, bool $isSelect): string
    {
        ob_start();

        printf('<form method="post" action="%s" class="rhbp-toggle-form">', esc_url(admin_url('admin-post.php')));
        wp_nonce_field(self::ACTION_TOGGLE);
        printf('<input type="hidden" name="action" value="%s" />', esc_attr(self::ACTION_TOGGLE));
        printf('<input type="hidden" name="feld" value="%s" />', esc_attr($fieldId));
        printf('<input type="hidden" name="sub" value="%s" />', esc_attr(Sections::current()));
        printf('<input type="hidden" name="auswahl" value="%s" />', $isSelect ? '1' : '0');
        printf(
            '<label class="rhbp-switch"><input type="checkbox" name="an" value="1" %s onchange="this.form.submit()" /><span class="rhbp-switch__track" aria-hidden="true"></span></label>',
            checked($on, true, false)
        );
        echo '</form>';

        return (string) ob_get_clean();
    }

    /**
     * Ein kurzer Zusatz rechts, aber nur wo er etwas sagt, das der Schalter
     * nicht schon zeigt. Ein "an" neben einem eingeschalteten Schalter ist
     * doppelt und macht die Zeile nur unruhig.
     */
    private function note(string $fieldId, bool $on, mixed $value): string
    {
        if (! $on) {
            return '';
        }

        // Beim Auswahlfeld ist die Stufe die eigentliche Information.
        if ($fieldId === HardeningGroup::FIELD_REST_MODE) {
            $label = (string) $value === 'strict'
                ? __('streng', 'rh-hardening')
                : __('standard', 'rh-hardening');

            return '<span class="rhbp-pill rhbp-pill--ok"><span class="rhbp-pill__dot"></span>' . esc_html($label) . '</span>';
        }

        return '';
    }

    /**
     * Alles, was über den Schalter hinausgeht, sitzt hier.
     */
    private function renderModal(string $fieldId): void
    {
        $extras = Sections::extras()[$fieldId] ?? [];

        if ($extras === []) {
            return;
        }

        $base = $this->field($fieldId);

        // Das Core-JS findet das Modal über die id und schaltet die Klasse
        // is-open. Kein hidden-Attribut dazu: das gewinnt gegen die Klasse und
        // das Modal bliebe unsichtbar.
        printf('<div class="rhbp-modal-backdrop" id="%s">', esc_attr('rhhard-' . $fieldId));
        echo '<div class="rhbp-modal">';
        printf('<form method="post" action="%s">', esc_url(admin_url('admin-post.php')));
        wp_nonce_field(self::ACTION_SAVE);
        printf('<input type="hidden" name="action" value="%s" />', esc_attr(self::ACTION_SAVE));
        printf('<input type="hidden" name="sub" value="%s" />', esc_attr(Sections::current()));

        echo '<div class="rhbp-modal__head"><div class="rhbp-modal__head-l">';
        printf('<h2 class="rhbp-modal__title">%s</h2>', esc_html($base?->label ?? ''));
        echo '</div>';
        printf(
            '<button type="button" class="rhbp-btn rhbp-btn--icon" data-rhbp-modal-close aria-label="%s">&times;</button>',
            esc_attr__('Schließen', 'rh-hardening')
        );
        echo '</div>';

        echo '<div class="rhbp-modal__body">';

        foreach ($extras as $extraId) {
            $field = $this->field($extraId);

            if ($field === null) {
                continue;
            }

            echo '<div class="rhbp-field">';

            // Trägt das Feld denselben Namen wie das Modal, wäre die
            // Beschriftung eine Doppelung.
            if ($field->label !== ($base?->label ?? '')) {
                printf('<label for="%s"><strong>%s</strong></label>', esc_attr($extraId), esc_html($field->label));
            }

            $field->render($extraId, $this->value($extraId));
            echo '</div>';
        }

        echo '</div>';

        echo '<div class="rhbp-modal__foot">';
        printf(
            '<button type="button" class="rhbp-btn rhbp-btn--ghost" data-rhbp-modal-close>%s</button>',
            esc_html__('Abbrechen', 'rh-hardening')
        );
        printf('<button type="submit" class="rhbp-btn rhbp-btn--primary">%s</button>', esc_html__('Speichern', 'rh-hardening'));
        echo '</div>';

        echo '</form></div></div>';
    }

    public function handleToggle(): void
    {
        $this->guard(self::ACTION_TOGGLE);

        $fieldId = isset($_POST['feld']) ? sanitize_key((string) wp_unslash($_POST['feld'])) : '';
        $field = $this->field($fieldId);

        if ($field === null) {
            $this->back();
        }

        $on = ! empty($_POST['an']);

        // Ein Auswahlfeld kennt kein An und Aus, deshalb bedeutet der Schalter
        // dort: zurück auf den Standard, oder ganz abschalten.
        if (! empty($_POST['auswahl'])) {
            $this->store($fieldId, $on ? (string) $field->default : 'off');
        } else {
            $this->store($fieldId, $on);
        }

        $this->back();
    }

    public function handleSave(): void
    {
        $this->guard(self::ACTION_SAVE);

        foreach (Sections::extras() as $extras) {
            foreach ($extras as $extraId) {
                if (! array_key_exists($extraId, $_POST)) {
                    continue;
                }

                $field = $this->field($extraId);

                if ($field === null) {
                    continue;
                }

                $this->store($extraId, $field->sanitize(wp_unslash($_POST[$extraId])));
            }
        }

        $this->back();
    }

    /**
     * Schreibt in dieselbe Option, die auch die Core-Automatik nutzt.
     */
    private function store(string $fieldId, mixed $value): void
    {
        $option = SettingsHub::optionName(HardeningGroup::GROUP_ID);
        $stored = get_option($option, []);
        $stored = is_array($stored) ? $stored : [];
        $stored[$fieldId] = $value;

        update_option($option, $stored);
    }

    private function value(string $fieldId): mixed
    {
        $field = $this->field($fieldId);

        return rhbp_setting(HardeningGroup::GROUP_ID, $fieldId, $field?->default ?? '');
    }

    private function field(string $fieldId): ?SettingField
    {
        static $map = null;

        if ($map === null) {
            $map = [];

            foreach ((new HardeningGroup())->fields() as $field) {
                $map[$field->id] = $field;
            }
        }

        return $map[$fieldId] ?? null;
    }

    /**
     * In der Zeile steht ein knapper Satz, damit alle Zeilen gleich hoch sind.
     * Fehlt einer, wird der erste Satz der langen Beschreibung genommen.
     */
    private function shortDescription(SettingField $field): string
    {
        $short = Sections::shortTexts()[$field->id] ?? '';

        if ($short !== '') {
            return $short;
        }

        $parts = preg_split('/(?<=\.)\s+/', $field->description, 2);

        return trim($parts[0] ?? $field->description);
    }

    private function guard(string $action): void
    {
        if (! current_user_can('manage_options')) {
            wp_die(esc_html__('Dazu fehlen die Rechte.', 'rh-hardening'), '', ['response' => 403]);
        }

        check_admin_referer($action);
    }

    private function back(): never
    {
        $sub = isset($_POST['sub']) ? sanitize_key((string) wp_unslash($_POST['sub'])) : Sections::TAB_OVERVIEW;

        wp_safe_redirect(self::url($sub));
        exit;
    }

    public static function url(string $sub): string
    {
        return admin_url(sprintf(
            'admin.php?page=%s&tab=%s&sub=%s',
            SettingsPage::MENU_SLUG,
            HardeningGroup::GROUP_ID,
            $sub
        ));
    }

    private function gearIcon(): string
    {
        return '<svg class="rhbp-ico" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.6a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>';
    }
}
