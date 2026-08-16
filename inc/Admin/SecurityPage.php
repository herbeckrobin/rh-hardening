<?php

declare(strict_types=1);

namespace RhHardening\Admin;

use RhBlueprint\Core\Admin\Ui;
use RhBlueprint\Core\Admin\Guard;
use RhBlueprint\Core\Settings\SettingField;
use RhBlueprint\Core\Settings\SettingsHub;
use RhHardening\Csp\Violations;
use RhHardening\Prevention\Csp;
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
                Ui::icon('gear')
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
        echo Ui::switch([
            'name' => 'an',
            'checked' => $on,
            'input' => ['onchange' => 'this.form.submit()'],
        ]);
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

        if ($fieldId === HardeningGroup::FIELD_CSP_MODE) {
            return $this->cspNote((string) $value);
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
     * Bei der Policy zeigt die Pille den Modus und, solange gesammelt wird, wie
     * lange noch. Das ist die Information, die man in der Zeile braucht: läuft
     * das noch, oder muss ich mich jetzt entscheiden.
     */
    private function cspNote(string $modus): string
    {
        if ($modus === Csp::MODE_ENFORCE) {
            return '<span class="rhbp-pill rhbp-pill--ok"><span class="rhbp-pill__dot"></span>'
                . esc_html__('scharf', 'rh-hardening') . '</span>';
        }

        if (! Csp::isCollecting()) {
            return '<span class="rhbp-pill"><span class="rhbp-pill__dot"></span>'
                . esc_html__('beobachtet, Sammlung beendet', 'rh-hardening') . '</span>';
        }

        $rest = Csp::collectingUntil() - time();
        $tage = (int) ceil($rest / DAY_IN_SECONDS);

        return '<span class="rhbp-pill rhbp-pill--warn"><span class="rhbp-pill__dot"></span>'
            . esc_html(sprintf(
                /* translators: %d: Anzahl Tage */
                _n('sammelt, noch %d Tag', 'sammelt, noch %d Tage', $tage, 'rh-hardening'),
                $tage
            ))
            . '</span>';
    }

    /**
     * Der Block unter den Feldern: was gesammelt wurde, der daraus gebaute
     * Vorschlag, und die Knöpfe dazu.
     */
    private function modalExtra(string $fieldId): void
    {
        if ($fieldId !== HardeningGroup::FIELD_CSP_MODE) {
            return;
        }

        $gruppen = Violations::all();
        $laeuft = Csp::isCollecting();

        echo '<div class="rhbp-field">';
        printf('<strong>%s</strong>', esc_html__('Gesammelt', 'rh-hardening'));

        if ($gruppen === []) {
            printf(
                '<p class="description">%s</p>',
                $laeuft
                    ? esc_html__('Noch nichts. Ein paar Seiten der Website aufrufen, dann füllt sich die Liste von allein.', 'rh-hardening')
                    : esc_html__('Nichts gesammelt. Die Sammlung läuft gerade nicht.', 'rh-hardening')
            );
        } else {
            // Häufigstes zuerst, das ist meistens das Wichtigste.
            uasort($gruppen, static fn (array $a, array $b): int => $b['anzahl'] <=> $a['anzahl']);

            echo '<table class="rhbp-table"><thead><tr>';
            printf('<th>%s</th>', esc_html__('Regel', 'rh-hardening'));
            printf('<th>%s</th>', esc_html__('Quelle', 'rh-hardening'));
            printf('<th>%s</th>', esc_html__('Fälle', 'rh-hardening'));
            echo '</tr></thead><tbody>';

            foreach (array_slice($gruppen, 0, 25) as $gruppe) {
                echo '<tr>';
                printf('<td><code>%s</code></td>', esc_html((string) $gruppe['direktive']));
                printf('<td><code>%s</code></td>', esc_html((string) $gruppe['quelle']));
                printf('<td>%s</td>', esc_html((string) $gruppe['anzahl']));
                echo '</tr>';
            }

            echo '</tbody></table>';

            $vorschlag = Violations::suggestion();

            if ($vorschlag !== '') {
                printf('<p><strong>%s</strong></p>', esc_html__('Daraus gebaute Regeln', 'rh-hardening'));
                printf('<pre class="rhbp-codebox">%s</pre>', esc_html($vorschlag));
                printf(
                    '<p class="description">%s</p>',
                    esc_html__('Das ist, was die Website tatsächlich lädt. Ob sie das auch laden soll, entscheidet niemand außer dir: eine fremde Quelle in dieser Liste kann genauso gut der Einbruch sein, den die Policy verhindern soll.', 'rh-hardening')
                );
            }
        }

        echo '<p class="rhhard-actions">';

        if ($laeuft) {
            printf(
                '<button type="submit" name="csp_aktion" value="stop" class="rhbp-btn rhbp-btn--ghost">%s</button> ',
                esc_html__('Sammlung beenden', 'rh-hardening')
            );
        } else {
            printf(
                '<button type="submit" name="csp_aktion" value="start" class="rhbp-btn rhbp-btn--ghost">%s</button> ',
                esc_html(sprintf(
                    /* translators: %d: Anzahl Tage */
                    __('Sammlung starten (%d Tage)', 'rh-hardening'),
                    Csp::COLLECT_DAYS
                ))
            );
        }

        if ($gruppen !== []) {
            printf(
                '<button type="submit" name="csp_aktion" value="uebernehmen" class="rhbp-btn rhbp-btn--ghost">%s</button> ',
                esc_html__('Regeln übernehmen', 'rh-hardening')
            );
            printf(
                '<button type="submit" name="csp_aktion" value="leeren" class="rhbp-btn rhbp-btn--ghost">%s</button>',
                esc_html__('Gesammeltes verwerfen', 'rh-hardening')
            );
        }

        echo '</p></div>';
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

        // Einmal auflösen statt an drei Stellen dieselbe Frage stellen.
        $titel = $base instanceof SettingField ? $base->label : '';

        // Das Formular umschliesst hier den ganzen Dialog, weil der
        // Speichern-Knopf im Fuss sitzt. Deshalb die Adresse an modalOpen und
        // form:true an modalClose, sonst laege der Knopf ausserhalb.
        echo Ui::modalOpen([
            'id' => 'rhhard-' . $fieldId,
            'title' => $titel !== '' ? $titel : __('Einstellungen', 'rh-hardening'),
            'titleTag' => 'h2',
            'icon' => '',
            'form' => admin_url('admin-post.php'),
        ]);

        wp_nonce_field(self::ACTION_SAVE);
        printf('<input type="hidden" name="action" value="%s" />', esc_attr(self::ACTION_SAVE));
        printf('<input type="hidden" name="sub" value="%s" />', esc_attr(Sections::current()));

        foreach ($extras as $extraId) {
            $field = $this->field($extraId);

            if ($field === null) {
                continue;
            }

            echo '<div class="rhbp-field">';

            // Trägt das Feld denselben Namen wie das Modal, wäre die
            // Beschriftung eine Doppelung.
            if ($field->label !== $titel) {
                printf('<label for="%s"><strong>%s</strong></label>', esc_attr($extraId), esc_html($field->label));
            }

            $field->render($extraId, $this->value($extraId));
            echo '</div>';
        }

        $this->modalExtra($fieldId);

        echo Ui::modalClose([
            'primary' => __('Speichern', 'rh-hardening'),
            'cancel' => __('Abbrechen', 'rh-hardening'),
            'form' => true,
        ]);
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
        if ($fieldId === HardeningGroup::FIELD_CSP_MODE) {
            // Beim Einschalten immer der beobachtende Modus, nie sofort scharf.
            // Und die Sammlung läuft mit an, weil ohne sie der Modus nichts
            // bringt: man sähe nicht, was die Regeln blockieren würden.
            if ($on) {
                $this->store($fieldId, Csp::MODE_REPORT);

                // Ohne Regeln geht kein Header raus, also würde auch nichts
                // gemeldet. Ein Schalter, der drei Tage lang nichts sammelt und
                // dabei "sammelt" anzeigt, ist schlimmer als keiner.
                if (trim((string) $this->value(HardeningGroup::FIELD_CSP_POLICY)) === '') {
                    $this->store(HardeningGroup::FIELD_CSP_POLICY, Csp::STARTER_POLICY);
                }

                Csp::startCollecting();
            } else {
                $this->store($fieldId, Csp::MODE_OFF);
                Csp::stopCollecting();
            }

            $this->back();
        }

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

        $this->handleCspAction();

        $this->back();
    }

    /**
     * Die Knöpfe im CSP-Block sitzen im selben Formular wie die Felder, weil
     * ein Formular im Formular nicht zulässig ist. Sie melden sich über einen
     * eigenen Parameter.
     */
    private function handleCspAction(): void
    {
        $aktion = isset($_POST['csp_aktion']) ? sanitize_key((string) wp_unslash($_POST['csp_aktion'])) : '';

        match ($aktion) {
            'start' => Csp::startCollecting(),
            'stop' => Csp::stopCollecting(),
            'leeren' => Violations::clear(),
            'uebernehmen' => $this->applySuggestion(),
            default => null,
        };
    }

    private function applySuggestion(): void
    {
        $vorschlag = Violations::suggestion();

        if ($vorschlag !== '') {
            $this->store(HardeningGroup::FIELD_CSP_POLICY, $vorschlag);
        }
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
        Guard::form($action);
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

}
