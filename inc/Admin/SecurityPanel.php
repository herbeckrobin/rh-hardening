<?php

declare(strict_types=1);

namespace RhHardening\Admin;

use RhBlueprint\Core\Settings\SettingsPage;
use RhHardening\Checks\DocrootHygiene;
use RhHardening\Integrity\HiddenScan;
use RhHardening\Integrity\ScanJob;
use RhHardening\Integrity\ScanRunner;
use RhHardening\Log\Event;
use RhHardening\Log\EventLog;
use RhHardening\Prevention\Uploads;
use RhHardening\Radar\Radar;
use RhHardening\Shield\Rules;
use RhHardening\Shield\Shield;

/**
 * Zustand und Chronik unter dem Tab "Sicherheit".
 *
 * Hängt an `tab_content_after`, nicht an der GroupInterface-Automatik: das hier
 * ist keine Formularmaske, sondern Ausgabe. Baut ausschliesslich auf den
 * Komponenten des Core auf, damit es aussieht wie der Rest der Suite.
 */
final class SecurityPanel
{
    public const ACTION_SCAN = 'rh_hardening_scan';
    public const ACTION_DEEP_SCAN = 'rh_hardening_deep_scan';
    public const ACTION_BASELINE = 'rh_hardening_baseline';
    private const NOTICE_TRANSIENT = 'rhhard_scan_notice';

    public function boot(): void
    {
        add_action('rh-blueprint/settings/tab_content_after', [$this, 'render'], 10, 1);
        add_action('admin_post_' . self::ACTION_SCAN, [$this, 'handleScan']);
        add_action('admin_post_' . self::ACTION_DEEP_SCAN, [$this, 'handleDeepScan']);
        add_action('admin_post_' . self::ACTION_BASELINE, [$this, 'handleBaseline']);
    }

    public function render(string $tabId): void
    {
        if ($tabId !== HardeningGroup::GROUP_ID) {
            return;
        }

        $this->renderNotice();
        $this->renderState();
        $this->renderRadar();
        $this->renderIntegrity();
        $this->renderChronicle();
    }

    /**
     * Bekannte Lücken in der installierten Software.
     */
    private function renderRadar(): void
    {
        $result = Radar::lastResult();

        echo '<div class="rhbp-card">';
        echo '<div class="rhbp-card__head"><h3 class="rhbp-card__title">' . esc_html__('Bekannte Lücken', 'rh-hardening') . '</h3></div>';

        if ($result === null) {
            echo '<p class="rhbp-empty">' . esc_html__('Noch kein Abgleich. Sobald ein Verteiler eingetragen ist, prüft die Website täglich, ob für eines ihrer Plugins, Themes oder den Kern eine Lücke bekannt ist.', 'rh-hardening') . '</p>';
            echo '</div>';

            return;
        }

        $hits = is_array($result['treffer'] ?? null) ? $result['treffer'] : [];

        printf(
            '<p class="rhbp-hint">%s</p>',
            esc_html(sprintf(
                /* translators: 1: Zeitpunkt, 2: Anzahl geprüfter Teile */
                __('Zuletzt am %1$s abgeglichen, %2$d Teile geprüft.', 'rh-hardening'),
                wp_date('d.m.Y H:i', (int) ($result['zeitpunkt'] ?? 0)),
                (int) ($result['geprueft'] ?? 0)
            ))
        );

        if (($result['status'] ?? '') !== 'ok') {
            printf(
                '<div class="rhbp-callout rhbp-callout--warn">%s</div>',
                esc_html(sprintf(
                    /* translators: %s: Grund */
                    __('Der Abgleich lief nicht durch: %s', 'rh-hardening'),
                    (string) $result['status']
                ))
            );
            echo '</div>';

            return;
        }

        if ($hits === []) {
            echo '<div class="rhbp-callout rhbp-callout--success">' . esc_html__('Für keines der installierten Teile ist eine Lücke bekannt.', 'rh-hardening') . '</div>';
            echo '</div>';

            return;
        }

        echo '<table class="rhbp-table"><thead><tr>';
        echo '<th>' . esc_html__('Betroffen', 'rh-hardening') . '</th>';
        echo '<th>' . esc_html__('Einstufung', 'rh-hardening') . '</th>';
        echo '<th>' . esc_html__('Was zu tun ist', 'rh-hardening') . '</th>';
        echo '</tr></thead><tbody>';

        foreach ($hits as $hit) {
            $rating = strtolower((string) ($hit['rating'] ?? ''));
            $pill = in_array($rating, ['critical', 'high'], true)
                ? 'rhbp-pill rhbp-pill--err'
                : 'rhbp-pill rhbp-pill--warn';

            printf(
                '<tr><td><strong>%s</strong> %s<br><span class="rhbp-hint">%s</span></td><td><span class="%s"><span class="rhbp-pill__dot"></span>%s</span></td><td>%s</td></tr>',
                esc_html((string) $hit['name']),
                esc_html((string) $hit['version']),
                esc_html(mb_substr((string) $hit['titel'], 0, 90)),
                esc_attr($pill),
                esc_html((string) ($hit['rating'] ?: '?')),
                esc_html(! empty($hit['patch_verfuegbar'])
                    ? sprintf(__('Update auf %s', 'rh-hardening'), (string) $hit['gefixt_in'])
                    : __('Noch kein Fix verfügbar', 'rh-hardening'))
            );
        }

        echo '</tbody></table>';
        echo '<p class="rhbp-hint">' . esc_html__('Daten aus der Wordfence Intelligence Vulnerability Database. Das Modul spielt nichts von selbst ein.', 'rh-hardening') . '</p>';
        echo '</div>';
    }

    /**
     * Ergebnis des Dateiabgleichs gegen wordpress.org plus die Wächter.
     */
    private function renderIntegrity(): void
    {
        $job = ScanJob::load();
        $result = ScanRunner::lastResult();

        echo '<div class="rhbp-card">';
        echo '<div class="rhbp-card__head"><h3 class="rhbp-card__title">' . esc_html__('Dateien', 'rh-hardening') . '</h3></div>';

        if ($job->isRunning() && ! $job->isStale()) {
            printf(
                '<p class="rhbp-hint">%s</p>',
                esc_html(sprintf(
                    /* translators: 1: Abschnitt, 2: Anzahl Dateien */
                    __('Prüflauf läuft gerade, Abschnitt "%1$s", %2$d Dateien verglichen. Er arbeitet im Hintergrund weiter, diese Seite kann geschlossen werden.', 'rh-hardening'),
                    $this->stageLabel($job->stage),
                    $job->filesChecked
                ))
            );
        } elseif ($result === null) {
            echo '<p class="rhbp-empty">' . esc_html__('Noch kein Prüflauf. Er vergleicht den WordPress-Kern und alle Plugins von wordpress.org mit den amtlichen Prüfsummen, bewacht die Stellen, die WordPress ungefragt lädt, und sucht ausführbare Dateien im Upload-Verzeichnis.', 'rh-hardening') . '</p>';
        } else {
            $this->renderResult($result);
        }

        echo '<div class="rhbp-card__actions">';
        echo $this->actionButton(self::ACTION_DEEP_SCAN, __('Prüflauf starten', 'rh-hardening'), 'rhbp-btn');

        if (HiddenScan::hasBaseline()) {
            echo ' ' . $this->actionButton(
                self::ACTION_BASELINE,
                __('Aktuellen Zustand als normal übernehmen', 'rh-hardening'),
                'rhbp-btn rhbp-btn--ghost'
            );
        }

        echo '</div>';
        echo '</div>';
    }

    /**
     * @param array<string, mixed> $result
     */
    private function renderResult(array $result): void
    {
        $findings = is_array($result['findings'] ?? null) ? $result['findings'] : [];
        $types = ScanRunner::findingTypes();

        $duration = (int) ($result['duration'] ?? 0);

        printf(
            '<p class="rhbp-hint">%s%s</p>',
            esc_html(sprintf(
                /* translators: 1: Zeitpunkt, 2: Anzahl Dateien */
                __('Letzter Prüflauf am %1$s, %2$d Dateien verglichen.', 'rh-hardening'),
                wp_date('d.m.Y H:i', (int) ($result['finished'] ?? 0)),
                (int) ($result['files'] ?? 0)
            )),
            $duration > 0 ? esc_html(sprintf(
                /* translators: %d: Dauer in Sekunden */
                __(' Dauer: %d Sekunden.', 'rh-hardening'),
                $duration
            )) : ''
        );

        $rows = [];

        foreach ($types as $key => $meta) {
            $count = count($findings[$key] ?? []);

            if ($count === 0) {
                continue;
            }

            $rows[$key] = ['meta' => $meta, 'count' => $count, 'files' => $findings[$key]];
        }

        if ($rows === []) {
            echo '<div class="rhbp-callout rhbp-callout--success">' . esc_html__('Keine Abweichung gefunden.', 'rh-hardening') . '</div>';

            return;
        }

        echo '<table class="rhbp-table"><thead><tr>';
        echo '<th>' . esc_html__('Befund', 'rh-hardening') . '</th>';
        echo '<th>' . esc_html__('Anzahl', 'rh-hardening') . '</th>';
        echo '<th>' . esc_html__('Beispiele', 'rh-hardening') . '</th>';
        echo '</tr></thead><tbody>';

        foreach ($rows as $row) {
            $pill = $row['meta']['severity'] === Event::SEVERITY_CRITICAL
                ? 'rhbp-pill rhbp-pill--err'
                : ($row['meta']['severity'] === Event::SEVERITY_WARN ? 'rhbp-pill rhbp-pill--warn' : 'rhbp-pill');

            printf(
                '<tr><td><span class="%s"><span class="rhbp-pill__dot"></span>%s</span></td><td>%d</td><td>%s</td></tr>',
                esc_attr($pill),
                esc_html((string) $row['meta']['label']),
                (int) $row['count'],
                esc_html(implode(', ', array_slice((array) $row['files'], 0, 4)))
            );
        }

        echo '</tbody></table>';
    }

    private function stageLabel(string $stage): string
    {
        return match ($stage) {
            'core' => __('WordPress-Kern', 'rh-hardening'),
            'plugins' => __('Plugins', 'rh-hardening'),
            'hidden' => __('heikle Stellen', 'rh-hardening'),
            'uploads' => __('Upload-Verzeichnis', 'rh-hardening'),
            default => $stage,
        };
    }

    private function renderNotice(): void
    {
        $notice = get_transient(self::NOTICE_TRANSIENT);

        if (! is_array($notice)) {
            return;
        }

        delete_transient(self::NOTICE_TRANSIENT);

        printf(
            '<div class="rhbp-callout rhbp-callout--%s">%s</div>',
            esc_attr((string) ($notice['variant'] ?? 'info')),
            esc_html((string) ($notice['message'] ?? ''))
        );
    }

    private function renderState(): void
    {
        $counts = EventLog::countsSince(gmdate('Y-m-d H:i:s', time() - WEEK_IN_SECONDS));
        $uploads = Uploads::lastStatus();

        echo '<div class="rhbp-card">';
        echo '<div class="rhbp-card__head"><h3 class="rhbp-card__title">' . esc_html__('Zustand', 'rh-hardening') . '</h3></div>';

        echo '<div class="rhbp-card-grid">';

        $this->stat(
            __('Kritisch, letzte 7 Tage', 'rh-hardening'),
            (string) $counts[Event::SEVERITY_CRITICAL]
        );
        $this->stat(
            __('Auffällig, letzte 7 Tage', 'rh-hardening'),
            (string) $counts[Event::SEVERITY_WARN]
        );

        echo '</div>';

        $shield = new Shield();

        echo '<dl class="rhbp-meta">';
        echo '<dt>' . esc_html__('Schutzwall', 'rh-hardening') . '</dt>';
        echo '<dd>' . $this->shieldPill($shield->state()) . '</dd>';
        echo '<dt>' . esc_html__('PHP im Upload-Verzeichnis', 'rh-hardening') . '</dt>';
        echo '<dd>' . $this->uploadsPill($uploads) . '</dd>';
        echo '</dl>';

        if (is_array($uploads) && ! empty($uploads['message'])) {
            echo '<p class="rhbp-hint">' . esc_html((string) $uploads['message']) . '</p>';
        }

        echo '<div class="rhbp-card__actions">' . $this->scanButton() . '</div>';
        echo '</div>';
    }

    /**
     * Zustand der Wall-Datei in mu-plugins.
     */
    private function shieldPill(string $state): string
    {
        [$class, $label] = match ($state) {
            Shield::STATE_ACTIVE => ['rhbp-pill rhbp-pill--ok', sprintf(
                /* translators: %d: Anzahl der Regeln */
                __('aktiv, %d Regeln', 'rh-hardening'),
                count(Rules::all())
            )],
            Shield::STATE_TAMPERED => ['rhbp-pill rhbp-pill--err', __('wurde verändert', 'rh-hardening')],
            Shield::STATE_UNWRITABLE => ['rhbp-pill rhbp-pill--err', __('mu-plugins nicht beschreibbar', 'rh-hardening')],
            Shield::STATE_OUTDATED => ['rhbp-pill rhbp-pill--warn', __('alter Stand', 'rh-hardening')],
            Shield::STATE_MISSING => ['rhbp-pill rhbp-pill--warn', __('noch nicht ausgelegt', 'rh-hardening')],
            default => ['rhbp-pill', __('abgeschaltet', 'rh-hardening')],
        };

        return sprintf(
            '<span class="%s"><span class="rhbp-pill__dot"></span>%s</span>',
            esc_attr($class),
            esc_html($label)
        );
    }

    private function uploadsPill(?array $uploads): string
    {
        $status = is_array($uploads) ? (string) ($uploads['status'] ?? 'unknown') : 'unknown';

        [$class, $label] = match ($status) {
            'blocked' => ['rhbp-pill rhbp-pill--ok', __('gesperrt', 'rh-hardening')],
            'executing' => ['rhbp-pill rhbp-pill--err', __('wird ausgeführt', 'rh-hardening')],
            default => ['rhbp-pill rhbp-pill--warn', __('noch nicht geprüft', 'rh-hardening')],
        };

        return sprintf(
            '<span class="%s"><span class="rhbp-pill__dot"></span>%s</span>',
            esc_attr($class),
            esc_html($label)
        );
    }

    private function stat(string $label, string $value): void
    {
        printf(
            '<div class="rhbp-stat"><span class="rhbp-stat__value">%s</span><span class="rhbp-stat__label">%s</span></div>',
            esc_html($value),
            esc_html($label)
        );
    }

    private function scanButton(): string
    {
        return $this->actionButton(self::ACTION_SCAN, __('Jetzt prüfen', 'rh-hardening'), 'rhbp-btn');
    }

    private function actionButton(string $action, string $label, string $class): string
    {
        $url = wp_nonce_url(admin_url('admin-post.php?action=' . $action), $action);

        return sprintf(
            '<a class="%s" href="%s">%s</a>',
            esc_attr($class),
            esc_url($url),
            esc_html($label)
        );
    }

    public function handleDeepScan(): void
    {
        $this->guard(self::ACTION_DEEP_SCAN);

        $started = (new ScanRunner())->start('manuell');

        $this->finish($started
            ? ['variant' => 'info', 'message' => __('Der Prüflauf ist gestartet. Er arbeitet im Hintergrund, das Ergebnis erscheint hier, sobald er durch ist.', 'rh-hardening')]
            : ['variant' => 'warn', 'message' => __('Es läuft bereits ein Prüflauf.', 'rh-hardening')]);
    }

    public function handleBaseline(): void
    {
        $this->guard(self::ACTION_BASELINE);

        $count = HiddenScan::acceptCurrentState();

        $this->finish([
            'variant' => 'success',
            'message' => sprintf(
                /* translators: %d: Anzahl Dateien */
                __('Der aktuelle Zustand gilt jetzt als normal, %d Dateien wurden übernommen.', 'rh-hardening'),
                $count
            ),
        ]);
    }

    private function guard(string $action): void
    {
        if (! current_user_can('manage_options')) {
            wp_die(esc_html__('Dazu fehlen die Rechte.', 'rh-hardening'), '', ['response' => 403]);
        }

        check_admin_referer($action);
    }

    /**
     * @param array{variant: string, message: string} $notice
     */
    private function finish(array $notice): void
    {
        set_transient(self::NOTICE_TRANSIENT, $notice, 5 * MINUTE_IN_SECONDS);

        wp_safe_redirect(admin_url('admin.php?page=' . SettingsPage::MENU_SLUG . '&tab=' . HardeningGroup::GROUP_ID));
        exit;
    }

    private function renderChronicle(): void
    {
        $rows = EventLog::query(['limit' => 50]);

        echo '<div class="rhbp-card">';
        echo '<div class="rhbp-card__head"><h3 class="rhbp-card__title">' . esc_html__('Chronik', 'rh-hardening') . '</h3></div>';

        if ($rows === []) {
            echo '<p class="rhbp-empty">' . esc_html__('Noch nichts festgehalten. Hier erscheinen aktivierte Plugins, gewechselte Themes, neue Administratoren und die Ergebnisse der Prüfungen.', 'rh-hardening') . '</p>';
            echo '</div>';
            return;
        }

        echo '<table class="rhbp-table"><thead><tr>';
        echo '<th>' . esc_html__('Zeitpunkt', 'rh-hardening') . '</th>';
        echo '<th>' . esc_html__('Einstufung', 'rh-hardening') . '</th>';
        echo '<th>' . esc_html__('Vorgang', 'rh-hardening') . '</th>';
        echo '<th>' . esc_html__('Herkunft', 'rh-hardening') . '</th>';
        echo '</tr></thead><tbody>';

        foreach ($rows as $row) {
            printf(
                '<tr><td>%s</td><td><span class="%s"><span class="rhbp-pill__dot"></span>%s</span></td><td>%s</td><td>%s</td></tr>',
                esc_html(get_date_from_gmt((string) $row->created_at, 'd.m.Y H:i')),
                esc_attr(Event::severityPill((string) $row->severity)),
                esc_html(Event::severityLabel((string) $row->severity)),
                esc_html((string) $row->message),
                esc_html((string) $row->ip_prefix)
            );
        }

        echo '</tbody></table>';
        echo '<p class="rhbp-hint">' . esc_html(sprintf(
            /* translators: %d: Anzahl Tage */
            __('Die Chronik hält %d Tage. Die Herkunft steht gekürzt drin und lässt keine Person erkennen.', 'rh-hardening'),
            EventLog::RETENTION_DAYS
        )) . '</p>';
        echo '</div>';
    }

    /**
     * Führt die Prüfungen aus, die einen echten Abruf brauchen.
     */
    public function handleScan(): void
    {
        $this->guard(self::ACTION_SCAN);

        $uploads = (new Uploads())->probe();
        $findings = (new DocrootHygiene())->run();
        $reachable = count(array_filter($findings, static fn (array $f): bool => $f['erreichbar']));

        if ($reachable > 0) {
            $notice = [
                'variant' => 'err',
                'message' => sprintf(
                    /* translators: %d: Anzahl der Funde */
                    _n(
                        '%d Datei im Wurzelverzeichnis ist von aussen abrufbar. Einzelheiten stehen in der Chronik.',
                        '%d Dateien im Wurzelverzeichnis sind von aussen abrufbar. Einzelheiten stehen in der Chronik.',
                        $reachable,
                        'rh-hardening'
                    ),
                    $reachable
                ),
            ];
        } elseif ($uploads['status'] === 'executing') {
            $notice = [
                'variant' => 'err',
                'message' => $uploads['message'],
            ];
        } else {
            $notice = [
                'variant' => 'success',
                'message' => __('Prüfung durchgelaufen, nichts Auffälliges gefunden.', 'rh-hardening'),
            ];
        }

        EventLog::record(Event::info(
            Event::TYPE_SCAN_COMPLETED,
            __('Prüfung von Hand ausgelöst', 'rh-hardening'),
            ['uploads' => $uploads['status'], 'funde' => $reachable]
        ));

        $this->finish($notice);
    }
}
