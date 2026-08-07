<?php

declare(strict_types=1);

namespace RhHardening\Integrity;

/**
 * Zustand eines laufenden Durchlaufs.
 *
 * Der Prüflauf geht über den kompletten Kern (bei WordPress 7.0 sind das gut
 * 4000 Dateien) plus alle Plugins. Das ist auf einem Shared-Hoster mit dreissig
 * Sekunden Zeitlimit nicht in einem Rutsch zu schaffen, deshalb arbeitet er in
 * Häppchen: jeder Tick bekommt ein Zeitbudget, merkt sich, wo er stehen
 * geblieben ist, und der nächste macht dort weiter.
 *
 * Der Zustand liegt in einer Option mit autoload=no, nicht in einem Transient.
 * Ein halb fertiger Durchlauf darf nicht verschwinden, weil jemand den
 * Objekt-Cache leert. Dasselbe Muster wie in rh-sync.
 */
final class ScanJob
{
    public const OPTION = 'rhhard_scan_job';

    /** Reihenfolge der Abschnitte. Der Kern zuerst, weil dort das Schlimmste sitzt. */
    public const STAGES = ['core', 'plugins', 'hidden', 'uploads'];

    public const STATUS_IDLE = 'idle';
    public const STATUS_RUNNING = 'running';
    public const STATUS_DONE = 'done';
    public const STATUS_FAILED = 'failed';

    /** Ein Lauf, der so lange keinen Fortschritt macht, gilt als abgestürzt. */
    private const STALE_AFTER = 600;

    public string $status = self::STATUS_IDLE;
    public string $stage = 'core';
    public int $cursor = 0;

    /** Zweite Ebene, etwa die Datei innerhalb des gerade geprüften Plugins. */
    public int $subCursor = 0;
    public int $filesChecked = 0;
    public int $startedAt = 0;
    public int $updatedAt = 0;
    public string $trigger = 'manuell';
    public string $error = '';

    /** @var array<string, array<int, string>> Funde je Abschnitt, gedeckelt. */
    public array $findings = [];

    public static function load(): self
    {
        $stored = get_option(self::OPTION, null);
        $job = new self();

        if (! is_array($stored)) {
            return $job;
        }

        foreach (get_object_vars($job) as $key => $default) {
            if (array_key_exists($key, $stored)) {
                $job->{$key} = $stored[$key];
            }
        }

        return $job;
    }

    public function save(): void
    {
        $this->updatedAt = time();

        update_option(self::OPTION, get_object_vars($this), false);
    }

    public static function start(string $trigger): self
    {
        $job = new self();
        $job->status = self::STATUS_RUNNING;
        $job->stage = self::STAGES[0];
        $job->cursor = 0;
        $job->startedAt = time();
        $job->trigger = $trigger;
        $job->save();

        return $job;
    }

    public function isRunning(): bool
    {
        return $this->status === self::STATUS_RUNNING;
    }

    /**
     * Steht ein laufender Job schon zu lange still, hat der Tick es zerrissen
     * (Zeitlimit, Speicher, abgeschossener Prozess). Dann nicht ewig warten.
     */
    public function isStale(): bool
    {
        return $this->isRunning() && (time() - $this->updatedAt) > self::STALE_AFTER;
    }

    public function nextStage(): ?string
    {
        $index = array_search($this->stage, self::STAGES, true);

        if ($index === false) {
            return null;
        }

        return self::STAGES[$index + 1] ?? null;
    }

    /**
     * Hält höchstens so viele Dateinamen je Abschnitt fest. Bei einem
     * kompromittierten Kern wären es sonst tausende, und die ersten reichen,
     * um zu wissen, dass etwas nicht stimmt.
     */
    public function addFinding(string $stage, string $file): void
    {
        $this->findings[$stage] ??= [];

        if (count($this->findings[$stage]) < 25) {
            $this->findings[$stage][] = $file;
        }
    }

    public function findingCount(string $stage): int
    {
        return count($this->findings[$stage] ?? []);
    }

    public function totalFindings(): int
    {
        return array_sum(array_map('count', $this->findings));
    }

    public function fail(string $message): void
    {
        $this->status = self::STATUS_FAILED;
        $this->error = $message;
        $this->save();
    }

    public function finish(): void
    {
        $this->status = self::STATUS_DONE;
        $this->save();
    }
}
