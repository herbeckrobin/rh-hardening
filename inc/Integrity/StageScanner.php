<?php

declare(strict_types=1);

namespace RhHardening\Integrity;

/**
 * Ein Abschnitt des Prüflaufs.
 *
 * Jeder Abschnitt arbeitet bis zur übergebenen Frist und meldet zurück, ob er
 * fertig geworden ist. Ist er es nicht, steht im Cursor des Jobs, wo der
 * nächste Tick weitermachen muss.
 */
interface StageScanner
{
    /**
     * @param float $deadline Zeitpunkt aus microtime(true), bis zu dem gearbeitet werden darf.
     * @return bool true, wenn der Abschnitt vollständig durch ist.
     */
    public function run(ScanJob $job, float $deadline): bool;
}
