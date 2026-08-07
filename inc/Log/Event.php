<?php

declare(strict_types=1);

namespace RhHardening\Log;

/**
 * Ein Eintrag der Sicherheits-Chronik.
 *
 * Die Chronik ist die Ausgabe des ganzen Moduls: was auffällt, landet hier,
 * und aus schweren Einträgen wird eine Mail. Das Modul verändert die Site
 * nicht von sich aus, es berichtet.
 */
final class Event
{
    /** Notiz, taucht nur in der Chronik auf. */
    public const SEVERITY_INFO = 'info';

    /** Sollte sich jemand ansehen, geht in den Sammelbericht. */
    public const SEVERITY_WARN = 'warn';

    /** Verdacht auf Übernahme, löst sofort eine Mail aus. */
    public const SEVERITY_CRITICAL = 'critical';

    // Vorgangsarten. Bewusst grob gehalten, die Einzelheiten stehen im Kontext.
    public const TYPE_SETTING_CHANGED = 'setting_changed';
    public const TYPE_PLUGIN_ACTIVATED = 'plugin_activated';
    public const TYPE_PLUGIN_DEACTIVATED = 'plugin_deactivated';
    public const TYPE_THEME_SWITCHED = 'theme_switched';
    public const TYPE_ADMIN_CREATED = 'admin_created';
    public const TYPE_ROLE_ESCALATED = 'role_escalated';
    public const TYPE_FILE_CHANGED = 'file_changed';
    public const TYPE_INTEGRITY_FAILED = 'integrity_failed';
    public const TYPE_SUSPICIOUS_UPLOAD = 'suspicious_upload';
    public const TYPE_DOCROOT_FINDING = 'docroot_finding';
    public const TYPE_VULNERABILITY = 'vulnerability';
    public const TYPE_REQUEST_BLOCKED = 'request_blocked';
    public const TYPE_SCAN_COMPLETED = 'scan_completed';

    /**
     * @param array<string, scalar|null> $context
     */
    public function __construct(
        public readonly string $type,
        public readonly string $severity,
        public readonly string $message,
        public readonly array $context = [],
        public readonly int $userId = 0,
    ) {
    }

    public static function info(string $type, string $message, array $context = [], int $userId = 0): self
    {
        return new self($type, self::SEVERITY_INFO, $message, $context, $userId);
    }

    public static function warn(string $type, string $message, array $context = [], int $userId = 0): self
    {
        return new self($type, self::SEVERITY_WARN, $message, $context, $userId);
    }

    public static function critical(string $type, string $message, array $context = [], int $userId = 0): self
    {
        return new self($type, self::SEVERITY_CRITICAL, $message, $context, $userId);
    }

    /**
     * @return array<int, string>
     */
    public static function severities(): array
    {
        return [self::SEVERITY_INFO, self::SEVERITY_WARN, self::SEVERITY_CRITICAL];
    }

    public static function severityLabel(string $severity): string
    {
        return match ($severity) {
            self::SEVERITY_CRITICAL => __('Kritisch', 'rh-hardening'),
            self::SEVERITY_WARN => __('Auffällig', 'rh-hardening'),
            default => __('Notiz', 'rh-hardening'),
        };
    }

    /**
     * Pill-Variante des Core-Komponentensystems für diesen Schweregrad.
     */
    public static function severityPill(string $severity): string
    {
        return match ($severity) {
            self::SEVERITY_CRITICAL => 'rhbp-pill rhbp-pill--err',
            self::SEVERITY_WARN => 'rhbp-pill rhbp-pill--warn',
            default => 'rhbp-pill',
        };
    }
}
