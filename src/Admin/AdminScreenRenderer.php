<?php

declare(strict_types=1);

namespace PDS\WP2FA\Admin;

final class AdminScreenRenderer
{
    public function renderSettings(SettingsSnapshot $settings): string
    {
        $html = '<div class="wrap"><h1>PDS WP 2FA settings</h1><form method="post">';
        $html .= '<label>Global enforcement <input type="checkbox" name="global_enforcement" value="1"' . ($settings->globalEnforcement() ? ' checked' : '') . '></label>';
        $html .= '<table><thead><tr><th>Role</th><th>Status</th><th>Enabled</th><th>Grace seconds</th></tr></thead><tbody>';
        foreach ($settings->rolePolicies() as $policy) {
            $key = self::escape($policy->roleKey());
            $html .= '<tr><td>' . self::escape($policy->label()) . '</td><td>' . self::escape($policy->status()) . '</td><td>';
            if ($policy->isEditable()) {
                $html .= '<input type="checkbox" name="role_policy[' . $key . '][enabled]" value="1"' . ($policy->enabled() ? ' checked' : '') . '>';
            } else {
                $html .= 'read-only';
            }
            $html .= '</td><td>' . $policy->gracePeriodSeconds() . '</td></tr>';
        }
        $html .= '</tbody></table><p>Audit retention: ' . $settings->auditRetentionDays() . ' days</p></form></div>';

        return $html;
    }

    /** @param iterable<array<string, mixed>> $rows */
    public function renderUsers(iterable $rows): string
    {
        $html = '<div class="wrap"><h1>PDS WP 2FA users</h1><table><thead><tr><th>User</th><th>Policy</th><th>Deadline</th></tr></thead><tbody>';
        foreach ($rows as $row) {
            $safe = SafeOutput::userRow($row);
            $html .= '<tr><td>' . self::escape((string) ($safe['user_login'] ?? $safe['user_id'] ?? '')) . '</td><td>'
                . self::escape((string) ($safe['policy_state'] ?? '')) . '</td><td>'
                . self::escape((string) ($safe['effective_deadline'] ?? '')) . '</td></tr>';
        }

        return $html . '</tbody></table></div>';
    }

    /** @param iterable<AuditEvent|array<string, mixed>> $events */
    public function renderAudit(iterable $events): string
    {
        $html = '<div class="wrap"><h1>PDS WP 2FA audit</h1><table><thead><tr><th>When</th><th>Event</th><th>Outcome</th></tr></thead><tbody>';
        foreach ($events as $event) {
            $row = $event instanceof AuditEvent ? $event->toSafeArray() : $event;
            $safe = SafeOutput::auditRow($row);
            $html .= '<tr><td>' . self::escape((string) ($safe['occurred_at'] ?? '')) . '</td><td>'
                . self::escape((string) ($safe['event_type'] ?? '')) . '</td><td>'
                . self::escape((string) ($safe['outcome'] ?? '')) . '</td></tr>';
        }

        return $html . '</tbody></table></div>';
    }

    private static function escape(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}
