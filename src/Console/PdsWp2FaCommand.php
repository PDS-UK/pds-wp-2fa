<?php

declare(strict_types=1);

namespace PDS\WP2FA\Console;

use PDS\WP2FA\Admin\AdminException;
use PDS\WP2FA\Admin\ReasonCode;

final class PdsWp2FaCommand
{
    public function __construct(
        private readonly CliOperations $operations,
        private readonly CliOutput $output,
    ) {
    }

    public function register(CliRegistrar $registrar): void
    {
        $registrar->addCommand('pds-wp-2fa', $this);
    }

    /** @param list<string> $args @param array<string, mixed> $assocArgs */
    public function status(array $args, array $assocArgs): void
    {
        $this->run(function () use ($assocArgs): void {
            $this->display($this->operations->status(isset($assocArgs['user']) ? $this->userReference($assocArgs['user']) : null), $assocArgs);
        });
    }

    /** @param list<string> $args @param array<string, mixed> $assocArgs */
    public function settings(array $args, array $assocArgs): void
    {
        $this->run(function () use ($args, $assocArgs): void {
            $subcommand = $args[0] ?? 'get';
            if ($subcommand === 'get') {
                $this->display($this->operations->settings(), $assocArgs);
                return;
            }
            if ($subcommand !== 'set') {
                throw new CliException('Usage: settings get|set.', CliExitCode::USAGE);
            }
            $enabled = $this->onOff($this->required($assocArgs, 'enforcement'));
            $reason = $this->reason($assocArgs);
            $confirmedProduction = $this->flag($assocArgs, 'confirm-production');
            if (!$confirmedProduction && !$this->flag($assocArgs, 'confirm')) {
                throw new CliException('This mutation requires --confirm.', CliExitCode::CONFIRMATION);
            }
            $this->operations->setEnforcement($enabled, $reason, $confirmedProduction);
            $this->output->line('Settings updated.');
        });
    }

    /** @param list<string> $args @param array<string, mixed> $assocArgs */
    public function role(array $args, array $assocArgs): void
    {
        $this->run(function () use ($args, $assocArgs): void {
            $subcommand = $args[0] ?? 'list';
            if ($subcommand === 'list') {
                $this->display($this->operations->roles(), $assocArgs);
                return;
            }
            if ($subcommand !== 'set' || !isset($args[1])) {
                throw new CliException('Usage: role list|set <role-key>.', CliExitCode::USAGE);
            }
            if (!$this->flag($assocArgs, 'confirm')) {
                throw new CliException('Role changes require --confirm.', CliExitCode::CONFIRMATION);
            }
            $grace = isset($assocArgs['grace-seconds']) ? $this->integer($assocArgs['grace-seconds'], 0, 31536000) : null;
            $this->operations->setRole($args[1], $this->onOff($this->required($assocArgs, 'enabled')), $grace, $this->reason($assocArgs));
            $this->output->line('Role policy updated.');
        });
    }

    /** @param list<string> $args @param array<string, mixed> $assocArgs */
    public function user(array $args, array $assocArgs): void
    {
        $this->run(function () use ($args, $assocArgs): void {
            $subcommand = $args[0] ?? 'status';
            $user = $this->userReference($assocArgs['user'] ?? null);
            if ($subcommand === 'status') {
                $this->display($this->operations->userStatus($user), $assocArgs);
                return;
            }
            if (!$this->flag($assocArgs, 'confirm')) {
                throw new CliException('User changes require --confirm.', CliExitCode::CONFIRMATION);
            }
            $reason = $this->reason($assocArgs);
            if ($subcommand === 'extend-grace') {
                $this->operations->extendGrace($user, $this->integer($this->required($assocArgs, 'seconds'), 1, 31536000), $reason);
            } elseif ($subcommand === 'reset-sessions') {
                $this->operations->resetSessions($user, $reason);
            } elseif ($subcommand === 'reset-enrollment') {
                if (!$this->flag($assocArgs, 'confirm-production')) {
                    throw new CliException('Enrollment reset requires --confirm-production.', CliExitCode::CONFIRMATION);
                }
                $this->operations->resetEnrollment($user, $reason);
            } else {
                throw new CliException('Usage: user status|extend-grace|reset-sessions|reset-enrollment.', CliExitCode::USAGE);
            }
            $this->output->line('User operation completed.');
        });
    }

    /** @param list<string> $args @param array<string, mixed> $assocArgs */
    public function recovery(array $args, array $assocArgs): void
    {
        $this->run(function () use ($args, $assocArgs): void {
            $user = $this->userReference($assocArgs['user'] ?? null);
            $subcommand = $args[0] ?? 'status';
            if ($subcommand === 'status') {
                $this->display($this->operations->recoveryStatus($user), $assocArgs);
                return;
            }
            if ($subcommand !== 'revoke' || !$this->flag($assocArgs, 'confirm')) {
                throw new CliException('Usage: recovery status|revoke with --confirm.', CliExitCode::USAGE);
            }
            $this->operations->revokeRecovery($user, $this->reason($assocArgs));
            $this->output->line('Recovery generation revoked.');
        });
    }

    /** @param list<string> $args @param array<string, mixed> $assocArgs */
    public function method(array $args, array $assocArgs): void
    {
        $this->run(function () use ($args, $assocArgs): void {
            if (($args[0] ?? null) !== 'revoke' || !$this->flag($assocArgs, 'confirm')) {
                throw new CliException('Usage: method revoke with --confirm.', CliExitCode::USAGE);
            }
            $this->operations->revokeMethod($this->userReference($assocArgs['user'] ?? null), (string) $this->required($assocArgs, 'method'), $this->reason($assocArgs));
            $this->output->line('Method revoked.');
        });
    }

    /** @param list<string> $args @param array<string, mixed> $assocArgs */
    public function audit(array $args, array $assocArgs): void
    {
        $this->run(function () use ($args, $assocArgs): void {
            $subcommand = $args[0] ?? 'list';
            if ($subcommand === 'list') {
                $filters = array_intersect_key($assocArgs, array_flip(['event', 'severity', 'actor', 'user', 'role', 'source', 'outcome', 'since', 'until', 'per-page']));
                if (isset($filters['per-page'])) {
                    $filters['per-page'] = $this->integer($filters['per-page'], 1, 100);
                }
                $this->display($this->operations->auditList($filters), $assocArgs);
                return;
            }
            if ($subcommand !== 'prune' || !$this->flag($assocArgs, 'confirm')) {
                throw new CliException('Usage: audit list|prune with --confirm for pruning.', CliExitCode::USAGE);
            }
            $this->display($this->operations->pruneAudit(isset($assocArgs['before']) ? (string) $assocArgs['before'] : null, $this->flag($assocArgs, 'dry-run')), $assocArgs);
        });
    }

    /** @param list<string> $args @param array<string, mixed> $assocArgs */
    public function identity(array $args, array $assocArgs): void
    {
        $this->run(function () use ($args, $assocArgs): void {
            $subcommand = $args[0] ?? 'status';
            if ($subcommand === 'generate') {
                if (!$this->output->isTty() || array_key_exists('format', $assocArgs)) {
                    throw new CliException('Identity generation is available only on a direct TTY.', CliExitCode::CONFIRMATION);
                }
                $this->output->writeSecret($this->operations->identityGenerate());
                return;
            }
            if ($subcommand === 'status') {
                $this->display($this->operations->identityStatus(), $assocArgs);
                return;
            }
            if (!$this->flag($assocArgs, 'confirm')) {
                throw new CliException('Identity changes require --confirm.', CliExitCode::CONFIRMATION);
            }
            if ($subcommand === 'init') {
                $this->operations->identityInit();
            } elseif ($subcommand === 'rebind') {
                if (!$this->flag($assocArgs, 'from-clone')) {
                    throw new CliException('Rebind requires --from-clone.', CliExitCode::CONFIRMATION);
                }
                $this->operations->identityRebind();
            } elseif ($subcommand === 'rotate') {
                if (!$this->flag($assocArgs, 'confirm-production')) {
                    throw new CliException('Rotation requires --confirm-production.', CliExitCode::CONFIRMATION);
                }
                $this->operations->identityRotate();
            } else {
                throw new CliException('Usage: identity generate|status|init|rebind|rotate.', CliExitCode::USAGE);
            }
            $this->output->line('Identity operation completed.');
        });
    }

    /** @param callable(): void $operation */
    private function run(callable $operation): void
    {
        try {
            $operation();
        } catch (CliException $exception) {
            $this->output->error($exception->getMessage(), $exception->exitCode());
            throw $exception;
        } catch (AdminException $exception) {
            $message = match ($exception->reason()) {
                'target_not_found' => 'The requested user was not found.',
                'unavailable' => 'The installation binding is unavailable.',
                'confirmation_required' => 'The requested operation needs explicit confirmation.',
                'authorization_denied' => 'The command is not authorized for this operation.',
                default => 'The operation could not be completed.',
            };
            $this->output->error($message, $exception->reason() === 'unavailable' ? CliExitCode::IDENTITY_UNAVAILABLE : CliExitCode::CONFLICT);
            throw new CliException($message, $exception->reason() === 'unavailable' ? CliExitCode::IDENTITY_UNAVAILABLE : CliExitCode::CONFLICT);
        } catch (\Throwable) {
            $this->output->error('The operation could not be completed.', CliExitCode::CONFLICT);
            throw new CliException('The operation could not be completed.', CliExitCode::CONFLICT);
        }
    }

    /** @param array<string, mixed> $assocArgs */
    private function display(array $data, array $assocArgs): void
    {
        $this->output->render($data, OutputFormat::fromOption($assocArgs['format'] ?? null));
    }

    /** @param array<string, mixed> $assocArgs */
    private function required(array $assocArgs, string $key): mixed
    {
        if (!array_key_exists($key, $assocArgs) || $assocArgs[$key] === '') {
            throw new CliException('Missing required option --' . $key . '.', CliExitCode::USAGE);
        }

        return $assocArgs[$key];
    }

    /** @param array<string, mixed> $assocArgs */
    private function reason(array $assocArgs): ReasonCode
    {
        $reason = ReasonCode::tryFrom((string) $this->required($assocArgs, 'reason'));
        if ($reason === null) {
            throw new CliException('Reason code is invalid.', CliExitCode::USAGE);
        }

        return $reason;
    }

    private function userReference(mixed $value): string
    {
        if (is_int($value) || (is_string($value) && ctype_digit($value))) {
            if ((int) $value < 1) {
                throw new CliException('User reference is invalid.', CliExitCode::USAGE);
            }
            return (string) (int) $value;
        }
        if (!is_string($value) || preg_match('/^[A-Za-z0-9_.-]{1,60}$/', $value) !== 1) {
            throw new CliException('User reference must be a numeric ID or exact login.', CliExitCode::USAGE);
        }

        return $value;
    }

    private function onOff(mixed $value): bool
    {
        return match (strtolower((string) $value)) {
            'on', '1', 'true' => true,
            'off', '0', 'false' => false,
            default => throw new CliException('Value must be on or off.', CliExitCode::USAGE),
        };
    }

    /** @param array<string, mixed> $assocArgs */
    private function flag(array $assocArgs, string $key): bool
    {
        return in_array($assocArgs[$key] ?? false, [true, 1, '1', 'true', 'on', ''], true);
    }

    private function integer(mixed $value, int $min, int $max): int
    {
        $integer = filter_var($value, FILTER_VALIDATE_INT);
        if ($integer === false || $integer < $min || $integer > $max) {
            throw new CliException('Numeric option is outside its allowed range.', CliExitCode::USAGE);
        }

        return $integer;
    }
}
