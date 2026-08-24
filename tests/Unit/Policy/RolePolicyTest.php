<?php

declare(strict_types=1);

use PDS\WP2FA\Policy\EnrollmentCycleId;
use PDS\WP2FA\Policy\GraceExtension;
use PDS\WP2FA\Policy\RoleDiscoverySnapshot;
use PDS\WP2FA\Policy\RoleKey;
use PDS\WP2FA\Policy\RolePolicy;
use PDS\WP2FA\Policy\RolePolicyLifecycle;
use PDS\WP2FA\Policy\RolePolicyLifecycleEvent;
use PDS\WP2FA\Policy\RolePolicyResolutionInput;
use PDS\WP2FA\Policy\RolePolicyResolver;
use PDS\WP2FA\Policy\RolePolicyStatus;
use PDS\WP2FA\Policy\UserRolePolicyAnchor;

foreach (glob(__DIR__ . '/../../../src/Policy/*.php') as $sourceFile) {
    require_once $sourceFile;
}

function policyTestInstant(string $value): DateTimeImmutable
{
    return new DateTimeImmutable($value, new DateTimeZone('UTC'));
}

function policyTestSame($expected, $actual, string $message): void
{
    if ($expected instanceof DateTimeImmutable && $actual instanceof DateTimeImmutable) {
        if ($expected->getTimestamp() !== $actual->getTimestamp()) {
            throw new RuntimeException($message . "\nExpected: " . var_export($expected, true) . "\nActual: " . var_export($actual, true));
        }

        return;
    }

    if ($expected !== $actual) {
        throw new RuntimeException($message . "\nExpected: " . var_export($expected, true) . "\nActual: " . var_export($actual, true));
    }
}

function policyTestTrue(bool $actual, string $message): void
{
    policyTestSame(true, $actual, $message);
}

function policyTestFalse(bool $actual, string $message): void
{
    policyTestSame(false, $actual, $message);
}

function policyTestNull($actual, string $message): void
{
    policyTestSame(null, $actual, $message);
}

function policyTestThrows(callable $callback, string $message): void
{
    try {
        $callback();
    } catch (Throwable $exception) {
        return;
    }

    throw new RuntimeException($message);
}

function policyTestEventTypes(array $events): array
{
    return array_map(static function (RolePolicyLifecycleEvent $event): string {
        return $event->type();
    }, $events);
}

function policyTestNewRolesAreDisabledAndLabelsAreNotIdentity(): void
{
    $lifecycle = new RolePolicyLifecycle();
    $result = $lifecycle->reconcile(
        RoleDiscoverySnapshot::fromRoleLabels(
            array('editor' => 'Reviewers', 'reviewer' => 'Reviewers'),
            policyTestInstant('2026-01-01T00:00:00+00:00')
        ),
        array()
    );

    $editor = $result->policy(new RoleKey('editor'));
    $reviewer = $result->policy(new RoleKey('reviewer'));

    policyTestTrue($editor !== null, 'The editor role must be discovered.');
    policyTestTrue($reviewer !== null, 'The reviewer role must be discovered.');
    policyTestSame(RolePolicyStatus::DISABLED, $editor->status()->value(), 'New roles default to disabled.');
    policyTestFalse($editor->enabledConfiguration(), 'New roles are not implicitly enabled.');
    policyTestNull($editor->activatedAt(), 'A disabled role has no activation anchor.');
    policyTestSame('editor', $editor->roleKey()->value(), 'The exact role key identifies the policy.');
    policyTestSame('reviewer', $reviewer->roleKey()->value(), 'Equal labels do not collapse distinct role keys.');
    policyTestSame(array('role_policy_discovered', 'role_policy_discovered'), policyTestEventTypes($result->events()), 'Discovery emits one event per new role.');
}

function policyTestEnableDisableAndReenableRetainsActivation(): void
{
    $lifecycle = new RolePolicyLifecycle();
    $discovered = $lifecycle->reconcile(
        RoleDiscoverySnapshot::fromRoleLabels(
            array('editor' => 'Editor'),
            policyTestInstant('2026-01-01T00:00:00+00:00')
        ),
        array()
    )->policy(new RoleKey('editor'));

    $enabled = $lifecycle->enable($discovered, policyTestInstant('2026-01-02T00:00:00+00:00'));
    $disabled = $lifecycle->disable($enabled->policy(), policyTestInstant('2026-01-03T00:00:00+00:00'));
    $reenabled = $lifecycle->enable($disabled->policy(), policyTestInstant('2026-01-04T00:00:00+00:00'));

    policyTestSame(RolePolicyStatus::ACTIVE, $reenabled->policy()->status()->value(), 'Re-enabled discovered policies are active.');
    policyTestTrue($reenabled->policy()->enabledConfiguration(), 'Re-enabled policies retain enabled configuration.');
    policyTestSame(
        policyTestInstant('2026-01-02T00:00:00+00:00'),
        $reenabled->policy()->activatedAt(),
        'Re-enabling a policy never restarts its activation anchor.'
    );
    policyTestSame(array('role_policy_reenabled'), policyTestEventTypes($reenabled->events()), 'Re-enabling emits a distinct lifecycle event.');
}

function policyTestDeletionAndSameKeyReappearanceRetainPolicyHistory(): void
{
    $lifecycle = new RolePolicyLifecycle();
    $policy = $lifecycle->reconcile(
        RoleDiscoverySnapshot::fromRoleLabels(
            array('editor' => 'Editor'),
            policyTestInstant('2026-01-01T00:00:00+00:00')
        ),
        array()
    )->policy(new RoleKey('editor'));
    $policy = $lifecycle->enable($policy, policyTestInstant('2026-01-02T00:00:00+00:00'))->policy();

    $orphaned = $lifecycle->reconcile(
        RoleDiscoverySnapshot::fromRoleLabels(array(), policyTestInstant('2026-01-03T00:00:00+00:00')),
        array($policy)
    )->policy(new RoleKey('editor'));
    $reappearedResult = $lifecycle->reconcile(
        RoleDiscoverySnapshot::fromRoleLabels(
            array('editor' => 'Content editor'),
            policyTestInstant('2026-01-04T00:00:00+00:00')
        ),
        array($orphaned)
    );
    $reappeared = $reappearedResult->policy(new RoleKey('editor'));

    policyTestSame(RolePolicyStatus::ORPHANED, $orphaned->status()->value(), 'Missing role keys become orphaned.');
    policyTestSame(RolePolicyStatus::ACTIVE, $reappeared->status()->value(), 'A configured role key becomes active when it reappears.');
    policyTestSame('Content editor', $reappeared->currentRoleLabel(), 'The current label is mutable metadata.');
    policyTestSame(policyTestInstant('2026-01-02T00:00:00+00:00'), $reappeared->activatedAt(), 'Same-key reappearance retains activation history.');
    policyTestSame(
        array('role_policy_reappeared', 'role_label_changed'),
        policyTestEventTypes($reappearedResult->events()),
        'Reappearance and a changed label are independently explainable.'
    );
}

function policyTestGraceChangesDoNotRewriteActivation(): void
{
    $lifecycle = new RolePolicyLifecycle();
    $policy = RolePolicy::discovered(
        new RoleKey('editor'),
        'Editor',
        policyTestInstant('2026-01-01T00:00:00+00:00')
    );
    $policy = $lifecycle->enable($policy, policyTestInstant('2026-01-02T00:00:00+00:00'))->policy();
    $changed = $lifecycle->setGracePeriod($policy, 604800, policyTestInstant('2026-01-03T00:00:00+00:00'));

    policyTestSame(604800, $changed->policy()->gracePeriodSeconds(), 'Grace-period changes update configuration.');
    policyTestSame(policyTestInstant('2026-01-02T00:00:00+00:00'), $changed->policy()->activatedAt(), 'Grace-period changes retain activation.');
    policyTestSame(array('role_policy_grace_changed'), policyTestEventTypes($changed->events()), 'Grace-period changes are explainable lifecycle outputs.');
}

function policyTestExistingHolderGetsPolicyActivationAsAffectedSince(): void
{
    $policy = RolePolicy::discovered(
        new RoleKey('editor'),
        'Editor',
        policyTestInstant('2026-01-01T00:00:00+00:00')
    );
    $policy = (new RolePolicyLifecycle())->enable($policy, policyTestInstant('2026-01-02T00:00:00+00:00'))->policy();
    $resolution = (new RolePolicyResolver())->resolve(new RolePolicyResolutionInput(
        42,
        array(new RoleKey('editor')),
        array($policy),
        array(),
        false,
        new EnrollmentCycleId('cycle-1'),
        array(),
        policyTestInstant('2026-01-03T00:00:00+00:00')
    ));

    policyTestTrue($resolution->isProtected(), 'An active role policy protects the current role holder.');
    policyTestSame(
        policyTestInstant('2026-01-02T00:00:00+00:00'),
        $resolution->anchorsToPersist()[0]->affectedSince(),
        'A holder affected at activation uses the immutable policy activation anchor.'
    );
    policyTestSame(
        policyTestInstant('2026-01-02T00:00:00+00:00'),
        $resolution->contributingRoles()[0]->affectedSince(),
        'The contributing-role explanation exposes affected-since.'
    );
    policyTestSame(
        policyTestInstant('2026-01-02T00:00:00+00:00'),
        $resolution->baseDeadline(),
        'The role deadline uses the anchor plus the configured grace period.'
    );
}

function policyTestFirstObservationAfterActivationStartsAtObservation(): void
{
    $policy = RolePolicy::discovered(
        new RoleKey('editor'),
        'Editor',
        policyTestInstant('2026-01-01T00:00:00+00:00')
    );
    $policy = (new RolePolicyLifecycle())->enable($policy, policyTestInstant('2026-01-02T00:00:00+00:00'))->policy();
    $policy = (new RolePolicyLifecycle())->setGracePeriod($policy, 604800, policyTestInstant('2026-01-02T00:00:00+00:00'))->policy();
    $resolution = (new RolePolicyResolver())->resolve(new RolePolicyResolutionInput(
        42,
        array(new RoleKey('editor')),
        array($policy),
        array(),
        false,
        new EnrollmentCycleId('cycle-1'),
        array(),
        policyTestInstant('2026-01-10T00:00:00+00:00'),
        array('editor' => policyTestInstant('2026-01-10T00:00:00+00:00'))
    ));

    policyTestSame(
        policyTestInstant('2026-01-10T00:00:00+00:00'),
        $resolution->anchorsToPersist()[0]->affectedSince(),
        'A user first observed after activation starts at first observation.'
    );
    policyTestSame(
        policyTestInstant('2026-01-17T00:00:00+00:00'),
        $resolution->effectiveDeadline(),
        'A later first observation receives the configured grace period.'
    );
}

function policyTestExistingAffectedSinceIsNeverReset(): void
{
    $policy = RolePolicy::fromStorage(
        new RoleKey('editor'),
        'Editor',
        new RolePolicyStatus(RolePolicyStatus::ACTIVE),
        true,
        604800,
        policyTestInstant('2026-01-01T00:00:00+00:00'),
        policyTestInstant('2026-01-01T00:00:00+00:00'),
        policyTestInstant('2026-01-01T00:00:00+00:00'),
        policyTestInstant('2026-01-01T00:00:00+00:00'),
        policyTestInstant('2026-01-01T00:00:00+00:00')
    );
    $anchor = new UserRolePolicyAnchor(
        42,
        new RoleKey('editor'),
        policyTestInstant('2026-01-02T00:00:00+00:00')
    );
    $resolution = (new RolePolicyResolver())->resolve(new RolePolicyResolutionInput(
        42,
        array(new RoleKey('editor')),
        array($policy),
        array($anchor),
        false,
        new EnrollmentCycleId('cycle-1'),
        array(),
        policyTestInstant('2026-01-20T00:00:00+00:00')
    ));

    policyTestSame(array(), $resolution->anchorsToPersist(), 'Repeated reconciliation does not rewrite an existing affected-since anchor.');
    policyTestSame(policyTestInstant('2026-01-02T00:00:00+00:00'), $resolution->contributingRoles()[0]->affectedSince(), 'Existing affected-since remains immutable.');
    policyTestTrue($resolution->isOverdue(), 'A user at or beyond the unchanged deadline is overdue.');
}

function policyTestMultipleRolesUseEarliestDeadlineAndExplainContributors(): void
{
    $lifecycle = new RolePolicyLifecycle();
    $editor = RolePolicy::discovered(new RoleKey('editor'), 'Editor', policyTestInstant('2026-01-01T00:00:00+00:00'));
    $editor = $lifecycle->enable($editor, policyTestInstant('2026-01-01T00:00:00+00:00'))->policy();
    $editor = $lifecycle->setGracePeriod($editor, 1209600, policyTestInstant('2026-01-01T00:00:00+00:00'))->policy();
    $reviewer = RolePolicy::discovered(new RoleKey('reviewer'), 'Reviewer', policyTestInstant('2026-01-03T00:00:00+00:00'));
    $reviewer = $lifecycle->enable($reviewer, policyTestInstant('2026-01-03T00:00:00+00:00'))->policy();
    $reviewer = $lifecycle->setGracePeriod($reviewer, 259200, policyTestInstant('2026-01-03T00:00:00+00:00'))->policy();

    $resolution = (new RolePolicyResolver())->resolve(new RolePolicyResolutionInput(
        42,
        array(new RoleKey('reviewer'), new RoleKey('editor')),
        array($reviewer, $editor),
        array(
            new UserRolePolicyAnchor(42, new RoleKey('editor'), policyTestInstant('2026-01-01T00:00:00+00:00')),
            new UserRolePolicyAnchor(42, new RoleKey('reviewer'), policyTestInstant('2026-01-03T00:00:00+00:00')),
        ),
        false,
        new EnrollmentCycleId('cycle-1'),
        array(),
        policyTestInstant('2026-01-04T00:00:00+00:00')
    ));

    policyTestSame(2, count($resolution->contributingRoles()), 'Every active contributing role is returned.');
    policyTestSame('editor', $resolution->contributingRoles()[0]->roleKey()->value(), 'Contributing output is deterministic by role key.');
    policyTestSame('reviewer', $resolution->contributingRoles()[1]->roleKey()->value(), 'Contributing output includes the stricter role.');
    policyTestSame(policyTestInstant('2026-01-15T00:00:00+00:00'), $resolution->contributingRoles()[0]->deadline(), 'The editor deadline is explained.');
    policyTestSame(policyTestInstant('2026-01-06T00:00:00+00:00'), $resolution->contributingRoles()[1]->deadline(), 'The reviewer deadline is explained.');
    policyTestSame(policyTestInstant('2026-01-06T00:00:00+00:00'), $resolution->baseDeadline(), 'The strictest active role wins by minimum deadline.');
}

function policyTestOrphanedAndDisabledPoliciesDoNotProtect(): void
{
    $lifecycle = new RolePolicyLifecycle();
    $policy = RolePolicy::discovered(new RoleKey('editor'), 'Editor', policyTestInstant('2026-01-01T00:00:00+00:00'));
    $orphaned = $lifecycle->reconcile(
        RoleDiscoverySnapshot::fromRoleLabels(array(), policyTestInstant('2026-01-02T00:00:00+00:00')),
        array($policy)
    )->policy(new RoleKey('editor'));
    $resolution = (new RolePolicyResolver())->resolve(new RolePolicyResolutionInput(
        42,
        array(new RoleKey('editor')),
        array($orphaned),
        array(),
        false,
        new EnrollmentCycleId('cycle-1'),
        array(),
        policyTestInstant('2026-01-03T00:00:00+00:00')
    ));

    policyTestFalse($resolution->isProtected(), 'Orphaned policies never protect users.');
    policyTestNull($resolution->effectiveDeadline(), 'Orphaned policies have no effective deadline.');
    policyTestSame(array(), $resolution->contributingRoles(), 'Orphaned policies do not contribute a role explanation.');
}

function policyTestEnrolledUsersHaveNoEnrollmentDeadlineButKeepContributors(): void
{
    $policy = RolePolicy::fromStorage(
        new RoleKey('editor'),
        'Editor',
        new RolePolicyStatus(RolePolicyStatus::ACTIVE),
        true,
        0,
        policyTestInstant('2026-01-01T00:00:00+00:00'),
        policyTestInstant('2026-01-01T00:00:00+00:00'),
        policyTestInstant('2026-01-01T00:00:00+00:00'),
        policyTestInstant('2026-01-01T00:00:00+00:00'),
        policyTestInstant('2026-01-01T00:00:00+00:00')
    );
    $resolution = (new RolePolicyResolver())->resolve(new RolePolicyResolutionInput(
        42,
        array(new RoleKey('editor')),
        array($policy),
        array(new UserRolePolicyAnchor(42, new RoleKey('editor'), policyTestInstant('2026-01-01T00:00:00+00:00'))),
        true,
        new EnrollmentCycleId('cycle-1'),
        array(),
        policyTestInstant('2026-01-02T00:00:00+00:00')
    ));

    policyTestTrue($resolution->isProtected(), 'Enrollment does not remove the active role policy contribution.');
    policyTestSame(1, count($resolution->contributingRoles()), 'Enrolled users remain explainable.');
    policyTestNull($resolution->effectiveDeadline(), 'Enrolled users have no applicable enrollment deadline.');
    policyTestFalse($resolution->isOverdue(), 'Enrolled users are never overdue for enrollment.');
}

function policyTestDeadlineBoundaryEnforcesAtNow(): void
{
    $policy = RolePolicy::fromStorage(
        new RoleKey('editor'),
        'Editor',
        new RolePolicyStatus(RolePolicyStatus::ACTIVE),
        true,
        86400,
        policyTestInstant('2026-01-01T00:00:00+00:00'),
        policyTestInstant('2026-01-01T00:00:00+00:00'),
        policyTestInstant('2026-01-01T00:00:00+00:00'),
        policyTestInstant('2026-01-01T00:00:00+00:00'),
        policyTestInstant('2026-01-01T00:00:00+00:00')
    );
    $anchor = new UserRolePolicyAnchor(42, new RoleKey('editor'), policyTestInstant('2026-01-01T00:00:00+00:00'));
    $resolver = new RolePolicyResolver();
    $before = $resolver->resolve(new RolePolicyResolutionInput(
        42,
        array(new RoleKey('editor')),
        array($policy),
        array($anchor),
        false,
        new EnrollmentCycleId('cycle-1'),
        array(),
        policyTestInstant('2026-01-01T23:59:59+00:00')
    ));
    $at = $resolver->resolve(new RolePolicyResolutionInput(
        42,
        array(new RoleKey('editor')),
        array($policy),
        array($anchor),
        false,
        new EnrollmentCycleId('cycle-1'),
        array(),
        policyTestInstant('2026-01-02T00:00:00+00:00')
    ));

    policyTestFalse($before->isOverdue(), 'Grace remains eligible before the deadline.');
    policyTestTrue($at->isOverdue(), 'Enforcement begins when now equals the deadline.');
}

function policyTestExtensionsAreAbsoluteCycleScopedAndAppliedAfterMinimum(): void
{
    $policy = RolePolicy::fromStorage(
        new RoleKey('reviewer'),
        'Reviewer',
        new RolePolicyStatus(RolePolicyStatus::ACTIVE),
        true,
        432000,
        policyTestInstant('2026-01-01T00:00:00+00:00'),
        policyTestInstant('2026-01-01T00:00:00+00:00'),
        policyTestInstant('2026-01-01T00:00:00+00:00'),
        policyTestInstant('2026-01-01T00:00:00+00:00'),
        policyTestInstant('2026-01-01T00:00:00+00:00')
    );
    $cycle = new EnrollmentCycleId('cycle-1');
    $extension = GraceExtension::grant(
        42,
        $cycle,
        policyTestInstant('2026-01-04T00:00:00+00:00'),
        345600,
        policyTestInstant('2026-01-06T00:00:00+00:00'),
        'admin:7',
        'support case 123'
    );
    $wrongCycle = GraceExtension::grant(
        42,
        new EnrollmentCycleId('cycle-2'),
        policyTestInstant('2026-01-04T00:00:00+00:00'),
        2592000,
        policyTestInstant('2026-01-06T00:00:00+00:00'),
        'admin:7',
        'wrong cycle'
    );
    $resolution = (new RolePolicyResolver())->resolve(new RolePolicyResolutionInput(
        42,
        array(new RoleKey('reviewer')),
        array($policy),
        array(new UserRolePolicyAnchor(42, new RoleKey('reviewer'), policyTestInstant('2026-01-01T00:00:00+00:00'))),
        false,
        $cycle,
        array($extension, $wrongCycle),
        policyTestInstant('2026-01-05T00:00:00+00:00')
    ));

    policyTestSame(policyTestInstant('2026-01-06T00:00:00+00:00'), $resolution->baseDeadline(), 'The base deadline is resolved before extensions.');
    policyTestSame(policyTestInstant('2026-01-10T00:00:00+00:00'), $extension->grantedUntil(), 'A grant stores an absolute cycle deadline.');
    policyTestSame(policyTestInstant('2026-01-10T00:00:00+00:00'), $resolution->extensionUntil(), 'Only the current cycle extension is applicable.');
    policyTestSame(policyTestInstant('2026-01-10T00:00:00+00:00'), $resolution->effectiveDeadline(), 'The extension is applied after the multi-role base deadline.');
}

function policyTestExtensionGrantsCannotShortenTheCurrentDeadline(): void
{
    $extension = GraceExtension::grant(
        42,
        new EnrollmentCycleId('cycle-1'),
        policyTestInstant('2026-01-04T00:00:00+00:00'),
        172800,
        policyTestInstant('2026-01-10T00:00:00+00:00'),
        'system:recovery',
        'recovery'
    );

    policyTestSame(policyTestInstant('2026-01-10T00:00:00+00:00'), $extension->previousEffectiveDeadline(), 'The grant records the previous effective deadline.');
    policyTestSame(policyTestInstant('2026-01-12T00:00:00+00:00'), $extension->grantedUntil(), 'A grant starts from the later of now and the current deadline.');
    policyTestSame(policyTestInstant('2026-01-12T00:00:00+00:00'), $extension->newEffectiveDeadline(), 'The grant records the new absolute effective deadline.');
}

function policyTestInvalidRoleAndExtensionInputsAreRejected(): void
{
    policyTestThrows(static function (): void {
        new RoleKey('');
    }, 'An empty role key must not be accepted.');
    policyTestThrows(static function (): void {
        new EnrollmentCycleId('');
    }, 'An empty enrollment cycle ID must not be accepted.');
    policyTestThrows(static function (): void {
        GraceExtension::grant(
            42,
            new EnrollmentCycleId('cycle-1'),
            policyTestInstant('2026-01-01T00:00:00+00:00'),
            -1,
            policyTestInstant('2026-01-02T00:00:00+00:00'),
            'admin:7',
            'invalid'
        );
    }, 'Negative extension durations must be rejected.');
}

$policyTests = array(
    'new roles are disabled and labels are not identity' => 'policyTestNewRolesAreDisabledAndLabelsAreNotIdentity',
    'enable disable reenable retains activation' => 'policyTestEnableDisableAndReenableRetainsActivation',
    'deletion and reappearance retain policy history' => 'policyTestDeletionAndSameKeyReappearanceRetainPolicyHistory',
    'grace changes retain activation' => 'policyTestGraceChangesDoNotRewriteActivation',
    'existing holders anchor at policy activation' => 'policyTestExistingHolderGetsPolicyActivationAsAffectedSince',
    'later observations anchor at observation' => 'policyTestFirstObservationAfterActivationStartsAtObservation',
    'affected since is immutable' => 'policyTestExistingAffectedSinceIsNeverReset',
    'multiple roles use earliest deadline' => 'policyTestMultipleRolesUseEarliestDeadlineAndExplainContributors',
    'orphaned and disabled policies do not protect' => 'policyTestOrphanedAndDisabledPoliciesDoNotProtect',
    'enrolled users have no deadline' => 'policyTestEnrolledUsersHaveNoEnrollmentDeadlineButKeepContributors',
    'deadline boundary enforces at now' => 'policyTestDeadlineBoundaryEnforcesAtNow',
    'extensions are cycle scoped and absolute' => 'policyTestExtensionsAreAbsoluteCycleScopedAndAppliedAfterMinimum',
    'extensions cannot shorten deadlines' => 'policyTestExtensionGrantsCannotShortenTheCurrentDeadline',
    'invalid inputs are rejected' => 'policyTestInvalidRoleAndExtensionInputsAreRejected',
);

$passed = 0;
foreach ($policyTests as $description => $test) {
    $test();
    $passed++;
    echo "PASS {$description}\n";
}

echo "{$passed} policy tests passed.\n";
