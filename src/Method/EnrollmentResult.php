<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method;

final class EnrollmentResult
{
    public function __construct(
        private MethodDraft $draft,
        private SafeMetadata $metadata,
    ) {
    }

    public function draft(): MethodDraft
    {
        return $this->draft;
    }

    public function methodDraft(): MethodDraft
    {
        return $this->draft;
    }

    public function metadata(): SafeMetadata
    {
        return $this->metadata;
    }
}
