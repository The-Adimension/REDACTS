<?php
// Negative: class definition with method bodies that operate on
// already-validated input via a typed signature. Nothing dangerous
// about a domain model.
final class SubjectIdentifier
{
    public function __construct(private readonly string $value) {}

    public function value(): string { return $this->value; }
}
