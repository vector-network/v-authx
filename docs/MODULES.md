# Modules

## `src/types.rs`
Shared protocol data model.

Contains:
- `VectorState`
- `CanonicalVector`
- `VectorType`
- `EvaluationContext`
- `OperationClass`
- `ThresholdPolicy`
- `AuthWeights`
- `ExtensionFactors`
- `CertificationState`
- `CertificationResult`
- `DrainRule`
- `DrainResult`
- math and validation helpers

This file is the schema layer for the crate.

## `src/auth_ratio.rs`
AuthRatio scoring engine.

Responsibilities:
- compute factor scores
- clamp the final score
- compare against threshold
- produce a factor breakdown
- carry reference metadata for replay and audit

This module is the numerical center of the policy path.

## `src/certification.rs`
Certification engine.

Responsibilities:
- validate the vector before scoring
- call the AuthRatio engine
- resolve the final certification state
- build certification records
- provide helper constructors for common input patterns

This module is the primary policy gate for restricted actions.

## `src/origin.rs`
Origin creation engine.

Responsibilities:
- validate creation requests
- check effort or origin proof
- enforce origin challenge rules
- require certification before acceptance
- emit origin records

This module acts like a controlled mint/origin gate.

## `src/drain.rs`
Drain engine.

Responsibilities:
- apply percentage drain
- apply absolute drain
- reduce drain through policy-linked credit
- keep final output bounded
- support deterministic replay

This module prevents hidden or arbitrary cost adjustment.

## `src/record.rs`
Record and hash utilities.

Responsibilities:
- define `RecordEvent`
- generate stable event identifiers
- generate event hashes
- generate signature payloads
- keep event assembly deterministic

This module is the persistence-facing event description layer.

## `src/error.rs`
Error taxonomy.

Responsibilities:
- keep every failure explicit
- avoid silent fallthrough
- provide human-readable display strings
- keep protocol decisions fail-closed

## `src/lib.rs`
Public API surface.

Responsibilities:
- export modules
- export the prelude
- provide the cleanest entry point for downstream code

## `python/authratio_model.py`
Exploration model.

Responsibilities:
- prototype formula ideas
- compare scoring strategies
- validate threshold intuition
- support quick experimentation outside Rust
