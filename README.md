# v-authx

`v-authx` is the authentication, certification, AuthRatio, origin, and drain core for the Vector Network blueprint.

It is designed to match the canonical requirements in the protocol docs:

- AuthRatio is a deterministic score in `[0, 1]`
- certification is threshold-based and fail-closed
- create/origin is gated by a measurable origin proof
- drain is explicit and can be reduced through policy-defined offset credit
- no private keys are stored in network state
- records are immutable and replay-friendly

This crate is intentionally self-contained and uses only the Rust standard library so it can serve as a portable kernel-stage implementation or a reference implementation.

## Included modules

`src/auth_ratio.rs`
: deterministic AuthRatio scoring and factor breakdowns

`src/certification.rs`
: certification engine and certification record generation

`src/origin.rs`
: origin creation pipeline and origin event assembly

`src/drain.rs`
: drain logic, including AuthRatio-linked reduction

`src/record.rs`
: immutable event record structure and deterministic hash helpers

`src/types.rs`
: canonical types for vectors, evaluation, thresholds, and results

`python/authratio_model.py`
: a Python model for exploring AuthRatio formulas and thresholds

## Key protocol behaviors implemented

### Certification

A vector is certified when its AuthRatio meets or exceeds the configured threshold for the current context. The engine returns a state of `Certified`, `Uncertified`, `Suspended`, `Revoked`, or `Pending`, matching the protocol rules in the blueprint and the canonical docs.

### AuthRatio

AuthRatio uses the base factors:

- magnitude validity
- composition validity
- ownership proof validity

It also supports documented optional factors:

- age of vector
- origin confidence
- historical integrity
- space trust level
- behavior reputation
- proof depth

The final score is clamped to `[0, 1]`.

### Origin engine

Origin creation requires:

- an origin identifier
- a challenge with a valid origin prefix
- an effort score above policy minimum
- a non-empty proof payload
- a final certification pass before the creation record is emitted

### Drain logic

Drain supports:

- percentage drain
- absolute drain
- AuthRatio-linked drain credit

The effective drain obeys:

`delta_effective = max(delta - credit, 0)`

### Records

State-changing operations create immutable records containing:

- causal metadata
- hashes
- signatures
- actor public key
- pre/post vector state
- auth score and certification outcome

Private keys are never stored in records.

## Usage example

```rust
use v_authx::prelude::*;
use std::collections::BTreeMap;

let vector = VectorState::from_pairs([("alpha", 60), ("beta", 40)]);
let canonical = CanonicalVector::new(vector.clone(), "pk_test_1".to_string(), VectorType::Free);

let ctx = EvaluationContext {
    vector_type: VectorType::Free,
    operation_class: OperationClass::Certify,
    space_policy: "default".to_string(),
    risk_profile: "medium".to_string(),
    protocol_version: "1.1".to_string(),
};

let input = default_certification_input(
    canonical,
    ctx,
    ThresholdPolicy::Explicit { version: "1.1".to_string(), threshold: 0.8 },
    AuthWeights::new(0.35, 0.25, 0.30, 0.10)?,
    ExtensionFactors::empty(),
    "weights-v1".to_string(),
    "policy-v1".to_string(),
    "eval-001".to_string(),
    true,
);

let engine = CertificationEngine::default();
let result = engine.certify(&input)?;
assert!(matches!(result.state, CertificationState::Certified | CertificationState::Uncertified));
# Ok::<(), v_authx::AuthxError>(())
```

## Notes for integration

This crate gives you the kernel-facing policy model. In a full network implementation, you would wire the record layer into:

- an append-only storage engine
- a spatial index
- a snapshot subsystem
- node synchronization
- replay and reconstruction tooling
- wallet and SDK wrappers

The protocol docs call for deterministic replay, explicit thresholds, and failure-closed validation; this crate keeps those constraints as first-class concerns.
