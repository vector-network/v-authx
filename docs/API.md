# API

## Main public types

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
- `RecordEvent`
- `AuthxError`

## Main engines

- `AuthRatioEngine`
- `CertificationEngine`
- `OriginEngine`
- `DrainEngine`

## Common helpers

- `default_certification_input`
- `is_certified`
- stable record hash helpers
- signature payload helpers

## Error behavior

All engines return `Result<T, AuthxError>`.

That means:
- validation failures are explicit
- policy mismatches are explicit
- zero-vector safety is explicit
- invalid origin conditions are explicit
- invalid drain inputs are explicit

The crate is designed so that invalid state never silently becomes authoritative.
