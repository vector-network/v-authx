# Testing

## Terminal checks

From the crate root:

```bash
cargo check
cargo test
cargo run --example demo
```

## What the integration tests should cover

### 1. AuthRatio certification
Use a standard non-zero vector with valid ownership and a threshold below the computed score.

Expected:
- score inside `[0, 1]`
- certification succeeds

### 2. Drain with AuthRatio credit
Use an AuthRatio-linked drain rule and a high AuthRatio value.

Expected:
- effective delta is reduced
- effective delta stays non-negative

### 3. Origin creation
Use a valid origin challenge, sufficient effort score, and non-empty proof payload.

Expected:
- origin event is created
- record hash is stable
- origin creation is rejected when any required field is invalid

## Warning hygiene
The crate should compile without unused-import warnings in the core files and with only intentional warnings in tests or examples.

## Useful manual commands

```bash
cargo test -- --nocapture
cargo test auth_ratio_certifies_expected_vector -- --nocapture
cargo test drain_uses_authratio_credit -- --nocapture
cargo test origin_creation_requires_effort_and_certifies -- --nocapture
```
