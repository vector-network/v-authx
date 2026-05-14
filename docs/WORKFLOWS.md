# Workflows

## Certification workflow

1. Construct a `VectorState`.
2. Wrap it in a `CanonicalVector`.
3. Prepare an `EvaluationContext`.
4. Select a `ThresholdPolicy`.
5. Define `AuthWeights`.
6. Call the certification engine.
7. Inspect the returned certification state.
8. If accepted, write a certification record.

### Expected outputs
- valid score in `[0, 1]`
- factor breakdown
- certified or uncertified state
- stable record fields if emitted

## Origin workflow

1. Provide an origin identifier.
2. Provide a challenge ID with the expected origin prefix.
3. Provide a measurable effort score.
4. Provide proof material.
5. Run the origin engine.
6. Require a certification pass.
7. Emit the origin event only when allowed.

### Expected outputs
- accepted origin only when proof and effort are sufficient
- record hash and signature payload
- no record when validation fails

## Drain workflow

1. Select a vector.
2. Select a drain rule.
3. Provide the current AuthRatio.
4. Compute credit reduction if enabled.
5. Apply the final drain delta.
6. Emit the drain result and record when needed.

### Expected outputs
- effective delta never below zero
- bounded adjusted magnitude
- deterministic output for the same input

## Replay workflow

1. Load immutable records.
2. Reconstruct derived state in causal order.
3. Re-evaluate policy using the same configuration.
4. Compare reconstructed results against expected state.

### Expected outputs
- same inputs produce same outputs
- divergent state indicates tampering or version mismatch
