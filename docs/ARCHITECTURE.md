# Architecture

`v-authx` is structured as a policy-first kernel module. Its job is to decide whether a vector transition, origin event, or drain action is valid enough to be accepted and recorded.

The crate is intentionally narrow. It does not try to solve transport, consensus, or persistence. Instead it focuses on deterministic trust evaluation.

## Layer model

### 1. Input layer
The input layer receives:
- vectors
- origin proofs
- threshold policies
- evaluation contexts
- drain rules
- actor public keys
- protocol metadata

This layer should be treated as untrusted.

### 2. Validation layer
The validation layer checks:
- vector structure
- zero-vector safety
- ownership proof presence
- policy compatibility
- threshold validity
- origin proof requirements
- drain bounds

If validation fails, the operation is rejected before mutation.

### 3. Scoring layer
The scoring layer computes AuthRatio from the selected factors. The result is bounded to `[0, 1]` and is deterministic for a given input.

### 4. Decision layer
The decision layer maps the score and status controls into one of the protocol certification states.

### 5. Record layer
If an operation is accepted, the record layer assembles an immutable event containing:
- causal metadata
- hashes
- signatures
- actor public key
- before and after state
- protocol output

## Determinism rules

Determinism is the central architectural requirement.

`v-authx` avoids:
- hidden mutable state
- random scoring behavior
- non-replayable transitions
- implicit threshold changes

Every accepted decision should be reproducible from the same inputs.

## Why the crate is split this way

The split lets each module do one thing well:

- `auth_ratio` measures validity
- `certification` turns validity into protocol status
- `origin` governs creation
- `drain` governs cost reduction
- `record` preserves the output
- `types` keeps the model consistent
- `error` keeps failures explicit

That keeps the policy path auditable and easy to reason about.

## Recommended embedding strategy

In a larger network, this crate should sit near the kernel boundary:
- upstream of storage writes
- upstream of consensus proposals
- upstream of replication fan-out
- upstream of SDK responses that imply finality

Any subsystem that needs a final answer about whether a vector action is allowed should consult this layer first.

## Replay compatibility

Because decisions are made from explicit inputs and stable outputs, the crate can support replay systems that:
- rebuild derived state from events
- re-check certification under the same policy version
- validate origin records deterministically
- apply drain logic identically across nodes
