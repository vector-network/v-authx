# Integration Notes

`v-authx` is intended to be embedded into a larger Vector Network stack.

## Typical upstream consumers
- kernel / state machine layer
- node validation layer
- wallet and SDK operations
- contract runtime
- origin creation services
- replay and audit tooling

## Typical downstream outputs
- certification result
- origin event
- drain result
- immutable record
- policy rejection

## Best practice
Call `v-authx` before any operation that would mutate durable state.

That keeps the protocol:
- deterministic
- fail-closed
- replay-friendly
- auditable

## Storage integration
This crate is not the storage engine. It is the policy gate that should precede:
- append-only storage
- snapshotting
- indexing
- replication
- synchronization

## Versioning
Any change to:
- thresholds
- AuthRatio factor definitions
- origin proof rules
- drain credit rules
- certification states

should be treated as a protocol version change, not just a code change.
