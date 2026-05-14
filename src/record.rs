use crate::types::{CertificationState, LogicalClock, PublicKey, Score, VectorState};
use std::collections::BTreeMap;

/// Canonical immutable event record.
///
/// The record never stores private keys. It captures state transitions only.
#[derive(Debug, Clone, PartialEq)]
pub struct RecordEvent {
    pub eid: String,
    pub parent_hashes: Vec<String>,
    pub region_id: String,
    pub entity_id: String,
    pub v_before: VectorState,
    pub v_after: VectorState,
    pub operation: String,
    pub params: BTreeMap<String, String>,
    pub auth_ratio: Score,
    pub certified: bool,
    pub certification_state: CertificationState,
    pub actor_pk: PublicKey,
    pub proof: String,
    pub logical_clock: LogicalClock,
    pub timestamp: u64,
    pub signature: String,
    pub event_hash: String,
}

impl RecordEvent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        eid: String,
        parent_hashes: Vec<String>,
        region_id: String,
        entity_id: String,
        v_before: VectorState,
        v_after: VectorState,
        operation: String,
        params: BTreeMap<String, String>,
        auth_ratio: Score,
        certified: bool,
        certification_state: CertificationState,
        actor_pk: PublicKey,
        proof: String,
        logical_clock: LogicalClock,
        timestamp: u64,
        signature: String,
        event_hash: String,
    ) -> Self {
        Self {
            eid,
            parent_hashes,
            region_id,
            entity_id,
            v_before,
            v_after,
            operation,
            params,
            auth_ratio,
            certified,
            certification_state,
            actor_pk,
            proof,
            logical_clock,
            timestamp,
            signature,
            event_hash,
        }
    }
}

/// Deterministic, self-contained hashing helper for event identifiers and proofs.
///
/// Production deployments should replace this with the protocol's canonical cryptographic hash
/// (for example BLAKE3) while preserving the same byte-level serialization order.
pub fn stable_hash_hex(parts: &[&[u8]]) -> String {
    let mut state: [u64; 4] = [
        0xcbf29ce484222325,
        0x84222325cbf29ce4,
        0x9e3779b185ebca87,
        0x94d049bb133111eb,
    ];

    for part in parts {
        for (idx, byte) in part.iter().enumerate() {
            let lane = idx % 4;
            state[lane] ^= u64::from(*byte);
            state[lane] = state[lane].wrapping_mul(0x100000001b3);
            state[lane] = state[lane].rotate_left(13) ^ 0x9e3779b97f4a7c15;
        }
        // Domain separation between parts.
        for lane in &mut state {
            *lane ^= 0xA5A5A5A5A5A5A5A5;
            *lane = lane.rotate_left(7).wrapping_add(0x517cc1b727220a95);
        }
    }

    let mut out = String::with_capacity(64);
    for lane in state {
        out.push_str(&format!("{lane:016x}"));
    }
    out
}

pub fn hash_record_fields(fields: &[String]) -> String {
    let refs: Vec<&[u8]> = fields.iter().map(|s| s.as_bytes()).collect();
    stable_hash_hex(&refs)
}

pub fn vector_signature_payload(
    eid: &str,
    operation: &str,
    entity_id: &str,
    actor_pk: &str,
    event_hash: &str,
) -> String {
    format!("{eid}:{operation}:{entity_id}:{actor_pk}:{event_hash}")
}

pub fn vector_event_hash(
    eid: &str,
    parent_hashes: &[String],
    region_id: &str,
    entity_id: &str,
    operation: &str,
    auth_ratio: Score,
    certified: bool,
    logical_clock: LogicalClock,
    timestamp: u64,
    v_before: &VectorState,
    v_after: &VectorState,
    proof: &str,
) -> String {
    let mut parts = vec![
        eid.to_owned(),
        region_id.to_owned(),
        entity_id.to_owned(),
        operation.to_owned(),
        format!("{auth_ratio:.12}"),
        certified.to_string(),
        logical_clock.to_string(),
        timestamp.to_string(),
        format!("before={:?}", v_before.components),
        format!("after={:?}", v_after.components),
        proof.to_owned(),
    ];
    parts.extend(parent_hashes.iter().cloned());
    hash_record_fields(&parts)
}