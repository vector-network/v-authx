use crate::certification::{default_certification_input, CertificationEngine};
use crate::drain::DrainEngine;
use crate::error::{AuthxError, Result};
use crate::record::{stable_hash_hex, vector_event_hash, vector_signature_payload, RecordEvent};
use crate::types::{
    AuthWeights, CanonicalVector, CertificationState, EvaluationContext, ExtensionFactors,
    LogicalClock, OriginProof, OriginResult, PublicKey, Score, ThresholdPolicy, VectorState,
};
use std::collections::BTreeMap;

/// Protocol controls for the origin engine.
#[derive(Debug, Clone)]
pub struct OriginPolicy {
    pub minimum_effort_score: Score,
    pub expected_challenge_prefix: String,
    pub allow_zero_vector_origin: bool,
    pub certification_threshold: ThresholdPolicy,
    pub auth_weights: AuthWeights,
    pub extension_factors: ExtensionFactors,
    pub weight_set_reference: String,
    pub policy_version_reference: String,
}

impl Default for OriginPolicy {
    fn default() -> Self {
        Self {
            minimum_effort_score: 0.75,
            expected_challenge_prefix: "origin:".to_string(),
            allow_zero_vector_origin: false,
            certification_threshold: ThresholdPolicy::Explicit {
                version: "v1".to_string(),
                threshold: 0.85,
            },
            auth_weights: AuthWeights {
                w_m: 0.35,
                w_c: 0.25,
                w_o: 0.30,
                w_x: 0.10,
            },
            extension_factors: ExtensionFactors::empty(),
            weight_set_reference: "default-origin-weight-set".to_string(),
            policy_version_reference: "origin-policy-v1".to_string(),
        }
    }
}

/// Input to the origin engine.
#[derive(Debug, Clone, PartialEq)]
pub struct OriginInput {
    pub origin_id: String,
    pub region_id: String,
    pub entity_id: String,
    pub owner_pk: PublicKey,
    pub vector: VectorState,
    pub vector_type: crate::types::VectorType,
    pub proof: OriginProof,
    pub context: EvaluationContext,
    pub logical_clock: LogicalClock,
    pub timestamp: u64,
    pub parent_hashes: Vec<String>,
    pub proof_material_override: Option<String>,
}

/// Origin engine executes the creation pipeline, writes the origin record, and returns a certified vector.
#[derive(Debug, Clone)]
pub struct OriginEngine {
    pub certification_engine: CertificationEngine,
    pub drain_engine: DrainEngine,
    pub policy: OriginPolicy,
}

impl Default for OriginEngine {
    fn default() -> Self {
        Self {
            certification_engine: CertificationEngine::default(),
            drain_engine: DrainEngine::default(),
            policy: OriginPolicy::default(),
        }
    }
}

impl OriginEngine {
    pub fn create(&self, input: &OriginInput) -> Result<OriginResult> {
        if input.origin_id.trim().is_empty() {
            return Err(AuthxError::ErrMissingField("origin_id"));
        }
        if input.region_id.trim().is_empty() {
            return Err(AuthxError::ErrMissingField("region_id"));
        }
        if input.entity_id.trim().is_empty() {
            return Err(AuthxError::ErrMissingField("entity_id"));
        }
        if input.owner_pk.trim().is_empty() {
            return Err(AuthxError::ErrMissingField("owner_pk"));
        }
        if input.proof.challenge_id.trim().is_empty() {
            return Err(AuthxError::ErrMissingField("proof.challenge_id"));
        }
        if !input.proof.challenge_id.starts_with(&self.policy.expected_challenge_prefix) {
            return Err(AuthxError::ErrInvalidOrigin(
                "challenge id does not match the required origin prefix".to_string(),
            ));
        }
        if input.proof.effort_score < self.policy.minimum_effort_score {
            return Err(AuthxError::ErrInvalidOrigin(format!(
                "insufficient effort score: {} < {}",
                input.proof.effort_score, self.policy.minimum_effort_score
            )));
        }
        if input.vector.is_zero() && !self.policy.allow_zero_vector_origin {
            return Err(AuthxError::ErrInvalidOrigin(
                "zero-vector origin is not allowed by policy".to_string(),
            ));
        }

        let proof_material = input
            .proof_material_override
            .clone()
            .unwrap_or_else(|| input.proof.proof_material.clone());

        let origin_hash = stable_hash_hex(&[
            input.origin_id.as_bytes(),
            input.region_id.as_bytes(),
            input.entity_id.as_bytes(),
            input.owner_pk.as_bytes(),
            input.proof.challenge_id.as_bytes(),
            proof_material.as_bytes(),
            &input.logical_clock.to_le_bytes(),
            &input.timestamp.to_le_bytes(),
        ]);

        let vector = CanonicalVector {
            v: input.vector.clone(),
            pk: input.owner_pk.clone(),
            tau: input.vector_type,
            meta: BTreeMap::from([
                ("origin_id".to_string(), input.origin_id.clone()),
                ("origin_hash".to_string(), origin_hash.clone()),
                ("origin_challenge".to_string(), input.proof.challenge_id.clone()),
            ]),
        };

        let cert_input = default_certification_input(
            vector.clone(),
            input.context.clone(),
            self.policy.certification_threshold.clone(),
            self.policy.auth_weights,
            self.policy.extension_factors.clone(),
            self.policy.weight_set_reference.clone(),
            self.policy.policy_version_reference.clone(),
            "origin-certification".to_string(),
            true,
        );

        let mut certification = self.certification_engine.certify(&cert_input)?;
        if !certification.evaluation.certified {
            certification.state = CertificationState::Uncertified;
        }

        let eid = stable_hash_hex(&[
            input.origin_id.as_bytes(),
            input.entity_id.as_bytes(),
            input.owner_pk.as_bytes(),
            origin_hash.as_bytes(),
        ]);

        let event_hash = vector_event_hash(
            &eid,
            &input.parent_hashes,
            &input.region_id,
            &input.entity_id,
            "CREATE",
            certification.evaluation.score,
            certification.evaluation.certified,
            input.logical_clock,
            input.timestamp,
            &VectorState::zero(),
            &input.vector,
            &proof_material,
        );

        let signature = vector_signature_payload(
            &eid,
            "CREATE",
            &input.entity_id,
            &input.owner_pk,
            &event_hash,
        );

        let mut params = BTreeMap::new();
        params.insert("origin_id".to_string(), input.origin_id.clone());
        params.insert("origin_hash".to_string(), origin_hash.clone());
        params.insert("challenge_id".to_string(), input.proof.challenge_id.clone());
        params.insert("effort_score".to_string(), format!("{:.12}", input.proof.effort_score));
        params.insert("certified".to_string(), certification.evaluation.certified.to_string());
        params.insert("threshold".to_string(), format!("{:.12}", certification.evaluation.threshold));

        let record = RecordEvent::new(
            eid,
            input.parent_hashes.clone(),
            input.region_id.clone(),
            input.entity_id.clone(),
            VectorState::zero(),
            input.vector.clone(),
            "CREATE".to_string(),
            params,
            certification.evaluation.score,
            certification.evaluation.certified,
            certification.state,
            input.owner_pk.clone(),
            proof_material,
            input.logical_clock,
            input.timestamp,
            signature,
            event_hash,
        );

        Ok(OriginResult {
            origin_id: input.origin_id.clone(),
            origin_hash,
            created_vector: vector,
            certification,
            record,
        })
    }
}

/// A more direct utility for origin hashing only.
pub fn origin_hash(origin_id: &str, challenge_id: &str, owner_pk: &str, proof_material: &str) -> String {
    stable_hash_hex(&[
        origin_id.as_bytes(),
        challenge_id.as_bytes(),
        owner_pk.as_bytes(),
        proof_material.as_bytes(),
    ])
}
