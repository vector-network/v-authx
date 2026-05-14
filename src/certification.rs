use crate::auth_ratio::{AuthRatioEngine, AuthRatioInput};
use crate::error::Result;
use crate::record::{stable_hash_hex, vector_event_hash, vector_signature_payload, RecordEvent};
use crate::types::{
    CertificationResult, CertificationState, CanonicalVector, EvaluationContext, LogicalClock,
    PublicKey, Score, ThresholdPolicy,
};
use std::collections::BTreeMap;

/// Incoming certification request.
#[derive(Debug, Clone, PartialEq)]
pub struct CertificationInput {
    pub vector: CanonicalVector,
    pub ctx: EvaluationContext,
    pub expected_composition: Option<Vec<(String, Score)>>,
    pub ownership_proof_valid: bool,
    pub threshold_policy: ThresholdPolicy,
    pub weights: crate::types::AuthWeights,
    pub extension_factors: crate::types::ExtensionFactors,
    pub weight_set_reference: String,
    pub policy_version_reference: String,
    pub evaluation_marker: String,
    pub magnitude_bounds: Option<(u128, u128)>,
    pub force_pending: bool,
    pub revoked: bool,
    pub suspended: bool,
}

/// Deterministic certification engine.
#[derive(Debug, Clone)]
pub struct CertificationEngine {
    pub auth_ratio_engine: AuthRatioEngine,
}

impl Default for CertificationEngine {
    fn default() -> Self {
        Self {
            auth_ratio_engine: AuthRatioEngine::default(),
        }
    }
}

impl CertificationEngine {
    pub fn certify(&self, input: &CertificationInput) -> Result<CertificationResult> {
        input.vector.v.validate_nonnegative()?;

        let evaluation = self.auth_ratio_engine.evaluate(&AuthRatioInput {
            vector: input.vector.v.clone(),
            ctx: input.ctx.clone(),
            expected_composition: input.expected_composition.clone(),
            ownership_proof_valid: input.ownership_proof_valid,
            extension_factors: input.extension_factors.clone(),
            weights: input.weights,
            threshold_policy: input.threshold_policy.clone(),
            weight_set_reference: input.weight_set_reference.clone(),
            policy_version_reference: input.policy_version_reference.clone(),
            evaluation_marker: input.evaluation_marker.clone(),
            magnitude_bounds: input.magnitude_bounds,
            require_zero_guard: !matches!(input.vector.tau, crate::types::VectorType::Zero),
        })?;

        let mut state = if input.force_pending {
            CertificationState::Pending
        } else if input.revoked {
            CertificationState::Revoked
        } else if input.suspended {
            CertificationState::Suspended
        } else if evaluation.certified {
            CertificationState::Certified
        } else {
            CertificationState::Uncertified
        };

        if matches!(state, CertificationState::Certified) && !evaluation.certified {
            state = CertificationState::Uncertified;
        }

        let reason = match state {
            CertificationState::Certified => None,
            CertificationState::Pending => Some("pending validation".to_string()),
            CertificationState::Uncertified => {
                Some("AuthRatio below threshold or proof missing".to_string())
            }
            CertificationState::Suspended => Some("temporarily blocked by policy".to_string()),
            CertificationState::Revoked => {
                Some("revoked by policy or explicit reauthorization required".to_string())
            }
        };

        Ok(CertificationResult {
            state,
            evaluation,
            reason,
        })
    }

    /// Build a record event that captures the certification transition.
    pub fn certification_record(
        &self,
        input: &CertificationInput,
        certification: &CertificationResult,
        region_id: &str,
        entity_id: &str,
        actor_pk: &PublicKey,
        parent_hashes: &[String],
        logical_clock: LogicalClock,
        timestamp: u64,
        proof: &str,
    ) -> RecordEvent {
        let eid = stable_hash_hex(&[
            region_id.as_bytes(),
            entity_id.as_bytes(),
            actor_pk.as_bytes(),
            proof.as_bytes(),
            &logical_clock.to_le_bytes(),
            &timestamp.to_le_bytes(),
        ]);

        let event_hash = vector_event_hash(
            &eid,
            parent_hashes,
            region_id,
            entity_id,
            "CERTIFY",
            certification.evaluation.score,
            certification.evaluation.certified,
            logical_clock,
            timestamp,
            &input.vector.v,
            &input.vector.v,
            proof,
        );

        let signature = vector_signature_payload(&eid, "CERTIFY", entity_id, actor_pk, &event_hash);

        let mut params = BTreeMap::new();
        params.insert(
            "threshold".into(),
            format!("{:.12}", certification.evaluation.threshold),
        );
        params.insert(
            "score".into(),
            format!("{:.12}", certification.evaluation.score),
        );
        params.insert("state".into(), format!("{:?}", certification.state));
        params.insert(
            "policy_version".into(),
            certification.evaluation.policy_version_reference.clone(),
        );
        params.insert(
            "weight_set".into(),
            certification.evaluation.weight_set_reference.clone(),
        );

        RecordEvent::new(
            eid,
            parent_hashes.to_vec(),
            region_id.to_string(),
            entity_id.to_string(),
            input.vector.v.clone(),
            input.vector.v.clone(),
            "CERTIFY".to_string(),
            params,
            certification.evaluation.score,
            certification.evaluation.certified,
            certification.state,
            actor_pk.clone(),
            proof.to_string(),
            logical_clock,
            timestamp,
            signature,
            event_hash,
        )
    }
}

/// Standalone helper that converts a result into a compliance flag.
pub fn is_certified(result: &CertificationResult) -> bool {
    matches!(result.state, CertificationState::Certified)
}

/// Build a default certification input for a vector with explicit policy controls.
#[allow(clippy::too_many_arguments)]
pub fn default_certification_input(
    vector: CanonicalVector,
    ctx: EvaluationContext,
    threshold_policy: ThresholdPolicy,
    weights: crate::types::AuthWeights,
    extension_factors: crate::types::ExtensionFactors,
    weight_set_reference: String,
    policy_version_reference: String,
    evaluation_marker: String,
    ownership_proof_valid: bool,
) -> CertificationInput {
    CertificationInput {
        vector,
        ctx,
        expected_composition: None,
        ownership_proof_valid,
        threshold_policy,
        weights,
        extension_factors,
        weight_set_reference,
        policy_version_reference,
        evaluation_marker,
        magnitude_bounds: None,
        force_pending: false,
        revoked: false,
        suspended: false,
    }
}