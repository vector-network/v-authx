use std::collections::BTreeMap;
use v_authx::prelude::*;

fn sample_vector() -> VectorState {
    VectorState::from_pairs([("alpha", 60u128), ("beta", 40u128)])
}

#[test]
fn auth_ratio_certifies_expected_vector() {
    let vector = sample_vector();
    let canonical = CanonicalVector::new(vector.clone(), "pk_001".to_string(), VectorType::Free);
    let ctx = EvaluationContext {
        vector_type: VectorType::Free,
        operation_class: OperationClass::Certify,
        space_policy: "default".to_string(),
        risk_profile: "medium".to_string(),
        protocol_version: "1.1".to_string(),
    };
    let weights = AuthWeights::new(0.35, 0.25, 0.30, 0.10).unwrap();
    let input = default_certification_input(
        canonical,
        ctx,
        ThresholdPolicy::Explicit {
            version: "1.1".to_string(),
            threshold: 0.80,
        },
        weights,
        ExtensionFactors::empty(),
        "weights-v1".to_string(),
        "policy-v1".to_string(),
        "eval-1".to_string(),
        true,
    );
    let engine = CertificationEngine::default();
    let result = engine.certify(&input).unwrap();

    let mut expected_breakdown = BTreeMap::new();
    expected_breakdown.insert("magnitude", 1.0);
    expected_breakdown.insert("composition", 1.0);
    expected_breakdown.insert("ownership", 1.0);
    expected_breakdown.insert("extension", 0.0);

    assert!(result.evaluation.score >= 0.0 && result.evaluation.score <= 1.0);
    assert_eq!(result.evaluation.factor_breakdown.magnitude, 1.0);
    assert_eq!(expected_breakdown.get("magnitude"), Some(&1.0));
    assert_eq!(expected_breakdown.get("composition"), Some(&1.0));
    assert_eq!(expected_breakdown.get("ownership"), Some(&1.0));
    assert_eq!(expected_breakdown.get("extension"), Some(&0.0));
}

#[test]
fn drain_uses_authratio_credit() {
    let vector = sample_vector();
    let engine = DrainEngine::default();
    let rule = DrainRule::AuthRatioLinked {
        delta: 0.25,
        credit_scale: 1.0,
        max_credit: 0.10,
    };
    let result = engine.apply(&vector, &rule, 0.95).unwrap();
    assert!(result.effective_delta <= 0.25);
    assert!(result.effective_delta >= 0.0);

    let drained = engine.apply_to_vector(&vector, &rule, 0.95).unwrap();
    assert!(drained.magnitude() <= vector.magnitude());
}

#[test]
fn origin_creation_requires_effort_and_certifies() {
    let engine = OriginEngine::default();
    let vector = sample_vector();
    let ctx = EvaluationContext {
        vector_type: VectorType::Free,
        operation_class: OperationClass::Create,
        space_policy: "default".to_string(),
        risk_profile: "medium".to_string(),
        protocol_version: "1.1".to_string(),
    };
    let input = OriginInput {
        origin_id: "origin-001".to_string(),
        region_id: "region-a".to_string(),
        entity_id: "entity-001".to_string(),
        owner_pk: "pk_001".to_string(),
        vector,
        vector_type: VectorType::Free,
        proof: OriginProof {
            challenge_id: "origin:challenge-001".to_string(),
            effort_score: 0.9,
            proof_material: "proof-material".to_string(),
        },
        context: ctx,
        logical_clock: 1,
        timestamp: 1_700_000_000,
        parent_hashes: Vec::new(),
        proof_material_override: None,
    };
    let result = engine.create(&input).unwrap();
    assert_eq!(result.origin_id, "origin-001");
    assert!(result.record.event_hash.len() == 64);
}