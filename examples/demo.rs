use v_authx::prelude::*;

fn main() -> Result<()> {
    let vector = VectorState::from_pairs([("alpha", 60u128), ("beta", 40u128)]);
    let canonical = CanonicalVector::new(vector.clone(), "pk_demo".to_string(), VectorType::Free);
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
        "demo-eval".to_string(),
        true,
    );

    let cert_engine = CertificationEngine::default();
    let cert = cert_engine.certify(&input)?;
    println!("certification state: {:?}, score={:.4}", cert.state, cert.evaluation.score);
    println!("breakdown magnitude={:.2} composition={:.2} ownership={:.2} extension={:.2}",
        cert.evaluation.factor_breakdown.magnitude,
        cert.evaluation.factor_breakdown.composition,
        cert.evaluation.factor_breakdown.ownership,
        cert.evaluation.factor_breakdown.extension,
    );

    let drain_engine = DrainEngine::default();
    let drain_result = drain_engine.apply(&vector, &DrainRule::AuthRatioLinked {
        delta: 0.25,
        credit_scale: 1.0,
        max_credit: 0.10,
    }, cert.evaluation.score)?;
    println!("drain effective delta: {:.4}", drain_result.effective_delta);

    Ok(())
}
