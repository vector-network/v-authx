use crate::error::{AuthxError, Result};
use crate::types::{
    approx_equal, clamp_score, AuthRatioEvaluation, AuthWeights, EvaluationContext,
    ExtensionFactors, FactorBreakdown, Score, ThresholdPolicy, VectorState,
};

/// Input bundle for AuthRatio evaluation.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthRatioInput {
    pub vector: VectorState,
    pub ctx: EvaluationContext,
    pub expected_composition: Option<Vec<(String, Score)>>,
    pub ownership_proof_valid: bool,
    pub extension_factors: ExtensionFactors,
    pub weights: AuthWeights,
    pub threshold_policy: ThresholdPolicy,
    pub weight_set_reference: String,
    pub policy_version_reference: String,
    pub evaluation_marker: String,
    pub magnitude_bounds: Option<(u128, u128)>,
    pub require_zero_guard: bool,
}

/// Deterministic AuthRatio evaluator.
#[derive(Debug, Clone)]
pub struct AuthRatioEngine {
    /// When comparing weights, allow a tiny tolerance for representation noise.
    pub weight_tolerance: Score,
    /// Composition matching tolerance for the normalized vector template.
    pub composition_tolerance: Score,
}

impl Default for AuthRatioEngine {
    fn default() -> Self {
        Self {
            weight_tolerance: 1e-9,
            composition_tolerance: 1e-9,
        }
    }
}

impl AuthRatioEngine {
    pub fn evaluate(&self, input: &AuthRatioInput) -> Result<AuthRatioEvaluation> {
        input.weights.validate(self.weight_tolerance)?;

        if input.require_zero_guard && input.vector.is_zero() {
            return Err(AuthxError::ErrZeroVectorNormalization);
        }

        input.vector.validate_nonnegative()?;

        let threshold = input.threshold_policy.threshold(&input.ctx)?;
        let magnitude = self.magnitude_score(&input.vector, input.magnitude_bounds, &input.ctx)?;
        let composition = self.composition_score(&input.vector, input.expected_composition.as_ref())?;
        let ownership = if input.ownership_proof_valid { 1.0 } else { 0.0 };
        let optional = self.extension_score(&input.extension_factors)?;

        let score = clamp_score(
            input.weights.w_m * magnitude
                + input.weights.w_c * composition
                + input.weights.w_o * ownership
                + input.weights.w_x * optional,
        );

        let factor_breakdown = FactorBreakdown {
            magnitude,
            composition,
            ownership,
            extension: optional,
            optional_factors: input
                .extension_factors
                .iter_scores()
                .into_iter()
                .map(|(n, s)| (n.to_string(), s))
                .collect(),
        };

        Ok(AuthRatioEvaluation {
            score,
            threshold,
            certified: score >= threshold,
            factor_breakdown,
            weight_set_reference: input.weight_set_reference.clone(),
            policy_version_reference: input.policy_version_reference.clone(),
            evaluation_marker: input.evaluation_marker.clone(),
        })
    }

    fn magnitude_score(
        &self,
        vector: &VectorState,
        bounds: Option<(u128, u128)>,
        ctx: &EvaluationContext,
    ) -> Result<Score> {
        let mag = vector.magnitude();
        if let Some((min, max)) = bounds {
            if min > max {
                return Err(AuthxError::ErrInvalidInput(
                    "magnitude bounds are inverted".to_string(),
                ));
            }
            if mag < min || mag > max {
                return Ok(0.0);
            }
        }

        // Enforce explicit zero behavior: the zero vector is valid only if the active type permits it.
        if mag == 0 {
            return Ok(match ctx.vector_type {
                crate::types::VectorType::Zero => 1.0,
                _ => 0.5,
            });
        }

        Ok(1.0)
    }

    fn composition_score(
        &self,
        vector: &VectorState,
        expected: Option<&Vec<(String, Score)>>,
    ) -> Result<Score> {
        match expected {
            None => Ok(1.0),
            Some(template) => {
                if template.is_empty() {
                    return Ok(1.0);
                }
                let composition = vector.normalized_composition()?;
                let mut error = 0.0;
                for (name, target) in template {
                    let actual = composition.get(name).copied().unwrap_or(0.0);
                    error += (actual - *target).abs();
                }
                let score = clamp_score(1.0 - error);
                Ok(score)
            }
        }
    }

    fn extension_score(&self, extensions: &ExtensionFactors) -> Result<Score> {
        let scores = extensions.iter_scores();
        if scores.is_empty() {
            return Ok(0.0);
        }
        let mut total = 0.0;
        for (_, score) in &scores {
            if !(0.0..=1.0).contains(score) {
                return Err(AuthxError::ErrScoreOutOfBounds { score: *score });
            }
            total += *score;
        }
        Ok(clamp_score(total / scores.len() as Score))
    }
}

/// Convenience function for a one-shot AuthRatio evaluation.
pub fn evaluate_auth_ratio(input: &AuthRatioInput) -> Result<AuthRatioEvaluation> {
    AuthRatioEngine::default().evaluate(input)
}

/// Helper for validating a factor score list and producing a normalized scalar.
pub fn normalize_factor_scores(scores: &[Score]) -> Result<Score> {
    if scores.is_empty() {
        return Err(AuthxError::ErrInvalidInput(
            "factor score list cannot be empty".to_string(),
        ));
    }
    let mut sum = 0.0;
    for score in scores {
        if !(0.0..=1.0).contains(score) {
            return Err(AuthxError::ErrScoreOutOfBounds { score: *score });
        }
        sum += *score;
    }
    Ok(clamp_score(sum / scores.len() as Score))
}

/// Validate that a normalized composition exactly matches a template within tolerance.
pub fn composition_matches(
    actual: &[(String, Score)],
    template: &[(String, Score)],
    tolerance: Score,
) -> Result<bool> {
    if template.is_empty() {
        return Ok(actual.is_empty());
    }
    let mut actual_map = std::collections::BTreeMap::new();
    for (k, v) in actual {
        actual_map.insert(k.clone(), *v);
    }
    let mut error = 0.0;
    for (k, target) in template {
        let observed = actual_map.get(k).copied().unwrap_or(0.0);
        error += (observed - *target).abs();
    }
    Ok(approx_equal(error, 0.0, tolerance))
}
