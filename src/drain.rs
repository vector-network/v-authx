use crate::error::{AuthxError, Result};
use crate::types::{clamp_score, CertificationState, DrainResult, DrainRule, Score, VectorState};

/// Deterministic drain evaluator.
#[derive(Debug, Clone, Copy)]
pub struct DrainEngine {
    /// When the policy uses credit logic, this factor scales the available credit.
    pub credit_scale: Score,
}

impl Default for DrainEngine {
    fn default() -> Self {
        Self { credit_scale: 1.0 }
    }
}

impl DrainEngine {
    pub fn apply(&self, vector: &VectorState, rule: &DrainRule, auth_ratio: Score) -> Result<DrainResult> {
        if !(0.0..=1.0).contains(&auth_ratio) {
            return Err(AuthxError::ErrScoreOutOfBounds { score: auth_ratio });
        }

        let magnitude = vector.magnitude();
        let (requested_delta, credit, effective_delta) = match rule {
            DrainRule::Percentage { delta } => {
                self.validate_delta(*delta)?;
                (*delta, 0.0, *delta)
            }
            DrainRule::Absolute { amount } => {
                if *amount == 0 {
                    return Ok(DrainResult {
                        requested_delta: 0.0,
                        credit: 0.0,
                        effective_delta: 0.0,
                        removed_amount: 0,
                        retained_amount: magnitude,
                    });
                }
                if *amount > magnitude {
                    return Err(AuthxError::ErrInvalidDrain(
                        "absolute drain exceeds magnitude".to_string(),
                    ));
                }
                let delta = if magnitude == 0 { 0.0 } else { (*amount as Score) / (magnitude as Score) };
                (delta, 0.0, delta)
            }
            DrainRule::AuthRatioLinked {
                delta,
                credit_scale,
                max_credit,
            } => {
                self.validate_delta(*delta)?;
                if !(*credit_scale >= 0.0 && *max_credit >= 0.0) {
                    return Err(AuthxError::ErrInvalidDrain(
                        "credit parameters must be nonnegative".to_string(),
                    ));
                }
                let credit_raw = clamp_score(auth_ratio * *credit_scale);
                let credit = credit_raw.min(*max_credit);
                let effective = (*delta - credit).max(0.0);
                (*delta, credit, effective)
            }
        };

        let removed_amount = ((magnitude as Score) * effective_delta).round() as u128;
        let retained_amount = magnitude.saturating_sub(removed_amount);
        Ok(DrainResult {
            requested_delta,
            credit,
            effective_delta,
            removed_amount,
            retained_amount,
        })
    }

    pub fn apply_to_vector(&self, vector: &VectorState, rule: &DrainRule, auth_ratio: Score) -> Result<VectorState> {
        let result = self.apply(vector, rule, auth_ratio)?;
        let ratio = if vector.magnitude() == 0 {
            0.0
        } else {
            result.retained_amount as Score / vector.magnitude() as Score
        };
        vector.scaled_by_ratio(ratio)
    }

    pub fn certification_gate(state: CertificationState) -> bool {
        matches!(state, CertificationState::Certified)
    }

    fn validate_delta(&self, delta: Score) -> Result<()> {
        if !(0.0..=1.0).contains(&delta) {
            return Err(AuthxError::ErrInvalidDrain(format!(
                "drain delta {delta} must be within [0,1]"
            )));
        }
        Ok(())
    }
}

/// Compute the effective drain delta according to the blueprint's offset rule.
pub fn delta_effective(delta: Score, credit: Score) -> Score {
    (delta - credit).max(0.0)
}

/// Compute AuthRatio-linked drain credit from a score and a policy cap.
pub fn authratio_credit(auth_ratio: Score, credit_scale: Score, max_credit: Score) -> Score {
    let scaled = clamp_score(auth_ratio * credit_scale);
    scaled.min(max_credit)
}
