use crate::error::{AuthxError, Result};
use std::collections::BTreeMap;

/// Scalar type used throughout the scoring and threshold model.
pub type Score = f64;

/// Canonical component value type for vector balances.
pub type Amount = u128;

/// Public key / wallet identifier placeholder.
pub type PublicKey = String;

/// Stable logical clock for deterministic replay.
pub type LogicalClock = u64;

/// Canonical vector type tags stored in `tau` in the blueprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VectorType {
    Position,
    Free,
    Bound,
    Unit,
    Zero,
    Spatial,
}

/// Allowed operation classes in the protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OperationClass {
    Create,
    Certify,
    Transfer,
    Drain,
    Project,
    Reconstruct,
    Query,
    Record,
    Move,
    Rotate,
    Scale,
    Normalize,
    Constrain,
}

/// Certification states as defined by the canonical docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificationState {
    Pending,
    Certified,
    Uncertified,
    Suspended,
    Revoked,
}

/// Result of a deterministic proof-of-effort / origin validation step.
#[derive(Debug, Clone, PartialEq)]
pub struct OriginProof {
    pub challenge_id: String,
    pub effort_score: Score,
    pub proof_material: String,
}

/// A stable vector state representation using canonical ordering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VectorState {
    pub components: BTreeMap<String, Amount>,
}

impl VectorState {
    pub fn new(components: BTreeMap<String, Amount>) -> Self {
        Self { components }
    }

    pub fn from_pairs<I, S>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (S, Amount)>,
        S: Into<String>,
    {
        let mut components = BTreeMap::new();
        for (k, v) in pairs {
            components.insert(k.into(), v);
        }
        Self { components }
    }

    pub fn zero() -> Self {
        Self {
            components: BTreeMap::new(),
        }
    }

    pub fn is_zero(&self) -> bool {
        self.components.values().all(|v| *v == 0)
    }

    pub fn magnitude(&self) -> Amount {
        self.components.values().copied().sum()
    }

    pub fn validate_nonnegative(&self) -> Result<()> {
        // Amount is unsigned by type, so the primary structural check is presence/canonical ordering.
        // We still reject absurdly large component sets by allowing the caller to impose policy bounds.
        if self.components.keys().any(|k| k.trim().is_empty()) {
            return Err(AuthxError::ErrInvalidInput(
                "component keys must be non-empty".to_string(),
            ));
        }
        Ok(())
    }

    pub fn normalized_composition(&self) -> Result<BTreeMap<String, Score>> {
        let mag = self.magnitude();
        if mag == 0 {
            return Err(AuthxError::ErrZeroVectorNormalization);
        }
        let mag_f = mag as Score;
        let mut out = BTreeMap::new();
        for (k, v) in &self.components {
            out.insert(k.clone(), *v as Score / mag_f);
        }
        Ok(out)
    }

    pub fn scaled_by_ratio(&self, ratio: Score) -> Result<Self> {
        if !(0.0..=1.0).contains(&ratio) {
            return Err(AuthxError::ErrInvalidInput(
                "scale ratio must be within [0,1] for this helper".to_string(),
            ));
        }
        let mut components = BTreeMap::new();
        for (k, v) in &self.components {
            let scaled = ((*v as Score) * ratio).round();
            if scaled.is_sign_negative() {
                return Err(AuthxError::ErrInvalidInput(
                    "scaled component became negative".to_string(),
                ));
            }
            components.insert(k.clone(), scaled as Amount);
        }
        Ok(Self { components })
    }

    pub fn add_assign(&mut self, other: &Self) {
        for (k, v) in &other.components {
            self.components
                .entry(k.clone())
                .and_modify(|lhs| *lhs = lhs.saturating_add(*v))
                .or_insert(*v);
        }
    }

    pub fn sub_assign(&mut self, other: &Self) -> Result<()> {
        for (k, v) in &other.components {
            let lhs = self.components.get_mut(k).ok_or_else(|| {
                AuthxError::ErrInvalidState(format!("component {k} missing in subtraction"))
            })?;
            if *lhs < *v {
                return Err(AuthxError::ErrInvalidState(format!(
                    "component {k} would become negative"
                )));
            }
            *lhs -= *v;
        }
        self.components.retain(|_, v| *v > 0);
        Ok(())
    }
}

/// Wallet envelope: no private key is stored on-network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletState {
    pub wallet_id: String,
    pub pk: PublicKey,
    pub wallet_meta: BTreeMap<String, String>,
}

/// Canonical vector object used by certification and operation flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalVector {
    pub v: VectorState,
    pub pk: PublicKey,
    pub tau: VectorType,
    pub meta: BTreeMap<String, String>,
}

impl CanonicalVector {
    pub fn new(v: VectorState, pk: PublicKey, tau: VectorType) -> Self {
        Self {
            v,
            pk,
            tau,
            meta: BTreeMap::new(),
        }
    }
}

/// Context for threshold selection and factor evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationContext {
    pub vector_type: VectorType,
    pub operation_class: OperationClass,
    pub space_policy: String,
    pub risk_profile: String,
    pub protocol_version: String,
}

/// Threshold policy reference used by certification.
#[derive(Debug, Clone, PartialEq)]
pub enum ThresholdPolicy {
    Explicit {
        version: String,
        threshold: Score,
    },
    Contextual {
        version: String,
        base: Score,
        risk_adjustment: Score,
        operation_adjustment: Score,
        type_adjustment: Score,
    },
}

impl ThresholdPolicy {
    pub fn threshold(&self, ctx: &EvaluationContext) -> Result<Score> {
        let threshold = match self {
            ThresholdPolicy::Explicit { threshold, .. } => *threshold,
            ThresholdPolicy::Contextual {
                base,
                risk_adjustment,
                operation_adjustment,
                type_adjustment,
                ..
            } => {
                let mut t = *base;
                t += Self::risk_delta(&ctx.risk_profile, *risk_adjustment);
                t += Self::operation_delta(ctx.operation_class, *operation_adjustment);
                t += Self::type_delta(ctx.vector_type, *type_adjustment);
                t
            }
        };

        if !(0.0..=1.0).contains(&threshold) {
            return Err(AuthxError::ErrInvalidInput(format!(
                "threshold {threshold} must be within [0,1]"
            )));
        }
        Ok(threshold)
    }

    fn risk_delta(profile: &str, magnitude: Score) -> Score {
        match profile.to_ascii_lowercase().as_str() {
            "low" => 0.0,
            "medium" => magnitude * 0.5,
            "high" => magnitude,
            "critical" => magnitude * 1.2,
            _ => magnitude * 0.75,
        }
    }

    fn operation_delta(class: OperationClass, magnitude: Score) -> Score {
        use OperationClass::*;
        match class {
            Query | Certify | Record => 0.0,
            Create => magnitude * 0.5,
            Transfer | Drain | Project | Reconstruct => magnitude,
            Move | Rotate | Scale | Normalize | Constrain => magnitude * 0.75,
        }
    }

    fn type_delta(vector_type: VectorType, magnitude: Score) -> Score {
        match vector_type {
            VectorType::Zero => magnitude,
            VectorType::Unit => magnitude * 0.25,
            VectorType::Free => magnitude * 0.5,
            VectorType::Bound => magnitude * 0.75,
            VectorType::Position | VectorType::Spatial => magnitude * 0.6,
        }
    }
}

/// Documented optional factor bundle used in the AuthRatio extension score.
#[derive(Debug, Clone, PartialEq)]
pub struct ExtensionFactors {
    pub age_of_vector: Option<Score>,
    pub origin_confidence: Option<Score>,
    pub historical_integrity: Option<Score>,
    pub space_trust_level: Option<Score>,
    pub behavior_reputation: Option<Score>,
    pub proof_depth: Option<Score>,
}

impl ExtensionFactors {
    pub fn empty() -> Self {
        Self {
            age_of_vector: None,
            origin_confidence: None,
            historical_integrity: None,
            space_trust_level: None,
            behavior_reputation: None,
            proof_depth: None,
        }
    }

    pub fn iter_scores(&self) -> Vec<(&'static str, Score)> {
        let mut out = Vec::new();
        if let Some(v) = self.age_of_vector {
            out.push(("age_of_vector", v));
        }
        if let Some(v) = self.origin_confidence {
            out.push(("origin_confidence", v));
        }
        if let Some(v) = self.historical_integrity {
            out.push(("historical_integrity", v));
        }
        if let Some(v) = self.space_trust_level {
            out.push(("space_trust_level", v));
        }
        if let Some(v) = self.behavior_reputation {
            out.push(("behavior_reputation", v));
        }
        if let Some(v) = self.proof_depth {
            out.push(("proof_depth", v));
        }
        out
    }
}

/// Canonical weights for the base AuthRatio model.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AuthWeights {
    pub w_m: Score,
    pub w_c: Score,
    pub w_o: Score,
    pub w_x: Score,
}

impl AuthWeights {
    pub fn new(w_m: Score, w_c: Score, w_o: Score, w_x: Score) -> Result<Self> {
        let weights = Self { w_m, w_c, w_o, w_x };
        weights.validate(1e-9)?;
        Ok(weights)
    }

    pub fn validate(&self, tolerance: Score) -> Result<()> {
        let sum = self.w_m + self.w_c + self.w_o + self.w_x;
        if (sum - 1.0).abs() > tolerance {
            return Err(AuthxError::ErrWeightSumOutOfBounds { sum, tolerance });
        }
        for (name, value) in [
            ("w_m", self.w_m),
            ("w_c", self.w_c),
            ("w_o", self.w_o),
            ("w_x", self.w_x),
        ] {
            if !(0.0..=1.0).contains(&value) {
                return Err(AuthxError::ErrInvalidInput(format!(
                    "{name} must be within [0,1]"
                )));
            }
        }
        Ok(())
    }
}

/// Result bundle from the scoring engine.
#[derive(Debug, Clone, PartialEq)]
pub struct FactorBreakdown {
    pub magnitude: Score,
    pub composition: Score,
    pub ownership: Score,
    pub extension: Score,
    pub optional_factors: Vec<(String, Score)>,
}

impl FactorBreakdown {
    pub fn empty() -> Self {
        Self {
            magnitude: 0.0,
            composition: 0.0,
            ownership: 0.0,
            extension: 0.0,
            optional_factors: Vec::new(),
        }
    }
}

/// Final output contract for a full AuthRatio evaluation.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthRatioEvaluation {
    pub score: Score,
    pub threshold: Score,
    pub certified: bool,
    pub factor_breakdown: FactorBreakdown,
    pub weight_set_reference: String,
    pub policy_version_reference: String,
    pub evaluation_marker: String,
}

/// Certification result, including the state transition outcome.
#[derive(Debug, Clone, PartialEq)]
pub struct CertificationResult {
    pub state: CertificationState,
    pub evaluation: AuthRatioEvaluation,
    pub reason: Option<String>,
}

/// Origin validation result.
#[derive(Debug, Clone, PartialEq)]
pub struct OriginResult {
    pub origin_id: String,
    pub origin_hash: String,
    pub created_vector: CanonicalVector,
    pub certification: CertificationResult,
    pub record: crate::record::RecordEvent,
}

/// Drain rule definitions.
#[derive(Debug, Clone, PartialEq)]
pub enum DrainRule {
    Percentage {
        delta: Score,
    },
    Absolute {
        amount: Amount,
    },
    AuthRatioLinked {
        delta: Score,
        credit_scale: Score,
        max_credit: Score,
    },
}

/// Drain result structure.
#[derive(Debug, Clone, PartialEq)]
pub struct DrainResult {
    pub requested_delta: Score,
    pub credit: Score,
    pub effective_delta: Score,
    pub removed_amount: Amount,
    pub retained_amount: Amount,
}

/// A minimal deterministic helper for normalizing scores into the closed interval [0,1].
pub fn clamp_score(value: Score) -> Score {
    value.clamp(0.0, 1.0)
}

/// A stable comparison helper for floating point policy values.
pub fn approx_equal(a: Score, b: Score, tolerance: Score) -> bool {
    (a - b).abs() <= tolerance
}
