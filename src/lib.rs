//! v-authx: authentication, certification, AuthRatio, origin, and drain core for Vector Network.
//!
//! The crate follows the blueprint's fail-closed, deterministic, record-producing model.
//! It is intentionally self-contained so the protocol layer can be embedded into a kernel,
//! simulator, node, or SDK-facing service without exposing private keys in shared state.

pub mod auth_ratio;
pub mod certification;
pub mod drain;
pub mod error;
pub mod origin;
pub mod record;
pub mod types;

pub use auth_ratio::*;
pub use certification::*;
pub use drain::*;
pub use error::{AuthxError, Result};
pub use origin::*;
pub use record::*;
pub use types::*;

/// Convenience prelude for application code.
pub mod prelude {
    pub use crate::auth_ratio::{evaluate_auth_ratio, AuthRatioEngine, AuthRatioInput};
    pub use crate::certification::{default_certification_input, CertificationEngine, CertificationInput};
    pub use crate::drain::{authratio_credit, delta_effective, DrainEngine};
    pub use crate::error::{AuthxError, Result};
    pub use crate::origin::{origin_hash, OriginEngine, OriginInput, OriginPolicy};
    pub use crate::record::RecordEvent;
    pub use crate::types::{
        approx_equal, clamp_score, Amount, AuthRatioEvaluation, AuthWeights, CanonicalVector,
        CertificationResult, CertificationState, DrainResult, DrainRule, EvaluationContext,
        ExtensionFactors, FactorBreakdown, LogicalClock, OperationClass, OriginProof,
        OriginResult, PublicKey, Score, ThresholdPolicy, VectorState, VectorType, WalletState,
    };
}
