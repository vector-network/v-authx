use std::fmt::{Display, Formatter};

/// Protocol-level error classes for the Vector Network authentication layer.
#[derive(Debug, Clone, PartialEq)]
pub enum AuthxError {
    ErrAuthFailed(String),
    ErrUnauthorized(String),
    ErrUncertified(String),
    ErrInvalidType(String),
    ErrInvalidState(String),
    ErrInvalidDrain(String),
    ErrInvalidProjection(String),
    ErrInvalidReconstruction(String),
    ErrInvalidOrigin(String),
    ErrInvalidRecord(String),
    ErrInvalidInput(String),
    ErrMissingField(&'static str),
    ErrAmbiguousThreshold(String),
    ErrWeightSumOutOfBounds { sum: f64, tolerance: f64 },
    ErrScoreOutOfBounds { score: f64 },
    ErrZeroVectorNormalization,
    ErrUnknownPolicyVersion(String),
    ErrRevalidationBlocked(String),
}

pub type Result<T> = std::result::Result<T, AuthxError>;

impl Display for AuthxError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ErrAuthFailed(s) => write!(f, "authentication failed: {s}"),
            Self::ErrUnauthorized(s) => write!(f, "unauthorized: {s}"),
            Self::ErrUncertified(s) => write!(f, "uncertified: {s}"),
            Self::ErrInvalidType(s) => write!(f, "invalid type: {s}"),
            Self::ErrInvalidState(s) => write!(f, "invalid state: {s}"),
            Self::ErrInvalidDrain(s) => write!(f, "invalid drain: {s}"),
            Self::ErrInvalidProjection(s) => write!(f, "invalid projection: {s}"),
            Self::ErrInvalidReconstruction(s) => write!(f, "invalid reconstruction: {s}"),
            Self::ErrInvalidOrigin(s) => write!(f, "invalid origin: {s}"),
            Self::ErrInvalidRecord(s) => write!(f, "invalid record: {s}"),
            Self::ErrInvalidInput(s) => write!(f, "invalid input: {s}"),
            Self::ErrMissingField(s) => write!(f, "missing field: {s}"),
            Self::ErrAmbiguousThreshold(s) => write!(f, "ambiguous threshold: {s}"),
            Self::ErrWeightSumOutOfBounds { sum, tolerance } => {
                write!(f, "weight sum {sum} outside tolerance {tolerance}")
            }
            Self::ErrScoreOutOfBounds { score } => write!(f, "score out of bounds: {score}"),
            Self::ErrZeroVectorNormalization => write!(f, "zero vector cannot be normalized"),
            Self::ErrUnknownPolicyVersion(s) => write!(f, "unknown policy version: {s}"),
            Self::ErrRevalidationBlocked(s) => write!(f, "revalidation blocked: {s}"),
        }
    }
}

impl std::error::Error for AuthxError {}