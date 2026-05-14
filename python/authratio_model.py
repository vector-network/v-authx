"""AuthRatio modeling utilities for the Vector Network blueprint.

This module is a Python-side model for experimenting with scoring formulas,
threshold rules, offset credits, and certification decisions.

It mirrors the Rust implementation in `v-authx` but is intentionally flexible
for notebook analysis, parameter sweeps, and design exploration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from math import isfinite
from typing import Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple


class VectorType(str, Enum):
    POSITION = "Position"
    FREE = "Free"
    BOUND = "Bound"
    UNIT = "Unit"
    ZERO = "Zero"
    SPATIAL = "Spatial"


class OperationClass(str, Enum):
    CREATE = "Create"
    CERTIFY = "Certify"
    TRANSFER = "Transfer"
    DRAIN = "Drain"
    PROJECT = "Project"
    RECONSTRUCT = "Reconstruct"
    QUERY = "Query"
    RECORD = "Record"
    MOVE = "Move"
    ROTATE = "Rotate"
    SCALE = "Scale"
    NORMALIZE = "Normalize"
    CONSTRAIN = "Constrain"


@dataclass(frozen=True)
class WeightSet:
    w_m: float = 0.35
    w_c: float = 0.25
    w_o: float = 0.30
    w_x: float = 0.10

    def validate(self, tolerance: float = 1e-9) -> None:
        if not all(isfinite(v) for v in (self.w_m, self.w_c, self.w_o, self.w_x)):
            raise ValueError("weights must be finite")
        for name, value in (("w_m", self.w_m), ("w_c", self.w_c), ("w_o", self.w_o), ("w_x", self.w_x)):
            if value < 0.0 or value > 1.0:
                raise ValueError(f"{name} must be within [0, 1]")
        total = self.w_m + self.w_c + self.w_o + self.w_x
        if abs(total - 1.0) > tolerance:
            raise ValueError(f"weight sum {total} outside tolerance {tolerance}")


@dataclass(frozen=True)
class ThresholdPolicy:
    version: str = "1.1"
    threshold: float = 0.80

    def evaluate(self, *, vector_type: VectorType, operation_class: OperationClass, risk_profile: str) -> float:
        base = self.threshold
        risk = risk_profile.lower().strip()
        if risk == "low":
            delta = 0.0
        elif risk == "medium":
            delta = 0.03
        elif risk == "high":
            delta = 0.08
        else:
            delta = 0.05

        op_delta = {
            OperationClass.QUERY: 0.0,
            OperationClass.CERTIFY: 0.0,
            OperationClass.RECORD: 0.0,
            OperationClass.CREATE: 0.05,
            OperationClass.TRANSFER: 0.08,
            OperationClass.DRAIN: 0.08,
            OperationClass.PROJECT: 0.08,
            OperationClass.RECONSTRUCT: 0.08,
            OperationClass.MOVE: 0.05,
            OperationClass.ROTATE: 0.05,
            OperationClass.SCALE: 0.05,
            OperationClass.NORMALIZE: 0.05,
            OperationClass.CONSTRAIN: 0.05,
        }[operation_class]

        type_delta = {
            VectorType.ZERO: 0.15,
            VectorType.UNIT: 0.03,
            VectorType.FREE: 0.04,
            VectorType.BOUND: 0.06,
            VectorType.POSITION: 0.05,
            VectorType.SPATIAL: 0.05,
        }[vector_type]

        return min(max(base + delta + op_delta + type_delta, 0.0), 1.0)


@dataclass
class VectorState:
    components: MutableMapping[str, int] = field(default_factory=dict)

    def magnitude(self) -> int:
        return int(sum(self.components.values()))

    def is_zero(self) -> bool:
        return self.magnitude() == 0

    def normalize(self) -> Dict[str, float]:
        mag = self.magnitude()
        if mag == 0:
            raise ZeroDivisionError("zero vector cannot be normalized")
        return {k: v / mag for k, v in sorted(self.components.items())}


@dataclass(frozen=True)
class AuthRatioInputs:
    vector: VectorState
    vector_type: VectorType
    operation_class: OperationClass
    ownership_proof_valid: bool
    expected_composition: Optional[Mapping[str, float]] = None
    magnitude_bounds: Optional[Tuple[int, int]] = None
    extension_factors: Mapping[str, float] = field(default_factory=dict)
    risk_profile: str = "medium"
    weight_set: WeightSet = field(default_factory=WeightSet)
    threshold_policy: ThresholdPolicy = field(default_factory=ThresholdPolicy)


@dataclass(frozen=True)
class AuthRatioBreakdown:
    magnitude: float
    composition: float
    ownership: float
    extension: float
    optional_factors: Dict[str, float]


@dataclass(frozen=True)
class AuthRatioResult:
    score: float
    threshold: float
    certified: bool
    breakdown: AuthRatioBreakdown


def _clamp01(value: float) -> float:
    return min(max(value, 0.0), 1.0)


def magnitude_score(vector: VectorState, bounds: Optional[Tuple[int, int]], vector_type: VectorType) -> float:
    mag = vector.magnitude()
    if bounds is not None:
        lo, hi = bounds
        if lo > hi:
            raise ValueError("magnitude bounds are inverted")
        if mag < lo or mag > hi:
            return 0.0
    if mag == 0:
        return 1.0 if vector_type == VectorType.ZERO else 0.5
    return 1.0


def composition_score(vector: VectorState, expected: Optional[Mapping[str, float]]) -> float:
    if expected is None:
        return 1.0
    if not expected:
        return 1.0
    actual = vector.normalize()
    error = 0.0
    for key, target in expected.items():
        error += abs(actual.get(key, 0.0) - float(target))
    return _clamp01(1.0 - error)


def ownership_score(valid: bool) -> float:
    return 1.0 if valid else 0.0


def extension_score(extension_factors: Mapping[str, float]) -> Tuple[float, Dict[str, float]]:
    optional: Dict[str, float] = {}
    if not extension_factors:
        return 0.0, optional
    for k, v in extension_factors.items():
        fv = float(v)
        if not isfinite(fv) or fv < 0.0 or fv > 1.0:
            raise ValueError(f"extension factor {k!r} must be finite and within [0, 1]")
        optional[k] = fv
    return _clamp01(sum(optional.values()) / len(optional)), optional


def auth_ratio(inputs: AuthRatioInputs) -> AuthRatioResult:
    inputs.weight_set.validate()

    m = magnitude_score(inputs.vector, inputs.magnitude_bounds, inputs.vector_type)
    c = composition_score(inputs.vector, inputs.expected_composition)
    o = ownership_score(inputs.ownership_proof_valid)
    x, optional = extension_score(inputs.extension_factors)
    threshold = inputs.threshold_policy.evaluate(
        vector_type=inputs.vector_type,
        operation_class=inputs.operation_class,
        risk_profile=inputs.risk_profile,
    )
    score = _clamp01(
        inputs.weight_set.w_m * m
        + inputs.weight_set.w_c * c
        + inputs.weight_set.w_o * o
        + inputs.weight_set.w_x * x
    )
    breakdown = AuthRatioBreakdown(
        magnitude=m,
        composition=c,
        ownership=o,
        extension=x,
        optional_factors=optional,
    )
    return AuthRatioResult(score=score, threshold=threshold, certified=score >= threshold, breakdown=breakdown)


@dataclass(frozen=True)
class DrainPolicy:
    delta: float
    credit_scale: float = 1.0
    max_credit: float = 0.2

    def effective_delta(self, auth_ratio_value: float) -> float:
        credit = _clamp01(auth_ratio_value * self.credit_scale)
        credit = min(credit, self.max_credit)
        return max(self.delta - credit, 0.0)


@dataclass(frozen=True)
class DrainResult:
    requested_delta: float
    credit: float
    effective_delta: float
    removed_amount: int
    retained_amount: int


def drain(vector: VectorState, policy: DrainPolicy, auth_ratio_value: float) -> DrainResult:
    if policy.delta < 0.0 or policy.delta > 1.0:
        raise ValueError("delta must be within [0, 1]")
    eff = policy.effective_delta(auth_ratio_value)
    mag = vector.magnitude()
    removed = int(round(mag * eff))
    retained = max(mag - removed, 0)
    credit = min(_clamp01(auth_ratio_value * policy.credit_scale), policy.max_credit)
    return DrainResult(policy.delta, credit, eff, removed, retained)


if __name__ == "__main__":
    # A tiny design-time example.
    vector = VectorState({"alpha": 60, "beta": 40})
    inputs = AuthRatioInputs(
        vector=vector,
        vector_type=VectorType.FREE,
        operation_class=OperationClass.CERTIFY,
        ownership_proof_valid=True,
        expected_composition={"alpha": 0.6, "beta": 0.4},
    )
    result = auth_ratio(inputs)
    print(result)
