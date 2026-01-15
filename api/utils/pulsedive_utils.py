from collections import Counter
from typing import Any, Iterable


VALID_RISKS = {"unknown", "none", "low", "medium", "high", "critical"}


def apply_riskfactors_to_pending_record(
    riskfactors: Iterable[dict], pending_record: Any
) -> Any:
    """
    Conta os riskfactors por tipo de risco e
    popula os campos do pending_record
    """
    risk_counts = Counter()

    for rf in riskfactors or []:
        risk = rf.get("risk", "unknown")
        if risk not in VALID_RISKS:
            risk = "unknown"

        risk_counts[risk] += 1

    for risk in VALID_RISKS:
        setattr(pending_record, risk, risk_counts.get(risk, 0))

    return pending_record
