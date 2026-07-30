"""
Phishing evaluation helpers.

Computes deterministic per-sample and batch metrics for phishing test runs.
The positive class is phishing.
"""

from typing import Any, Dict, Iterable, List, Optional


POSITIVE_LABEL = "phishing"
NEGATIVE_LABEL = "legitimate"


def evaluate_phishing_prediction(
    expected_label: Optional[str],
    predicted_is_phishing: bool,
    confidence: float = 0,
) -> Dict[str, Any]:
    expected = _normalize_expected_label(expected_label)
    expected_is_phishing = expected == POSITIVE_LABEL
    predicted_label = POSITIVE_LABEL if predicted_is_phishing else NEGATIVE_LABEL
    correct = expected_is_phishing == bool(predicted_is_phishing)

    if expected_is_phishing and predicted_is_phishing:
        outcome = "true_positive"
    elif not expected_is_phishing and predicted_is_phishing:
        outcome = "false_positive"
    elif expected_is_phishing and not predicted_is_phishing:
        outcome = "false_negative"
    else:
        outcome = "true_negative"

    return {
        "expected_label": expected,
        "expected_is_phishing": expected_is_phishing,
        "predicted_label": predicted_label,
        "predicted_is_phishing": bool(predicted_is_phishing),
        "correct": correct,
        "outcome": outcome,
        "confidence": confidence,
    }


def summarize_phishing_evaluations(results: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    results = list(results)
    evaluated = []
    failed = 0
    for result in results:
        if not result.get("success"):
            failed += 1
            continue
        evaluation = result.get("evaluation")
        if evaluation:
            evaluated.append(evaluation)

    true_positives = _count(evaluated, "true_positive")
    false_positives = _count(evaluated, "false_positive")
    false_negatives = _count(evaluated, "false_negative")
    true_negatives = _count(evaluated, "true_negative")

    total_evaluated = len(evaluated)
    correct = true_positives + true_negatives
    incorrect = false_positives + false_negatives
    predicted_phishing = true_positives + false_positives
    predicted_safe = true_negatives + false_negatives
    expected_phishing = true_positives + false_negatives
    expected_legitimate = true_negatives + false_positives

    accuracy = _ratio(correct, total_evaluated)
    precision = _ratio(true_positives, true_positives + false_positives)
    recall = _ratio(true_positives, true_positives + false_negatives)
    f1_score = _ratio(2 * precision * recall, precision + recall)
    specificity = _ratio(true_negatives, true_negatives + false_positives)
    false_positive_rate = _ratio(false_positives, false_positives + true_negatives)
    false_negative_rate = _ratio(false_negatives, false_negatives + true_positives)

    return {
        "total_evaluated": total_evaluated,
        "failed": failed,
        "correct": correct,
        "incorrect": incorrect,
        "expected_phishing": expected_phishing,
        "expected_legitimate": expected_legitimate,
        "predicted_phishing": predicted_phishing,
        "predicted_safe": predicted_safe,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1_score,
        "specificity": specificity,
        "false_positive_rate": false_positive_rate,
        "false_negative_rate": false_negative_rate,
        "accuracy_percent": round(accuracy * 100, 1),
        "precision_percent": round(precision * 100, 1),
        "recall_percent": round(recall * 100, 1),
        "f1_score_percent": round(f1_score * 100, 1),
        "confusion_matrix": {
            "true_positives": true_positives,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
            "true_negatives": true_negatives,
            "tp": true_positives,
            "fp": false_positives,
            "fn": false_negatives,
            "tn": true_negatives,
        },
        "misclassifications": [
            {
                "sample_id": result.get("sample_id"),
                "scan_id": result.get("scan_id"),
                "threat_id": result.get("threat_id"),
                "subject": result.get("subject"),
                "sender": result.get("sender"),
                "expected_label": result.get("evaluation", {}).get("expected_label"),
                "predicted_label": result.get("evaluation", {}).get("predicted_label"),
                "outcome": result.get("evaluation", {}).get("outcome"),
                "confidence": result.get("confidence"),
            }
            for result in results
            if result.get("evaluation") and not result["evaluation"].get("correct")
        ],
    }


def _normalize_expected_label(label: Optional[str]) -> str:
    value = str(label or "").strip().lower()
    if value in {"phish", "phishing", "malicious", "threat", "positive", "1", "true"}:
        return POSITIVE_LABEL
    return NEGATIVE_LABEL


def _count(evaluations: List[Dict[str, Any]], outcome: str) -> int:
    return sum(1 for evaluation in evaluations if evaluation.get("outcome") == outcome)


def _ratio(numerator: float, denominator: float) -> float:
    if not denominator:
        return 0.0
    return round(float(numerator) / float(denominator), 4)
