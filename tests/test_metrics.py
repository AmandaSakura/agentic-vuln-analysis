from cv_agent.metrics import evaluate_ternary


def test_ternary_metrics_do_not_count_abstentions_as_safe():
    labels = {"tp": True, "fn": True, "ap": True, "fp": False, "tn": False, "an": False}
    predictions = {
        "tp": "VULNERABLE",
        "fn": "SAFE",
        "ap": "ABSTAIN",
        "fp": "VULNERABLE",
        "tn": "SAFE",
        "an": "ABSTAIN",
    }
    result = evaluate_ternary(labels, predictions)
    assert result.true_positive == 1
    assert result.false_positive == 1
    assert result.true_negative == 1
    assert result.false_negative == 1
    assert result.abstain_positive == 1
    assert result.abstain_negative == 1
    assert result.coverage == 4 / 6
    assert result.strict_recall == 1 / 3
    assert result.covered_recall == 1 / 2
    assert result.population_false_positive_rate == 1 / 3
    assert result.conservative_false_positive_rate == 2 / 3
    assert result.covered_false_positive_rate == 1 / 2
