"""Shared bytes, producer caching and certificate delivery are separate."""
import pytest
import json

from cv_agent.application.delivery import CertificateDelivery, DeliveryBudgetError, allocation_plan
from cv_agent.domain.evidence import ToolObservation
from test_product_reducer import proof


def certificate(producer, size):
    observed = proof("CONFIRMED").model_copy(update={"content": json.dumps({"owned": True, "padding": ""})})
    def serialize(value):
        return json.dumps({"producer_id": producer, "observation": value.model_dump(mode="json")},
                          sort_keys=True, separators=(",", ":")).encode()
    padding = size - len(serialize(observed))
    assert padding >= 0
    observed = observed.model_copy(update={"content": json.dumps({"owned": True, "padding": "x"*padding})})
    payload = serialize(observed)
    assert len(payload) == size
    checked = ToolObservation.model_validate(json.loads(payload)["observation"])
    assert checked.validation_status == "CONFIRMED"
    assert checked.fixture_proof.coverage == "candidate"
    return payload


def test_unequal_complete_certificates_fit_shared_budget():
    plan = allocation_plan({"a": 2500, "b": 1000, "c": 1000, "d": 1000}, total_bytes=8192,
                           diagnostic_reserve=256)
    delivery = CertificateDelivery(plan)
    for producer, size in plan.minimum_bytes.items():
        delivery.store(producer, certificate(producer, size), physical_execution=False)
        assert delivery.deliver(producer).size_bytes == size
    assert delivery.used_bytes == 5500
    assert delivery.physical_executions == 0
    assert delivery.remaining_bytes == 8192 - 256 - 5500


def test_impossible_plan_is_rejected_before_any_producer_runs():
    with pytest.raises(DeliveryBudgetError, match="minimum"):
        allocation_plan({"a": 8000, "b": 1000}, total_bytes=8192, diagnostic_reserve=256)


def test_cached_redelivery_is_billed_but_has_one_original_producer():
    delivery = CertificateDelivery(allocation_plan({"a": 100}, total_bytes=8192, diagnostic_reserve=256))
    delivery.store("a", b"x" * 100, physical_execution=True)
    first = delivery.deliver("a")
    second = delivery.deliver("a")
    assert first.producer_id == second.producer_id == "a"
    assert first.delivery_id != second.delivery_id
    assert first.cached is False and second.cached is True
    assert delivery.used_bytes == 200
    assert delivery.physical_executions == 1
    assert len(delivery.producers) == 1


def test_redelivery_does_not_borrow_other_required_reservations():
    delivery = CertificateDelivery(allocation_plan({"a": 2500, "b": 1000}, total_bytes=3800,
        diagnostic_reserve=256))
    delivery.store("a", b"x" * 2500, physical_execution=True)
    delivery.deliver("a")
    with pytest.raises(DeliveryBudgetError):
        delivery.deliver("a")
    delivery.store("b", b"x" * 1000, physical_execution=False)
    assert delivery.deliver("b").size_bytes == 1000
    assert delivery.used_bytes == 3500
    assert delivery.physical_executions == 1


def test_failed_delivery_retains_original_and_cannot_mark_proof_delivered():
    delivery = CertificateDelivery(allocation_plan({"a": 100}, total_bytes=8192, diagnostic_reserve=256))
    delivery.store("a", b"x" * 8192, physical_execution=True)
    with pytest.raises(DeliveryBudgetError):
        delivery.deliver("a")
    assert delivery.producers["a"] == b"x" * 8192
    assert delivery.used_bytes == 0
    assert delivery.physical_executions == 1
    assert delivery.receipts == []


def test_reusing_producer_id_with_different_result_is_rejected():
    delivery = CertificateDelivery(allocation_plan({}, total_bytes=8192, diagnostic_reserve=256))
    delivery.store("a", b"original", physical_execution=False)
    with pytest.raises(ValueError, match="producer"):
        delivery.store("a", b"different", physical_execution=False)


def test_identical_manifest_results_from_two_runs_are_two_producers():
    delivery = CertificateDelivery(allocation_plan({}, total_bytes=8192, diagnostic_reserve=256))
    for producer in ("owned-run/1", "owned-run/2"):
        delivery.store(producer, b"same approved manifest result", physical_execution=True)
        delivery.deliver(producer)
    assert delivery.physical_executions == 2
    assert len(delivery.producers) == 2
