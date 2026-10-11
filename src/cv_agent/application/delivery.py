"""Conserved public-certificate byte budgets; no execution or implicit retry."""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from collections.abc import Mapping

from cv_agent.domain.types import FrozenModel


class DeliveryBudgetError(ValueError):
    pass


@dataclass(frozen=True)
class AllocationPlan:
    total_bytes: int
    diagnostic_reserve: int
    minimum_bytes: Mapping[str, int]


def allocation_plan(minimum_bytes: Mapping[str, int], *, total_bytes: int,
                    diagnostic_reserve: int = 256) -> AllocationPlan:
    values = [total_bytes, diagnostic_reserve, *minimum_bytes.values()]
    if any(type(value) is not int or value < 0 for value in values) or total_bytes < 1:
        raise ValueError("Allocation byte limits must be finite nonnegative integers")
    if sum(minimum_bytes.values()) + diagnostic_reserve > total_bytes:
        raise DeliveryBudgetError("Required minimum certificate bytes exceed the total budget")
    return AllocationPlan(total_bytes, diagnostic_reserve, MappingProxyType(dict(minimum_bytes)))


class DeliveryReceipt(FrozenModel):
    delivery_id: str
    producer_id: str
    size_bytes: int
    cached: bool
    complete: bool = True


class CertificateDelivery:
    """Cache immutable producer bytes and bill each complete delivery separately.

    A delivery failure keeps the producer result private and supplies no proof.
    Reserved undelivered certificates cannot be consumed by optional replays.
    """
    def __init__(self, plan: AllocationPlan):
        self.plan = plan
        self.used_bytes = 0
        self.physical_executions = 0
        self._producers: dict[str, bytes] = {}
        self._receipts: list[DeliveryReceipt] = []
        self._delivered: set[str] = set()

    @property
    def producers(self):
        return MappingProxyType(self._producers)

    @property
    def receipts(self):
        return list(self._receipts)

    @property
    def remaining_bytes(self) -> int:
        return self.plan.total_bytes - self.plan.diagnostic_reserve - self.used_bytes

    def store(self, producer_id: str, payload: bytes, *, physical_execution: bool) -> None:
        if not producer_id or type(payload) is not bytes:
            raise ValueError("producer identity and immutable serialized bytes are required")
        if producer_id in self._producers:
            if self._producers[producer_id] != payload:
                raise ValueError("producer identity was reused with different bytes")
            return
        self._producers[producer_id] = payload
        self.physical_executions += int(physical_execution)

    def deliver(self, producer_id: str) -> DeliveryReceipt:
        payload = self._producers[producer_id]
        others_reserved = sum(size for producer, size in self.plan.minimum_bytes.items()
                              if producer != producer_id and producer not in self._delivered)
        if len(payload) + others_reserved > self.remaining_bytes:
            raise DeliveryBudgetError("Complete certificate cannot fit the remaining reserved byte budget")
        receipt = DeliveryReceipt(delivery_id=f"delivery/{len(self._receipts) + 1}",
            producer_id=producer_id, size_bytes=len(payload), cached=producer_id in self._delivered)
        self.used_bytes += len(payload)
        self._delivered.add(producer_id)
        self._receipts.append(receipt)
        return receipt
