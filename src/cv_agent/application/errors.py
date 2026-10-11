"""Typed delivery failures shared by the static service and its owned worker."""


class ProductDeliveryError(RuntimeError):
    """A retained local stage failed; publication is not a completed review."""

    stage = "presentation"

    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)
