import logging

import httpx

from usb_analyzer.core.events import DeviceEvent

logger = logging.getLogger(__name__)


class ApiEventClient:
    """Send device events to the USB Analyzer HTTP API."""

    def __init__(
        self,
        base_url: str,
        api_prefix: str,
        timeout_seconds: float = 5.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero")
        self._events_url = (
            f"{base_url.rstrip('/')}{api_prefix.rstrip('/')}/events"
        )
        self._client = httpx.Client(timeout=timeout_seconds, transport=transport)

    def add(self, event: DeviceEvent) -> DeviceEvent:
        """Post an event and return the event accepted by the API."""

        try:
            response = self._client.post(
                self._events_url,
                json=event.model_dump(mode="json"),
            )
            response.raise_for_status()
        except httpx.HTTPError:
            logger.exception(
                "Failed to send device event %s to the API at %s",
                event.id,
                self._events_url,
            )
            raise

        accepted_event = DeviceEvent.model_validate(response.json())
        if accepted_event.id != event.id:
            raise RuntimeError(
                "The API returned an event ID that does not match the submitted event"
            )
        return accepted_event

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "ApiEventClient":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()
