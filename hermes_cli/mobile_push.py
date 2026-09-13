"""Fixed-contract client for the central Hermes Mobile push relay."""

from __future__ import annotations

from enum import StrEnum
import time
from urllib.parse import urlsplit

import httpx


class MobilePushEvent(StrEnum):
    APPROVAL_REQUIRED = "approval_required"
    QUESTION_REQUIRED = "question_required"
    RUN_COMPLETED = "run_completed"
    RUN_FAILED = "run_failed"


class MobilePushRelayClient:
    def __init__(
        self,
        *,
        base_url: str,
        credential: str,
        transport: httpx.BaseTransport | None = None,
        clock=time.time,
    ) -> None:
        if not isinstance(base_url, str) or any(
            ord(char) < 0x21 or ord(char) == 0x7F for char in base_url
        ):
            raise ValueError("push relay URL must be an HTTPS origin")
        try:
            parsed = urlsplit(base_url)
            # Force validation of malformed ports (urlsplit is otherwise lazy).
            parsed.port
        except ValueError as exc:
            raise ValueError("push relay URL must be an HTTPS origin") from exc
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("push relay URL must be an HTTPS origin")
        if (
            not isinstance(credential, str)
            or len(credential) < 32
            or any(ord(char) < 0x21 or ord(char) > 0x7E for char in credential)
        ):
            raise ValueError("push relay credential is invalid")
        self._base_url = base_url.rstrip("/")
        self._credential = credential
        self._transport = transport
        self._clock = clock

    def _request(self, method: str, path: str, *, body: dict | None = None) -> None:
        with httpx.Client(
            base_url=self._base_url,
            transport=self._transport,
            timeout=10,
            follow_redirects=False,
        ) as client:
            response = client.request(
                method,
                path,
                headers={"Authorization": f"Bearer {self._credential}"},
                json=body,
            )
            response.raise_for_status()

    def register_device(self, device_handle: str, fcm_token: str) -> None:
        self._request(
            "PUT",
            f"/v1/devices/{device_handle}",
            body={"fcm_token": fcm_token},
        )

    def revoke_device(self, device_handle: str) -> None:
        self._request("DELETE", f"/v1/devices/{device_handle}")

    def notify(
        self,
        *,
        event_type: MobilePushEvent,
        event_id: str,
        device_handle: str,
        ttl_seconds: int,
    ) -> None:
        if not 1 <= ttl_seconds <= 86_400:
            raise ValueError("push TTL must be between 1 second and 1 day")
        self._request(
            "POST",
            "/v1/push",
            body={
                "event_type": event_type.value,
                "event_id": event_id,
                "device_handle": device_handle,
                "expires_at": int(self._clock()) + ttl_seconds,
            },
        )
