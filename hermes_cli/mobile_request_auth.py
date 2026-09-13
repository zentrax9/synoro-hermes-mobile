"""Composed authentication for requests reaching the mobile listener."""

from __future__ import annotations

from dataclasses import dataclass
import secrets
from typing import Protocol
from urllib.parse import urlsplit

from fastapi import HTTPException, Request

from hermes_cli.mobile_auth import AccessIdentity
from hermes_cli.mobile_devices import (
    DeviceAuthorization,
    DeviceNotAuthorized,
    InvalidDeviceToken,
    InvalidDpopProof,
    MobileDeviceError,
    MobileDeviceStore,
)
from hermes_cli.mobile_rate_limit import MobileRateLimiter, MobileRateLimitExceeded


_AUTHENTICATION_ERROR = "mobile authentication required"
_DEVICE_TOKEN_HEADER = "X-Hermes-Device-Token"
_DPOP_HEADER = "DPoP"


class AccessAuthorizer(Protocol):
    def __call__(self, request: Request) -> AccessIdentity: ...


@dataclass(frozen=True)
class MobileRequestIdentity:
    access: AccessIdentity
    device: DeviceAuthorization


class MobileRequestAuthorizer:
    """Require both Access identity and proof from an approved device key."""

    def __init__(
        self,
        *,
        access_authorize: AccessAuthorizer,
        devices: MobileDeviceStore,
        public_base_url: str,
        rate_limiter: MobileRateLimiter | None = None,
        requests_per_minute: int = 120,
    ) -> None:
        parsed = urlsplit(public_base_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("mobile public URL must be an HTTPS origin")
        self._access_authorize = access_authorize
        self._devices = devices
        self._public_origin = public_base_url.rstrip("/")
        self._rate_limiter = rate_limiter
        self._requests_per_minute = requests_per_minute

    def _rate_limit(
        self,
        request: Request,
        principals: tuple[tuple[str, str | None], ...],
    ) -> None:
        if self._rate_limiter is None:
            return
        route = request.scope.get("route")
        route_path = getattr(route, "path", None) or request.scope.get("path", "")
        action = f"{request.method.upper()} {route_path}"
        try:
            for dimension, principal in principals:
                if principal:
                    self._rate_limiter.check(
                        dimension=dimension,
                        principal=principal,
                        action=action,
                        limit=self._requests_per_minute,
                        window_seconds=60,
                    )
        except MobileRateLimitExceeded as exc:
            raise HTTPException(
                status_code=429,
                detail="mobile request rate exceeded",
                headers={"Retry-After": str(exc.retry_after)},
            ) from exc

    def rate_limit_profile(
        self,
        request: Request,
        identity: MobileRequestIdentity,
        *,
        profile: str,
    ) -> None:
        """Rate-limit a profile after its opaque ID has been authorized.

        Profile-scoped routes resolve the client-facing opaque ID against the
        authenticated device grant in the server layer.  User and device
        buckets are charged by :meth:`authorize`; this follow-up only charges
        the resolved profile bucket so invalid IDs cannot create arbitrary
        profile principals and valid requests are not charged twice.
        """

        if not isinstance(identity, MobileRequestIdentity):
            raise HTTPException(status_code=401, detail=_AUTHENTICATION_ERROR)
        if not isinstance(profile, str) or not profile:
            raise HTTPException(status_code=401, detail=_AUTHENTICATION_ERROR)
        self._rate_limit(request, (("profile", profile),))

    def authorize_access(
        self,
        request: Request,
        *,
        apply_rate_limit: bool = True,
    ) -> AccessIdentity:
        identity = self._access_authorize(request)
        if not isinstance(identity, AccessIdentity):
            raise HTTPException(status_code=401, detail=_AUTHENTICATION_ERROR)
        if apply_rate_limit:
            self._rate_limit(request, (("user", identity.subject),))
        return identity

    def _external_url(self, request: Request) -> str:
        raw_path = request.scope.get("raw_path", b"")
        try:
            path = raw_path.decode("ascii") if raw_path else request.url.path
        except UnicodeDecodeError as exc:
            raise HTTPException(status_code=401, detail=_AUTHENTICATION_ERROR) from exc
        if not path.startswith("/") or "//" in path:
            raise HTTPException(status_code=401, detail=_AUTHENTICATION_ERROR)
        return f"{self._public_origin}{path}"

    def authorize(
        self,
        request: Request,
        *,
        profile: str | None = None,
        scope: str | None = None,
    ) -> MobileRequestIdentity:
        access = self.authorize_access(request, apply_rate_limit=False)
        device_token = request.headers.get(_DEVICE_TOKEN_HEADER, "")
        dpop = request.headers.get(_DPOP_HEADER, "")
        if not device_token or not dpop:
            raise HTTPException(status_code=401, detail=_AUTHENTICATION_ERROR)
        try:
            device = self._devices.authorize_request(
                device_token,
                dpop,
                method=request.method,
                url=self._external_url(request),
                profile=profile,
                scope=scope,
            )
            record = self._devices.get_device(device.device_id)
            if not record.access_subject or not secrets.compare_digest(
                record.access_subject,
                access.subject,
            ):
                raise DeviceNotAuthorized("device identity does not match")
        except (DeviceNotAuthorized, InvalidDeviceToken, InvalidDpopProof, MobileDeviceError) as exc:
            raise HTTPException(status_code=401, detail=_AUTHENTICATION_ERROR) from exc

        self._rate_limit(
            request,
            (
                ("user", access.subject),
                ("device", device.device_id),
                ("profile", profile),
            ),
        )

        identity = MobileRequestIdentity(access=access, device=device)
        request.state.mobile_identity = identity
        return identity
