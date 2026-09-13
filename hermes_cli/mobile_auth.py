"""Cloudflare Access authentication for the isolated mobile listener."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from typing import Any
from urllib.parse import urlsplit

from fastapi import HTTPException, Request
import jwt


_ACCESS_ASSERTION_HEADER = "Cf-Access-Jwt-Assertion"
_AUTHENTICATION_ERROR = "mobile authentication required"
_ALLOWED_ACCESS_ALGORITHMS = ("RS256",)


@dataclass(frozen=True)
class CloudflareAccessConfig:
    """Pinned identity-provider values for one Hermes installation."""

    issuer: str
    audience: str

    def __post_init__(self) -> None:
        parsed = urlsplit(self.issuer)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or not parsed.hostname.endswith(".cloudflareaccess.com")
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Cloudflare Access issuer must be an HTTPS team domain")
        if not self.audience or len(self.audience) > 256:
            raise ValueError("Cloudflare Access audience must be 1 to 256 characters")

    @property
    def normalized_issuer(self) -> str:
        return self.issuer.rstrip("/")

    @property
    def jwks_url(self) -> str:
        return f"{self.normalized_issuer}/cdn-cgi/access/certs"


@dataclass(frozen=True)
class AccessIdentity:
    subject: str
    email: str


class CloudflareAccessAuthorizer:
    """Validate Access assertions received directly from loopback cloudflared."""

    def __init__(self, config: CloudflareAccessConfig, *, jwks_client: Any = None) -> None:
        self._config = config
        self._jwks_client = jwks_client or jwt.PyJWKClient(
            config.jwks_url,
            cache_keys=True,
            lifespan=300,
        )

    @staticmethod
    def _peer_is_trusted(request: Request) -> bool:
        if request.client is None:
            return False
        try:
            return ipaddress.ip_address(request.client.host).is_loopback
        except ValueError:
            return False

    def authorize(self, request: Request) -> AccessIdentity:
        if not self._peer_is_trusted(request):
            raise HTTPException(status_code=401, detail=_AUTHENTICATION_ERROR)

        assertion = request.headers.get(_ACCESS_ASSERTION_HEADER, "")
        if not assertion:
            raise HTTPException(status_code=401, detail=_AUTHENTICATION_ERROR)

        try:
            signing_key = self._jwks_client.get_signing_key_from_jwt(assertion)
            claims = jwt.decode(
                assertion,
                signing_key.key,
                algorithms=list(_ALLOWED_ACCESS_ALGORITHMS),
                audience=self._config.audience,
                issuer=self._config.normalized_issuer,
                options={"require": ["iss", "aud", "sub", "email", "iat", "exp"]},
            )
            subject = claims["sub"]
            email = claims["email"]
            if not isinstance(subject, str) or not subject or not isinstance(email, str) or not email:
                raise jwt.InvalidTokenError("invalid identity claims")
        except (jwt.InvalidTokenError, jwt.PyJWKClientError, KeyError, TypeError, ValueError) as exc:
            raise HTTPException(status_code=401, detail=_AUTHENTICATION_ERROR) from exc

        identity = AccessIdentity(subject=subject, email=email)
        request.state.mobile_access_identity = identity
        return identity
