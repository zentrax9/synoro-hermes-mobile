from base64 import urlsafe_b64encode
import hashlib
import time

from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import HTTPException
import jwt
import pytest
from starlette.requests import Request

from hermes_cli.mobile_auth import AccessIdentity
from hermes_cli.mobile_devices import MobileDeviceStore, public_jwk_from_key
from hermes_cli.mobile_request_auth import MobileRequestAuthorizer


def _b64(value: bytes) -> str:
    return urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _request(*, token: str, proof: str, host: str = "attacker.invalid") -> Request:
    headers = [
        (b"host", host.encode()),
        (b"x-hermes-device-token", token.encode()),
        (b"dpop", proof.encode()),
        (b"x-forwarded-host", b"also-attacker.invalid"),
    ]
    return Request(
        {
            "type": "http",
            "method": "GET",
            "scheme": "http",
            "path": "/mobile/v1/capabilities",
            "raw_path": b"/mobile/v1/capabilities",
            "query_string": b"",
            "headers": headers,
            "client": ("127.0.0.1", 1234),
            "server": (host, 80),
        }
    )


def _approved_device(store: MobileDeviceStore, subject: str):
    background = ec.generate_private_key(ec.SECP256R1())
    user = ec.generate_private_key(ec.SECP256R1())
    challenge = store.create_enrollment_code(
        public_jwk_from_key(background),
        public_jwk_from_key(user),
        access_subject=subject,
        profiles=("profile-1",),
        scopes=("chat",),
    )
    store.redeem_enrollment_code(challenge.code)
    store.approve_device(challenge.device_id)
    return background, store.issue_device_token(challenge.device_id)


def _proof(key, token: str, *, url: str) -> str:
    now = int(time.time())
    request_id = _b64(hashlib.sha256(f"request-{now}-{url}".encode()).digest())
    return jwt.encode(
        {
            "htm": "GET",
            "htu": url,
            "iat": now,
            "jti": request_id,
            "nonce": "nonce-0000000001",
            "request_id": request_id,
            "ath": _b64(hashlib.sha256(token.encode("ascii")).digest()),
        },
        key,
        algorithm="ES256",
        headers={"typ": "dpop+jwt", "jwk": public_jwk_from_key(key)},
    )


def test_composed_auth_uses_pinned_public_origin_not_request_headers(tmp_path):
    store = MobileDeviceStore(tmp_path / "devices.sqlite")
    key, token = _approved_device(store, "access-user")
    auth = MobileRequestAuthorizer(
        access_authorize=lambda _request: AccessIdentity("access-user", "owner@example.com"),
        devices=store,
        public_base_url="https://mobile.example.com",
    )
    proof = _proof(key, token, url="https://mobile.example.com/mobile/v1/capabilities")

    identity = auth.authorize(_request(token=token, proof=proof), scope="chat")

    assert identity.access.subject == "access-user"


def test_composed_auth_rejects_device_enrolled_by_another_access_identity(tmp_path):
    store = MobileDeviceStore(tmp_path / "devices.sqlite")
    key, token = _approved_device(store, "first-user")
    auth = MobileRequestAuthorizer(
        access_authorize=lambda _request: AccessIdentity("second-user", "other@example.com"),
        devices=store,
        public_base_url="https://mobile.example.com",
    )
    proof = _proof(key, token, url="https://mobile.example.com/mobile/v1/capabilities")

    with pytest.raises(HTTPException) as error:
        auth.authorize(_request(token=token, proof=proof))

    assert error.value.status_code == 401
    assert error.value.detail == "mobile authentication required"


def test_profile_rate_limit_uses_resolved_opaque_profile_dimension(tmp_path):
    class RecordingLimiter:
        def __init__(self):
            self.calls = []

        def check(self, **kwargs):
            self.calls.append(kwargs)

    store = MobileDeviceStore(tmp_path / "devices.sqlite")
    key, token = _approved_device(store, "access-user")
    limiter = RecordingLimiter()
    auth = MobileRequestAuthorizer(
        access_authorize=lambda _request: AccessIdentity("access-user", "owner@example.com"),
        devices=store,
        public_base_url="https://mobile.example.com",
        rate_limiter=limiter,
    )
    request = _request(
        token=token,
        proof=_proof(
            key,
            token,
            url="https://mobile.example.com/mobile/v1/capabilities",
        ),
    )
    identity = auth.authorize(request, scope="chat")

    auth.rate_limit_profile(request, identity, profile="opaque-profile-id")

    assert [(call["dimension"], call["principal"]) for call in limiter.calls] == [
        ("user", "access-user"),
        ("device", identity.device.device_id),
        ("profile", "opaque-profile-id"),
    ]


@pytest.mark.parametrize(
    "url",
    ["http://mobile.example.com", "https://user@mobile.example.com", "https://mobile.example.com/path"],
)
def test_public_origin_must_be_an_https_origin(url, tmp_path):
    store = MobileDeviceStore(tmp_path / "devices.sqlite")
    with pytest.raises(ValueError, match="HTTPS origin"):
        MobileRequestAuthorizer(
            access_authorize=lambda _request: AccessIdentity("user", "owner@example.com"),
            devices=store,
            public_base_url=url,
        )
