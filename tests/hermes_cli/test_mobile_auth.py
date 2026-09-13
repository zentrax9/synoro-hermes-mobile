from __future__ import annotations

import time

from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
import jwt

from hermes_cli.mobile_auth import CloudflareAccessAuthorizer, CloudflareAccessConfig
from hermes_cli.mobile_server import create_mobile_app


class _SigningKey:
    def __init__(self, key) -> None:
        self.key = key


class _JwksClient:
    def __init__(self, key) -> None:
        self._key = key

    def get_signing_key_from_jwt(self, _token: str) -> _SigningKey:
        return _SigningKey(self._key)


def _access_token(*, audience: str = "install-audience") -> tuple[str, object]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = int(time.time())
    token = jwt.encode(
        {
            "iss": "https://team.cloudflareaccess.com",
            "aud": [audience],
            "sub": "cloudflare-user-id",
            "email": "owner@example.test",
            "iat": now,
            "exp": now + 60,
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "test-key"},
    )
    return token, private_key.public_key()


def test_mobile_access_headers_are_rejected_from_a_non_tunnel_peer() -> None:
    token, public_key = _access_token()
    authorizer = CloudflareAccessAuthorizer(
        CloudflareAccessConfig(
            issuer="https://team.cloudflareaccess.com",
            audience="install-audience",
        ),
        jwks_client=_JwksClient(public_key),
    )
    client = TestClient(
        create_mobile_app(authorize=authorizer.authorize),
        client=("203.0.113.10", 43120),
    )

    response = client.get(
        "/mobile/v1/capabilities",
        headers={"Cf-Access-Jwt-Assertion": token},
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "mobile authentication required"}


def test_mobile_access_assertion_requires_the_installation_audience() -> None:
    token, public_key = _access_token(audience="another-installation")
    authorizer = CloudflareAccessAuthorizer(
        CloudflareAccessConfig(
            issuer="https://team.cloudflareaccess.com",
            audience="install-audience",
        ),
        jwks_client=_JwksClient(public_key),
    )
    client = TestClient(
        create_mobile_app(authorize=authorizer.authorize),
        client=("127.0.0.1", 43120),
    )

    response = client.get(
        "/mobile/v1/capabilities",
        headers={"Cf-Access-Jwt-Assertion": token},
    )

    assert response.status_code == 401


def test_valid_mobile_access_assertion_reaches_the_mobile_route() -> None:
    token, public_key = _access_token()
    authorizer = CloudflareAccessAuthorizer(
        CloudflareAccessConfig(
            issuer="https://team.cloudflareaccess.com",
            audience="install-audience",
        ),
        jwks_client=_JwksClient(public_key),
    )
    client = TestClient(
        create_mobile_app(authorize=authorizer.authorize),
        client=("127.0.0.1", 43120),
    )

    response = client.get(
        "/mobile/v1/capabilities",
        headers={"Cf-Access-Jwt-Assertion": token},
    )

    assert response.status_code == 200
    assert response.json()["api_version"] == "v1"
