from __future__ import annotations

import base64
import hashlib
import json
import time

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
import jwt
import pytest

from hermes_cli.mobile_devices import (
    DeviceNotAuthorized,
    InvalidDpopProof,
    MobileDeviceStore,
    public_jwk_from_key,
    token_challenge_message,
)


def _key_pair() -> tuple[ec.EllipticCurvePrivateKey, dict[str, str]]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, public_jwk_from_key(private_key.public_key())


def _store(tmp_path):
    return MobileDeviceStore(
        db_path=tmp_path / "mobile-devices.sqlite3",
        profile_allowlist={"default", "work"},
        scope_allowlist={"chat", "settings:read"},
    )


def _enroll_and_approve(store: MobileDeviceStore, background_jwk: dict, user_jwk: dict):
    challenge = store.create_enrollment_code(
        background_jwk,
        user_jwk,
        device_label="Owner phone",
        profiles={"default"},
        scopes={"chat"},
        now=1_000.0,
    )
    pending = store.redeem_enrollment_code(challenge.code, now=1_001.0)
    approved = store.approve_device(pending.device_id, now=1_002.0)
    return challenge, approved


def _dpop(
    private_key: ec.EllipticCurvePrivateKey,
    *,
    access_token: str,
    method: str = "GET",
    url: str = "https://example.test/mobile/v1/capabilities",
    now: int = 1_003,
    jti: str = "proof-1",
    nonce: str = "nonce-0000000001",
    request_id: str | None = None,
    ath: str | None = None,
) -> str:
    token_hash = hashlib.sha256(access_token.encode("ascii")).digest()
    computed_ath = base64.urlsafe_b64encode(token_hash).decode("ascii").rstrip("=")
    claims = {
        "htm": method,
        "htu": url,
        "iat": now,
        "jti": jti,
        "nonce": nonce,
        "request_id": jti if request_id is None else request_id,
        "ath": computed_ath if ath is None else ath,
    }
    return jwt.encode(
        claims,
        private_key,
        algorithm="ES256",
        headers={"typ": "dpop+jwt", "jwk": public_jwk_from_key(private_key.public_key())},
    )


def test_enrollment_validates_two_distinct_p256_public_keys_and_uses_opaque_ids(tmp_path) -> None:
    store = _store(tmp_path)
    background_key, background_jwk = _key_pair()
    _, user_jwk = _key_pair()

    challenge = store.create_enrollment_code(
        background_jwk,
        user_jwk,
        device_label="Owner phone",
        profiles={"default"},
        scopes={"chat"},
        now=1_000.0,
    )

    assert challenge.device_id
    assert challenge.code
    assert challenge.device_id != challenge.code
    assert challenge.expires_at == 1_300.0
    assert challenge.background_jkt
    assert challenge.user_jkt

    pending = store.redeem_enrollment_code(challenge.code, now=1_001.0)
    assert pending.status == "pending"
    assert pending.background_jkt == challenge.background_jkt
    assert pending.user_jkt == challenge.user_jkt
    assert pending.background_jwk == background_jwk
    assert pending.device_label == "Owner phone"
    assert pending.push_handle != pending.device_id
    assert len(pending.push_handle) >= 16

    with pytest.raises(ValueError):
        store.create_enrollment_code(background_jwk, background_jwk, profiles={"default"}, scopes={"chat"})


def test_approval_allowlists_issue_five_minute_token_and_revocation_is_immediate(tmp_path) -> None:
    store = _store(tmp_path)
    background_key, background_jwk = _key_pair()
    _, user_jwk = _key_pair()
    challenge, pending = _enroll_and_approve(store, background_jwk, user_jwk)

    token = store.issue_device_token(pending.device_id, now=1_003.0)
    claims = store.verify_device_token(token, now=1_004.0)
    assert claims["sub"] == pending.device_id
    assert claims["cnf"]["jkt"] == challenge.background_jkt
    assert claims["exp"] - claims["iat"] == 300
    assert claims["profiles"] == ["default"]
    assert claims["scope"] == "chat"

    # The approval is server-owned and cannot be widened by passing foreign values.
    with pytest.raises(ValueError):
        store.approve_device(pending.device_id, profiles={"work"}, scopes={"chat"}, now=1_004.0)

    store.revoke_device(pending.device_id, now=1_005.0)
    with pytest.raises(DeviceNotAuthorized):
        store.verify_device_token(token, now=1_006.0)


def test_dpop_requires_binding_normalized_url_and_one_time_jti(tmp_path) -> None:
    store = _store(tmp_path)
    background_key, background_jwk = _key_pair()
    _, user_jwk = _key_pair()
    challenge, pending = _enroll_and_approve(store, background_jwk, user_jwk)
    token = store.issue_device_token(pending.device_id, now=1_003.0)

    proof = _dpop(
        background_key,
        access_token=token,
        url="HTTPS://EXAMPLE.TEST:443/mobile/v1/capabilities?ignored=yes",
    )
    identity = store.authorize_request(
        token,
        proof,
        method="get",
        url="https://example.test/mobile/v1/capabilities",
        profile="default",
        scope="chat",
        now=1_004.0,
    )
    assert identity.device_id == pending.device_id
    assert identity.profile == "default"
    assert identity.scope == "chat"

    with pytest.raises(InvalidDpopProof):
        store.authorize_request(
            token,
            proof,
            method="GET",
            url="https://example.test/mobile/v1/capabilities",
            profile="default",
            scope="chat",
            now=1_004.0,
        )


def test_dpop_requires_nonce_and_request_id_to_match_replay_identity(tmp_path) -> None:
    store = _store(tmp_path)
    background_key, background_jwk = _key_pair()
    _, user_jwk = _key_pair()
    _, pending = _enroll_and_approve(store, background_jwk, user_jwk)
    token = store.issue_device_token(pending.device_id, now=1_003.0)

    missing_nonce = _dpop(
        background_key,
        access_token=token,
        jti="proof-missing-nonce",
        nonce="",
    )
    with pytest.raises(InvalidDpopProof):
        store.authorize_request(
            token,
            missing_nonce,
            method="GET",
            url="https://example.test/mobile/v1/capabilities",
            profile="default",
            scope="chat",
            now=1_004.0,
        )

    mismatched_request_id = _dpop(
        background_key,
        access_token=token,
        jti="proof-request-id",
        request_id="different-request-id",
    )
    with pytest.raises(InvalidDpopProof):
        store.authorize_request(
            token,
            mismatched_request_id,
            method="GET",
            url="https://example.test/mobile/v1/capabilities",
            profile="default",
            scope="chat",
            now=1_004.0,
        )

    wrong_method = _dpop(background_key, access_token=token, jti="proof-2", method="POST")
    with pytest.raises(InvalidDpopProof):
        store.authorize_request(
            token,
            wrong_method,
            method="GET",
            url="https://example.test/mobile/v1/capabilities",
            profile="default",
            scope="chat",
            now=1_004.0,
        )

    wrong_key, _ = _key_pair()
    wrong_key_proof = _dpop(wrong_key, access_token=token, jti="proof-3")
    with pytest.raises(InvalidDpopProof):
        store.authorize_request(
            token,
            wrong_key_proof,
            method="GET",
            url="https://example.test/mobile/v1/capabilities",
            profile="default",
            scope="chat",
            now=1_004.0,
        )


def test_dpop_rejects_bad_access_hash_stale_iat_and_cross_scope_requests(tmp_path) -> None:
    store = _store(tmp_path)
    background_key, background_jwk = _key_pair()
    _, user_jwk = _key_pair()
    _, pending = _enroll_and_approve(store, background_jwk, user_jwk)
    token = store.issue_device_token(pending.device_id, now=1_003.0)

    bad_ath = _dpop(background_key, access_token=token, jti="proof-ath", ath="wrong")
    with pytest.raises(InvalidDpopProof):
        store.authorize_request(
            token,
            bad_ath,
            method="GET",
            url="https://example.test/mobile/v1/capabilities",
            profile="default",
            scope="chat",
            now=1_004.0,
        )

    stale = _dpop(background_key, access_token=token, jti="proof-stale", now=600)
    with pytest.raises(InvalidDpopProof):
        store.authorize_request(
            token,
            stale,
            method="GET",
            url="https://example.test/mobile/v1/capabilities",
            profile="default",
            scope="chat",
            now=1_004.0,
        )

    cross_scope = _dpop(background_key, access_token=token, jti="proof-scope")
    with pytest.raises(DeviceNotAuthorized):
        store.authorize_request(
            token,
            cross_scope,
            method="GET",
            url="https://example.test/mobile/v1/capabilities",
            profile="work",
            scope="chat",
            now=1_004.0,
        )


def test_jwk_validation_rejects_private_or_non_p256_material(tmp_path) -> None:
    store = _store(tmp_path)
    _, background_jwk = _key_pair()
    _, user_jwk = _key_pair()

    private_jwk = dict(background_jwk, d="private")
    with pytest.raises(ValueError):
        store.create_enrollment_code(private_jwk, user_jwk, profiles={"default"}, scopes={"chat"})

    wrong_curve_key = ec.generate_private_key(ec.SECP384R1())
    with pytest.raises(ValueError):
        store.create_enrollment_code(
            public_jwk_from_key(wrong_curve_key.public_key()),
            user_jwk,
            profiles={"default"},
            scopes={"chat"},
        )


def test_expired_enrollment_code_is_single_use_and_does_not_leak_secret_in_repr(tmp_path) -> None:
    store = _store(tmp_path)
    _, background_jwk = _key_pair()
    _, user_jwk = _key_pair()
    challenge = store.create_enrollment_code(
        background_jwk,
        user_jwk,
        profiles={"default"},
        scopes={"chat"},
        ttl_seconds=2,
        now=1_000.0,
    )

    assert challenge.code not in repr(challenge)
    assert challenge.code not in str(challenge)
    with pytest.raises(DeviceNotAuthorized):
        store.redeem_enrollment_code(challenge.code, now=1_003.0)
    with pytest.raises(DeviceNotAuthorized):
        store.redeem_enrollment_code(challenge.code, now=1_003.0)


def test_device_token_refresh_requires_a_single_use_server_nonce(tmp_path) -> None:
    store = _store(tmp_path)
    background_key, background_jwk = _key_pair()
    _, user_jwk = _key_pair()
    _, device = _enroll_and_approve(store, background_jwk, user_jwk)
    challenge = store.create_token_challenge(device.device_id, now=1_003.0)
    signature = background_key.sign(
        token_challenge_message(device.device_id, challenge.nonce),
        ec.ECDSA(hashes.SHA256()),
    )
    encoded_signature = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")

    token = store.complete_token_challenge(
        device.device_id,
        nonce=challenge.nonce,
        signature=encoded_signature,
        now=1_004.0,
    )

    assert store.verify_device_token(token, now=1_005.0)["sub"] == device.device_id
    with pytest.raises(DeviceNotAuthorized):
        store.complete_token_challenge(
            device.device_id,
            nonce=challenge.nonce,
            signature=encoded_signature,
            now=1_005.0,
        )


def test_server_policy_rejects_unknown_mobile_scopes(tmp_path) -> None:
    with pytest.raises(ValueError, match="unsupported mobile scope"):
        MobileDeviceStore(
            tmp_path / "devices.sqlite",
            profile_allowlist=("profile-a",),
            scope_allowlist=("shell:admin",),
        )
