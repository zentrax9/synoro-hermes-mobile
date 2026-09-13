"""Biometric/device-credential step-up challenges for sensitive mobile actions."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import secrets
import sqlite3
import time
from typing import Any, Mapping
from uuid import UUID, uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from hermes_cli.mobile_devices import DeviceNotAuthorized, MobileDeviceStore, validate_public_jwk


STEP_UP_TTL_SECONDS = 120


@dataclass(frozen=True, slots=True)
class StepUpChallenge:
    challenge_id: UUID
    device_id: str
    action: str
    context_digest: str
    nonce: str = field(repr=False)
    expires_at: float

    def __str__(self) -> str:
        return "[redacted step-up challenge]"


def _canonical_context(context: Mapping[str, Any]) -> tuple[str, str]:
    try:
        encoded = json.dumps(context, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise ValueError("step-up context must be JSON data") from exc
    if len(encoded.encode("utf-8")) > 16_384:
        raise ValueError("step-up context is too large")
    return encoded, hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def step_up_message(challenge: StepUpChallenge) -> bytes:
    return (
        "hermes-mobile-step-up-v1\0"
        f"{challenge.challenge_id}\0{challenge.device_id}\0{challenge.action}\0"
        f"{challenge.context_digest}\0{challenge.nonce}\0{int(challenge.expires_at)}"
    ).encode("utf-8")


def _public_key(jwk: Mapping[str, Any]) -> ec.EllipticCurvePublicKey:
    canonical = validate_public_jwk(jwk)
    decode = lambda value: base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    return ec.EllipticCurvePublicNumbers(
        int.from_bytes(decode(canonical["x"]), "big"),
        int.from_bytes(decode(canonical["y"]), "big"),
        ec.SECP256R1(),
    ).public_key()


class MobileStepUpStore:
    def __init__(self, path: str | Path, *, devices: MobileDeviceStore, clock=time.time) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._devices = devices
        self._clock = clock
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS mobile_step_up_challenges (
                    challenge_id TEXT PRIMARY KEY,
                    device_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    context_digest TEXT NOT NULL,
                    nonce_hash BLOB NOT NULL,
                    expires_at REAL NOT NULL,
                    consumed_at REAL
                )
                """
            )

    def _connect(self):
        connection = sqlite3.connect(self._path, isolation_level=None, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def create(
        self,
        *,
        device_id: str,
        action: str,
        context: Mapping[str, Any],
        now: float | None = None,
    ) -> StepUpChallenge:
        record = self._devices.get_device(device_id)
        if not record.approved:
            raise DeviceNotAuthorized("device is not authorized")
        if not action or len(action) > 128 or any(ord(character) < 0x21 for character in action):
            raise ValueError("invalid step-up action")
        _, digest = _canonical_context(context)
        current = float(self._clock() if now is None else now)
        challenge = StepUpChallenge(
            challenge_id=uuid4(),
            device_id=device_id,
            action=action,
            context_digest=digest,
            nonce=secrets.token_urlsafe(32),
            expires_at=current + STEP_UP_TTL_SECONDS,
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "DELETE FROM mobile_step_up_challenges WHERE expires_at <= ?",
                (current,),
            )
            connection.execute(
                """
                INSERT INTO mobile_step_up_challenges (
                    challenge_id, device_id, action, context_digest, nonce_hash, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    str(challenge.challenge_id),
                    challenge.device_id,
                    challenge.action,
                    challenge.context_digest,
                    hashlib.sha256(challenge.nonce.encode()).digest(),
                    challenge.expires_at,
                ),
            )
            connection.commit()
        return challenge

    def verify(
        self,
        challenge: StepUpChallenge,
        *,
        context: Mapping[str, Any],
        signature: str,
        now: float | None = None,
    ) -> None:
        _, context_digest = _canonical_context(context)
        current = float(self._clock() if now is None else now)
        try:
            signature_bytes = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
        except (ValueError, TypeError) as exc:
            raise DeviceNotAuthorized("step-up authorization is invalid") from exc
        if len(signature_bytes) > 144 or not signature_bytes:
            raise DeviceNotAuthorized("step-up authorization is invalid")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM mobile_step_up_challenges WHERE challenge_id = ?",
                (str(challenge.challenge_id),),
            ).fetchone()
            if (
                row is None
                or row["consumed_at"] is not None
                or current >= float(row["expires_at"])
                or row["device_id"] != challenge.device_id
                or row["action"] != challenge.action
                or row["context_digest"] != challenge.context_digest
                or context_digest != challenge.context_digest
                or not secrets.compare_digest(
                    bytes(row["nonce_hash"]),
                    hashlib.sha256(challenge.nonce.encode()).digest(),
                )
            ):
                connection.rollback()
                raise DeviceNotAuthorized("step-up authorization is invalid")
            record = self._devices.get_device(challenge.device_id)
            if not record.approved:
                connection.rollback()
                raise DeviceNotAuthorized("step-up authorization is invalid")
            try:
                _public_key(record.user_jwk).verify(
                    signature_bytes,
                    step_up_message(challenge),
                    ec.ECDSA(hashes.SHA256()),
                )
            except (InvalidSignature, ValueError, TypeError) as exc:
                connection.rollback()
                raise DeviceNotAuthorized("step-up authorization is invalid") from exc
            changed = connection.execute(
                "UPDATE mobile_step_up_challenges SET consumed_at = ? "
                "WHERE challenge_id = ? AND consumed_at IS NULL",
                (current, str(challenge.challenge_id)),
            ).rowcount
            if changed != 1:
                connection.rollback()
                raise DeviceNotAuthorized("step-up authorization is invalid")
            connection.commit()
