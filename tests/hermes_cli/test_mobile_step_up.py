import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
import pytest

from hermes_cli.mobile_devices import DeviceNotAuthorized, MobileDeviceStore, public_jwk_from_key
from hermes_cli.mobile_step_up import MobileStepUpStore, step_up_message


def _approved(tmp_path):
    devices = MobileDeviceStore(
        tmp_path / "devices.sqlite",
        profile_allowlist=("profile",),
        scope_allowlist=("approvals",),
    )
    background = ec.generate_private_key(ec.SECP256R1())
    user = ec.generate_private_key(ec.SECP256R1())
    enrollment = devices.create_enrollment_code(
        public_jwk_from_key(background),
        public_jwk_from_key(user),
    )
    devices.redeem_enrollment_code(enrollment.code)
    devices.approve_device(enrollment.device_id)
    return devices, user, enrollment.device_id


def test_step_up_binds_exact_context_and_is_single_use(tmp_path):
    devices, user, device_id = _approved(tmp_path)
    store = MobileStepUpStore(tmp_path / "step-up.sqlite", devices=devices)
    context = {
        "instance_id": "instance",
        "run_id": "run",
        "tool_call_id": "call",
        "arguments_digest": "abc",
    }
    challenge = store.create(
        device_id=device_id,
        action="approval.once",
        context=context,
        now=100.0,
    )
    signature = user.sign(step_up_message(challenge), ec.ECDSA(hashes.SHA256()))
    encoded = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()

    store.verify(challenge, context=context, signature=encoded, now=101.0)

    with pytest.raises(DeviceNotAuthorized):
        store.verify(challenge, context=context, signature=encoded, now=102.0)


def test_step_up_rejects_altered_context_and_expiry(tmp_path):
    devices, user, device_id = _approved(tmp_path)
    store = MobileStepUpStore(tmp_path / "step-up.sqlite", devices=devices)
    challenge = store.create(
        device_id=device_id,
        action="settings.soul.write",
        context={"revision": 4, "diff_digest": "abc"},
        now=100.0,
    )
    signature = user.sign(step_up_message(challenge), ec.ECDSA(hashes.SHA256()))
    encoded = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()

    with pytest.raises(DeviceNotAuthorized):
        store.verify(
            challenge,
            context={"revision": 4, "diff_digest": "changed"},
            signature=encoded,
            now=101.0,
        )
    with pytest.raises(DeviceNotAuthorized):
        store.verify(
            challenge,
            context={"revision": 4, "diff_digest": "abc"},
            signature=encoded,
            now=221.0,
        )
