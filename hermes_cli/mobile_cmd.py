"""Host-only administration commands for Hermes Mobile device trust."""

from __future__ import annotations

import argparse
from collections.abc import Mapping
import os
from pathlib import Path
import sys

import httpx

from hermes_constants import get_hermes_home
from hermes_cli.config import load_config
from hermes_cli.mobile_devices import DeviceNotAuthorized, MobileDeviceStore
from hermes_cli.mobile_push import MobilePushRelayClient
from hermes_cli.mobile_startup import _load_or_create_token_signing_key
from hermes_cli.profiles import normalize_profile_name, profile_exists


def _configured_store() -> MobileDeviceStore:
    config = load_config()
    mobile = config.get("mobile") or {}
    profiles = mobile.get("allowed_profiles")
    scopes = mobile.get("allowed_scopes")
    if not isinstance(profiles, list) or not profiles:
        raise SystemExit("Configure a non-empty mobile.allowed_profiles host policy")
    if not isinstance(scopes, list) or not scopes:
        raise SystemExit("Configure a non-empty mobile.allowed_scopes host policy")
    live_profiles: list[str] = []
    for raw_profile in profiles:
        try:
            profile_name = normalize_profile_name(raw_profile)
        except (TypeError, ValueError):
            continue
        if profile_exists(profile_name) and profile_name not in live_profiles:
            live_profiles.append(profile_name)
    if not live_profiles:
        raise SystemExit("mobile.allowed_profiles contains no live Hermes profiles")
    root = Path(get_hermes_home()) / "mobile"
    key = _load_or_create_token_signing_key(root / "device-token-key.pem")
    return MobileDeviceStore(
        root / "devices.sqlite3",
        token_signing_key=key,
        profile_allowlist=live_profiles,
        scope_allowlist=scopes,
    )


def _configured_relay() -> MobilePushRelayClient | None:
    config = load_config()
    mobile = config.get("mobile") or {}
    if not isinstance(mobile, Mapping):
        raise SystemExit("Configure mobile as a mapping")
    push = mobile.get("push_relay")
    if push is None:
        push = {}
    if not isinstance(push, Mapping):
        raise SystemExit("Configure mobile.push_relay as a mapping")
    url = push.get("url")
    credential = os.environ.get("HERMES_MOBILE_PUSH_RELAY_TOKEN", "")
    if not url and not credential:
        return None
    if not isinstance(url, str) or not isinstance(credential, str) or not url or not credential:
        raise SystemExit("Configure both mobile.push_relay.url and HERMES_MOBILE_PUSH_RELAY_TOKEN")
    return MobilePushRelayClient(base_url=url, credential=credential)


def cmd_mobile(args: argparse.Namespace) -> int:
    if args.mobile_action != "devices":
        raise SystemExit("Choose a Hermes Mobile administration action")
    try:
        with _configured_store() as store:
            if args.device_action == "list":
                records = store.list_devices()
                if not records:
                    print("No Hermes Mobile devices enrolled.")
                    return 0
                for record in records:
                    profiles = ",".join(record.profile_allowlist) or "none"
                    scopes = ",".join(record.scope_allowlist) or "none"
                    print(
                        f"{record.device_id}  {record.status}  {record.device_label}  "
                        f"profiles={profiles} scopes={scopes}"
                    )
                return 0
            if args.device_action == "approve":
                pending = store.redeem_enrollment_code(args.code)
                approved = store.approve_device(
                    pending.device_id,
                    profiles=args.profiles,
                    scopes=args.scopes,
                )
                print(f"Approved Hermes Mobile device {approved.device_id} ({approved.device_label}).")
                return 0
            if args.device_action == "revoke":
                revoked = store.revoke_device(args.device_id)
                try:
                    relay = _configured_relay()
                    if relay is not None:
                        relay.revoke_device(revoked.push_handle)
                except (httpx.HTTPError, ValueError) as exc:
                    # Local token revocation is already durable; surface relay
                    # failure so an operator can reconcile the central handle.
                    print(
                        f"Warning: local revocation succeeded but push relay revocation failed: {exc}",
                        file=sys.stderr,
                    )
                print(f"Revoked Hermes Mobile device {revoked.device_id} ({revoked.device_label}).")
                return 0
    except (DeviceNotAuthorized, ValueError) as exc:
        raise SystemExit(f"Hermes Mobile device operation refused: {exc}") from exc
    raise SystemExit("Choose a Hermes Mobile device action")
