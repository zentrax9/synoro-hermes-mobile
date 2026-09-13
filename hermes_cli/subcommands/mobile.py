"""``hermes mobile`` host administration parser."""

from __future__ import annotations

from typing import Callable


def build_mobile_parser(subparsers, *, cmd_mobile: Callable) -> None:
    mobile = subparsers.add_parser(
        "mobile",
        help="Manage approved Hermes Mobile devices",
        description="List, approve, or immediately revoke mobile devices on this host",
    )
    actions = mobile.add_subparsers(dest="mobile_action", required=True)
    devices = actions.add_parser("devices", help="Manage the device trust registry")
    device_actions = devices.add_subparsers(dest="device_action", required=True)

    device_actions.add_parser("list", help="List pending, approved, and revoked devices")
    approve = device_actions.add_parser(
        "approve",
        help="Consume an enrollment code and approve that device",
    )
    approve.add_argument("code", help="One-time enrollment code shown by the mobile app")
    approve.add_argument(
        "--profiles",
        nargs="+",
        required=True,
        help="Allowed host profile names (never exposed directly to the client)",
    )
    approve.add_argument(
        "--scopes",
        nargs="+",
        required=True,
        help="Allowed mobile API scopes",
    )

    revoke = device_actions.add_parser("revoke", help="Immediately revoke one device")
    revoke.add_argument("device_id", help="Opaque device ID from 'hermes mobile devices list'")
    mobile.set_defaults(func=cmd_mobile)
