"""Lifecycle wiring for the optional sibling mobile listener."""

from __future__ import annotations

from collections.abc import Mapping
from contextlib import contextmanager
import math
import os
import ipaddress
from pathlib import Path
import stat
from typing import Any
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from hermes_constants import get_hermes_home
from hermes_cli.config import load_config
from hermes_cli.mobile_attachments import MobileAttachmentStore
from hermes_cli.mobile_auth import CloudflareAccessAuthorizer, CloudflareAccessConfig
from hermes_cli.mobile_approvals import MobileApprovalStore
from hermes_cli.mobile_catalog import CatalogEntry, MobileCatalog
from hermes_cli.mobile_chat import (
    HermesMobileChatExecutor,
    MobileChatService,
    ProfileSessionBackendPool,
)
from hermes_cli.mobile_devices import DEVICE_SCOPES, MobileDeviceStore, _validate_allowlist
from hermes_cli.mobile_event_store import MobileEventStore
from hermes_cli.mobile_group_execution import MobileGroupExecutionService
from hermes_cli.mobile_groups import MobileGroupCoordinator
from hermes_cli.mobile_objects import MobileObjectRegistry
from hermes_cli.mobile_push import MobilePushRelayClient
from hermes_cli.mobile_request_auth import MobileRequestAuthorizer
from hermes_cli.mobile_rate_limit import MobileRateLimiter
from hermes_cli.mobile_routines import MobileRoutineService, RoutineDefinition, RoutineError
from hermes_cli.mobile_settings import MobileSettingsStore
from hermes_cli.mobile_step_up import MobileStepUpStore
from hermes_cli.mobile_server import running_mobile_listener


def _validate_https_origin(value: Any, *, field_name: str) -> None:
    if not isinstance(value, str) or not value or any(
        ord(char) < 0x21 or ord(char) == 0x7F for char in value
    ):
        raise ValueError(f"{field_name} must be an HTTPS origin")
    try:
        parsed = urlsplit(value)
        # Force validation of malformed ports (urlsplit is otherwise lazy).
        parsed.port
    except ValueError as exc:
        raise ValueError(f"{field_name} must be an HTTPS origin") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"{field_name} must be an HTTPS origin")


def validate_mobile_operator_config(
    mobile: Any,
    *,
    push_token: str = "",
) -> None:
    """Validate deployment-owned mobile settings before touching persistent state."""

    if not isinstance(mobile, Mapping):
        raise ValueError("mobile configuration must be a mapping")

    access = mobile.get("cloudflare_access")
    if not isinstance(access, Mapping):
        raise ValueError("Configure mobile.cloudflare_access with a Cloudflare Access issuer and audience")
    issuer = access.get("issuer")
    audience = access.get("audience")
    if not isinstance(issuer, str) or not issuer or not isinstance(audience, str) or not audience:
        raise ValueError("Configure mobile.cloudflare_access with a Cloudflare Access issuer and audience")
    if any(ord(char) < 0x21 or ord(char) > 0x7E for char in audience):
        raise ValueError("mobile.cloudflare_access.audience contains invalid characters")
    _validate_https_origin(issuer, field_name="mobile.cloudflare_access.issuer")
    CloudflareAccessConfig(issuer=issuer, audience=audience)

    _validate_https_origin(mobile.get("public_url"), field_name="mobile.public_url")

    profiles = mobile.get("allowed_profiles")
    scopes = mobile.get("allowed_scopes")
    if not isinstance(profiles, list) or not profiles:
        raise ValueError("Configure a non-empty mobile.allowed_profiles host policy")
    if not isinstance(scopes, list) or not scopes:
        raise ValueError("Configure a non-empty mobile.allowed_scopes host policy")
    try:
        _validate_allowlist(profiles, field_name="mobile.allowed_profiles")
        _validate_allowlist(scopes, field_name="mobile.allowed_scopes")
    except ValueError as exc:
        raise ValueError(str(exc)) from exc
    if not set(scopes) <= DEVICE_SCOPES:
        raise ValueError("mobile.allowed_scopes contains an unsupported scope")

    allow_private_bind = mobile.get("allow_private_bind", False)
    if not isinstance(allow_private_bind, bool):
        raise ValueError("mobile.allow_private_bind must be a boolean")

    turn_timeout = mobile.get("turn_timeout_seconds", 600)
    if (
        isinstance(turn_timeout, bool)
        or not isinstance(turn_timeout, (int, float))
        or not math.isfinite(float(turn_timeout))
        or not 10 <= float(turn_timeout) <= 3600
    ):
        raise ValueError("mobile.turn_timeout_seconds must be between 10 and 3600")

    push = mobile.get("push_relay")
    if push is None:
        push = {}
    if not isinstance(push, Mapping):
        raise ValueError("mobile.push_relay must be a mapping")
    push_url = push.get("url")
    if push_url is None:
        push_url = ""
    if not isinstance(push_url, str) or not isinstance(push_token, str):
        raise ValueError("Configure both mobile.push_relay.url and HERMES_MOBILE_PUSH_RELAY_TOKEN")
    if bool(push_url) != bool(push_token):
        raise ValueError("Configure both mobile.push_relay.url and HERMES_MOBILE_PUSH_RELAY_TOKEN")
    if push_url:
        # Constructor validation is intentionally local and network-free.
        MobilePushRelayClient(base_url=push_url, credential=push_token)

    for field_name in (
        "model_allowlist",
        "provider_allowlist",
        "skill_allowlist",
        "toolset_allowlist",
    ):
        values = mobile.get(field_name)
        if values is not None and not isinstance(values, list):
            raise ValueError(f"mobile.{field_name} must be a list")
    initial_settings = mobile.get("initial_settings")
    if initial_settings is not None and not isinstance(initial_settings, Mapping):
        raise ValueError("mobile.initial_settings must be a mapping")
    for field_name in ("catalog", "routines"):
        values = mobile.get(field_name)
        if values is not None and not isinstance(values, list):
            raise ValueError(f"mobile.{field_name} must be a list")


def _load_or_create_token_signing_key(path: Path) -> ec.EllipticCurvePrivateKey:
    """Load the installation key, creating it without a world-readable window."""

    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        metadata = None
    if metadata is not None:
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
            raise ValueError("mobile signing key path must be a regular file")
        if os.name != "nt" and metadata.st_mode & 0o077:
            raise ValueError("mobile signing key permissions must be 0600")
        payload = path.read_bytes()
    else:
        generated = ec.generate_private_key(ec.SECP256R1())
        payload = generated.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        try:
            descriptor = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                stat.S_IRUSR | stat.S_IWUSR,
            )
        except FileExistsError:
            return _load_or_create_token_signing_key(path)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    try:
        loaded = serialization.load_pem_private_key(payload, password=None)
    except (TypeError, ValueError) as exc:
        raise ValueError("mobile signing key is invalid") from exc
    if not isinstance(loaded, ec.EllipticCurvePrivateKey) or not isinstance(
        loaded.curve,
        ec.SECP256R1,
    ):
        raise ValueError("mobile signing key must use P-256")
    return loaded


@contextmanager
def mobile_listener_for_serve(args: Any):
    """Start mobile only when both explicit ``hermes serve`` bind flags are set."""

    host = getattr(args, "mobile_host", None)
    port = getattr(args, "mobile_port", None)
    if host is None and port is None:
        yield None
        return
    if not getattr(args, "headless_backend", False):
        raise SystemExit("The mobile listener is available only with hermes serve")
    if not host or port is None:
        raise SystemExit("--mobile-host and --mobile-port must be provided together")
    if not 0 <= port <= 65535:
        raise SystemExit("--mobile-port must be between 0 and 65535")

    config = load_config()
    mobile = config.get("mobile") if isinstance(config, Mapping) else None
    if mobile is None:
        mobile = {}
    if not isinstance(mobile, Mapping):
        raise SystemExit("Invalid mobile configuration: mobile configuration must be a mapping")
    try:
        host_address = ipaddress.ip_address(host)
        if host_address.is_unspecified:
            raise SystemExit(
                "--mobile-host must not be a wildcard address (0.0.0.0 or ::)"
            )
        host_is_loopback = host_address.is_loopback
    except ValueError:
        host_is_loopback = host.lower() == "localhost"
    if not host_is_loopback:
        # Cloudflared is expected to be the only public-facing process.  A private
        # VPN bind is an explicit operator choice and still cannot be wildcard-bound.
        allow_private_bind = bool(mobile.get("allow_private_bind", False))
        try:
            private_host = ipaddress.ip_address(host).is_private
        except ValueError:
            private_host = False
        if not allow_private_bind or not private_host:
            raise SystemExit(
                "--mobile-host must be loopback unless mobile.allow_private_bind enables a private VPN address"
            )
    try:
        validate_mobile_operator_config(
            mobile,
            push_token=os.environ.get("HERMES_MOBILE_PUSH_RELAY_TOKEN", ""),
        )
    except (TypeError, ValueError) as exc:
        raise SystemExit(f"Invalid mobile configuration: {exc}") from exc

    access = mobile.get("cloudflare_access") or {}
    issuer = access.get("issuer")
    audience = access.get("audience")
    if not isinstance(issuer, str) or not issuer or not isinstance(audience, str) or not audience:
        raise SystemExit(
            "Configure mobile.cloudflare_access with a Cloudflare Access issuer and audience"
        )
    public_url = mobile.get("public_url")
    allowed_profiles = mobile.get("allowed_profiles")
    allowed_scopes = mobile.get("allowed_scopes")
    if not isinstance(public_url, str) or not public_url:
        raise SystemExit("Configure mobile.public_url with the external HTTPS origin")
    if not isinstance(allowed_profiles, list) or not allowed_profiles:
        raise SystemExit("Configure a non-empty mobile.allowed_profiles host policy")
    if not isinstance(allowed_scopes, list) or not allowed_scopes:
        raise SystemExit("Configure a non-empty mobile.allowed_scopes host policy")
    # Resolve the operator allowlist against the live host profile set before any mobile
    # database is initialized.  Missing/tombstoned names must not become phantom opaque bots;
    # a profile rename is intentionally treated as a new object and receives a fresh binding.
    from hermes_cli.profiles import normalize_profile_name, profile_exists
    live_allowed_profiles: list[str] = []
    for raw_profile in allowed_profiles:
        try:
            profile_name = normalize_profile_name(raw_profile)
        except (TypeError, ValueError):
            continue
        if not profile_exists(profile_name):
            continue
        if profile_name not in live_allowed_profiles:
            live_allowed_profiles.append(profile_name)
    if not live_allowed_profiles:
        raise SystemExit("mobile.allowed_profiles contains no live Hermes profiles")
    allowed_profiles = live_allowed_profiles
    push_config = mobile.get("push_relay") or {}
    push_url = push_config.get("url")
    push_token = os.environ.get("HERMES_MOBILE_PUSH_RELAY_TOKEN", "")
    if bool(push_url) != bool(push_token):
        raise SystemExit(
            "Configure both mobile.push_relay.url and HERMES_MOBILE_PUSH_RELAY_TOKEN, or neither"
        )

    devices = None
    objects = None
    chat_backends = None
    chat_executor = None
    attachments = None
    groups = None
    group_execution = None
    step_up = None
    settings = None
    approvals = None
    catalog = None
    routines = None
    try:
        access_authorizer = CloudflareAccessAuthorizer(
            CloudflareAccessConfig(issuer=issuer, audience=audience)
        )
        mobile_root = Path(get_hermes_home()) / "mobile"
        signing_key = _load_or_create_token_signing_key(mobile_root / "device-token-key.pem")
        # Group cursors are not bearer credentials, but their MAC must still be keyed with
        # installation-secret material so a client cannot manufacture arbitrary pagination state.
        # Reuse the already-persisted device-token key rather than creating another secret file.
        cursor_secret = signing_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        devices = MobileDeviceStore(
            mobile_root / "devices.sqlite3",
            token_signing_key=signing_key,
            profile_allowlist=allowed_profiles,
            scope_allowlist=allowed_scopes,
        )
        request_authorizer = MobileRequestAuthorizer(
            access_authorize=access_authorizer.authorize,
            devices=devices,
            public_base_url=public_url,
            rate_limiter=MobileRateLimiter(mobile_root / "rate-limits.sqlite3"),
        )
        objects = MobileObjectRegistry(mobile_root / "objects.sqlite3")
        # Materialize the host-owned profile bindings at startup.  This keeps
        # opaque IDs stable for device approvals, settings/audit rows, and
        # push/sync events even before the first mobile profile-list request.
        # Remove bindings for deleted/renamed profiles before materializing the current live
        # set.  This is delete-only: old opaque IDs stay invalid and can never be redirected.
        objects.reconcile_profiles(tuple(allowed_profiles))
        objects.profiles(tuple(allowed_profiles))
        events = MobileEventStore(
            mobile_root / "events.sqlite3",
            instance_id=str(objects.instance_id),
        )
        step_up = MobileStepUpStore(mobile_root / "step-up.sqlite3", devices=devices)
        initial_settings = mobile.get("initial_settings")
        if not isinstance(initial_settings, dict):
            initial_settings = {profile: {} for profile in allowed_profiles}
        else:
            initial_settings = {
                profile: initial_settings.get(profile, {}) for profile in allowed_profiles
            }
        model_allowlist = mobile.get("model_allowlist") or []
        provider_allowlist = mobile.get("provider_allowlist") or []
        skill_allowlist = mobile.get("skill_allowlist") or []
        if not all(isinstance(values, list) for values in (model_allowlist, provider_allowlist, skill_allowlist)):
            raise ValueError("mobile model/provider/skill allowlists must be lists")
        settings = MobileSettingsStore(
            mobile_root / "settings.sqlite3",
            profile_allowlist=allowed_profiles,
            instance_id=str(objects.instance_id),
            model_allowlist=model_allowlist,
            provider_allowlist=provider_allowlist,
            skill_allowlist=skill_allowlist,
            initial_profiles=initial_settings,
            step_up=step_up,
        )
        approvals = MobileApprovalStore(
            mobile_root / "approvals.sqlite3",
            instance_id=str(objects.instance_id),
            profile_allowlist=allowed_profiles,
            step_up=step_up,
        )
        raw_catalog = mobile.get("catalog") or []
        if not isinstance(raw_catalog, list):
            raise ValueError("mobile.catalog must be a list")
        catalog_entries = []
        for raw_entry in raw_catalog:
            if not isinstance(raw_entry, dict):
                raise ValueError("mobile.catalog entries must be objects")
            catalog_entries.append(CatalogEntry(**raw_entry))
        catalog = MobileCatalog(
            entries=catalog_entries,
            profile_allowlist=allowed_profiles,
            model_allowlist=model_allowlist,
            provider_allowlist=provider_allowlist,
            skill_allowlist=skill_allowlist,
            toolset_allowlist=mobile.get("toolset_allowlist") or [],
        )
        raw_routines = mobile.get("routines") or []
        if not isinstance(raw_routines, list):
            raise ValueError("mobile.routines must be a list")
        routine_defs = []
        for raw_routine in raw_routines:
            if not isinstance(raw_routine, dict):
                raise ValueError("mobile.routines entries must be objects")
            routine_defs.append(RoutineDefinition(**raw_routine))
        routines = MobileRoutineService(
            mobile_root / "routines.sqlite3",
            instance_id=str(objects.instance_id),
            profile_allowlist=allowed_profiles,
            routines=routine_defs,
            step_up=step_up,
            recover_on_start=True,
        )
        push_relay = (
            MobilePushRelayClient(base_url=push_url, credential=push_token)
            if push_url and push_token
            else None
        )
        chat_backends = ProfileSessionBackendPool(allowed_profiles)
        chat_executor = HermesMobileChatExecutor(chat_backends)
        chat = MobileChatService(
            mobile_root / "chat.sqlite3",
            events=events,
            session_backend=chat_backends,
            executor=chat_executor,
        )

        def profile_marker(profile_name: str) -> str | None:
            try:
                return str(objects.binding_for_profile(profile_name).opaque_profile_id)
            except (KeyError, TypeError, ValueError):
                return None

        # A direct chat executor can die after its durable run row is created. Fence those rows
        # before accepting new traffic; routine/group stores perform their own startup fencing.
        chat.recover_uncertain_runs(profile_marker=profile_marker)
        # Any other mutation reservation left by the previous listener (settings, approvals,
        # attachments, or push registration) is likewise uncertain after a process restart.
        events.recover_pending_mutations()
        attachments = MobileAttachmentStore(mobile_root / "attachments")
        groups = MobileGroupCoordinator(
            mobile_root / "groups.sqlite3",
            instance_id=str(objects.instance_id),
        )

        def resolve_group_profile(profile_name: str) -> str:
            if profile_name not in allowed_profiles or not profile_exists(profile_name):
                raise KeyError("group profile is no longer allowed")
            return profile_name

        group_execution = MobileGroupExecutionService(
            groups,
            executor=chat_executor,
            profile_resolver=resolve_group_profile,
        )
    except (ValueError, RoutineError) as exc:
        if devices is not None:
            devices.close()
        if objects is not None:
            objects.close()
        if chat_executor is not None:
            chat_executor.close()
        if attachments is not None:
            attachments.close()
        if chat_backends is not None:
            chat_backends.close()
        raise SystemExit(f"Invalid mobile configuration: {exc}") from exc

    try:
        with running_mobile_listener(
            host=host,
            port=port,
            authorize=lambda request: request_authorizer.authorize(
                request,
                scope="chat",
            ),
            sync_authorize=lambda request: request_authorizer.authorize(
                request,
                scope="chat",
            ),
            profiles_authorize=lambda request: request_authorizer.authorize(
                request,
                scope="chat",
            ),
            events_authorize=lambda request: request_authorizer.authorize(
                request,
                scope="chat",
            ),
            push_authorize=request_authorizer.authorize,
            access_authorize=request_authorizer.authorize_access,
            devices=devices,
            events=events,
            objects=objects,
            allowed_profiles=tuple(allowed_profiles),
            profile_liveness=profile_exists,
            push_relay=push_relay,
            request_authorizer=request_authorizer,
            chat=chat,
            attachments=attachments,
            groups=groups,
            group_execution=group_execution,
            settings=settings,
            approvals=approvals,
            catalog=catalog,
            routines=routines,
            step_up=step_up,
            cursor_secret=cursor_secret,
        ) as listener:
            print(f"HERMES_MOBILE_READY port={listener.port}", flush=True)
            print(f"  Hermes mobile API listening on {host}:{listener.port}", flush=True)
            yield listener
    finally:
        if devices is not None:
            devices.close()
        if objects is not None:
            objects.close()
        if chat_executor is not None:
            chat_executor.close()
        if attachments is not None:
            attachments.close()
        if chat_backends is not None:
            chat_backends.close()
