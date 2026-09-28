"""GATT transport over bleak: connect, notify, and trsmitr framing.

The UUID constants below are evidence-based presets, not universal scooter
UUIDs. Callers can supply the actual service and characteristic UUIDs observed
on their device. No data is written until the selected GATT path validates.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Callable, Optional

from .protocol import TRS_DEFAULT_CHUNK, TrsmitrAssembler, trsmitr_encode

log = logging.getLogger("youfs.transport")

# GATT handles documented in docs/gatt.md. The actual scooter may differ.
SERVICE_UUID = "0000fd50-0000-1000-8000-00805f9b34fb"
WRITE_CHAR_UUID = "00000001-0000-1001-8001-00805f9b07d0"   # TX (app -> scooter)
NOTIFY_CHAR_UUID = "00000002-0000-1001-8001-00805f9b07d0"  # RX (scooter -> app)
CCCD_UUID = "00002902-0000-1000-8000-00805f9b34fb"

# Legacy P2/Telink group (bqdpddd.java:3169-3172).
LEGACY_SERVICE_UUID = "00001910-0000-1000-8000-00805f9b34fb"
LEGACY_WRITE_CHAR_UUID = "00002b11-0000-1000-8000-00805f9b34fb"
LEGACY_NOTIFY_CHAR_UUID = "00002b10-0000-1000-8000-00805f9b34fb"
P1_WIFI_SERVICE_UUID = "00001000-7475-7961-626c-636f6e666967"
P1_WIFI_WRITE_CHAR_UUID = "00001001-7475-7961-626c-636f6e666967"
P1_WIFI_NOTIFY_CHAR_UUID = "00001002-7475-7961-626c-636f6e666967"

WRITE_PROPERTIES = frozenset(("write", "write-without-response"))
NOTIFY_PROPERTIES = frozenset(("notify", "indicate"))


@dataclass(frozen=True)
class ProtocolGattProfile:
    protocol_type: int
    family: str
    service_uuid: str
    write_uuid: str
    notify_uuid: str
    requested_mtu: Optional[int]
    supports_trsmitr: bool


def profile_for_protocol_type(protocol_type: int) -> ProtocolGattProfile:
    """Resolve the APK's protocolType dispatcher to a GATT profile.

    The original factory maps 413 and 400..405 to P4, 100..102 to P1, and
    its default branch to P2. ``protocol_type`` must be provided explicitly;
    discovery alone cannot infer it from the advertisement.
    """
    if isinstance(protocol_type, bool) or not isinstance(protocol_type, int):
        raise ValueError("protocol_type must be an explicit integer from DeviceBean")
    if protocol_type == 413 or 400 <= protocol_type <= 405:
        return ProtocolGattProfile(protocol_type, "P4", SERVICE_UUID,
                                   WRITE_CHAR_UUID, NOTIFY_CHAR_UUID, 246, True)
    if protocol_type == 101:
        return ProtocolGattProfile(protocol_type, "P1-WiFi", P1_WIFI_SERVICE_UUID,
                                   P1_WIFI_WRITE_CHAR_UUID, P1_WIFI_NOTIFY_CHAR_UUID,
                                   None, False)
    if protocol_type in (100, 102):
        return ProtocolGattProfile(protocol_type, "P1", LEGACY_SERVICE_UUID,
                                   LEGACY_WRITE_CHAR_UUID, LEGACY_NOTIFY_CHAR_UUID,
                                   None, False)
    # The APK's default dispatcher branch is P2 and has no explicit MTU step.
    # Until the P2 app-frame/auth path is independently implemented, connecting
    # and enabling notifications does not authorize application writes.
    return ProtocolGattProfile(protocol_type, "P2", LEGACY_SERVICE_UUID,
                               LEGACY_WRITE_CHAR_UUID, LEGACY_NOTIFY_CHAR_UUID,
                               None, False)


class TransportError(RuntimeError):
    """BLE failure with a stable layer and enough context to diagnose it."""

    def __init__(self, layer: str, message: str, *, diagnostic: str = "") -> None:
        self.layer = layer
        self.message = message
        self.diagnostic = diagnostic
        detail = f"{layer}: {message}"
        if diagnostic:
            detail += f"\nGATT: {diagnostic}"
        super().__init__(detail)


def _uuid_key(value: object) -> str:
    """Compare full and Bluetooth-short UUID spellings consistently."""
    raw = str(value).strip().lower()
    if len(raw) == 4:
        return f"0000{raw}-0000-1000-8000-00805f9b34fb"
    if len(raw) == 8:
        return f"{raw}-0000-1000-8000-00805f9b34fb"
    return raw


class YouFsTransport:
    """Thin bleak wrapper. Frame callbacks receive complete trsmitr payloads."""

    def __init__(self, use_legacy_uuids: Optional[bool] = None,
                 chunk_size: int = TRS_DEFAULT_CHUNK, *,
                 protocol_type: Optional[int] = None,
                 service_uuid: Optional[str] = None,
                 write_uuid: Optional[str] = None,
                 notify_uuid: Optional[str] = None) -> None:
        self.protocol_type = protocol_type
        self._use_legacy_uuids = use_legacy_uuids
        self.service_uuid = service_uuid
        self.write_uuid = write_uuid
        self.notify_uuid = notify_uuid
        self.chunk_size = chunk_size
        self._client = None
        self._write_char = None
        self._notify_char = None
        self._profile: Optional[ProtocolGattProfile] = None
        self._assembler = TrsmitrAssembler()
        self.on_frame: Optional[Callable[[int, int, bytes], None]] = None
        self.mtu: Optional[int] = None
        self.payload_mtu: Optional[int] = None
        self.requested_mtu: Optional[int] = None
        self.mtu_request_supported: Optional[bool] = None

    def list_services(self) -> str:
        """Enumerate the connected device's complete discovered GATT tree."""
        if not self._client or not self._client.is_connected:
            return "(not connected)"
        try:
            services = self._client.services
        except Exception as exc:  # noqa: BLE001
            return f"(service discovery failed: {type(exc).__name__}: {exc})"
        lines = []
        for svc in services:
            lines.append(f"service {svc.uuid}  {getattr(svc, 'description', '') or ''}".rstrip())
            for char in svc.characteristics:
                properties = ",".join(sorted(char.properties))
                lines.append(f"    char {char.uuid}  [{properties}]")
                for desc in getattr(char, "descriptors", ()):
                    lines.append(f"        desc {desc.uuid}")
        return "\n".join(lines) if lines else "(no services discovered)"

    def inspect_connected_client(
            self, client: object) -> tuple[str, list[tuple[str, str, str]]]:
        """Read a connected client's GATT tree without adopting its ownership.

        This is for diagnostics that must inspect services before selecting an
        explicit UUID triplet. It never connects, subscribes, writes, or
        disconnects the supplied client.
        """
        if client is None or not getattr(client, "is_connected", False):
            raise TransportError("connection", "cannot inspect a BLE client that is not connected")
        if self._client is not None and self._client is not client:
            raise TransportError("connection", "transport already owns a different BLE client")

        previous_client = self._client
        self._client = client
        try:
            return self.list_services(), self.find_candidate_channels()
        finally:
            self._client = previous_client

    def find_candidate_channels(self) -> list[tuple[str, str, str]]:
        """Return writable/notifiable pairs belonging to the same service."""
        if not self._client or not self._client.is_connected:
            return []
        try:
            services = self._client.services
        except Exception:  # noqa: BLE001
            return []
        out = []
        for svc in services:
            writable = [c for c in svc.characteristics
                        if WRITE_PROPERTIES.intersection(c.properties)]
            notifiable = [c for c in svc.characteristics
                          if NOTIFY_PROPERTIES.intersection(c.properties)]
            for write_char in writable:
                for notify_char in notifiable:
                    if _uuid_key(write_char.uuid) != _uuid_key(notify_char.uuid):
                        out.append((str(svc.uuid), str(write_char.uuid),
                                    str(notify_char.uuid)))
        return out

    def _services(self):
        try:
            return self._client.services
        except Exception as exc:  # noqa: BLE001
            raise TransportError(
                "gatt-discovery", f"could not read discovered services: {type(exc).__name__}: {exc}",
                diagnostic=self.list_services(),
            ) from exc

    def _select_channel(self, service_uuid: str, write_uuid: str,
                        notify_uuid: str) -> tuple[object, object]:
        services = self._services()
        service = next((svc for svc in services
                        if _uuid_key(svc.uuid) == _uuid_key(service_uuid)), None)
        if service is None:
            raise TransportError(
                "gatt-selection", f"service {service_uuid!r} was not discovered",
                diagnostic=self.list_services(),
            )
        chars = list(service.characteristics)
        write = next((c for c in chars if _uuid_key(c.uuid) == _uuid_key(write_uuid)), None)
        notify = next((c for c in chars if _uuid_key(c.uuid) == _uuid_key(notify_uuid)), None)
        problems = []
        if write is None:
            problems.append(f"write characteristic {write_uuid!r} is absent from service {service.uuid}")
        elif not WRITE_PROPERTIES.intersection(write.properties):
            problems.append(f"write characteristic {write_uuid!r} has unsupported properties {sorted(write.properties)}")
        if notify is None:
            problems.append(f"notify characteristic {notify_uuid!r} is absent from service {service.uuid}")
        elif not NOTIFY_PROPERTIES.intersection(notify.properties):
            problems.append(f"notify characteristic {notify_uuid!r} has unsupported properties {sorted(notify.properties)}")
        if problems:
            raise TransportError("gatt-selection", "; ".join(problems),
                                 diagnostic=self.list_services())
        return write, notify

    def _resolve_profile(self, service_uuid: Optional[str],
                         write_uuid: Optional[str],
                         notify_uuid: Optional[str]) -> ProtocolGattProfile:
        chosen = (service_uuid or self.service_uuid,
                  write_uuid or self.write_uuid,
                  notify_uuid or self.notify_uuid)
        any_override = any(chosen)
        all_overrides = all(chosen)
        if any_override and not all_overrides:
            raise TransportError("protocol-selection",
                                 "provide the full service/write/notify UUID triplet")

        if self.protocol_type is None:
            if all_overrides:
                # Explicit GATT diagnostics are allowed, but do not authorize
                # application writes without a DeviceBean protocol type.
                return ProtocolGattProfile(-1, "custom-diagnostic", chosen[0],
                                           chosen[1], chosen[2], None, False)
            raise TransportError(
                "protocol-selection",
                "protocol_type is required; advertisement data does not select a protocol profile",
            )

        try:
            profile = profile_for_protocol_type(self.protocol_type)
        except ValueError as exc:
            raise TransportError("protocol-selection", str(exc)) from exc
        if self._use_legacy_uuids is True and profile.family not in ("P2", "P1"):
            raise TransportError("protocol-selection",
                                 "legacy UUID override conflicts with protocol_type")
        if any_override:
            return ProtocolGattProfile(profile.protocol_type, profile.family,
                                       chosen[0], chosen[1], chosen[2],
                                       profile.requested_mtu,
                                       profile.supports_trsmitr)
        return profile

    async def connect(self, address: object, timeout: float = 15.0,
                      notify_uuid: Optional[str] = None,
                      service_uuid: Optional[str] = None,
                      write_uuid: Optional[str] = None,
                      protocol_type: Optional[int] = None) -> None:
        """Connect and subscribe after validating an explicitly selected GATT path.

        UUID overrides are also available on the constructor. The third
        positional parameter remains ``notify_uuid`` for compatibility.
        """
        try:
            from bleak import BleakClient  # lazy import
        except ImportError as exc:  # pragma: no cover - environment dependent
            raise TransportError(
                "bleak-dependency", "BLE support needs bleak; install with `pip install -e .[ble]`"
            ) from exc
        if protocol_type is not None:
            self.protocol_type = protocol_type
        profile = self._resolve_profile(service_uuid, write_uuid, notify_uuid)
        self._profile = profile
        selected_service = profile.service_uuid
        selected_write = profile.write_uuid
        selected_notify = profile.notify_uuid
        connect_address = getattr(address, "address", address)
        try:
            # Bleak accepts either a scan-time BLEDevice or an address string.
            # Passing BLEDevice avoids an implicit backend re-scan/address lookup.
            self._client = BleakClient(address)
        except Exception as exc:  # noqa: BLE001
            self._client = None
            raise TransportError(
                "connection", f"could not create BLE client for {connect_address}: {type(exc).__name__}: {exc}"
            ) from exc
        try:
            await asyncio.wait_for(self._client.connect(), timeout=timeout)
        except asyncio.TimeoutError as exc:
            await self._close_client()
            raise TransportError("connection", f"timed out connecting to {connect_address} after {timeout:g}s") from exc
        except Exception as exc:  # noqa: BLE001
            await self._close_client()
            raise TransportError("connection", f"could not connect to {connect_address}: {type(exc).__name__}: {exc}") from exc
        if not self._client.is_connected:
            await self._close_client()
            raise TransportError("connection", f"BLE client did not connect to {connect_address}")
        try:
            self.mtu = self._client.mtu_size
        except Exception:
            self.mtu = None
        self.payload_mtu = max(0, self.mtu - 3) if self.mtu is not None else None
        self.requested_mtu = profile.requested_mtu
        self.mtu_request_supported = None
        try:
            self._write_char, self._notify_char = self._select_channel(
                selected_service, selected_write, selected_notify)

            def _notify_cb(_char, data: bytearray):
                try:
                    result = self._assembler.feed(bytes(data))
                except ValueError as exc:
                    log.warning("trsmitr assembly error: %s", exc)
                    return
                if result and self.on_frame:
                    cmd, seq, payload = result
                    try:
                        self.on_frame(cmd, seq, payload)
                    except Exception:  # noqa: BLE001 - never kill the notify loop
                        log.exception("on_frame callback failed")

            try:
                await self._client.start_notify(self._notify_char, _notify_cb)
            except Exception as exc:  # noqa: BLE001
                raise TransportError(
                    "notification-subscription",
                    f"could not subscribe to {selected_notify}: {type(exc).__name__}: {exc}",
                    diagnostic=self.list_services(),
                ) from exc

            # The APK subscribes to notifications before its P4 MTU action.
            # Bleak 3.0.2 exposes negotiated mtu_size but no public request_mtu;
            # use that API only on backends that explicitly provide it.
            if profile.requested_mtu is not None:
                request_mtu = getattr(self._client, "request_mtu", None)
                self.mtu_request_supported = callable(request_mtu)
                if callable(request_mtu):
                    try:
                        await request_mtu(profile.requested_mtu)
                    except Exception as exc:  # noqa: BLE001
                        log.warning("MTU request %d failed: %s", profile.requested_mtu, exc)
                try:
                    self.mtu = self._client.mtu_size
                except Exception:
                    pass
                self.payload_mtu = max(0, self.mtu - 3) if self.mtu is not None else None
            self.service_uuid = selected_service
            self.write_uuid = selected_write
            self.notify_uuid = selected_notify
        except Exception:
            await self._close_client()
            raise

    async def attach_connected_client(self, client: object, *,
                                      service_uuid: str,
                                      write_uuid: str,
                                      notify_uuid: str,
                                      protocol_type: Optional[int] = None) -> None:
        """Adopt an already-connected BleakClient and prepare its GATT path.

        This method never initiates a BLE connection. On success this transport
        owns the client and ``disconnect`` will stop notifications and close
        it. If setup fails, the caller retains ownership; any attempted notify
        subscription is stopped best-effort before internal state is cleared.
        """
        if self._client is not None:
            raise TransportError("connection", "transport already owns a BLE client")
        if client is None or not getattr(client, "is_connected", False):
            raise TransportError(
                "connection", "cannot attach a BLE client that is not connected")

        previous_protocol_type = self.protocol_type
        if protocol_type is not None:
            self.protocol_type = protocol_type
        try:
            if not service_uuid or not write_uuid or not notify_uuid:
                raise TransportError(
                    "protocol-selection",
                    "provide the full non-empty service/write/notify UUID triplet")
            profile = self._resolve_profile(service_uuid, write_uuid, notify_uuid)
        except Exception:
            self.protocol_type = previous_protocol_type
            raise

        # Ownership transfers only if the whole setup succeeds. While setup is
        # in progress, this reference lets the existing GATT validators inspect
        # services and lets the callback use the ordinary frame dispatcher.
        self._client = client
        self._profile = profile
        notify_attempted = False
        notify_char = None
        try:
            try:
                self.mtu = client.mtu_size
            except Exception:
                self.mtu = None
            self.payload_mtu = max(0, self.mtu - 3) if self.mtu is not None else None
            self.requested_mtu = profile.requested_mtu
            self.mtu_request_supported = None

            self._write_char, notify_char = self._select_channel(
                profile.service_uuid, profile.write_uuid, profile.notify_uuid)
            self._notify_char = notify_char

            def _notify_cb(_char, data: bytearray):
                try:
                    result = self._assembler.feed(bytes(data))
                except ValueError as exc:
                    log.warning("trsmitr assembly error: %s", exc)
                    return
                if result and self.on_frame:
                    cmd, seq, payload = result
                    try:
                        self.on_frame(cmd, seq, payload)
                    except Exception:  # noqa: BLE001 - never kill the notify loop
                        log.exception("on_frame callback failed")

            notify_attempted = True
            try:
                await client.start_notify(notify_char, _notify_cb)
            except Exception as exc:  # noqa: BLE001
                raise TransportError(
                    "notification-subscription",
                    f"could not subscribe to {profile.notify_uuid}: {type(exc).__name__}: {exc}",
                    diagnostic=self.list_services(),
                ) from exc

            # Match the app's order: notifications are enabled before the P4
            # MTU request. Some Bleak backends expose only negotiated mtu_size.
            if profile.requested_mtu is not None:
                request_mtu = getattr(client, "request_mtu", None)
                self.mtu_request_supported = callable(request_mtu)
                if callable(request_mtu):
                    try:
                        await request_mtu(profile.requested_mtu)
                    except Exception as exc:  # noqa: BLE001
                        log.warning("MTU request %d failed: %s", profile.requested_mtu, exc)
                try:
                    self.mtu = client.mtu_size
                except Exception:
                    pass
                self.payload_mtu = max(0, self.mtu - 3) if self.mtu is not None else None

            self.service_uuid = profile.service_uuid
            self.write_uuid = profile.write_uuid
            self.notify_uuid = profile.notify_uuid
        except Exception:
            if notify_attempted and notify_char is not None:
                try:
                    await client.stop_notify(notify_char)
                except Exception:  # noqa: BLE001
                    log.debug("notify cleanup after client adoption failure failed",
                              exc_info=True)
            self._reset_client_state()
            self.protocol_type = previous_protocol_type
            raise

    async def _close_client(self) -> None:
        client, self._client = self._client, None
        self._write_char = None
        self._notify_char = None
        if client and client.is_connected:
            try:
                await client.disconnect()
            except Exception:  # noqa: BLE001
                log.debug("BLE disconnect after setup failure failed", exc_info=True)

    def _reset_client_state(self) -> None:
        self._client = None
        self._write_char = None
        self._notify_char = None
        self._profile = None
        self.mtu = None
        self.payload_mtu = None
        self.requested_mtu = None
        self.mtu_request_supported = None
        self._assembler = TrsmitrAssembler()

    async def disconnect(self) -> None:
        client = self._client
        if client and client.is_connected:
            if self._notify_char is not None:
                try:
                    await client.stop_notify(self._notify_char)
                except Exception:  # noqa: BLE001
                    pass
            await client.disconnect()
        self._client = None
        self._write_char = None
        self._notify_char = None

    @property
    def is_connected(self) -> bool:
        return bool(self._client and self._client.is_connected)

    @property
    def notify_ready(self) -> bool:
        """Whether connect completed validation and notification subscription."""
        return bool(self.is_connected and self._notify_char is not None)

    def _write_target(self):
        if not self.is_connected or self._write_char is None:
            raise TransportError("write", "no validated GATT write channel; connect successfully first")
        if self._profile is None or not self._profile.supports_trsmitr:
            raise TransportError(
                "protocol-write",
                "selected GATT profile has no supported trsmitr application encoder; refusing to write",
            )
        return self._write_char

    async def _send(self, payload: bytes, response: bool) -> None:
        target = self._write_target()
        chunk = self.chunk_size
        if self.payload_mtu and self.payload_mtu >= TRS_DEFAULT_CHUNK:
            chunk = max(TRS_DEFAULT_CHUNK, self.payload_mtu)
        for packet in trsmitr_encode(payload, chunk_size=chunk):
            try:
                await self._client.write_gatt_char(target, packet, response=response)
            except Exception as exc:  # noqa: BLE001
                raise TransportError(
                    "gatt-write",
                    f"write to {self.write_uuid} failed (response={response}): {type(exc).__name__}: {exc}",
                    diagnostic=self.list_services(),
                ) from exc

    async def send_frame(self, payload: bytes) -> None:
        """Split and write a complete application frame without response."""
        await self._send(payload, response=False)

    async def send_frame_write_response(self, payload: bytes) -> None:
        """Split and write a frame using Write Request for each packet."""
        await self._send(payload, response=True)
