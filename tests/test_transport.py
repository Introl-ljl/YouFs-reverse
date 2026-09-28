"""Offline tests for GATT selection and transport diagnostics."""

import asyncio
import sys
import types

import pytest

from youfs.transport import TransportError, YouFsTransport


class FakeCharacteristic:
    def __init__(self, uuid, properties):
        self.uuid = uuid
        self.properties = properties
        self.descriptors = []


class FakeService:
    def __init__(self, uuid, characteristics):
        self.uuid = uuid
        self.characteristics = characteristics
        self.description = "test service"


class FakeClient:
    def __init__(self, address, services, *, start_notify_error=None):
        self.address = address
        self.services = services
        self.start_notify_error = start_notify_error
        self.is_connected = False
        self.mtu_size = 23
        self.writes = []
        self.subscriptions = []
        self.events = []
        self.connect_calls = 0
        self.disconnect_calls = 0

    async def connect(self):
        self.connect_calls += 1
        self.is_connected = True

    async def start_notify(self, characteristic, callback):
        self.events.append("notify")
        if self.start_notify_error:
            raise self.start_notify_error
        self.subscriptions.append(characteristic)

    async def request_mtu(self, value):
        self.events.append(("mtu", value))
        self.mtu_size = value

    async def stop_notify(self, characteristic):
        self.events.append(("stop_notify", characteristic))

    async def disconnect(self):
        self.disconnect_calls += 1
        self.events.append("disconnect")
        self.is_connected = False

    async def write_gatt_char(self, characteristic, data, response=False):
        self.writes.append((characteristic, data, response))


def install_bleak(monkeypatch, client):
    module = types.ModuleType("bleak")
    module.BleakClient = lambda address: (setattr(client, "input_device", address) or client)
    monkeypatch.setitem(sys.modules, "bleak", module)


def tree():
    write = FakeCharacteristic("a001", ["write"])
    notify = FakeCharacteristic("a002", ["notify"])
    service = FakeService("a000", [write, notify])
    return service, write, notify


def test_connect_uses_explicit_diagnostic_profile_and_characteristics(monkeypatch):
    service, write, notify = tree()
    client = FakeClient("scooter", [service])
    install_bleak(monkeypatch, client)
    transport = YouFsTransport(service_uuid="a000", write_uuid="a001", notify_uuid="a002")

    asyncio.run(transport.connect("scooter"))

    assert transport.is_connected
    assert transport.notify_ready
    assert client.subscriptions == [notify]
    assert transport.service_uuid == "a000"
    assert transport.mtu == 23
    assert transport.payload_mtu == 20
    with pytest.raises(TransportError, match="no supported trsmitr"):
        asyncio.run(transport.send_frame(b"diagnostic must not write"))


def test_connect_rejects_characteristic_without_write_property(monkeypatch):
    service, _, notify = tree()
    service.characteristics[0].properties = ["read"]
    client = FakeClient("scooter", [service])
    install_bleak(monkeypatch, client)
    transport = YouFsTransport(service_uuid="a000", write_uuid="a001", notify_uuid="a002")

    with pytest.raises(TransportError) as caught:
        asyncio.run(transport.connect("scooter"))

    assert caught.value.layer == "gatt-selection"
    assert "unsupported properties" in caught.value.message
    assert "service a000" in caught.value.diagnostic
    assert not client.is_connected
    assert not transport.notify_ready


def test_connect_rejects_characteristic_from_different_service(monkeypatch):
    service, write, _ = tree()
    other = FakeService("b000", [FakeCharacteristic("b002", ["notify"])])
    client = FakeClient("scooter", [service, other])
    install_bleak(monkeypatch, client)
    transport = YouFsTransport(service_uuid="a000", write_uuid="a001", notify_uuid="b002")

    with pytest.raises(TransportError) as caught:
        asyncio.run(transport.connect("scooter"))

    assert caught.value.layer == "gatt-selection"
    assert "absent from service" in caught.value.message
    assert "service b000" in caught.value.diagnostic
    assert not client.is_connected


def test_notify_subscription_failure_has_separate_layer(monkeypatch):
    service, _, _ = tree()
    client = FakeClient("scooter", [service], start_notify_error=OSError("permission denied"))
    install_bleak(monkeypatch, client)
    transport = YouFsTransport(service_uuid="a000", write_uuid="a001", notify_uuid="a002")

    with pytest.raises(TransportError) as caught:
        asyncio.run(transport.connect("scooter"))

    assert caught.value.layer == "notification-subscription"
    assert "permission denied" in caught.value.message
    assert "char a002" in caught.value.diagnostic
    assert not client.is_connected


def test_write_requires_validated_channel_and_uses_selected_characteristic(monkeypatch):
    service = FakeService(
        "0000fd50-0000-1000-8000-00805f9b34fb",
        [FakeCharacteristic("00000001-0000-1001-8001-00805f9b07d0", ["write"]),
         FakeCharacteristic("00000002-0000-1001-8001-00805f9b07d0", ["notify"])])
    write, notify = service.characteristics
    client = FakeClient("scooter", [service])
    install_bleak(monkeypatch, client)
    transport = YouFsTransport(protocol_type=413)

    with pytest.raises(TransportError) as caught:
        asyncio.run(transport.send_frame(b"payload"))
    assert caught.value.layer == "write"

    asyncio.run(transport.connect("scooter"))
    asyncio.run(transport.send_frame(b"payload"))
    assert client.writes
    assert all(record[0] is write for record in client.writes)
    assert all(record[2] is False for record in client.writes)


def test_discovery_report_includes_properties_and_descriptors():
    service, write, _ = tree()
    write.descriptors = [types.SimpleNamespace(uuid="2902")]
    client = FakeClient("scooter", [service])
    client.is_connected = True
    transport = YouFsTransport()
    transport._client = client

    report = transport.list_services()

    assert "service a000" in report
    assert "char a001  [write]" in report
    assert "desc 2902" in report


def test_missing_protocol_type_fails_closed_before_ble_client(monkeypatch):
    client = FakeClient("scooter", [])
    install_bleak(monkeypatch, client)
    transport = YouFsTransport()
    with pytest.raises(TransportError, match="protocol_type is required"):
        asyncio.run(transport.connect("scooter"))
    assert not hasattr(client, "input_device")


def test_protocol_type_profiles_follow_apk_dispatch():
    from youfs.transport import profile_for_protocol_type

    p4 = profile_for_protocol_type(413)
    assert (p4.family, p4.service_uuid, p4.write_uuid, p4.notify_uuid,
            p4.requested_mtu) == (
                "P4", "0000fd50-0000-1000-8000-00805f9b34fb",
                "00000001-0000-1001-8001-00805f9b07d0",
                "00000002-0000-1001-8001-00805f9b07d0", 246)
    assert profile_for_protocol_type(405).family == "P4"
    assert profile_for_protocol_type(101).family == "P1-WiFi"
    assert profile_for_protocol_type(100).family == "P1"
    assert profile_for_protocol_type(102).family == "P1"
    p2 = profile_for_protocol_type(777)
    assert p2.family == "P2"  # APK factory default.
    assert not p2.supports_trsmitr  # Mapping does not prove app protocol support.
    with pytest.raises(ValueError):
        profile_for_protocol_type(True)


def test_p4_notifies_before_requesting_mtu_and_reports_payload_mtu(monkeypatch):
    service = FakeService(
        "0000fd50-0000-1000-8000-00805f9b34fb",
        [FakeCharacteristic("00000001-0000-1001-8001-00805f9b07d0", ["write"]),
         FakeCharacteristic("00000002-0000-1001-8001-00805f9b07d0", ["notify"])])
    client = FakeClient("scooter", [service])
    install_bleak(monkeypatch, client)
    transport = YouFsTransport(protocol_type=413)

    asyncio.run(transport.connect("scooter"))

    assert client.events == ["notify", ("mtu", 246)]
    assert transport.requested_mtu == 246
    assert transport.mtu == 246
    assert transport.payload_mtu == 243
    assert transport.mtu_request_supported is True


def test_attach_connected_client_validates_notifies_and_takes_disconnect_ownership():
    service = FakeService(
        "0000fd50-0000-1000-8000-00805f9b34fb",
        [FakeCharacteristic("00000001-0000-1001-8001-00805f9b07d0", ["write"]),
         FakeCharacteristic("00000002-0000-1001-8001-00805f9b07d0", ["notify"])])
    write, notify = service.characteristics
    client = FakeClient("scan-time-device", [service])
    client.is_connected = True
    transport = YouFsTransport()

    asyncio.run(transport.attach_connected_client(
        client, service_uuid=service.uuid, write_uuid=write.uuid,
        notify_uuid=notify.uuid, protocol_type=413))

    assert client.connect_calls == 0
    assert transport.is_connected and transport.notify_ready
    assert client.subscriptions == [notify]
    assert client.events == ["notify", ("mtu", 246)]
    assert transport.mtu == 246
    assert transport.payload_mtu == 243
    assert transport.requested_mtu == 246
    assert transport.mtu_request_supported is True
    assert transport.write_uuid == write.uuid

    asyncio.run(transport.disconnect())
    assert client.events[-2:] == [("stop_notify", notify), "disconnect"]
    assert client.disconnect_calls == 1
    assert not transport.is_connected


def test_attach_failure_keeps_client_caller_owned_and_cleans_notify_attempt():
    service, _, notify = tree()
    client = FakeClient("scan-time-device", [service],
                        start_notify_error=OSError("notify rejected"))
    client.is_connected = True
    transport = YouFsTransport()

    with pytest.raises(TransportError) as caught:
        asyncio.run(transport.attach_connected_client(
            client, service_uuid="a000", write_uuid="a001", notify_uuid="a002"))

    assert caught.value.layer == "notification-subscription"
    assert client.connect_calls == 0
    assert client.is_connected  # caller still owns the existing connection
    assert client.disconnect_calls == 0
    assert client.events == ["notify", ("stop_notify", notify)]
    assert not transport.is_connected
    assert not transport.notify_ready


def test_attach_rejects_disconnected_client_without_connecting():
    service, write, notify = tree()
    client = FakeClient("scan-time-device", [service])
    transport = YouFsTransport()

    with pytest.raises(TransportError, match="not connected"):
        asyncio.run(transport.attach_connected_client(
            client, service_uuid="a000", write_uuid="a001", notify_uuid="a002"))

    assert client.connect_calls == 0
    assert client.disconnect_calls == 0
    assert not transport.is_connected


def test_inspect_connected_client_does_not_take_ownership_or_disconnect():
    service, _, _ = tree()
    client = FakeClient("scan-time-device", [service])
    client.is_connected = True
    transport = YouFsTransport()

    tree_text, candidates = transport.inspect_connected_client(client)

    assert "service a000" in tree_text
    assert candidates == [("a000", "a001", "a002")]
    assert transport._client is None
    assert client.is_connected
    assert client.connect_calls == client.disconnect_calls == 0


def test_connect_passes_scan_time_ble_device_directly_to_bleak(monkeypatch):
    service, _, _ = tree()
    client = FakeClient("scooter", [service])
    install_bleak(monkeypatch, client)
    ble_device = types.SimpleNamespace(address="AA:BB:CC:DD:EE:FF")
    transport = YouFsTransport(service_uuid="a000", write_uuid="a001", notify_uuid="a002")

    asyncio.run(transport.connect(ble_device))

    assert client.input_device is ble_device


def test_p1_profile_allows_gatt_but_refuses_unimplemented_encoder(monkeypatch):
    service = FakeService(
        "00001910-0000-1000-8000-00805f9b34fb",
        [FakeCharacteristic("00002b11-0000-1000-8000-00805f9b34fb", ["write"]),
         FakeCharacteristic("00002b10-0000-1000-8000-00805f9b34fb", ["notify"])])
    client = FakeClient("scooter", [service])
    install_bleak(monkeypatch, client)
    transport = YouFsTransport(protocol_type=100)

    asyncio.run(transport.connect("scooter"))
    assert transport.notify_ready
    with pytest.raises(TransportError, match="no supported trsmitr"):
        asyncio.run(transport.send_frame(b"unsafe"))
    assert not client.writes


def test_p2_default_dispatch_is_observed_but_protocol_write_fails_closed(monkeypatch):
    service = FakeService(
        "00001910-0000-1000-8000-00805f9b34fb",
        [FakeCharacteristic("00002b11-0000-1000-8000-00805f9b34fb", ["write"]),
         FakeCharacteristic("00002b10-0000-1000-8000-00805f9b34fb", ["notify"])])
    client = FakeClient("scooter", [service])
    install_bleak(monkeypatch, client)
    transport = YouFsTransport(protocol_type=777)

    asyncio.run(transport.connect("scooter"))
    assert transport.notify_ready
    with pytest.raises(TransportError, match="no supported trsmitr"):
        asyncio.run(transport.send_frame(b"P2 not implemented"))
    assert not client.writes
