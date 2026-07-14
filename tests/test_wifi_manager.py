from __future__ import annotations

import asyncio
import time

import pytest

from moonraker.components import wifi_manager as wifi_module
from moonraker.components.wifi_manager import (
    NM_AP_FLAGS_PRIVACY,
    NM_AP_SEC_KEY_MGMT_802_1X,
    NM_AP_SEC_KEY_MGMT_PSK,
    NM_AP_IFACE,
    NM_DEVICE_IFACE,
    NM_IP4_IFACE,
    WifiFailure,
    WifiManager,
)


def network(ssid, strength, connected=False, saved=True):
    return {
        "ssid": ssid,
        "security": "wpa-psk",
        "strength": strength,
        "saved": saved,
        "connected": connected,
        "frequency": 2412,
    }


class FakeEventLoop:
    def create_task(self, coro):
        return asyncio.create_task(coro)


class FakeServer:
    def __init__(self):
        self.events = []
        self.warnings = []
        self.event_loop = FakeEventLoop()

    def get_event_loop(self):
        return self.event_loop

    def send_event(self, name, payload):
        self.events.append((name, payload))

    def error(self, message, status):
        return RuntimeError(message)

    def add_warning(self, message, warning_id):
        self.warnings.append((message, warning_id))


def manager_for_cache(networks=None):
    manager = WifiManager.__new__(WifiManager)
    manager.server = FakeServer()
    manager.interface = "wlp1s0"
    manager._networks = list(networks or [])
    manager._operation = None
    manager._last_error = None
    manager._operation_lock = asyncio.Lock()
    manager._snapshot_lock = asyncio.Lock()
    manager._watcher_lock = asyncio.Lock()
    manager._desired_ap_paths = set()
    manager._desired_ip4_path = None
    manager._operation_task = None
    manager._notify_task = None
    manager._refresh_pending = False
    manager._closed = False
    manager._property_handlers = []
    manager._signal_handlers = []
    manager._ap_property_handlers = {}
    manager._ip4_property_handler = None
    manager._interface_cache = {}
    return manager


@pytest.mark.parametrize(
    "password, valid",
    [
        ("1234567", False),
        ("12345678", True),
        (" password ", True),
        ("a" * 63, True),
        ("A0" * 32, True),
        ("g" * 64, False),
        ("密" * 21, True),
        ("密" * 22, False),
    ],
)
def test_valid_psk(password, valid):
    assert WifiManager._valid_psk(password) is valid


@pytest.mark.parametrize(
    "flags, wpa, rsn, security",
    [
        (0, 0, 0, "open"),
        (NM_AP_FLAGS_PRIVACY, 0, NM_AP_SEC_KEY_MGMT_PSK, "wpa-psk"),
        (NM_AP_FLAGS_PRIVACY, 0, 0, None),
        (NM_AP_FLAGS_PRIVACY, NM_AP_SEC_KEY_MGMT_802_1X, 0, None),
    ],
)
def test_classify_security(flags, wpa, rsn, security):
    assert WifiManager._classify_security(flags, wpa, rsn) == security


@pytest.mark.asyncio
async def test_saved_encrypted_network_does_not_downgrade(monkeypatch):
    manager = WifiManager.__new__(WifiManager)

    async def get_access_points():
        return [
            {
                "path": "/open",
                "ssid": "Factory",
                "security": "open",
                "strength": 99,
                "frequency": 2412,
            },
            {
                "path": "/secure",
                "ssid": "Factory",
                "security": "wpa-psk",
                "strength": 60,
                "frequency": 2437,
            },
        ]

    async def get_saved_profiles():
        return [
            {"path": "/open-profile", "ssid": "Factory", "security": "open"},
            {"path": "/secure-profile", "ssid": "Factory", "security": "wpa-psk"},
        ]

    async def get_status():
        return {"ssid": None, "connected": False}

    monkeypatch.setattr(manager, "_get_access_points", get_access_points)
    monkeypatch.setattr(manager, "_get_saved_profiles", get_saved_profiles)
    monkeypatch.setattr(manager, "_get_status", get_status)

    networks = await manager._read_networks()

    assert networks == [{
        "ssid": "Factory",
        "security": "wpa-psk",
        "strength": 60,
        "saved": True,
        "connected": False,
        "frequency": 2437,
    }]


def test_profile_path_index_orders_numeric_networkmanager_paths():
    assert WifiManager._profile_path_index(
        "/org/freedesktop/NetworkManager/Settings/12"
    ) > WifiManager._profile_path_index(
        "/org/freedesktop/NetworkManager/Settings/9"
    )
    assert WifiManager._profile_path_index("/invalid") == -1


@pytest.mark.asyncio
async def test_status_event_reconciles_networks_and_emits_atomic_snapshot(
    monkeypatch,
):
    manager = manager_for_cache([
        network("Factory-A", 80, connected=True),
        network("Factory-B", 55),
    ])
    status = {
        "available": True,
        "state": "connected",
        "connected": True,
        "ssid": "Factory-B",
        "strength": 72,
        "ip_address": "192.0.2.10",
    }

    async def read_status():
        return dict(status)

    monkeypatch.setattr(manager, "_read_status", read_status)

    await manager._emit_status()

    assert [name for name, _ in manager.server.events] == [
        "machine:wifi_state_changed",
        "machine:wifi_networks_changed",
    ]
    snapshot = manager.server.events[1][1]
    assert snapshot["status"] == status
    assert [item["ssid"] for item in snapshot["networks"]] == [
        "Factory-B",
        "Factory-A",
    ]
    assert snapshot["networks"][0]["connected"] is True
    assert snapshot["networks"][0]["strength"] == 72
    assert snapshot["networks"][1]["connected"] is False


@pytest.mark.asyncio
async def test_successful_operation_can_force_unchanged_snapshot(monkeypatch):
    manager = manager_for_cache([
        network("Factory-A", 70, connected=True),
    ])
    status = {
        "connected": True,
        "ssid": "Factory-A",
        "strength": 70,
    }

    async def read_status():
        return dict(status)

    monkeypatch.setattr(manager, "_read_status", read_status)

    await manager._emit_status(force_snapshot=True)

    assert [name for name, _ in manager.server.events] == [
        "machine:wifi_state_changed",
        "machine:wifi_networks_changed",
    ]


def test_disconnected_status_clears_all_cached_connected_flags():
    manager = manager_for_cache([
        network("Factory-A", 70, connected=True),
        network("Factory-B", 60),
    ])

    changed = manager._reconcile_networks({
        "connected": False,
        "ssid": None,
        "strength": None,
    })

    assert changed is True
    assert not any(item["connected"] for item in manager._networks)


@pytest.mark.asyncio
async def test_scan_cooldown_rebuilds_networkmanager_cache(monkeypatch):
    manager = manager_for_cache([
        network("Factory-A", 80, connected=True),
    ])
    manager._last_scan_at = time.monotonic()
    manager._permissions = {"scan": True}
    read_count = 0
    status = {
        "connected": True,
        "ssid": "Factory-B",
        "strength": 65,
    }

    async def read_status():
        return dict(status)

    async def read_networks(received_status=None):
        nonlocal read_count
        read_count += 1
        assert received_status == status
        return [network("Factory-B", 65, connected=True)]

    monkeypatch.setattr(manager, "_check_local", lambda request: None)
    monkeypatch.setattr(manager, "_ensure_available", lambda: None)
    monkeypatch.setattr(manager, "_read_status", read_status)
    monkeypatch.setattr(manager, "_read_networks", read_networks)

    result = await manager._handle_scan(object())

    assert read_count == 1
    assert result == {
        "status": status,
        "networks": [network("Factory-B", 65, connected=True)],
    }


@pytest.mark.asyncio
async def test_passive_cache_uses_active_ap_strength(monkeypatch):
    manager = manager_for_cache([
        network("Factory-A", 40, connected=True),
    ])
    status = {
        "connected": True,
        "ssid": "Factory-A",
        "strength": 62,
    }

    async def read_status():
        return dict(status)

    async def read_networks(received_status=None):
        assert received_status == status
        # A stronger BSSID with the same SSID may be visible while the active
        # connection is still associated with the weaker access point.
        return [network("Factory-A", 88, connected=True)]

    monkeypatch.setattr(manager, "_read_status", read_status)
    monkeypatch.setattr(manager, "_read_networks", read_networks)

    result = await manager._refresh_network_snapshot(
        emit=True, preserve_on_failure=True
    )

    assert result["status"] == status
    assert result["networks"] == [
        network("Factory-A", 62, connected=True)
    ]
    assert manager.server.events[-1] == (
        "machine:wifi_networks_changed", result
    )


@pytest.mark.asyncio
async def test_scan_timestamp_updates_only_after_last_scan_changes(monkeypatch):
    manager = WifiManager.__new__(WifiManager)
    manager._last_scan_at = 0.0

    class SuccessfulWifi:
        def __init__(self):
            self.values = iter((10, 11))

        async def get_last_scan(self):
            return next(self.values)

        async def call_request_scan(self, options):
            return None

    async def no_sleep(delay):
        return None

    manager.wifi = SuccessfulWifi()
    monkeypatch.setattr(wifi_module.asyncio, "sleep", no_sleep)
    await manager._request_scan()
    assert manager._last_scan_at > 0

    class TimedOutWifi:
        async def get_last_scan(self):
            return 20

        async def call_request_scan(self, options):
            return None

    manager.wifi = TimedOutWifi()
    manager._last_scan_at = 123.0
    monkeypatch.setattr(wifi_module, "SCAN_TIMEOUT", 0.0)
    with pytest.raises(WifiFailure, match="Timed out"):
        await manager._request_scan()
    assert manager._last_scan_at == 123.0


@pytest.mark.asyncio
async def test_signals_coalesce_and_defer_during_operation(monkeypatch):
    manager = manager_for_cache()
    refreshes = 0

    async def refresh_snapshot(*, emit, preserve_on_failure):
        nonlocal refreshes
        refreshes += 1
        return {"status": {}, "networks": []}

    monkeypatch.setattr(
        manager, "_refresh_network_snapshot_locked", refresh_snapshot
    )
    monkeypatch.setattr(wifi_module, "PASSIVE_REFRESH_DELAY", .01)

    manager._on_properties_changed(NM_DEVICE_IFACE, {}, [])
    manager._on_access_point_added("/ap/1")
    manager._on_connection_added("/profile/1")
    manager._on_ipv4_properties_changed(NM_IP4_IFACE, {}, [])
    await asyncio.sleep(.03)
    assert refreshes == 1

    await manager._operation_lock.acquire()
    manager._on_properties_changed(NM_DEVICE_IFACE, {}, [])
    manager._on_access_point_added("/ap/2")
    await asyncio.sleep(.02)
    assert refreshes == 1
    assert manager._refresh_pending is True
    manager._operation_lock.release()
    manager._resume_pending_refresh()
    await asyncio.sleep(.03)
    assert refreshes == 2


@pytest.mark.asyncio
async def test_passive_refresh_rechecks_busy_after_waiting_for_snapshot_lock(
    monkeypatch,
):
    manager = manager_for_cache()
    refreshes = 0
    operation_release = asyncio.Event()

    async def refresh_snapshot(*, emit, preserve_on_failure):
        nonlocal refreshes
        refreshes += 1
        return {"status": {}, "networks": []}

    async def operation():
        await operation_release.wait()

    monkeypatch.setattr(
        manager, "_refresh_network_snapshot_locked", refresh_snapshot
    )
    monkeypatch.setattr(wifi_module, "PASSIVE_REFRESH_DELAY", 0.0)

    await manager._snapshot_lock.acquire()
    manager._schedule_notification()
    notify_task = manager._notify_task
    assert notify_task is not None
    await asyncio.sleep(0)
    await asyncio.sleep(0)

    operation_task = asyncio.create_task(operation())
    manager._operation_task = operation_task
    manager._snapshot_lock.release()
    await notify_task

    assert refreshes == 0
    assert manager._refresh_pending is True

    operation_release.set()
    await operation_task
    manager._operation_task = None


@pytest.mark.asyncio
async def test_connect_is_not_announced_until_inflight_snapshot_finishes(
    monkeypatch,
):
    manager = manager_for_cache()
    manager._permissions = {
        "network": True,
        "settings": True,
        "checkpoint": True,
    }
    operation_started = asyncio.Event()
    operation_release = asyncio.Event()

    class Request:
        def get_args(self):
            return {
                "ssid": "Factory-A",
                "security": "wpa-psk",
                "password": "password",
            }

    async def emit_status(force_snapshot=False):
        return None

    async def run_connect(ssid, security, password):
        operation_started.set()
        await operation_release.wait()

    monkeypatch.setattr(manager, "_check_local", lambda request: None)
    monkeypatch.setattr(manager, "_ensure_available", lambda: None)
    monkeypatch.setattr(manager, "_emit_status", emit_status)
    monkeypatch.setattr(manager, "_run_connect", run_connect)

    await manager._snapshot_lock.acquire()
    request_task = asyncio.create_task(manager._handle_connect(Request()))
    await asyncio.sleep(0)
    assert manager._operation is None
    assert operation_started.is_set() is False

    manager._snapshot_lock.release()
    result = await request_task
    await operation_started.wait()

    assert result["operation_id"] == manager._operation["id"]
    operation_release.set()
    assert manager._operation_task is not None
    await manager._operation_task


@pytest.mark.asyncio
async def test_status_poll_remains_responsive_during_serialized_operation(
    monkeypatch,
):
    manager = manager_for_cache([
        network("Factory-A", 70, connected=True),
    ])
    operation_release = asyncio.Event()
    status = {
        "connected": True,
        "ssid": "Factory-B",
        "strength": 60,
    }

    async def operation():
        await operation_release.wait()

    async def read_status():
        return dict(status)

    monkeypatch.setattr(manager, "_check_local", lambda request: None)
    monkeypatch.setattr(manager, "_read_status", read_status)

    await manager._snapshot_lock.acquire()
    operation_task = asyncio.create_task(operation())
    manager._operation_task = operation_task

    result = await asyncio.wait_for(
        manager._handle_status(object()), timeout=.1
    )

    assert result == status
    assert manager._networks == [
        network("Factory-A", 70, connected=True)
    ]
    assert manager.server.events == []

    operation_release.set()
    await operation_task
    manager._operation_task = None
    manager._snapshot_lock.release()


@pytest.mark.asyncio
async def test_unexpected_operation_exception_is_retrieved_and_reported(
    monkeypatch, caplog,
):
    manager = manager_for_cache()
    manager._operation = {
        "id": "operation-id",
        "type": "connect",
        "ssid": "Factory-A",
        "state": "running",
    }
    scheduled = 0

    async def fail_operation():
        raise RuntimeError("unexpected worker failure")

    def schedule_notification():
        nonlocal scheduled
        scheduled += 1

    monkeypatch.setattr(manager, "_schedule_notification", schedule_notification)
    task = asyncio.create_task(fail_operation())
    manager._operation_task = task
    with pytest.raises(RuntimeError, match="unexpected worker failure"):
        await task

    manager._on_operation_done(task)

    assert manager._operation_task is None
    assert manager._operation["state"] == "failed"
    assert manager._last_error == {
        "code": "internal_error",
        "message": "NetworkManager could not complete the operation",
        "recovered_ssid": None,
    }
    assert scheduled == 1
    assert "Unexpected Wi-Fi operation failure" in caplog.text


@pytest.mark.asyncio
async def test_cancelled_or_closed_operation_does_not_create_failure(
    monkeypatch, caplog,
):
    manager = manager_for_cache()
    manager._operation = {
        "id": "operation-id",
        "type": "connect",
        "ssid": "Factory-A",
        "state": "running",
    }
    scheduled = 0
    release = asyncio.Event()

    async def wait_operation():
        await release.wait()

    def schedule_notification():
        nonlocal scheduled
        scheduled += 1

    monkeypatch.setattr(manager, "_schedule_notification", schedule_notification)
    cancelled_task = asyncio.create_task(wait_operation())
    manager._operation_task = cancelled_task
    cancelled_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await cancelled_task
    manager._on_operation_done(cancelled_task)

    assert manager._operation["state"] == "running"
    assert manager._last_error is None
    assert scheduled == 0

    async def fail_during_close():
        raise RuntimeError("shutdown race")

    closed_task = asyncio.create_task(fail_during_close())
    manager._operation_task = closed_task
    manager._closed = True
    with pytest.raises(RuntimeError, match="shutdown race"):
        await closed_task
    manager._on_operation_done(closed_task)

    assert manager._operation["state"] == "running"
    assert manager._last_error is None
    assert scheduled == 0
    assert "shutdown race" not in caplog.text


@pytest.mark.asyncio
async def test_passive_refresh_failure_preserves_cache_and_error(monkeypatch):
    original_error = {
        "code": "invalid_password",
        "message": "bad password",
        "recovered_ssid": "Factory-A",
    }
    manager = manager_for_cache([
        network("Factory-A", 40, connected=True),
    ])
    manager._last_error = dict(original_error)
    status = {
        "connected": True,
        "ssid": "Factory-A",
        "strength": 75,
    }

    async def read_status():
        return dict(status)

    async def fail_read(received_status=None):
        raise RuntimeError("access point disappeared")

    monkeypatch.setattr(manager, "_read_status", read_status)
    monkeypatch.setattr(manager, "_read_networks", fail_read)

    result = await manager._refresh_network_snapshot(
        emit=True, preserve_on_failure=True
    )

    assert manager._last_error == original_error
    assert result["networks"] == [network(
        "Factory-A", 75, connected=True
    )]
    assert manager.server.events[-1][0] == "machine:wifi_networks_changed"


def test_new_connected_ssid_is_not_fabricated_in_stale_cache():
    manager = manager_for_cache([
        network("Factory-A", 40, connected=True),
    ])

    manager._reconcile_networks({
        "connected": True,
        "ssid": "Factory-B",
        "strength": 90,
    })

    assert manager._networks == [network(
        "Factory-A", 40, connected=False
    )]


@pytest.mark.asyncio
async def test_transient_interfaces_are_never_added_to_cache():
    manager = WifiManager.__new__(WifiManager)
    manager._interface_cache = {}

    class FakeDbusManager:
        def __init__(self):
            self.calls = []

        async def get_interface(self, bus, path, interface):
            result = object()
            self.calls.append((bus, path, interface, result))
            return result

    manager.dbus_mgr = FakeDbusManager()

    first = await manager._get_transient_interface("/ap/1", NM_AP_IFACE)
    second = await manager._get_transient_interface("/ap/1", NM_AP_IFACE)

    assert first is not second
    assert manager._interface_cache == {}
    assert len(manager.dbus_mgr.calls) == 2


@pytest.mark.asyncio
async def test_access_point_read_propagates_non_removal_failure(monkeypatch):
    manager = manager_for_cache()

    class FakeWifi:
        async def call_get_all_access_points(self):
            return ["/ap/removed", "/ap/broken"]

    async def sync_watchers(paths):
        return None

    async def get_interface(path, interface):
        if path == "/ap/removed":
            raise RuntimeError("Unknown object")
        raise RuntimeError("D-Bus transport disconnected")

    manager.wifi = FakeWifi()
    monkeypatch.setattr(manager, "_ensure_available", lambda: None)
    monkeypatch.setattr(manager, "_sync_access_point_watchers", sync_watchers)
    monkeypatch.setattr(manager, "_get_transient_interface", get_interface)

    with pytest.raises(RuntimeError, match="transport disconnected"):
        await manager._get_access_points()


@pytest.mark.asyncio
async def test_superseded_access_point_watcher_is_not_installed():
    manager = manager_for_cache()
    old_requested = asyncio.Event()
    release_old = asyncio.Event()

    class FakeProperties:
        def __init__(self):
            self.added = []
            self.removed = []

        def on_properties_changed(self, callback):
            self.added.append(callback)

        def off_properties_changed(self, callback):
            self.removed.append(callback)

    old_props = FakeProperties()
    new_props = FakeProperties()

    class FakeDbusManager:
        async def get_interface(self, bus, path, interface):
            if path == "/ap/old":
                old_requested.set()
                await release_old.wait()
                return old_props
            assert path == "/ap/new"
            return new_props

    manager.dbus_mgr = FakeDbusManager()

    old_task = asyncio.create_task(
        manager._sync_access_point_watchers(["/ap/old"])
    )
    await old_requested.wait()
    new_task = asyncio.create_task(
        manager._sync_access_point_watchers(["/ap/new"])
    )
    await asyncio.sleep(0)
    assert manager._desired_ap_paths == {"/ap/new"}

    release_old.set()
    await asyncio.gather(old_task, new_task)

    assert old_props.added == []
    assert len(new_props.added) == 1
    assert set(manager._ap_property_handlers) == {"/ap/new"}


@pytest.mark.asyncio
async def test_removed_access_point_is_not_watched_after_inflight_lookup():
    manager = manager_for_cache()
    interface_requested = asyncio.Event()
    release_interface = asyncio.Event()

    class FakeProperties:
        def __init__(self):
            self.added = []

        def on_properties_changed(self, callback):
            self.added.append(callback)

    props = FakeProperties()

    class FakeDbusManager:
        async def get_interface(self, bus, path, interface):
            interface_requested.set()
            await release_interface.wait()
            return props

    manager.dbus_mgr = FakeDbusManager()
    await manager._operation_lock.acquire()
    watcher_task = asyncio.create_task(
        manager._sync_access_point_watchers(["/ap/removed"])
    )
    await interface_requested.wait()

    manager._on_access_point_removed("/ap/removed")
    release_interface.set()
    await watcher_task
    manager._operation_lock.release()

    assert props.added == []
    assert manager._ap_property_handlers == {}


@pytest.mark.asyncio
async def test_superseded_ipv4_watcher_is_removed_without_leaking_handler():
    manager = manager_for_cache()
    old_requested = asyncio.Event()
    release_old = asyncio.Event()

    class FakeProperties:
        def __init__(self):
            self.added = []
            self.removed = []

        def on_properties_changed(self, callback):
            self.added.append(callback)

        def off_properties_changed(self, callback):
            self.removed.append(callback)

    previous_props = FakeProperties()
    stale_props = FakeProperties()
    current_props = FakeProperties()
    previous_callback = object()
    manager._ip4_property_handler = (
        "/ip4/previous", previous_props, previous_callback
    )

    class FakeDbusManager:
        async def get_interface(self, bus, path, interface):
            if path == "/ip4/stale":
                old_requested.set()
                await release_old.wait()
                return stale_props
            assert path == "/ip4/current"
            return current_props

    manager.dbus_mgr = FakeDbusManager()

    stale_task = asyncio.create_task(
        manager._sync_ipv4_watcher("/ip4/stale")
    )
    await old_requested.wait()
    current_task = asyncio.create_task(
        manager._sync_ipv4_watcher("/ip4/current")
    )
    await asyncio.sleep(0)
    assert manager._desired_ip4_path == "/ip4/current"

    release_old.set()
    await asyncio.gather(stale_task, current_task)

    assert previous_props.removed == [previous_callback]
    assert stale_props.added == []
    assert len(current_props.added) == 1
    assert manager._ip4_property_handler is not None
    assert manager._ip4_property_handler[0] == "/ip4/current"


@pytest.mark.asyncio
async def test_close_prevents_inflight_watcher_installation():
    manager = manager_for_cache()
    interface_requested = asyncio.Event()
    release_interface = asyncio.Event()

    class FakeProperties:
        def __init__(self):
            self.added = []

        def on_properties_changed(self, callback):
            self.added.append(callback)

        def off_properties_changed(self, callback):
            pass

    props = FakeProperties()

    class FakeDbusManager:
        async def get_interface(self, bus, path, interface):
            interface_requested.set()
            await release_interface.wait()
            return props

    manager.dbus_mgr = FakeDbusManager()

    watcher_task = asyncio.create_task(
        manager._sync_ipv4_watcher("/ip4/closing")
    )
    await interface_requested.wait()
    close_task = asyncio.create_task(manager.close())
    await asyncio.sleep(0)
    assert manager._closed is True

    release_interface.set()
    await asyncio.gather(watcher_task, close_task)

    assert props.added == []
    assert manager._ip4_property_handler is None


@pytest.mark.asyncio
async def test_component_init_failure_removes_partially_installed_handlers(
    monkeypatch,
):
    manager = manager_for_cache()
    manager.nm = None
    manager.settings = None
    manager.device = None
    manager.wifi = None
    manager.device_path = None
    manager._permissions = {
        "scan": False,
        "network": False,
        "settings": False,
        "checkpoint": False,
    }

    class FakeDbusManager:
        def is_connected(self):
            return True

        async def check_permission(self, action, message):
            return True

    class FakeInterface:
        def __init__(self):
            self.added = []
            self.removed = []

        async def call_get_device_by_ip_iface(self, interface):
            return "/device/wifi"

        def on_properties_changed(self, callback):
            self.added.append(("properties_changed", callback))

        def off_properties_changed(self, callback):
            self.removed.append(("properties_changed", callback))

        def on_access_point_added(self, callback):
            self.added.append(("access_point_added", callback))

        def off_access_point_added(self, callback):
            self.removed.append(("access_point_added", callback))

        def on_access_point_removed(self, callback):
            self.added.append(("access_point_removed", callback))

        def off_access_point_removed(self, callback):
            self.removed.append(("access_point_removed", callback))

        def on_new_connection(self, callback):
            self.added.append(("new_connection", callback))

        def off_new_connection(self, callback):
            self.removed.append(("new_connection", callback))

        def on_connection_removed(self, callback):
            self.added.append(("connection_removed", callback))

        def off_connection_removed(self, callback):
            self.removed.append(("connection_removed", callback))

    nm = FakeInterface()
    settings = FakeInterface()
    device = FakeInterface()
    wifi = FakeInterface()
    root_props = FakeInterface()
    device_props = FakeInterface()
    ap_props = FakeInterface()
    ip4_props = FakeInterface()
    interfaces = iter((
        nm, settings, device, wifi, root_props, device_props,
    ))
    ap_callback = object()
    ip4_callback = object()
    manager._ap_property_handlers = {
        "/ap/partial": (ap_props, ap_callback),
    }
    manager._ip4_property_handler = (
        "/ip4/partial", ip4_props, ip4_callback
    )
    manager._interface_cache = {("/partial", "iface"): object()}
    manager.dbus_mgr = FakeDbusManager()

    async def get_interface(path, interface):
        return next(interfaces)

    async def fail_initial_snapshot(*, emit, preserve_on_failure):
        raise RuntimeError("initial snapshot failed")

    monkeypatch.setattr(manager, "_get_interface", get_interface)
    monkeypatch.setattr(
        manager, "_refresh_network_snapshot", fail_initial_snapshot
    )

    await manager.component_init()

    assert manager._closed is True
    assert manager.nm is None
    assert manager.settings is None
    assert manager.device is None
    assert manager.wifi is None
    assert manager.device_path is None
    assert root_props.removed == root_props.added
    assert device_props.removed == device_props.added
    assert sorted(name for name, _ in wifi.removed) == [
        "access_point_added", "access_point_removed",
    ]
    assert sorted(name for name, _ in settings.removed) == [
        "connection_removed", "new_connection",
    ]
    assert ap_props.removed == [("properties_changed", ap_callback)]
    assert ip4_props.removed == [("properties_changed", ip4_callback)]
    assert manager._property_handlers == []
    assert manager._signal_handlers == []
    assert manager._ap_property_handlers == {}
    assert manager._ip4_property_handler is None
    assert manager._interface_cache == {}
    assert manager.server.warnings[-1][1] == "wifi_manager_adapter"


@pytest.mark.asyncio
async def test_close_unsubscribes_all_signals_and_clears_cache():
    manager = manager_for_cache()

    class FakeProperties:
        def __init__(self):
            self.removed = []

        def off_properties_changed(self, callback):
            self.removed.append(callback)

    class FakeSignals:
        def __init__(self):
            self.removed = []

        def off_access_point_added(self, callback):
            self.removed.append(callback)

    root_props = FakeProperties()
    ap_props = FakeProperties()
    ip4_props = FakeProperties()
    signals = FakeSignals()
    root_callback = object()
    ap_callback = object()
    signal_callback = object()
    manager._property_handlers = [(root_props, root_callback)]
    manager._ap_property_handlers = {
        "/ap/1": (ap_props, ap_callback),
    }
    manager._ip4_property_handler = (
        "/ip4/1", ip4_props, ap_callback
    )
    manager._signal_handlers = [(
        signals, "off_access_point_added", signal_callback
    )]
    manager._interface_cache = {("/device", NM_DEVICE_IFACE): object()}

    await manager.close()

    assert root_props.removed == [root_callback]
    assert ap_props.removed == [ap_callback]
    assert ip4_props.removed == [ap_callback]
    assert signals.removed == [signal_callback]
    assert manager._property_handlers == []
    assert manager._ap_property_handlers == {}
    assert manager._ip4_property_handler is None
    assert manager._signal_handlers == []
    assert manager._interface_cache == {}
    manager._on_access_point_added("/ap/after-close")
    await manager._sync_access_point_watchers(["/ap/after-close"])
    await manager._sync_ipv4_watcher("/ip4/after-close")
    assert manager._desired_ap_paths == set()
    assert manager._desired_ip4_path is None
