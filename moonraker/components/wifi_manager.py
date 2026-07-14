# Direct NetworkManager Wi-Fi control for local touchscreen clients
#
# Copyright (C) 2026 Infinity3DP
#
# This file may be distributed under the terms of the GNU GPLv3 license.

from __future__ import annotations

import asyncio
import logging
import time
import uuid

from dbus_fast import Variant

from ..common import RequestType

# Annotation imports
from typing import (
    TYPE_CHECKING,
    Any,
    Dict,
    List,
    NoReturn,
    Optional,
    Set,
    Tuple,
)

if TYPE_CHECKING:
    from ..common import WebRequest
    from ..confighelper import ConfigHelper
    from .dbus_manager import DbusManager
    from dbus_fast.aio.proxy_object import ProxyInterface


NM_BUS = "org.freedesktop.NetworkManager"
NM_PATH = "/org/freedesktop/NetworkManager"
NM_IFACE = "org.freedesktop.NetworkManager"
NM_SETTINGS_PATH = f"{NM_PATH}/Settings"
NM_SETTINGS_IFACE = f"{NM_IFACE}.Settings"
NM_CONNECTION_IFACE = f"{NM_SETTINGS_IFACE}.Connection"
NM_DEVICE_IFACE = f"{NM_IFACE}.Device"
NM_WIFI_IFACE = f"{NM_DEVICE_IFACE}.Wireless"
NM_AP_IFACE = f"{NM_IFACE}.AccessPoint"
NM_IP4_IFACE = f"{NM_IFACE}.IP4Config"
NM_ACTIVE_IFACE = f"{NM_IFACE}.Connection.Active"
DBUS_PROPERTIES_IFACE = "org.freedesktop.DBus.Properties"

NM_DEVICE_STATE_UNAVAILABLE = 20
NM_DEVICE_STATE_DISCONNECTED = 30
NM_DEVICE_STATE_NEED_AUTH = 60
NM_DEVICE_STATE_ACTIVATED = 100
NM_DEVICE_STATE_FAILED = 120

NM_ACTIVE_CONNECTION_STATE_ACTIVATED = 2
NM_ACTIVE_CONNECTION_STATE_DEACTIVATED = 4

NM_AP_FLAGS_PRIVACY = 0x1
NM_AP_SEC_KEY_MGMT_PSK = 0x100
NM_AP_SEC_KEY_MGMT_802_1X = 0x200
NM_AP_SEC_KEY_MGMT_SAE = 0x400
NM_AP_SEC_KEY_MGMT_OWE = 0x800

NM_CHECKPOINT_DELETE_NEW_CONNECTIONS = 0x2

SCAN_INTERVAL = 10.0
SCAN_TIMEOUT = 5.0
CONNECT_TIMEOUT = 30.0
CHECKPOINT_TIMEOUT = 45
RECOVERY_TIMEOUT = 15.0
PASSIVE_REFRESH_DELAY = .25

CONNECTIVITY_STATES = {
    0: "unknown",
    1: "none",
    2: "portal",
    3: "limited",
    4: "full",
}

# NetworkManager reasons most commonly associated with failed PSK auth.
AUTH_FAILURE_REASONS = {7, 8, 9, 10, 11}

ERROR_HTTP_STATUS = {
    "busy": 409,
    "invalid_request": 400,
    "invalid_password": 400,
    "network_not_found": 404,
    "network_not_saved": 404,
    "unsupported_security": 400,
    "timeout": 504,
    "adapter_unavailable": 503,
    "permission_denied": 403,
    "rollback_failed": 500,
    "internal_error": 500,
}


class WifiFailure(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class WifiManager:
    def __init__(self, config: ConfigHelper) -> None:
        self.server = config.get_server()
        self.interface = config.get("interface", "wlp1s0")
        self.dbus_mgr: DbusManager = self.server.lookup_component("dbus_manager")

        self.nm: Optional[ProxyInterface] = None
        self.settings: Optional[ProxyInterface] = None
        self.device: Optional[ProxyInterface] = None
        self.wifi: Optional[ProxyInterface] = None
        self.device_path: Optional[str] = None

        self._interface_cache: Dict[Tuple[str, str], ProxyInterface] = {}
        self._property_handlers: List[Tuple[ProxyInterface, Any]] = []
        self._signal_handlers: List[Tuple[ProxyInterface, str, Any]] = []
        self._ap_property_handlers: Dict[
            str, Tuple[ProxyInterface, Any]
        ] = {}
        self._ip4_property_handler: Optional[
            Tuple[str, ProxyInterface, Any]
        ] = None
        self._operation_lock = asyncio.Lock()
        self._snapshot_lock = asyncio.Lock()
        self._watcher_lock = asyncio.Lock()
        self._desired_ap_paths: Set[str] = set()
        self._desired_ip4_path: Optional[str] = None
        self._operation_task: Optional[asyncio.Task] = None
        self._notify_task: Optional[asyncio.Task] = None
        self._refresh_pending = False
        self._closed = False
        self._last_scan_at = 0.0
        self._networks: List[Dict[str, Any]] = []
        self._operation: Optional[Dict[str, Any]] = None
        self._last_error: Optional[Dict[str, Any]] = None
        self._permissions: Dict[str, bool] = {
            "scan": False,
            "network": False,
            "settings": False,
            "checkpoint": False,
        }

        self.server.register_endpoint(
            "/machine/wifi/status", RequestType.GET, self._handle_status
        )
        self.server.register_endpoint(
            "/machine/wifi/scan", RequestType.POST, self._handle_scan
        )
        self.server.register_endpoint(
            "/machine/wifi/connect", RequestType.POST, self._handle_connect
        )
        self.server.register_endpoint(
            "/machine/wifi/forget", RequestType.POST, self._handle_forget
        )
        self.server.register_notification(
            "machine:wifi_state_changed", local_only=True
        )
        self.server.register_notification(
            "machine:wifi_networks_changed", local_only=True
        )

    async def component_init(self) -> None:
        if not self.dbus_mgr.is_connected():
            self.server.add_warning(
                "[wifi_manager]: D-Bus is unavailable; Wi-Fi control is disabled",
                "wifi_manager_dbus"
            )
            return
        try:
            self._permissions["scan"] = await self.dbus_mgr.check_permission(
                "org.freedesktop.NetworkManager.wifi.scan",
                "Local Wi-Fi scanning will be disabled"
            )
            self._permissions["network"] = await self.dbus_mgr.check_permission(
                "org.freedesktop.NetworkManager.network-control",
                "Local Wi-Fi connection control will be disabled"
            )
            self._permissions["settings"] = await self.dbus_mgr.check_permission(
                "org.freedesktop.NetworkManager.settings.modify.system",
                "Saving and forgetting Wi-Fi networks will be disabled"
            )
            self._permissions["checkpoint"] = await self.dbus_mgr.check_permission(
                "org.freedesktop.NetworkManager.checkpoint-rollback",
                "Safe Wi-Fi connection rollback will be disabled"
            )
            self.nm = await self._get_interface(NM_PATH, NM_IFACE)
            self.settings = await self._get_interface(
                NM_SETTINGS_PATH, NM_SETTINGS_IFACE
            )
            get_device = self.nm.call_get_device_by_ip_iface  # type: ignore
            self.device_path = await get_device(self.interface)
            assert self.device_path is not None
            self.device = await self._get_interface(
                self.device_path, NM_DEVICE_IFACE
            )
            self.wifi = await self._get_interface(self.device_path, NM_WIFI_IFACE)
            await self._watch_properties(NM_PATH)
            await self._watch_properties(self.device_path)
            self._watch_signal(
                self.wifi, "access_point_added", self._on_access_point_added
            )
            self._watch_signal(
                self.wifi, "access_point_removed", self._on_access_point_removed
            )
            self._watch_signal(
                self.settings, "new_connection", self._on_connection_added
            )
            self._watch_signal(
                self.settings,
                "connection_removed",
                self._on_connection_removed,
            )
            await self._refresh_network_snapshot(
                emit=False, preserve_on_failure=True
            )
        except asyncio.CancelledError:
            raise
        except Exception as err:
            # Initialization is not retried.  Stop callbacks before disabling
            # the adapter so a partially installed signal set cannot continue
            # scheduling work for the lifetime of the component.
            self._closed = True
            notify_task = self._notify_task
            if notify_task is not None:
                if not notify_task.done():
                    notify_task.cancel()
                try:
                    await notify_task
                except (asyncio.CancelledError, Exception):
                    pass
            await self._remove_dbus_handlers()
            logging.info(
                "[wifi_manager]: Unable to initialize NetworkManager adapter %s: %s",
                self.interface, self._safe_dbus_message(err)
            )
            self.nm = self.settings = self.device = self.wifi = None
            self.device_path = None
            self.server.add_warning(
                f"[wifi_manager]: Wi-Fi adapter '{self.interface}' is unavailable",
                "wifi_manager_adapter"
            )

    async def close(self) -> None:
        self._closed = True
        tasks = [self._operation_task, self._notify_task]
        for task in tasks:
            if task is not None and not task.done():
                task.cancel()
        for task in tasks:
            if task is None:
                continue
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        await self._remove_dbus_handlers()
        self._refresh_pending = False

    async def _remove_dbus_handlers(self) -> None:
        self._desired_ap_paths.clear()
        self._desired_ip4_path = None
        for props, callback in self._property_handlers:
            try:
                props.off_properties_changed(callback)  # type: ignore
            except Exception:
                pass
        self._property_handlers.clear()
        async with self._watcher_lock:
            for path in list(self._ap_property_handlers):
                self._unwatch_access_point(path)
            self._unwatch_ipv4_config()
        for interface, off_method, callback in self._signal_handlers:
            try:
                getattr(interface, off_method)(callback)
            except Exception:
                pass
        self._signal_handlers.clear()
        self._interface_cache.clear()

    async def _get_interface(self, path: str, name: str) -> ProxyInterface:
        key = (path, name)
        cached = self._interface_cache.get(key)
        if cached is not None:
            return cached
        interface = await self.dbus_mgr.get_interface(NM_BUS, path, name)
        self._interface_cache[key] = interface
        return interface

    async def _get_transient_interface(
        self, path: str, name: str
    ) -> ProxyInterface:
        # AccessPoint, ActiveConnection, and IP4Config objects may disappear at
        # any time.  Keeping their proxy interfaces in the component cache can
        # otherwise retain stale NetworkManager objects after an automatic roam.
        return await self.dbus_mgr.get_interface(NM_BUS, path, name)

    async def _watch_properties(self, path: str) -> None:
        props = await self._get_interface(path, DBUS_PROPERTIES_IFACE)
        callback = self._on_properties_changed
        props.on_properties_changed(callback)  # type: ignore
        self._property_handlers.append((props, callback))

    def _watch_signal(
        self, interface: ProxyInterface, signal: str, callback: Any
    ) -> None:
        on_method = f"on_{signal}"
        off_method = f"off_{signal}"
        getattr(interface, on_method)(callback)
        self._signal_handlers.append((interface, off_method, callback))

    async def _sync_access_point_watchers(self, paths: List[str]) -> None:
        if self._closed:
            return
        active_paths = set(paths)
        # Keep a distinct set so add/remove signal handlers can invalidate this
        # in-flight generation without mutating its comparison snapshot.
        self._desired_ap_paths = set(active_paths)
        async with self._watcher_lock:
            if self._closed or active_paths != self._desired_ap_paths:
                return
            for path in set(self._ap_property_handlers) - active_paths:
                self._unwatch_access_point(path)
            for path in active_paths - set(self._ap_property_handlers):
                try:
                    props = await self._get_transient_interface(
                        path, DBUS_PROPERTIES_IFACE
                    )
                    # A newer AP list or a removal signal may arrive while the
                    # transient object is being introspected.  Never install a
                    # handler from that superseded list.
                    if self._closed or active_paths != self._desired_ap_paths:
                        return
                    callback = self._on_access_point_properties_changed
                    props.on_properties_changed(callback)  # type: ignore
                    self._ap_property_handlers[path] = (props, callback)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    # An AP may vanish between GetAllAccessPoints and installing
                    # its signal handler.  The next AP list signal will retry.
                    continue

    def _unwatch_access_point(self, path: str) -> None:
        handler = self._ap_property_handlers.pop(path, None)
        if handler is None:
            return
        props, callback = handler
        try:
            props.off_properties_changed(callback)  # type: ignore
        except Exception:
            pass

    async def _sync_ipv4_watcher(self, path: Optional[str]) -> None:
        if self._closed:
            return
        desired_path = path if path and path != "/" else None
        self._desired_ip4_path = desired_path
        async with self._watcher_lock:
            if self._closed or desired_path != self._desired_ip4_path:
                return
            current = self._ip4_property_handler
            if current is not None and current[0] == desired_path:
                return
            self._unwatch_ipv4_config()
            if desired_path is None:
                return
            try:
                props = await self._get_transient_interface(
                    desired_path, DBUS_PROPERTIES_IFACE
                )
                # A concurrent status read may have observed a replacement
                # IP4Config while introspection was in flight.
                if self._closed or desired_path != self._desired_ip4_path:
                    return
                callback = self._on_ipv4_properties_changed
                props.on_properties_changed(callback)  # type: ignore
                self._ip4_property_handler = (
                    desired_path, props, callback
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                # The IP4Config may be replaced while a lease is changing.  The
                # corresponding Device properties signal will schedule a retry.
                pass

    def _unwatch_ipv4_config(self) -> None:
        handler = self._ip4_property_handler
        self._ip4_property_handler = None
        if handler is None:
            return
        _, props, callback = handler
        try:
            props.off_properties_changed(callback)  # type: ignore
        except Exception:
            pass

    def _on_access_point_added(self, path: str) -> None:
        if self._closed:
            return
        self._desired_ap_paths.add(path)
        self._schedule_notification()

    def _on_access_point_removed(self, path: str) -> None:
        if self._closed:
            return
        self._desired_ap_paths.discard(path)
        self._unwatch_access_point(path)
        self._interface_cache.pop((path, NM_AP_IFACE), None)
        self._schedule_notification()

    def _on_connection_added(self, path: str) -> None:
        self._schedule_notification()

    def _on_connection_removed(self, path: str) -> None:
        self._interface_cache.pop((path, NM_CONNECTION_IFACE), None)
        self._schedule_notification()

    def _on_access_point_properties_changed(
        self, interface: str, changed: Dict[str, Variant], invalidated: List[str]
    ) -> None:
        if interface == NM_AP_IFACE:
            self._schedule_notification()

    def _on_ipv4_properties_changed(
        self, interface: str, changed: Dict[str, Variant], invalidated: List[str]
    ) -> None:
        if interface == NM_IP4_IFACE:
            self._schedule_notification()

    def _on_properties_changed(
        self, interface: str, changed: Dict[str, Variant], invalidated: List[str]
    ) -> None:
        if interface not in (NM_IFACE, NM_DEVICE_IFACE, NM_WIFI_IFACE):
            return
        self._schedule_notification()

    def _schedule_notification(self) -> None:
        if self._closed:
            return
        self._refresh_pending = True
        if self._is_busy():
            return
        if self._notify_task is not None and not self._notify_task.done():
            return
        self._notify_task = self.server.get_event_loop().create_task(
            self._drain_passive_refresh()
        )

    def _resume_pending_refresh(self) -> None:
        if self._refresh_pending and not self._closed and not self._is_busy():
            self._schedule_notification()

    def _on_operation_done(self, task: asyncio.Task) -> None:
        is_current = self._operation_task is task
        if is_current:
            self._operation_task = None
        error: Optional[BaseException] = None
        if not task.cancelled():
            try:
                error = task.exception()
            except asyncio.CancelledError:
                pass
        if error is not None and not self._closed:
            logging.error(
                "[wifi_manager]: Unexpected Wi-Fi operation failure: %s",
                self._safe_dbus_message(error),
            )
            operation = self._operation
            if (
                is_current and operation is not None and
                operation.get("state") == "running"
            ):
                failure = WifiFailure(
                    "internal_error",
                    "NetworkManager could not complete the operation",
                )
                self._finish_operation(False, failure)
                self._schedule_notification()
        self._resume_pending_refresh()

    async def _drain_passive_refresh(self) -> None:
        try:
            while self._refresh_pending and not self._closed:
                await asyncio.sleep(PASSIVE_REFRESH_DELAY)
                async with self._snapshot_lock:
                    # The operation may have started while this task was asleep
                    # or queued for the snapshot lock.  Leave the request pending
                    # so the operation's completion callback drains it once.
                    if self._is_busy():
                        return
                    self._refresh_pending = False
                    await self._refresh_network_snapshot_locked(
                        emit=True, preserve_on_failure=True
                    )
        finally:
            self._notify_task = None
            self._resume_pending_refresh()

    def _network_snapshot(self, status: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "status": dict(status),
            "networks": [dict(item) for item in self._networks],
        }

    def _send_network_snapshot(self, status: Dict[str, Any]) -> None:
        self.server.send_event(
            "machine:wifi_networks_changed",
            self._network_snapshot(status),
        )

    def _reconcile_networks(self, status: Dict[str, Any]) -> bool:
        connected_ssid = (
            status.get("ssid") if status.get("connected") else None
        )
        connected_strength = status.get("strength")
        networks: List[Dict[str, Any]] = []
        for cached in self._networks:
            network = dict(cached)
            connected = bool(
                connected_ssid is not None and
                network.get("ssid") == connected_ssid
            )
            network["connected"] = connected
            if connected and connected_strength is not None:
                network["strength"] = int(connected_strength)
            networks.append(network)
        networks.sort(
            key=lambda item: (
                not item["connected"],
                -item["strength"],
                item["ssid"],
            )
        )
        if networks == self._networks:
            return False
        self._networks = networks
        return True

    async def _refresh_network_snapshot(
        self, *, emit: bool, preserve_on_failure: bool
    ) -> Dict[str, Any]:
        async with self._snapshot_lock:
            return await self._refresh_network_snapshot_locked(
                emit=emit, preserve_on_failure=preserve_on_failure
            )

    async def _refresh_network_snapshot_locked(
        self, *, emit: bool, preserve_on_failure: bool
    ) -> Dict[str, Any]:
        status = await self._read_status()
        changed = False
        try:
            networks = await self._read_networks(status)
        except asyncio.CancelledError:
            raise
        except Exception as err:
            if not preserve_on_failure:
                raise
            # Keep the last complete AP/profile snapshot.  Live connection flags
            # may still be reconciled safely, and an operation error must not be
            # replaced by a passive cache-read failure.
            changed = self._reconcile_networks(status)
            logging.info(
                "[wifi_manager]: Unable to refresh the passive Wi-Fi cache: %s",
                self._safe_dbus_message(err),
            )
        else:
            previous_networks = self._networks
            self._networks = networks
            # The strongest AP returned for an SSID is not necessarily the AP
            # NetworkManager is currently using.  Always apply the live status
            # after rebuilding the cache so the atomic snapshot carries the
            # active AP's strength as well as the correct connected row.
            self._reconcile_networks(status)
            changed = self._networks != previous_networks
        if emit:
            self.server.send_event("machine:wifi_state_changed", status)
            if changed:
                self._send_network_snapshot(status)
        return self._network_snapshot(status)

    async def _emit_status(self, force_snapshot: bool = False) -> None:
        status = await self._read_status()
        networks_changed = self._reconcile_networks(status)
        self.server.send_event("machine:wifi_state_changed", status)
        if force_snapshot or networks_changed:
            self._send_network_snapshot(status)

    def _check_local(self, web_request: WebRequest) -> None:
        ip_addr = web_request.get_ip_address()
        peer_ip_addr = web_request.get_peer_ip_address()
        if (
            ip_addr is None or not ip_addr.is_loopback or
            peer_ip_addr is None or not peer_ip_addr.is_loopback
        ):
            raise self.server.error(
                "permission_denied: Wi-Fi settings are only available on localhost",
                403
            )

    def _ensure_available(self) -> None:
        if any(
            obj is None
            for obj in (self.nm, self.settings, self.device, self.wifi)
        ) or self.device_path is None:
            raise WifiFailure(
                "adapter_unavailable",
                f"Wi-Fi adapter '{self.interface}' is unavailable",
            )

    def _ensure_permissions(self, *permissions: str) -> None:
        if not all(self._permissions.get(name, False) for name in permissions):
            raise WifiFailure(
                "permission_denied",
                "Moonraker is not authorized to perform this Wi-Fi operation"
            )

    def _is_busy(self) -> bool:
        task = self._operation_task
        return self._operation_lock.locked() or (task is not None and not task.done())

    def _raise_failure(self, failure: WifiFailure) -> NoReturn:
        status = ERROR_HTTP_STATUS.get(failure.code, 500)
        raise self.server.error(f"{failure.code}: {failure.message}", status)

    def _new_operation(self, op_type: str, ssid: Optional[str]) -> Dict[str, Any]:
        operation = {
            "id": str(uuid.uuid4()),
            "type": op_type,
            "ssid": ssid,
            "state": "running",
            "started_at": time.time(),
        }
        self._operation = operation
        self._last_error = None
        return operation

    def _finish_operation(
        self,
        succeeded: bool,
        failure: Optional[WifiFailure] = None,
        recovered_ssid: Optional[str] = None,
    ) -> None:
        if self._operation is not None:
            self._operation["state"] = "succeeded" if succeeded else "failed"
        if succeeded:
            self._last_error = None
        elif failure is not None:
            self._last_error = {
                "code": failure.code,
                "message": failure.message,
                "recovered_ssid": recovered_ssid,
            }

    async def _handle_status(self, web_request: WebRequest) -> Dict[str, Any]:
        self._check_local(web_request)
        # Status polling must remain responsive throughout a connect/forget
        # operation, which intentionally owns the snapshot lock for its full
        # lifetime.  The operation itself publishes the authoritative snapshots.
        if self._is_busy():
            return await self._read_status()
        async with self._snapshot_lock:
            # Re-check after waiting behind a passive/cooldown rebuild.  An
            # operation accepted in the meantime must not be blocked here.
            if self._is_busy():
                return await self._read_status()
            status = await self._read_status()
            if self._reconcile_networks(status):
                self._send_network_snapshot(status)
            return status

    async def _handle_scan(self, web_request: WebRequest) -> Dict[str, Any]:
        self._check_local(web_request)
        try:
            self._ensure_available()
            self._ensure_permissions("scan")
            if self._is_busy():
                raise WifiFailure("busy", "Another Wi-Fi operation is running")
            try:
                async with self._snapshot_lock:
                    # A connect/forget request may have been accepted while this
                    # request waited for an in-flight passive snapshot.
                    if self._is_busy():
                        raise WifiFailure(
                            "busy", "Another Wi-Fi operation is running"
                        )
                    elapsed = time.monotonic() - self._last_scan_at
                    if self._last_scan_at and elapsed < SCAN_INTERVAL:
                        return await self._refresh_network_snapshot_locked(
                            emit=True, preserve_on_failure=True
                        )
                    async with self._operation_lock:
                        self._new_operation("scan", None)
                        await self._emit_status()
                        try:
                            await self._request_scan()
                            await self._refresh_network_snapshot_locked(
                                emit=False, preserve_on_failure=False
                            )
                        except asyncio.CancelledError:
                            raise
                        except Exception as err:
                            failure = self._map_exception(err)
                            self._finish_operation(False, failure)
                            await self._emit_status()
                            self._raise_failure(failure)
                        self._finish_operation(True)
                        status = await self._get_status()
                        self.server.send_event(
                            "machine:wifi_state_changed", status
                        )
                        self._send_network_snapshot(status)
                        return self._network_snapshot(status)
            finally:
                self._resume_pending_refresh()
        except WifiFailure as failure:
            self._raise_failure(failure)

    async def _handle_connect(self, web_request: WebRequest) -> Dict[str, str]:
        self._check_local(web_request)
        try:
            self._ensure_available()
            self._ensure_permissions("network", "settings", "checkpoint")
            if self._is_busy():
                raise WifiFailure("busy", "Another Wi-Fi operation is running")
            args = web_request.get_args()
            ssid = args.get("ssid")
            security = args.get("security")
            password = args.get("password")
            if not isinstance(ssid, str) or not isinstance(security, str):
                raise WifiFailure(
                    "invalid_request", "SSID and security must be strings"
                )
            if password is not None and not isinstance(password, str):
                raise WifiFailure("invalid_request", "Password must be a string")
            security = security.strip().lower()
            try:
                ssid_size = len(ssid.encode("utf-8"))
            except UnicodeEncodeError:
                ssid_size = 0
            if not ssid_size or ssid_size > 32 or "\x00" in ssid:
                raise WifiFailure(
                    "invalid_request", "SSID must contain 1 to 32 bytes"
                )
            if security not in ("open", "wpa-psk"):
                raise WifiFailure(
                    "unsupported_security",
                    "Only open and WPA/WPA2 Personal networks are supported",
                )
            if password is not None:
                if security == "open":
                    password = None
                elif not self._valid_psk(password):
                    raise WifiFailure(
                        "invalid_password",
                        "WPA/WPA2 passwords must be 8 to 63 UTF-8 bytes or "
                        "64 hex digits",
                    )
            async with self._snapshot_lock:
                if self._is_busy():
                    raise WifiFailure(
                        "busy", "Another Wi-Fi operation is running"
                    )
                operation = self._new_operation("connect", ssid)
                # Do not retain the caller's argument dictionary or password
                # beyond the operation task.  The task clears its local reference
                # in all paths.
                self._operation_task = self.server.get_event_loop().create_task(
                    self._run_connect(ssid, security, password)
                )
                self._operation_task.add_done_callback(self._on_operation_done)
                await self._emit_status()
                return {"operation_id": operation["id"]}
        except WifiFailure as failure:
            self._raise_failure(failure)

    async def _handle_forget(self, web_request: WebRequest) -> Dict[str, str]:
        self._check_local(web_request)
        try:
            self._ensure_available()
            self._ensure_permissions("network", "settings")
            if self._is_busy():
                raise WifiFailure("busy", "Another Wi-Fi operation is running")
            ssid = web_request.get_args().get("ssid")
            if not isinstance(ssid, str) or not ssid:
                raise WifiFailure("invalid_request", "SSID is required")
            async with self._snapshot_lock:
                if self._is_busy():
                    raise WifiFailure(
                        "busy", "Another Wi-Fi operation is running"
                    )
                operation = self._new_operation("forget", ssid)
                self._operation_task = self.server.get_event_loop().create_task(
                    self._run_forget(ssid)
                )
                self._operation_task.add_done_callback(self._on_operation_done)
                await self._emit_status()
                return {"operation_id": operation["id"]}
        except WifiFailure as failure:
            self._raise_failure(failure)

    async def _request_scan(self) -> None:
        assert self.wifi is not None
        before: int = await self.wifi.get_last_scan()  # type: ignore
        try:
            await self.wifi.call_request_scan({})  # type: ignore
        except Exception as err:
            raise self._map_exception(err)
        deadline = time.monotonic() + SCAN_TIMEOUT
        while time.monotonic() < deadline:
            await asyncio.sleep(.25)
            current: int = await self.wifi.get_last_scan()  # type: ignore
            if current != before:
                self._last_scan_at = time.monotonic()
                return
        raise WifiFailure("timeout", "Timed out while scanning for Wi-Fi networks")

    async def _get_access_points(self) -> List[Dict[str, Any]]:
        self._ensure_available()
        assert self.wifi is not None
        paths: List[str] = await self.wifi.call_get_all_access_points()  # type: ignore
        await self._sync_access_point_watchers(paths)
        access_points: List[Dict[str, Any]] = []
        for path in paths:
            try:
                ap = await self._get_transient_interface(path, NM_AP_IFACE)
                raw_ssid = await ap.get_ssid()  # type: ignore
                ssid = self._decode_ssid(raw_ssid)
                frequency: int = await ap.get_frequency()  # type: ignore
                if not ssid or not 2400 <= frequency <= 2500:
                    continue
                flags: int = await ap.get_flags()  # type: ignore
                wpa_flags: int = await ap.get_wpa_flags()  # type: ignore
                rsn_flags: int = await ap.get_rsn_flags()  # type: ignore
                security = self._classify_security(flags, wpa_flags, rsn_flags)
                if security is None:
                    continue
                access_points.append({
                    "path": path,
                    "ssid": ssid,
                    "security": security,
                    "strength": int(await ap.get_strength()),  # type: ignore
                    "frequency": frequency,
                })
            except asyncio.CancelledError:
                raise
            except Exception as err:
                # A path may legitimately disappear between enumeration and
                # reading.  Other D-Bus failures mean this is not a complete
                # snapshot and must reach the passive preserve-on-failure path.
                if self._is_missing_object_error(err):
                    continue
                raise
        return access_points

    async def _read_networks(
        self, status: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        access_points = await self._get_access_points()
        profiles = await self._get_saved_profiles()
        saved_security: Dict[str, Set[str]] = {}
        for profile in profiles:
            saved_security.setdefault(profile["ssid"], set()).add(profile["security"])
        if status is None:
            status = await self._get_status()
        connected_ssid = status["ssid"] if status["connected"] else None

        grouped: Dict[str, List[Dict[str, Any]]] = {}
        for ap in access_points:
            grouped.setdefault(ap["ssid"], []).append(ap)
        networks: List[Dict[str, Any]] = []
        for ssid, candidates in grouped.items():
            saved = saved_security.get(ssid, set())
            encrypted = [
                ap for ap in candidates if ap["security"] == "wpa-psk"
            ]
            if "wpa-psk" in saved:
                # A saved encrypted profile always wins over a same-name open
                # network, even when the latter advertises a stronger signal.
                if not encrypted:
                    continue
                candidates = encrypted
            elif encrypted:
                # Prefer encryption when the same SSID advertises both variants.
                # If only an obsolete open profile is saved, expose the new
                # encrypted network as unsaved instead of hiding or downgrading it.
                candidates = encrypted
            strongest = max(candidates, key=lambda item: item["strength"])
            networks.append({
                "ssid": ssid,
                "security": strongest["security"],
                "strength": strongest["strength"],
                "saved": strongest["security"] in saved,
                "connected": ssid == connected_ssid,
                "frequency": strongest["frequency"],
            })
        networks.sort(
            key=lambda item: (not item["connected"], -item["strength"], item["ssid"])
        )
        return networks

    async def _run_connect(
        self, ssid: str, security: str, password: Optional[str]
    ) -> None:
        async with self._snapshot_lock:
            await self._run_connect_locked(ssid, security, password)

    async def _run_connect_locked(
        self, ssid: str, security: str, password: Optional[str]
    ) -> None:
        failure: Optional[WifiFailure] = None
        recovered_ssid: Optional[str] = None
        checkpoint: Optional[str] = None
        temp_profile: Optional[str] = None
        temp_settings: Optional[Dict[str, Dict[str, Variant]]] = None
        old_ssid: Optional[str] = None
        try:
            async with self._operation_lock:
                assert self.nm is not None and self.device_path is not None
                initial = await self._get_status()
                old_ssid = initial["ssid"] if initial["connected"] else None
                profiles = await self._get_saved_profiles(ssid)
                matching = [p for p in profiles if p["security"] == security]
                aps = await self._get_access_points()
                candidates = [
                    ap for ap in aps
                    if ap["ssid"] == ssid and ap["security"] == security
                ]
                if not candidates:
                    raise WifiFailure(
                        "network_not_found",
                        "The selected 2.4 GHz network is no longer available",
                    )
                target_ap = max(candidates, key=lambda item: item["strength"])
                if security == "wpa-psk" and password is None and not matching:
                    raise WifiFailure(
                        "invalid_password", "A password is required for this network"
                    )

                checkpoint = await self.nm.call_checkpoint_create(  # type: ignore
                    [self.device_path], CHECKPOINT_TIMEOUT,
                    NM_CHECKPOINT_DELETE_NEW_CONNECTIONS
                )
                if password is not None or not matching:
                    temp_profile, temp_settings = await self._add_unsaved_profile(
                        ssid, security, password
                    )
                    profile_path = temp_profile
                else:
                    profile_path = max(
                        matching,
                        key=lambda item: (
                            item.get("timestamp", 0),
                            self._profile_path_index(item["path"]),
                        ),
                    )["path"]

                activate = self.nm.call_activate_connection  # type: ignore
                active_path: str = await activate(
                    profile_path, self.device_path, target_ap["path"]
                )
                await self._wait_for_connection(active_path)

                if temp_profile is not None:
                    assert temp_settings is not None
                    connection = await self._get_interface(
                        temp_profile, NM_CONNECTION_IFACE
                    )
                    temp_settings["connection"]["autoconnect"] = Variant("b", True)
                    await connection.call_update_unsaved(temp_settings)  # type: ignore
                    await connection.call_save()  # type: ignore
                await self.nm.call_checkpoint_destroy(checkpoint)  # type: ignore
                checkpoint = None
                if temp_profile is not None:
                    for profile in profiles:
                        if profile["path"] != temp_profile:
                            try:
                                await self._delete_profile(profile["path"])
                            except Exception:
                                logging.info(
                                    "[wifi_manager]: Unable to remove an obsolete "
                                    "profile for SSID %s", ssid
                                )
                try:
                    self._networks = await self._read_networks()
                except Exception:
                    # The connection has already been committed.  A stale scan
                    # cache must not turn a successful connection into failure.
                    pass
                self._finish_operation(True)
        except asyncio.CancelledError:
            if checkpoint is not None:
                await self._rollback_checkpoint(checkpoint, temp_profile)
            raise
        except WifiFailure as err:
            failure = err
        except Exception as err:
            failure = self._map_exception(err)
        finally:
            # Drop the only component-owned reference to the supplied password.
            password = None
            if temp_settings is not None:
                security_settings = temp_settings.get(
                    "802-11-wireless-security"
                )
                if security_settings is not None:
                    security_settings.pop("psk", None)
                temp_settings.clear()

        if failure is not None:
            if checkpoint is not None:
                try:
                    await self._rollback_checkpoint(checkpoint, temp_profile)
                except Exception:
                    failure = WifiFailure(
                        "rollback_failed",
                        "Connection failed and the previous network could not "
                        "be restored",
                    )
                recovered_ssid = await self._wait_for_recovery(old_ssid)
                if old_ssid is not None and recovered_ssid is None:
                    failure = WifiFailure(
                        "rollback_failed",
                        "Connection failed and the previous network was not restored",
                    )
            else:
                current = await self._get_status()
                if current["connected"]:
                    recovered_ssid = current["ssid"]
            self._finish_operation(False, failure, recovered_ssid)
        await self._emit_status(force_snapshot=failure is None)

    async def _wait_for_connection(self, active_path: str) -> None:
        active = await self._get_transient_interface(
            active_path, NM_ACTIVE_IFACE
        )
        deadline = time.monotonic() + CONNECT_TIMEOUT
        while time.monotonic() < deadline:
            device_state, reason = await self._get_device_state_reason()
            if (
                device_state == NM_DEVICE_STATE_NEED_AUTH and
                reason in AUTH_FAILURE_REASONS
            ):
                raise WifiFailure(
                    "invalid_password", "NetworkManager rejected the password"
                )
            try:
                active_state: int = await active.get_state()  # type: ignore
            except Exception:
                if reason in AUTH_FAILURE_REASONS:
                    raise WifiFailure(
                        "invalid_password", "NetworkManager rejected the saved password"
                    )
                raise WifiFailure("network_not_found", "The Wi-Fi connection failed")
            if active_state == NM_ACTIVE_CONNECTION_STATE_ACTIVATED:
                status = await self._get_status()
                if status["connected"] and status["ip_address"]:
                    return
            elif (
                active_state == NM_ACTIVE_CONNECTION_STATE_DEACTIVATED or
                device_state == NM_DEVICE_STATE_FAILED
            ):
                if reason in AUTH_FAILURE_REASONS:
                    raise WifiFailure(
                        "invalid_password", "NetworkManager rejected the saved password"
                    )
                raise WifiFailure("network_not_found", "The Wi-Fi connection failed")
            await asyncio.sleep(.25)
        raise WifiFailure("timeout", "Timed out while connecting to the network")

    async def _rollback_checkpoint(
        self, checkpoint: str, temp_profile: Optional[str]
    ) -> None:
        assert self.nm is not None
        result: Dict[str, int] = await self.nm.call_checkpoint_rollback(  # type: ignore
            checkpoint
        )
        if any(code != 0 for code in result.values()):
            raise WifiFailure(
                "rollback_failed",
                "NetworkManager could not restore the previous network",
            )
        if temp_profile is not None:
            try:
                await self._delete_profile(temp_profile)
            except Exception:
                pass

    async def _wait_for_recovery(
        self, expected_ssid: Optional[str]
    ) -> Optional[str]:
        if expected_ssid is None:
            return None
        deadline = time.monotonic() + RECOVERY_TIMEOUT
        while time.monotonic() < deadline:
            status = await self._get_status()
            if status["connected"] and status["ssid"] == expected_ssid:
                return expected_ssid
            await asyncio.sleep(.25)
        return None

    async def _run_forget(self, ssid: str) -> None:
        async with self._snapshot_lock:
            await self._run_forget_locked(ssid)

    async def _run_forget_locked(self, ssid: str) -> None:
        failure: Optional[WifiFailure] = None
        try:
            async with self._operation_lock:
                assert self.nm is not None and self.device is not None
                profiles = await self._get_saved_profiles(ssid)
                if not profiles:
                    raise WifiFailure("network_not_saved", "The network is not saved")
                status = await self._get_status()
                active_path: Optional[str] = None
                if status["connected"] and status["ssid"] == ssid:
                    get_active = getattr(
                        self.device, "get_active_connection"
                    )
                    active_path = await get_active()
                for profile in profiles:
                    await self._delete_profile(profile["path"])
                if active_path and active_path != "/":
                    try:
                        await self.nm.call_deactivate_connection(  # type: ignore
                            active_path
                        )
                    except Exception as err:
                        # Deleting the active profile normally deactivates it.
                        # Ignore only an ActiveConnection object that vanished
                        # because NetworkManager already completed deactivation.
                        if not self._is_missing_object_error(err):
                            raise
                    deadline = time.monotonic() + 5.0
                    while time.monotonic() < deadline:
                        current = await self._get_status()
                        if not current["connected"] or current["ssid"] != ssid:
                            break
                        await asyncio.sleep(.25)
                    else:
                        raise WifiFailure(
                            "internal_error", "The forgotten network did not disconnect"
                        )
                self._networks = [
                    dict(item, saved=False)
                    if item["ssid"] == ssid else item
                    for item in self._networks
                ]
                try:
                    self._networks = await self._read_networks()
                except Exception:
                    pass
                self._finish_operation(True)
        except asyncio.CancelledError:
            raise
        except WifiFailure as err:
            failure = err
        except Exception as err:
            failure = self._map_exception(err)
        if failure is not None:
            self._finish_operation(False, failure)
        await self._emit_status(force_snapshot=failure is None)

    async def _add_unsaved_profile(
        self, ssid: str, security: str, password: Optional[str]
    ) -> Tuple[str, Dict[str, Dict[str, Variant]]]:
        assert self.settings is not None
        wireless: Dict[str, Variant] = {
            "ssid": Variant("ay", ssid.encode("utf-8")),
            "mode": Variant("s", "infrastructure"),
            "hidden": Variant("b", False),
        }
        settings: Dict[str, Dict[str, Variant]] = {
            "connection": {
                "id": Variant("s", ssid),
                "uuid": Variant("s", str(uuid.uuid4())),
                "type": Variant("s", "802-11-wireless"),
                "interface-name": Variant("s", self.interface),
                # Prevent NetworkManager from racing the explicit activation.
                # This is changed to true only after activation succeeds.
                "autoconnect": Variant("b", False),
            },
            "802-11-wireless": wireless,
            "ipv4": {"method": Variant("s", "auto")},
            "ipv6": {"method": Variant("s", "auto")},
        }
        if security == "wpa-psk":
            if password is None:
                raise WifiFailure("invalid_password", "A password is required")
            wireless["security"] = Variant("s", "802-11-wireless-security")
            settings["802-11-wireless-security"] = {
                "key-mgmt": Variant("s", "wpa-psk"),
                "psk": Variant("s", password),
            }
        path = await self.settings.call_add_connection_unsaved(settings)  # type: ignore
        return path, settings

    async def _get_saved_profiles(
        self, only_ssid: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        self._ensure_available()
        assert self.settings is not None
        paths: List[str] = await self.settings.call_list_connections()  # type: ignore
        profiles: List[Dict[str, Any]] = []
        for path in paths:
            try:
                connection = await self._get_interface(path, NM_CONNECTION_IFACE)
                raw = await connection.call_get_settings()  # type: ignore
                conn = raw.get("connection", {})
                if self._variant_value(conn.get("type")) != "802-11-wireless":
                    continue
                iface = self._variant_value(conn.get("interface-name"), "")
                if iface and iface != self.interface:
                    continue
                wireless = raw.get("802-11-wireless", {})
                ssid = self._decode_ssid(
                    self._variant_value(wireless.get("ssid"), b"")
                )
                if not ssid or (only_ssid is not None and ssid != only_ssid):
                    continue
                sec = raw.get("802-11-wireless-security")
                if sec is None:
                    security = "open"
                else:
                    key_mgmt = self._variant_value(sec.get("key-mgmt"), "")
                    if key_mgmt != "wpa-psk":
                        continue
                    security = "wpa-psk"
                profiles.append({
                    "path": path,
                    "ssid": ssid,
                    "security": security,
                    "timestamp": int(
                        self._variant_value(conn.get("timestamp"), 0) or 0
                    ),
                })
            except asyncio.CancelledError:
                raise
            except Exception as err:
                if self._is_missing_object_error(err):
                    continue
                raise
        return profiles

    async def _delete_profile(self, path: str) -> None:
        connection = await self._get_interface(path, NM_CONNECTION_IFACE)
        await connection.call_delete()  # type: ignore
        self._interface_cache.pop((path, NM_CONNECTION_IFACE), None)

    async def _get_status(self) -> Dict[str, Any]:
        status = await self._read_status()
        self._reconcile_networks(status)
        return status

    async def _read_status(self) -> Dict[str, Any]:
        base: Dict[str, Any] = {
            "interface": self.interface,
            "available": False,
            "state": "unavailable",
            "connected": False,
            "ssid": None,
            "strength": None,
            "ip_address": None,
            "connectivity": "unknown",
            "operation": dict(self._operation) if self._operation else None,
            "last_error": dict(self._last_error) if self._last_error else None,
        }
        try:
            self._ensure_available()
            assert self.nm is not None
            assert self.device is not None
            assert self.wifi is not None
            device_state: int = await self.device.get_state()  # type: ignore
            connectivity: int = await self.device.get_ip4_connectivity()  # type: ignore
            base["available"] = device_state > NM_DEVICE_STATE_UNAVAILABLE
            base["connectivity"] = CONNECTIVITY_STATES.get(
                connectivity, "unknown"
            )
            if device_state == NM_DEVICE_STATE_ACTIVATED:
                ap_path: str = await self.wifi.get_active_access_point()  # type: ignore
                if ap_path and ap_path != "/":
                    ap = await self._get_transient_interface(
                        ap_path, NM_AP_IFACE
                    )
                    raw_ssid = await ap.get_ssid()  # type: ignore
                    base["ssid"] = self._decode_ssid(raw_ssid)
                    base["strength"] = int(await ap.get_strength())  # type: ignore
                    base["ip_address"] = await self._get_ipv4_address()
                    base["connected"] = bool(base["ssid"] and base["ip_address"])
                else:
                    await self._sync_ipv4_watcher(None)
            else:
                await self._sync_ipv4_watcher(None)
            operation = self._operation
            if (
                operation and
                operation["state"] == "running" and
                operation["type"] == "connect"
            ):
                base["state"] = "connecting"
            elif base["connected"]:
                base["state"] = "connected"
            elif device_state < NM_DEVICE_STATE_DISCONNECTED:
                base["state"] = "unavailable"
            elif device_state == NM_DEVICE_STATE_DISCONNECTED:
                base["state"] = "disconnected"
            elif device_state == NM_DEVICE_STATE_FAILED:
                base["state"] = "error"
            else:
                base["state"] = "connecting"
        except asyncio.CancelledError:
            raise
        except Exception:
            pass
        return base

    async def _get_ipv4_address(self) -> Optional[str]:
        assert self.device is not None
        path: str = await self.device.get_ip4_config()  # type: ignore
        if not path or path == "/":
            await self._sync_ipv4_watcher(None)
            return None
        await self._sync_ipv4_watcher(path)
        ip4 = await self._get_transient_interface(path, NM_IP4_IFACE)
        data: List[Dict[str, Variant]] = await ip4.get_address_data()  # type: ignore
        for address in data:
            value = self._variant_value(address.get("address"))
            if isinstance(value, str) and value:
                return value
        return None

    async def _get_device_state_reason(self) -> Tuple[int, int]:
        assert self.device is not None
        state: int = await self.device.get_state()  # type: ignore
        state_reason = await self.device.get_state_reason()  # type: ignore
        return state, int(state_reason[1])

    @staticmethod
    def _variant_value(value: Any, default: Any = None) -> Any:
        if value is None:
            return default
        return value.value if isinstance(value, Variant) else value

    @staticmethod
    def _profile_path_index(path: str) -> int:
        try:
            return int(path.rsplit("/", 1)[-1])
        except (TypeError, ValueError):
            return -1

    @classmethod
    def _is_missing_object_error(cls, err: Exception) -> bool:
        message = cls._safe_dbus_message(err).lower()
        return any(token in message for token in (
            "unknown object",
            "unknown connection",
            "object does not exist",
            "object was removed",
            "no such object",
        ))

    @staticmethod
    def _decode_ssid(value: Any) -> str:
        if isinstance(value, Variant):
            value = value.value
        if isinstance(value, list):
            value = bytes(value)
        if isinstance(value, bytearray):
            value = bytes(value)
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace").strip("\x00")
        return str(value) if value else ""

    @staticmethod
    def _valid_psk(password: str) -> bool:
        try:
            byte_length = len(password.encode("utf-8"))
        except UnicodeEncodeError:
            return False
        if 8 <= byte_length <= 63:
            return True
        return (
            len(password) == 64 and
            all(char in "0123456789abcdefABCDEF" for char in password)
        )

    @staticmethod
    def _classify_security(
        flags: int, wpa_flags: int, rsn_flags: int
    ) -> Optional[str]:
        security_flags = wpa_flags | rsn_flags
        unsupported = (
            NM_AP_SEC_KEY_MGMT_802_1X |
            NM_AP_SEC_KEY_MGMT_SAE |
            NM_AP_SEC_KEY_MGMT_OWE
        )
        if security_flags & NM_AP_SEC_KEY_MGMT_PSK:
            return "wpa-psk"
        if security_flags & unsupported:
            return None
        if not flags & NM_AP_FLAGS_PRIVACY and security_flags == 0:
            return "open"
        # Privacy without WPA/RSN key management indicates WEP.
        return None

    def _map_exception(self, err: Exception) -> WifiFailure:
        if isinstance(err, WifiFailure):
            return err
        message = self._safe_dbus_message(err).lower()
        if any(token in message for token in (
            "not authorized", "notauthorized", "permission"
        )):
            return WifiFailure(
                "permission_denied", "NetworkManager denied the requested operation"
            )
        if any(token in message for token in (
            "no secrets", "password", "psk"
        )):
            return WifiFailure(
                "invalid_password", "NetworkManager rejected the password"
            )
        if "not found" in message or "unknown connection" in message:
            return WifiFailure(
                "network_not_found", "The selected network is unavailable"
            )
        return WifiFailure(
            "internal_error", "NetworkManager could not complete the operation"
        )

    @staticmethod
    def _safe_dbus_message(err: BaseException) -> str:
        # D-Bus errors may contain object names but should never include request
        # settings.  Keep log output bounded and strip line breaks regardless.
        return str(err).replace("\n", " ")[:300]


def load_component(config: ConfigHelper) -> WifiManager:
    return WifiManager(config)
