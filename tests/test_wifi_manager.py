from __future__ import annotations

import pytest

from moonraker.components.wifi_manager import (
    NM_AP_FLAGS_PRIVACY,
    NM_AP_SEC_KEY_MGMT_802_1X,
    NM_AP_SEC_KEY_MGMT_PSK,
    WifiManager,
)


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
