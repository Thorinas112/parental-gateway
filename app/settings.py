"""Runtime settings persisted in the database, with env/config fallbacks.

The setup wizard lets an operator choose the LAN/WAN interfaces and subnet at
install time without editing ``.env``. Values written here take precedence over
the environment so the wizard is genuinely effective rather than cosmetic.
"""

from __future__ import annotations

from typing import Any

from .config import Config
from .models import get_setting, set_setting

K_LAN_IFACE = "network.lan_iface"
K_WAN_IFACE = "network.wan_iface"
K_LAN_SUBNET = "network.lan_subnet"


def _clean(value: Any, fallback: str = "") -> str:
    return (str(value).strip() if value is not None else "") or fallback


def lan_iface() -> str:
    return _clean(get_setting(K_LAN_IFACE), _clean(Config.LAN_IFACE, "eth0"))


def wan_iface() -> str:
    return _clean(get_setting(K_WAN_IFACE), _clean(Config.WAN_IFACE, lan_iface()))


def lan_subnet() -> str:
    """Configured client subnet (CIDR) or '' when it should be auto-detected."""
    return _clean(get_setting(K_LAN_SUBNET), _clean(Config.LAN_SUBNET, ""))


def set_network(
    lan: str | None = None,
    wan: str | None = None,
    subnet: str | None = None,
) -> None:
    if lan is not None:
        set_setting(K_LAN_IFACE, _clean(lan, "eth0"))
    if wan is not None:
        set_setting(K_WAN_IFACE, _clean(wan, _clean(lan, "eth0")))
    if subnet is not None:
        set_setting(K_LAN_SUBNET, _clean(subnet))


def network_summary() -> dict[str, str]:
    return {
        "lan_iface": lan_iface(),
        "wan_iface": wan_iface(),
        "lan_subnet": lan_subnet(),
    }
