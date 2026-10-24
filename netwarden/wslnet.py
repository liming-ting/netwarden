"""
netwarden - wslnet.py: what WSL's networking means for netwarden (detection + advice).

Under WSL 2 with mirrored networking the Linux side shares the Windows LAN address, but
the Hyper-V firewall (on by default since WSL 2.0.9) drops INBOUND connections from the
LAN - so `run --lan` listens, yet a phone cannot reach it. Microsoft's documented fix
is a Hyper-V firewall rule for the WSL VM creator id
(learn.microsoft.com/windows/wsl/networking, "Mirrored mode networking"):

    New-NetFirewallHyperVRule -Name ... -DisplayName ... -Direction Inbound
        -VMCreatorId '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}' -Protocol TCP -LocalPorts N

and Remove-NetFirewallHyperVRule -Name ... to take it away again. netwarden NEVER runs
these: it only shows them (CLI banner, `pair`, the pairing card) for the user to paste
into an administrator PowerShell. The rule is limited to the home subnet when known.

The same firewall is why multicast replies (mDNS / SSDP) rarely reach WSL; identify.py
therefore also asks every device directly (unicast), and /api/status explains a quiet
result calmly (health.hints: status.hint.ident_silent_unicast).
"""
from __future__ import annotations

import ipaddress
from pathlib import Path

WSL_VM_CREATOR_ID = "{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}"
PROC_VERSION = Path("/proc/version")
RULE_PREFIX = "netwarden-lan-"


def is_wsl(proc_version: Path | None = None) -> bool:
    """Running inside WSL? (/proc/version names Microsoft's kernel.)"""
    try:
        text = (proc_version or PROC_VERSION).read_text(errors="replace")[:500]
    except OSError:
        return False
    return "microsoft" in text.lower()   # "...-microsoft-standard-WSL2"


def _subnet(lan_ip: str | None, network=None) -> str | None:
    """The private /N the LAN address sits in ("192.168.1.0/24"), or None if unsure."""
    try:
        ip = ipaddress.ip_address(lan_ip or "")
    except ValueError:
        return None
    if network is not None:
        try:
            net = ipaddress.ip_network(str(network), strict=False)
        except ValueError:
            net = None
        if net is not None and ip in net and net.is_private and net.prefixlen >= 8:
            return str(net)
    if ip.version == 4 and ip.is_private:
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    return None


def firewall_commands(port: int, lan_ip: str | None = None, network=None) -> dict:
    """{"allow", "remove", "name", "subnet"}: the two administrator PowerShell lines
    for `port` (only ever shown, never executed). Every value is built from an int
    port and a validated subnet, so nothing user-typed ends up in a command."""
    port = int(port)
    if not 0 < port < 65536:
        raise ValueError("port out of range")
    name = f"{RULE_PREFIX}{port}"
    subnet = _subnet(lan_ip, network)     # str(ip_network): digits, dots and "/" only
    allow = (f'New-NetFirewallHyperVRule -Name "{name}" -DisplayName "netwarden (port {port})" '
             f"-Direction Inbound -VMCreatorId '{WSL_VM_CREATOR_ID}' -Protocol TCP "
             f"-LocalPorts {port}" + (f" -RemoteAddresses {subnet}" if subnet else ""))
    return {"name": name, "subnet": subnet, "allow": allow,
            "remove": f'Remove-NetFirewallHyperVRule -Name "{name}"'}


def advice(port: int, lan_ip: str | None = None, network=None,
           proc_version: Path | None = None) -> dict | None:
    """firewall_commands() when running under WSL, else None (nothing to explain)."""
    if not is_wsl(proc_version):
        return None
    return firewall_commands(port, lan_ip, network)


def cli_lines(lang: str, port: int, lan_ip: str | None = None, network=None,
              proc_version: Path | None = None) -> list[str]:
    """What `run --lan` and `pair` print under WSL (localized; [] elsewhere)."""
    from netwarden import i18n
    a = advice(port, lan_ip, network, proc_version)
    if not a:
        return []
    t = lambda k, **kw: i18n.t("cli.wsl." + k, lang, **kw)  # noqa: E731
    return [t("firewall", port=port), t("allow"), "    " + a["allow"], t("remove"),
            "    " + a["remove"]]
