from typing import List
from pathlib import Path

FS_LIST = ["squashfs-root", "ubifs-root", "cpio-root", "fs"]


class ELFInfo:
    possible_lib_locations = [
        "/dumaos/ngcompat",
        "/etc",
        "/iQoS/R8900/TM",
        "/iQoS/R8900/tm_key",
        "/iQoS/R9000/TM",
        "/iQoS/R9000/tm_key",
        "/lib",
        "/lib/lua",
        "/lib/pptpd",
        "/tmp/root/lib",
        "/tmp/root/usr/lib",
        "/usr/lib",
        "/usr/lib/ebtables",
        "/usr/lib/forked-daapd",
        "/usr/lib/iptables",
        "/usr/lib/lua",
        "/usr/lib/lua/socket",
        "/usr/lib/pppd/2.4.3",
        "/usr/lib/tc",
        "/usr/lib/uams",
        "/usr/lib/xtables",
        "/usr/local/lib/openvpn/plugins",
        "/usr/share",
    ]

    def __init__(
        self, path: str, brand: str, firmware: str, sha: str, ld_paths: list = None
    ):
        self.path = path
        self.brand = brand
        self.firmware = firmware
        self.sha = sha
        if ld_paths is None:
            self.ld_paths = self.get_lib_locations()
        else:
            self.ld_paths = ld_paths

    def get_lib_locations(self) -> List[str]:
        firmware_fs = None
        for fs in FS_LIST:
            if fs in self.path:
                firmware_fs = fs
                break
        firmware_root = (
            Path(self.path[: self.path.index(firmware_fs)] + firmware_fs)
            .absolute()
            .resolve()
        )
        return [
            str(firmware_root / x)
            for x in ELFInfo.possible_lib_locations
            if (firmware_root / x).exists
        ]

    def __hash__(self):
        return hash(self.path)

    def to_dict(self):
        return {
            "path": self.path,
            "brand": self.brand,
            "firmware": self.firmware,
            "sha": self.sha,
            "ld_paths": self.ld_paths,
        }

    def __repr__(self):
        return str(self)

    def __str__(self):
        return f"<ELFInfo {self.brand} {self.firmware} {Path(self.path).name}>"