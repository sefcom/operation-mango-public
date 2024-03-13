import os
import sys
import subprocess
import json
import hashlib

from pathlib import Path

import binwalk

from rich.progress import Progress

from .keyword_finder import find_keywords
from .elf_info import FS_LIST


class FirmwareFinder:
    """
    The Finder assumes that each Vendor is a top-level directory in the given target directory.
    """

    def __init__(
        self, target_dir: Path, results_dir: Path, bin_prep=False, exclude_libs=True
    ):
        self.target_dir = target_dir.absolute().resolve()
        self.results_dir = results_dir
        self.exclude_libs = exclude_libs
        vendor_file = results_dir / "vendors.json"
        if vendor_file.exists() and not bin_prep:
            try:
                self.vendor_dict = json.loads(vendor_file.read_text())
            except json.decoder.JSONDecodeError:
                self.vendor_dict = {}
        else:
            self.vendor_dict = {}
        if bin_prep or not self.vendor_dict:
            new_vendor_dict = self.search()
            self.vendor_dict.update(new_vendor_dict)
            with open(vendor_file, "w+") as f:
                json.dump(self.vendor_dict, f, indent=4)

    def extract_firmware(self, vendor):
        for root, _, files in os.walk(vendor):
            for file in files:
                f = Path(root) / file
                if f.is_file():
                    modules = binwalk.scan(str(f), signature=True, quiet=True)
                    if any("filesystem" in x.description for result in modules for x in result.results):
                        binwalk.scan(str(f), signature=True, extract=True, quiet=True)

    def search(self):
        vendors = [x for x in self.target_dir.iterdir() if x.is_dir()]
        vendor_dict = dict()
        with Progress() as progress:
            progress.stop()
            vendor_task_str = "[red]Scanning Vendor"
            vendor_task = progress.add_task(
                f"{vendor_task_str} ...", total=len(vendors)
            )
            for idx, vendor in enumerate(vendors):
                progress.update(
                    vendor_task,
                    description=f"{vendor_task_str} {vendor.name} [{idx}/{len(vendors)}]",
                )
                found_fs = self.find_extracted_fs(vendor)
                if not found_fs:
                    self.extract_firmware(vendor)
                    found_fs = self.find_extracted_fs(vendor)
                vendor_dict[vendor.name] = {"path": str(vendor), "firmware": dict()}
                fs_task_str = "[green]Iterating FS"
                fs_task = progress.add_task(f"{fs_task_str} ...", total=len(found_fs))
                for fs_idx, fs in enumerate(found_fs):
                    keywords = find_keywords(fs, progress=progress)
                    firm_name = self.firm_name_from_path(fs)
                    if firm_name is None:
                        continue

                    progress.update(
                        fs_task,
                        description=f"{fs_task_str} {firm_name} [{fs_idx}/{len(found_fs)}]",
                    )
                    elf_dict = self.find_elf_files(
                        fs, progress, exclude_libs=self.exclude_libs
                    )

                    if firm_name in vendor_dict[vendor.name]["firmware"]:
                        vendor_dict[vendor.name]["firmware"][firm_name]["elfs"].update(
                            elf_dict
                        )
                    else:
                        vendor_dict[vendor.name]["firmware"][firm_name] = {
                            "path": str(fs.parent),
                            "elfs": elf_dict,
                        }
                    firmware = self.results_dir / vendor.name / firm_name
                    firmware.mkdir(exist_ok=True, parents=True)
                    progress.print("WRITING FILE", str(firmware / "vendor.json"))
                    with (firmware / "vendor.json").open("w+") as f:
                        json.dump(
                            vendor_dict[vendor.name]["firmware"][firm_name], f, indent=4
                        )
                    with (firmware / "keywords.json").open("w+") as f:
                        json.dump(keywords, f, indent=4)
                    progress.update(fs_task, advance=1)

                progress.update(fs_task, visible=False)
                progress.update(vendor_task, advance=1)
        return vendor_dict

    @staticmethod
    def firm_name_from_path(path: Path):
        if path.parent.name == "fw" or path.parent.name == "firmware":
            path = path.parent
        firm_name = (
            path.parent.name.replace(".bin", "")
            .replace(".extracted", "")
            .replace(".chk", "")
            .strip("_")
        )
        black_list = ["functions", "kernel", "qemu", "net", "squashfs-root"]
        if "qemu" in firm_name.lower() or firm_name.lower() in black_list:
            return None
        return firm_name

    @staticmethod
    def find_extracted_fs(root_dir: Path):
        found_fs = []
        for fs in FS_LIST:
            command = ["find", str(root_dir), "-type", "d", "-name", f"{fs}*"]
            output = subprocess.check_output(command)
            current_fs = [Path(x) for x in output.decode().split("\n") if x]
            # if any(fs.name in FS_LIST for fs in current_fs):
            #    current_fs = [fs for fs in current_fs if fs.name in FS_LIST]

            found_fs.extend(current_fs)
        return found_fs

    @staticmethod
    def find_elf_files(root_dir: Path, progress, exclude_libs=True):

        BANNED_LIST = ["busybox"]

        elf_task_str = "[cyan]Finding ELFs"
        elf_task = progress.add_task(f"{elf_task_str} ...", total=None)
        output = subprocess.check_output(
            ["find", str(root_dir), "-type", "f", "-exec", "file", "{}", ";"]
        )
        elfs = [
            x
            for x in output.decode().split("\n")
            if "ELF" in x and (not exclude_libs or "shared object" not in x)
        ]
        progress.update(
            elf_task, description=f"{elf_task_str} [0/{len(elfs)}]", total=len(elfs)
        )
        progress.start_task(elf_task)
        elf_dict = {}
        for idx, elf in enumerate(elfs):
            path = Path(elf.split(":")[0].strip())
            if path.is_symlink():
                continue
            if path.name in BANNED_LIST:
                continue
            with path.open("rb") as f:
                sha256 = hashlib.file_digest(f, "sha256").hexdigest()
                elf_dict[sha256] = {"path": str(path)}
            progress.update(
                elf_task, description=f"{elf_task_str} [{idx+1}/{len(elfs)}]", advance=1
            )
        progress.update(elf_task, visible=False)

        return elf_dict


if __name__ == "__main__":
    FirmwareFinder(Path(sys.argv[1]))
