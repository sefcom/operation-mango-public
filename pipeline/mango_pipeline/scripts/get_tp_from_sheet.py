import sys
import json
import subprocess
import csv

from pathlib import Path
from rich.table import Table
from rich.console import Console



def get_csv_data(csv_path: Path, prev=False, delim="\t"):
    out_data = {}
    title = []
    vendor = None
    firmware = None
    sha = None
    name = None
    cfg_time = None
    vra_time = None
    analysis_time = None
    found_bins = set()
    found_header = False

    with open(csv_path, newline='') as csvfile:
        spamreader = csv.reader(csvfile, delimiter=delim, quotechar='|')
        for line in spamreader:

            if line and line[0].strip() in ["Brand", "Firmware"]:
                if not title:
                    title = line
                found_header = not found_header
                continue

            if not found_header:
                continue

            if line and line[0]:
                vendor, firmware, sha, name = line[:4]
                cfg_time, vra_time, analysis_time = [float(x) if x else 0 for x in line[8:11]]

                if not vendor in out_data:
                    out_data[vendor] = {}
                if not firmware in out_data[vendor]:
                    out_data[vendor][firmware] = {}
                if not sha in out_data[vendor][firmware]:
                    out_data[vendor][firmware][sha] = {"name": name, "cfg_time": cfg_time, "vra_time": vra_time, "analysis_time": analysis_time, "rows": {}}
                else:
                    out_data[vendor][firmware][sha]["analysis_time"] += analysis_time
                    out_data[vendor][firmware][sha]["cfg_time"] = max(analysis_time, out_data[vendor][firmware][sha]["cfg_time"])
                    out_data[vendor][firmware][sha]["vra_time"] = max(analysis_time, out_data[vendor][firmware][sha]["vra_time"])
                continue

            if not any(x for x in line):
                continue

            if prev:
                line = line[1:]
            addr = line[5]
            out_data[vendor][firmware][sha]["rows"][addr] = line
    return out_data, title


def get_tp_count(csv_data, results_path):
    tp_dict = {}
    for brand, firm_dict in csv_data.items():
        for firmware, bin_dict in firm_dict.items():
            for sha, vals in bin_dict.items():
                val_dict = {}
                for row in vals["rows"].values():
                    key = row[6].strip()
                    if key not in val_dict:
                        val_dict[key] = 0
                    val_dict[key] += 1

                tp_dict[sha] = val_dict

    vendor_data = json.loads((results_path / "vendors.json").read_text())
    data_dict = {}
    for brand, firm_dict in vendor_data.items():
        data_dict[brand] = {}
        for firmware, elf_dict in firm_dict["firmware"].items():
            data_dict[brand][firmware] = {}
            for elf in elf_dict["elfs"]:
                if elf in tp_dict:
                    for key in tp_dict[elf]:
                        if key not in data_dict[brand][firmware]:
                            data_dict[brand][firmware][key] = 0
                        data_dict[brand][firmware][key] += tp_dict[elf][key]

    data_dict.pop("huawei_fastboot")
    data_dict.pop("lk")
    data_dict.pop("NVIDIA")
    all_keys = sorted({y for x in tp_dict.values() for y in x})

    table = Table(title="Total Data Info")
    table.add_column("Brand/Firmware")
    for key in all_keys:
        table.add_column(key)

    brand_data = {b: {x: 0 for x in all_keys} for b in data_dict}
    for brand, firmware_dict in data_dict.items():
        for firmware, values in firmware_dict.items():
            firmware_dict = {x: 0 for x in all_keys}
            for key, val in values.items():
                if key in firmware_dict:
                    brand_data[brand][key] += val
                    firmware_dict[key] += val
            #table.add_row(firmware, *[str(firmware_dict[x]) for x in all_keys])
        table.add_row(brand, *[str(brand_data[brand][x]) for x in all_keys])

    table.add_row("Total", *[str(sum(brand_data[b][x] for b in brand_data)) for x in all_keys])
    Console().print(table)


if __name__ == '__main__':
    sheet = Path(sys.argv[1])
    data, _ = get_csv_data(sheet, prev=True)
    results = Path(sys.argv[2])
    get_tp_count(data, results)
