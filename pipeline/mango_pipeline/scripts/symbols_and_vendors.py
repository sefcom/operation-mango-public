import sys
import subprocess
import json

import collections.abc
from pathlib import Path

def update(d, u):
    for k, v in u.items():
        if isinstance(v, collections.abc.Mapping):
            d[k] = update(d.get(k, {}), v)
        else:
            d[k] = v
    return d



if __name__ == '__main__':
    folder = sys.argv[1]
    vendors = subprocess.check_output(["find", folder, "-type", "f", "-name", "vendor.json"]).decode().strip().split("\n")
    symbols = subprocess.check_output(["find", folder, "-type", "f", "-name", "symbols.json"]).decode().strip().split("\n")
    vendor_out = {}
    for vendor_file in vendors:
        if vendor_file == Path(folder) / "vendor.json":
            continue
        with open(vendor_file, "r") as f:
            vendor_data = json.load(f)
            p = Path(vendor_file)
            vendor_data = {p.parent.parent.name: {"firmware": {p.parent.name: vendor_data}}}
            vendor_out = update(vendor_out, vendor_data)

    with open(Path(folder) / "vendor.json", "w+") as f:
        json.dump(vendor_out, f)

    symbol_out = {}
    for symbol_file in symbols:
        if symbol_file == Path(folder) / "symbols.json":
            continue
        with open(symbol_file, "r") as f:
            symbol_data = json.load(f)
            if "symbols" not in symbol_data:
                continue
            symbol_out.update(symbol_data["symbols"])

    with open(Path(folder) / "symbols.json", "w+") as f:
        json.dump(symbol_out, f)
