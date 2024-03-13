import sys
import subprocess
import json
import argparse

from rich.table import Table
from rich.console import Console
from rich.progress import track
from pathlib import Path


def parse_mango_result(data_path: Path, dataset: Path):
    output = subprocess.check_output(["find", data_path, "-type", "f", "-name", "*_results.json"]).decode().strip().split("\n")

    total_dict = {"Vendors": {}, "Firmware": {}}
    for file in track(output, description="Loading files", total=len(output)):
        fp = Path(file)
        if not fp.is_file():
            continue
        try:
            data = json.loads(fp.read_text())
            path = Path(data["path"])
            if dataset is not None:
                new_path = dataset / '/'.join(path.parts[path.parts.index(dataset.name)+1:])
            mango_time = data["mango_time"]
            if isinstance(mango_time, list):
                mango_time = sum(mango_time)
            file_res = {
                "brand": fp.parent.parent.parent.name,
                "firmware": fp.parent.parent.name,
                "has_sinks": data["has_sinks"],
                "time": (mango_time + data["vra_time"] + data["cfg_time"]) if data["error"] is None else 0,
                "hits": len(data["closures"]),
                "trupocs": len([x for x in data["closures"] if x["rank"] >= 7]),
                "error": data["ret_code"] if data["error"] else 0,
                "size": new_path.stat().st_size if dataset is not None else 0,
            }
        except json.decoder.JSONDecodeError:
            file_res = {
                "brand": fp.parent.parent.parent.name,
                "firmware": fp.parent.parent.name,
                "has_sinks": False,
                "time": 0,
                "hits": 0,
                "trupocs": 0,
                "error": "early_termination",
                "size": 0,
            }
        firm = file_res["firmware"]
        brand = file_res["brand"]

        if firm in total_dict["Firmware"]:
            total_dict["Firmware"][firm].append(file_res)
        else:
            total_dict["Firmware"][firm] = [file_res]

        if brand in total_dict["Vendors"]:
            total_dict["Vendors"][brand].append(file_res)
        else:
            total_dict["Vendors"][brand] = [file_res]

    return total_dict


def show_table(results: dict, show_firm):
    """Make a new table."""
    rows = []

    brand_data = {}
    for firm, res in results["Firmware"].items():
        firm_data = {"binaries": len(res), "bin_hits": 0, "resolved": 0, "no_sinks": 0, "hits": 0, "errors": 0, "timeouts": 0, "time": 0, "OOMKILLED": 0, "size": 0, "trupocs": 0, "trupoc_bins": 0}
        for r in res:
            firm_data["binaries"] += 1
            firm_data["size"] += r["size"]
            if r["hits"] > 0:
                firm_data["bin_hits"] += 1
                firm_data["hits"] += r["hits"]
                firm_data["trupocs"] += r["trupocs"]
                if r["trupocs"] > 0:
                    firm_data["trupoc_bins"] += 1
            elif r["error"] == 0:
                firm_data["resolved"] += 1
            elif r["error"] != 0:
                if r["error"] == 124:
                    firm_data["timeouts"] += 1
                    firm_data["time"] += 3 *60 *60
                elif r["error"] == -9:
                    firm_data["OOMKILLED"] += 1
                else:
                    firm_data["errors"] += 1

            if r["time"] < 0:
                r["time"] = 3 * 60 * 60
            firm_data["time"] += r["time"]
        if r["brand"] not in brand_data:
            brand_data[r["brand"]] = [firm_data]
        else:
            brand_data[r["brand"]].append(firm_data)

        firm_data["no_sinks"] = firm_data["binaries"] - (firm_data["bin_hits"] + firm_data["resolved"])
        if show_firm:
            rows.append([firm, "", f'{firm_data["binaries"]:,}', f'{firm_data["bin_hits"]:,}', f'{firm_data["trupoc_bins"]:,}', f'{firm_data["resolved"]:,}', f'{firm_data["no_sinks"]:,}', f'{firm_data["hits"]:,}', f'{firm_data["trupocs"]}', f'{firm_data["errors"]:,}', f'{firm_data["OOMKILLED"]:,}', f'{firm_data["timeouts"]:,}', f"{firm_data['time']/60:,.2f} Min", "", "", f"{firm_data['time']/(firm_data['binaries'] + firm_data['timeouts']):.2f} Sec"])

    total_data = {"binaries": 0, "bin_hits": 0, "resolved": 0, "no_sinks": 0, "hits": 0, "errors": 0, "timeouts": 0, "time": 0, "OOMKILLED": 0, "firm": 0, "size": 0, "trupocs": 0, "trupoc_bins": 0}
    for brand, data in brand_data.items():
        bins =      sum(x["binaries"] for x in data)
        bin_hits =  sum(x["bin_hits"] for x in data)
        resolved =  sum(x["resolved"] for x in data)
        no_sinks =  sum(x["no_sinks"] for x in data)
        hits =      sum(x["hits"] for x in data)
        trupocs =   sum(x["trupocs"] for x in data)
        trupoc_bins = sum(x["trupoc_bins"] for x in data)
        errors =    sum(x["errors"] for x in data)
        oomkilled = sum(x["OOMKILLED"] for x in data)
        timeouts =  sum(x["timeouts"] for x in data)
        size =      f"{(sum(x['size'] for x in data)/int(bins)):,.2f} B"
        time =      f"{(sum(x['time'] for x in data)/60):,.2f} Min"
        avg =      f"{(sum(x['time'] for x in data)/60)/len(data):,.2f} Min"
        avg_bin =  f"{(sum(x['time'] for x in data))/(int(bins) + int(timeouts)):.2f} Sec"

        total_data["binaries"] += int(bins)
        total_data["bin_hits"] += int(bin_hits)
        total_data["resolved"] += int(resolved)
        total_data["no_sinks"] += int(no_sinks)
        total_data["hits"] += int(hits)
        total_data["errors"] += int(errors)
        total_data["OOMKILLED"] += int(oomkilled)
        total_data["timeouts"] += int(timeouts)
        total_data["time"] += sum(x['time'] for x in data)
        total_data["firm"] += len(data)
        total_data["size"] += sum(x["size"] for x in data)
        total_data["trupocs"] += int(trupocs)
        total_data["trupoc_bins"] += int(trupoc_bins)


        rows.append([brand, f"{len(data):,}", f"{bins:,}", f"{bin_hits:,}", f"{trupoc_bins:,}", f"{resolved:,}", f"{no_sinks:,}", f"{hits:,}", f"{trupocs:,}", f"{errors:,}", f"{oomkilled:,}", f"{timeouts:,}", time, avg, size, avg_bin])
    rows.append(["Total", f'{total_data["firm"]:,}', f'{total_data["binaries"]:,}', f'{total_data["bin_hits"]:,}', f'{total_data["trupoc_bins"]:,}',  f'{total_data["resolved"]:,}', f'{total_data["no_sinks"]:,}', f'{total_data["hits"]:,}', f'{total_data["trupocs"]:,}', f'{total_data["errors"]:,}', str(total_data["OOMKILLED"]), str(total_data["timeouts"]), f"{total_data['time']/60:,.2f} Min", f"{(total_data['time']/(sum(len(x) for x in brand_data.values()) or 1))/60:.2f} Min", f"{total_data['size']/(total_data['binaries'] or 1):.2f} B", f"{(total_data['time']/(total_data['binaries'] or 1)):.2f} Sec"])

    table = Table(title="MANGO RESULTS", show_footer=True)
    table.add_column("Name", rows[-1][0])
    offset = 0
    table.add_column("# Firm", rows[-1][1], justify="right")
    offset = 1
    table.add_column("Binaries", rows[-1][1+offset], justify="right")
    table.add_column("[green]Alerted Bins", rows[-1][2+offset], justify="right")
    table.add_column("[bold green]TruPoC Bins", rows[-1][3+offset], justify="right")
    table.add_column("Binaries Resolved", rows[-1][4+offset], justify="right")
    table.add_column("No Sinks", rows[-1][5+offset], justify="right")
    table.add_column("[green]Alerts", rows[-1][6+offset], justify="right")
    table.add_column("[bold green]TruPoCs", rows[-1][7+offset], justify="right")
    table.add_column("[red]Error", rows[-1][8+offset], justify="right")
    table.add_column("[yellow]OOMKilled", rows[-1][9+offset], justify="right")
    table.add_column("[blue]Timeout", rows[-1][10+offset], justify="right")
    table.add_column("Analysis Time", rows[-1][11+offset], justify="right")
    table.add_column("AVG Time", rows[-1][12+offset], justify="right")
    #table.add_column("Avg Size", rows[-1][13+offset], justify="right")
    table.add_column("AVG Bin Time", rows[-1][14+offset], justify="right")
    found_start = False
    for idx, x in enumerate(rows[:-1]):
        if show_firm and not found_start and idx+1 < len(rows) and rows[idx+1][0] in brand_data:
            table.add_row(*x[:-2], x[-1], end_section=True)
            found_start = True
        else:
            table.add_row(*x[:-2], x[-1])

    Console().print(table)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("result_dir", type=str, help="Path to result directory")
    parser.add_argument("--dataset", type=str, default=None, help="Path to dataset used in experiment (only useful for binary size data)")
    parser.add_argument("--show-firmware", action="store_true", default=False, help="Show data by firmware instead of by vendor")
    args = parser.parse_args()

    results = parse_mango_result(args.result_dir, args.dataset)
    show_table(results, show_firm=args.show_firmware)

