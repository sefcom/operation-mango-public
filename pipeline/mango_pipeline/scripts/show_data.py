import rich
import subprocess
import sys
import json
import datetime

from collections import Counter
from functools import reduce

from pathlib import Path
from rich.progress import track
from rich.table import Table
from rich.console import Console


def get_all_data(result_dir: Path, de_dup=True):
    possible_starts = {
        "/home/clasm/projects/angr-squad/",
        "/shared/clasm/",
        "/tmp/firmwar",
    }
    all_jsons = (
        subprocess.check_output(
            ["find", result_dir, "-type", "f", "-iname", "cmdi_results.json"]
        )
        .decode()
        .strip()
        .split("\n")
    )
    all_jsons += (
        subprocess.check_output(
            ["find", result_dir, "-type", "f", "-iname", "overflow_results.json"]
        )
        .decode()
        .strip()
        .split("\n")
    )
    result_data = []
    vendor_data = json.loads((result_dir / "vendors.json").read_text())
    known_cmdi_shas = set()
    known_overflow_shas = set()
    for x in track(all_jsons, description="Extracting JSON Data", total=len(all_jsons)):
        if not x:
            continue

        p = Path(x)
        try:
            d = json.loads(p.read_text())
        except:
            continue

        symbols = json.loads((p.parent.parent / "symbols.json").read_text())
        d["vendor"] = symbols["brand"]
        d["firmware"] = symbols["firmware"]
        d["firm_path"] = "/".join(Path(x).parts[-3:])

        if "vendor" not in d:
            breakpoint()

        if de_dup and (
            d["path"].replace("shared/clasm", "home/clasm/projects/angr-squad")
            != vendor_data[d["vendor"]]["firmware"][d["firmware"]]["elfs"][d["sha256"]][
                "path"
            ]
        ):
            continue

        if de_dup:
            if "cmdi" in d["firm_path"]:
                if d["sha256"] in known_cmdi_shas:
                    continue
                known_cmdi_shas.add(d["sha256"])
            elif "overflow" in d["firm_path"]:
                if d["sha256"] in known_overflow_shas:
                    continue
                known_overflow_shas.add(d["sha256"])
        result_data.append(d)
    return result_data


def generate_mango_table(raw_data, show_firm, title) -> Table:
    """Make a new table."""
    table = Table(title=title)
    table.add_column("Vendor")
    if show_firm:
        table.add_column("Device")
    table.add_column("Binaries")
    table.add_column("[green]Binaries Hit")
    table.add_column("Binaries Resolved")
    table.add_column("No Sinks")
    table.add_column("[green]Total Hits")
    table.add_column("[red]Error")
    table.add_column("[blue]Timeout")
    table.add_column("[yellow]OOM")
    table.add_column("Analysis Time", justify="right")

    seen_bins = set()
    table_data = {}
    for bin_data in raw_data:
        vendor = bin_data["vendor"]
        if show_firm:
            vendor = bin_data["firmware"]
        seen = bin_data["firm_path"] in seen_bins
        if not seen:
            seen_bins.add(bin_data["firm_path"])
        if vendor not in table_data:
            table_data[vendor] = {
                "binaries": 0,
                "binaries_with_alerts": 0,
                "binaries_resolved": 0,
                "no_sinks": 0,
                "total_alerts": 0,
                "errors": 0,
                "timeouts": 0,
                "oom": 0,
                "time_taken": 0,
                "unique_sinks": Counter(),
                "alerted_sinks": Counter(),
                "sinks": Counter(),
                "vendor": bin_data["vendor"],
            }

        alerts = len(bin_data["closures"])
        has_sinks = bin_data["has_sinks"]
        resolved = has_sinks and not alerts > 0
        error = bin_data["error"] is not None
        timeout = error and bin_data["ret_code"] == 124
        oom = error and bin_data["ret_code"] == -9

        mango_time = bin_data["mango_time"]
        if isinstance(mango_time, list):
            mango_time = sum(mango_time)

        table_data[vendor]["binaries"] += 1 if not seen else 0
        table_data[vendor]["binaries_with_alerts"] += alerts > 0 and not seen
        table_data[vendor]["binaries_resolved"] += resolved and not seen
        table_data[vendor]["no_sinks"] += not has_sinks and not seen
        table_data[vendor]["total_alerts"] += alerts
        table_data[vendor]["errors"] += error and not timeout and not oom
        table_data[vendor]["timeouts"] += timeout
        table_data[vendor]["oom"] += oom
        table_data[vendor]["time_taken"] += (
            (mango_time or 0)
            + (bin_data["cfg_time"] or 0)
            + (bin_data["vra_time"] or 0)
        )
        table_data[vendor]["alerted_sinks"].update(
            Counter([c["sink"]["function"] for c in bin_data["closures"]])
        )
        unique_sinks = {
            c["sink"]["function"] + "-" + c["sink"]["ins_addr"]
            for c in bin_data["closures"]
        }
        for c in unique_sinks:
            name = c.split("-")[0]
            table_data[vendor]["unique_sinks"][name] += 1
        if "sinks" in bin_data:
            table_data[vendor]["sinks"].update(bin_data["sinks"])

    for idx, data in enumerate(
        sorted(table_data.items(), key=lambda r: r[1]["vendor"] + r[0])
    ):
        vendor, row = data
        row_data = [
            f"{row['vendor']}",
            f"{row['binaries']}",
            f"[green]{row['binaries_with_alerts']}",
            f"{row['binaries_resolved']}",
            f"{row['no_sinks']}",
            f"[green]{row['total_alerts']}",
            f"[red]{row['errors']}",
            f"[blue]{row['timeouts']}",
            f"[yellow]{row['oom']}",
            str(datetime.timedelta(seconds=int(row["time_taken"]))),
        ]
        if show_firm:
            row_data.insert(1, vendor)
        table.add_row(*row_data, end_section=idx == len(list(table_data)) - 1)
    final_sinks = Counter()
    final_unique_sinks = Counter()
    final_alerted_sinks = Counter()
    for x in table_data.values():
        final_sinks.update(x["sinks"])
        final_unique_sinks.update(x["unique_sinks"])
        final_alerted_sinks.update(x["alerted_sinks"])
    table_data["total"] = {
        "binaries": sum(x["binaries"] for x in table_data.values()),
        "binaries_with_alerts": sum(
            x["binaries_with_alerts"] for x in table_data.values()
        ),
        "binaries_resolved": sum(x["binaries_resolved"] for x in table_data.values()),
        "no_sinks": sum(x["no_sinks"] for x in table_data.values()),
        "total_alerts": sum(x["total_alerts"] for x in table_data.values()),
        "errors": sum(x["errors"] for x in table_data.values()),
        "timeouts": sum(x["timeouts"] for x in table_data.values()),
        "oom": sum(x["oom"] for x in table_data.values()),
        "time_taken": sum(x["time_taken"] for x in table_data.values()),
        "sinks": final_sinks,
        "unique_sinks": final_unique_sinks,
        "alerted_sinks": final_alerted_sinks,
    }
    row_data = [
        "Total",
        str(table_data["total"]["binaries"]),
        f"[green]{table_data['total']['binaries_with_alerts']}",
        f"{table_data['total']['binaries_resolved']}",
        f"{table_data['total']['no_sinks']}",
        f"[green]{table_data['total']['total_alerts']}",
        f"[red]{table_data['total']['errors']}",
        f"[blue]{table_data['total']['timeouts']}",
        f"[yellow]{table_data['total']['oom']}",
        str(datetime.timedelta(seconds=int(table_data["total"]["time_taken"]))),
    ]
    if show_firm:
        row_data.insert(1, "-")
    table.add_row(*row_data)
    return table, table_data


def print_table(
    result_data: list,
    orig_dir: Path,
    show_firm=False,
    unique=False,
    show_sinks=False,
    print_latex=False,
    title="Mango Results",
):
    if unique:
        unique_data = {}
        for d in result_data:
            if "sha" in d:
                sha = d["sha"]
                del d["sha"]
                d["sha256"] = sha
            unique_data[d["sha256"]] = d

        result_data = list(unique_data.values())

    with open(orig_dir.name + ".list", "w+") as f:
        shas = [
            x["firm_path"]
            for x in result_data
            if x["has_sinks"] and x["error"] is None and len(x["closures"]) > 0
        ]
        f.write("\n".join(sorted(shas)))
    table, table_data = generate_mango_table(
        result_data, show_firm=show_firm, title=title
    )
    with Console() as console:
        console.print(table)
        if show_sinks:
            console.print("Total Sinks", table_data["total"]["sinks"])
            console.print("Alerted Sinks", table_data["total"]["alerted_sinks"])
            console.print("Unique Sinks", table_data["total"]["unique_sinks"])
        if print_latex:
            name = orig_dir.name.replace("-", "").replace("_", "")
            for vendor, data in table_data.items():
                console.print(f"%{'-'*50}")
                console.print(f"%{name.upper()} {vendor.upper()} DATA")
                console.print(f"%{'-'*50}")
                for k, v in data.items():
                    if k == "time_taken":
                        analyzed_bins = (
                            data["binaries_with_alerts"] + data["binaries_resolved"]
                        )
                        out = f"\\newcommand{{\\{name}{vendor}AVGTimePerBin}}{{{v/analyzed_bins:.2f}\\xspace}}"
                        console.print(out)
                        v = str(datetime.timedelta(seconds=int(v)))
                    elif k in {"unique_sinks", "sinks", "alerted_sinks"}:
                        continue
                    out = f"\\newcommand{{\\{name}{vendor}{k.replace('_','')}}}{{{v}\\xspace}}"
                    console.print(out)


if __name__ == "__main__":
    only_unique = False
    print_latex = False
    combine = False
    firmware = False
    sinks = False
    if any(x == "-u" or x == "--unique" for x in sys.argv[1:]):
        only_unique = True
    if any(x == "-l" or x == "--latex" for x in sys.argv[1:]):
        print_latex = True
    if any(x == "-c" or x == "--combine" for x in sys.argv[1:]):
        combine = True
    if any(x == "-f" or x == "--firmware" for x in sys.argv[1:]):
        firmware = True
    if any(x == "-s" or x == "--sinks" for x in sys.argv[1:]):
        sinks = True
    all_data = []
    for res_dir in sys.argv[1:]:
        if res_dir in {
            "-u",
            "--unique",
            "-l",
            "--latex",
            "-c",
            "--combine",
            "-f",
            "--firmware",
            "-s",
            "--sinks",
        }:
            continue
        res_d = Path(res_dir).absolute()
        data = get_all_data(res_d, de_dup=False)

        if not combine:
            print_table(
                data,
                res_d,
                unique=only_unique,
                show_firm=firmware,
                show_sinks=sinks,
                print_latex=print_latex,
                title=res_d.name,
            )
        else:
            all_data.extend(data)
    if combine:
        print_table(
            all_data,
            Path("combined"),
            unique=only_unique,
            show_firm=firmware,
            show_sinks=sinks,
            print_latex=print_latex,
            title="combined",
        )
